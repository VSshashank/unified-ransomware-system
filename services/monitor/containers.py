"""Structural validation of a declared container format - AS.

The false-positive mitigation in detection.py trusts a file's first four bytes:
high entropy that a declared ZIP, PNG or JPEG header explains is compression,
not encryption. Four bytes cost an attacker nothing. The `spoofer` family in
scripts/ransomware_simulator.py writes exactly those four bytes over its
ciphertext, and reports/simulator_families.json records the result - 0 of 8
files flagged, verdict `benign_compressed`, reason "entropy 7.99 explained by
zip container". The mitigation was turned into the evasion.

This module asks the question a magic byte cannot: is the rest of the file
shaped like the format it claims to be? A container format is a structure, not a
prefix. ZIP frames each member in a local header and closes with a central
directory. PNG CRCs its image header and ends with IEND. JPEG chains
length-prefixed marker segments up to the start of scan. PDF numbers its objects
and names the offset of its cross-reference table. ISO base media tiles its boxes
end to end. Ciphertext satisfies none of them, and an encryptor that wanted to
satisfy them would have to leave enough real structure behind to still *be* that
format - which is the whole point. The cost of borrowing the exemption goes from
four bytes to a working encoder.

Three outcomes, not two
-----------------------
A file that is still being written also fails a structural check, and it fails
it for an innocent reason: an archiver appending to a 500MB ZIP has no central
directory yet, and a video export has no `moov` yet. Calling that forged would
invent a false-positive class that did not exist before - and it would fire on
every large legitimate write, which is worse than the hole it closes.

So every validator here separates two questions:

    does the *leading* structure parse?   -> is this the format at all
    is the *terminal* structure present?  -> is it finished

    head ok, tail ok      VALID        the format, complete
    head ok, tail absent  INCOMPLETE   the format, still being written
    head bad              FORGED       a header pasted over something else

`container_status` returns those by name; `validate_container` projects them to
the tri-state the detector consumes, where INCOMPLETE and "no validator for this
format" both become None - no verdict, keep the behaviour that existed before
this module. A file mid-write gets the benefit of the doubt and is judged
properly on the next write event, which arrives milliseconds later.

`None` for an unvalidated format is load-bearing and is not a failure. Treating
"I cannot parse RAR" as "this RAR is encrypted" would convert every format
without a validator into an alert, which is precisely the false-positive failure
this layer exists to prevent. Only the formats in `_VALIDATORS` are decided;
everything else keeps the behaviour it had before.

Known limits, stated rather than hidden:

  * A ZIP whose central directory sits between the sampled head and the sampled
    tail is checked for bounds but not for signature - reaching it would mean a
    third read on the detection path.
  * GZIP has no terminal check here. Its CRC-32 trailer can only be verified by
    inflating the whole member, so a truncated GZIP reads as VALID.
  * A JPEG truncated *before* its start-of-scan marker - the first few hundred
    bytes of a write - reads as FORGED rather than INCOMPLETE.

Every check is bounded. This runs on the detection path, which has a sub-100ms
budget, so each walk stops after MAX_WALK_RECORDS records or MAX_WALK_BYTES
bytes, and nothing inflates more than _GZIP_PROBE_OUTPUT bytes.
"""

from __future__ import annotations

import re
import struct
import zlib

# How much of the end of a file the terminal checks need. A ZIP's
# end-of-central-directory record may be followed by a comment of up to 65535
# bytes, which is the longest any validator here has to reach back through.
CONTAINER_TAIL_BYTES = 64 * 1024

# Walk bounds. A forged structure fails inside the first record or two; walking
# further buys nothing and costs latency on every legitimate file.
MAX_WALK_RECORDS = 64
MAX_WALK_BYTES = 256 * 1024

VALID = "valid"
FORGED = "forged"
INCOMPLETE = "incomplete"
UNVALIDATED = "unvalidated"
UNREADABLE = "unreadable"


# ------------------------------------------------------------------------ zip

_ZIP_LOCAL_HEADER = b"PK\x03\x04"
_ZIP_CENTRAL_HEADER = b"PK\x01\x02"
_ZIP_EOCD = b"PK\x05\x06"
_ZIP_SPANNED = b"PK\x07\x08"
_ZIP_EOCD_SIZE = 22
_ZIP_LOCAL_HEADER_SIZE = 30

# Compression methods APPNOTE assigns. Stored and deflate are essentially all
# that occur; the rest are listed so a legitimate exotic archive is not called a
# forgery. The value matters because it is two bytes an encryptor does not get
# to choose - random bytes land outside this set 99.97% of the time.
_ZIP_METHODS = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 19, 20, 93, 94, 95, 96, 97, 98})


def _zip_head(head: bytes) -> bool:
    """Does the first local file header parse as one?"""
    if head.startswith(_ZIP_EOCD):
        return True  # an empty archive is nothing but its EOCD

    body = head[4:] if head.startswith(_ZIP_SPANNED) else head
    if not body.startswith(_ZIP_LOCAL_HEADER) or len(body) < _ZIP_LOCAL_HEADER_SIZE:
        return False

    version, flags, method, _time, _date, _crc, _csize, _usize, name_length, extra_length = struct.unpack(
        "<HHHHHIIIHH", body[4:_ZIP_LOCAL_HEADER_SIZE]
    )
    if method not in _ZIP_METHODS or version > 100:
        return False
    if not 1 <= name_length <= 4096 or extra_length > 4096:
        return False

    name = body[_ZIP_LOCAL_HEADER_SIZE : _ZIP_LOCAL_HEADER_SIZE + name_length]
    if len(name) < name_length:
        return True  # header is sound, the name is past the sample
    # Member names are text. Control bytes in one mean these were never a name.
    return all(byte >= 0x20 or byte in (0x09,) for byte in name)


def _zip_tail(head: bytes, tail: bytes, size: int) -> bool:
    index = tail.rfind(_ZIP_EOCD)
    if index < 0 or len(tail) - index < _ZIP_EOCD_SIZE:
        return False

    record = tail[index : index + _ZIP_EOCD_SIZE]
    entries, directory_size, directory_offset, comment_length = struct.unpack("<HIIH", record[10:22])

    # Everything after the record is the archive comment, and its length is
    # declared. A record whose declared comment does not reach exactly the end
    # of the file is not the record that closes this archive.
    if len(tail) - index - _ZIP_EOCD_SIZE != comment_length:
        return False
    if entries == 0:
        return directory_size == 0

    # `tail` is a suffix of the file, so its own start is size - len(tail).
    tail_start = size - len(tail)
    if directory_offset + directory_size > tail_start + index:
        return False

    signature = _bytes_at(head, tail, tail_start, directory_offset, len(_ZIP_CENTRAL_HEADER))
    return signature is None or signature == _ZIP_CENTRAL_HEADER


def _validate_zip(head: bytes, tail: bytes, size: int) -> str:
    if not _zip_head(head):
        return FORGED
    return VALID if _zip_tail(head, tail, size) else INCOMPLETE


def _bytes_at(head: bytes, tail: bytes, tail_start: int, offset: int, length: int) -> bytes | None:
    """`length` bytes at absolute `offset`, or None when neither sample holds them."""
    if offset < 0 or length <= 0:
        return None
    if offset + length <= len(head):
        return head[offset : offset + length]
    if offset >= tail_start:
        start = offset - tail_start
        if start + length <= len(tail):
            return tail[start : start + length]
    return None


# ----------------------------------------------------------------------- gzip

# Enough of the stream to prove it inflates, and a cap on what that is allowed
# to produce. A gzip member is self-describing from its first block, so a
# forgery fails immediately; the caps exist so a legitimate 1MB member does not
# cost a megabyte of inflation on the detection path.
_GZIP_PROBE_BYTES = 64 * 1024
_GZIP_PROBE_OUTPUT = 64 * 1024


def _validate_gzip(head: bytes, tail: bytes, size: int) -> str:
    """Header fields, then a bounded inflate.

    The two header bytes after the magic are checkable on their own - deflate is
    the only compression method ever assigned, and three of the flag bits are
    reserved and must be zero - but they are only two bytes, and two bytes are
    as forgeable as four. The inflate is what actually costs something: to pass
    it an encryptor has to emit a real deflate stream.

    No INCOMPLETE state: gzip's only terminal structure is a CRC-32 over the
    uncompressed data, which cannot be checked without inflating the whole
    member. A truncated gzip therefore reads as VALID here.
    """
    if len(head) < 18:  # 10-byte header + a minimal member + 8-byte trailer
        return FORGED
    if head[2] != 8:  # CM: deflate
        return FORGED
    if head[3] & 0xE0:  # FLG: reserved bits
        return FORGED

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    produced = decompressor.decompress(head[:_GZIP_PROBE_BYTES], _GZIP_PROBE_OUTPUT)
    # A truncated member is expected - only a prefix was fed in - so "no error"
    # is the pass condition rather than "reached the end". It still has to have
    # produced something, or a file that is all header would pass.
    return VALID if (produced or decompressor.eof) else FORGED


# ------------------------------------------------------------------------ png

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_PNG_IEND = b"\x00\x00\x00\x00IEND\xaeB`\x82"
_PNG_IHDR_LENGTH = 13
_PNG_HEADER_END = 8 + 4 + 4 + _PNG_IHDR_LENGTH + 4


def _validate_png(head: bytes, tail: bytes, size: int) -> str:
    """IHDR first with a correct CRC, IEND last.

    The CRC-32 is what makes this expensive to forge: four bytes computed over a
    header the encryptor does not control, so it cannot be carried across from
    the original file while the pixel data underneath is replaced.
    """
    if not head.startswith(_PNG_MAGIC) or len(head) < _PNG_HEADER_END:
        return FORGED
    if head[12:16] != b"IHDR" or int.from_bytes(head[8:12], "big") != _PNG_IHDR_LENGTH:
        return FORGED
    if zlib.crc32(head[12:29]) != int.from_bytes(head[29:33], "big"):
        return FORGED
    if int.from_bytes(head[16:20], "big") == 0 or int.from_bytes(head[20:24], "big") == 0:
        return FORGED

    return VALID if tail.endswith(_PNG_IEND) else INCOMPLETE


# ----------------------------------------------------------------------- jpeg

# Markers that stand alone - no length field follows them.
_JPEG_STANDALONE = frozenset({0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9})
_JPEG_SOS = 0xDA
_JPEG_EOI = b"\xff\xd9"
# Some encoders and camera pipelines append a little padding after EOI. A short
# allowance keeps those legitimate without letting the check pass on a file
# where those two bytes merely occur by chance somewhere in the middle.
_JPEG_EOI_SLACK = 64


def _jpeg_head(head: bytes, size: int) -> bool:
    """Walk the marker chain from SOI to the start of scan.

    Reaching SOS is the bar rather than "some segments parsed", because every
    encoder writes the whole header block before any scan data - so a JPEG
    caught mid-write still has SOS, while random bytes have to guess their way
    to a 0xDA marker through length fields they do not control.
    """
    if not head.startswith(b"\xff\xd8"):
        return False

    offset = 2
    segments = 0
    limit = min(len(head), MAX_WALK_BYTES)

    while offset + 4 <= limit and segments < MAX_WALK_RECORDS:
        if head[offset] != 0xFF:
            return False
        marker = head[offset + 1]
        if marker == 0xFF:  # fill byte before the real marker
            offset += 1
            continue
        if marker in _JPEG_STANDALONE:
            offset += 2
            continue
        if marker == _JPEG_SOS:
            # Entropy-coded scan data follows and is not length-framed.
            return segments > 0
        length = int.from_bytes(head[offset + 2 : offset + 4], "big")
        if length < 2 or offset + 2 + length > size:
            return False
        offset += 2 + length
        segments += 1

    return False


def _validate_jpeg(head: bytes, tail: bytes, size: int) -> str:
    if not _jpeg_head(head, size):
        return FORGED
    complete = tail.rfind(_JPEG_EOI) >= len(tail) - len(_JPEG_EOI) - _JPEG_EOI_SLACK
    return VALID if complete else INCOMPLETE


# ------------------------------------------------------------------------ pdf

_PDF_OBJECT = re.compile(rb"\d+\s+\d+\s+obj")
_PDF_OBJECT_PROBE = 64 * 1024
_PDF_EOF = b"%%EOF"
# The trailer is the last thing written and %%EOF closes it. A little trailing
# whitespace is normal; a megabyte of ciphertext after it is not.
_PDF_EOF_SLACK = 64


def _validate_pdf(head: bytes, tail: bytes, size: int) -> str:
    """`%PDF-` and a numbered object, then `startxref` and `%%EOF` at the end.

    The five-byte header alone is no better than a magic number, so the leading
    check also requires a real indirect-object definition - `12 0 obj`. Random
    bytes produce that pattern about once in 70,000 sampled files.
    """
    if not head.startswith(b"%PDF-"):
        return FORGED
    if not _PDF_OBJECT.search(head[:_PDF_OBJECT_PROBE]):
        return FORGED

    if b"startxref" not in tail and b"startxref" not in head:
        return INCOMPLETE
    index = tail.rfind(_PDF_EOF)
    complete = index >= 0 and len(tail) - index - len(_PDF_EOF) <= _PDF_EOF_SLACK
    return VALID if complete else INCOMPLETE


# ------------------------------------------------------------------- iso-bmff

_BOX_TYPE = re.compile(rb"[A-Za-z0-9 \xa9\-_]{4}")
# Box types large enough to run past the end of a file that is still being
# written. A declared size that overruns EOF is only forgiven for one of these -
# random bytes reach a four-character type from this set about once in 10^9
# files, so the forgiveness cannot be borrowed by a forgery.
_BMFF_STREAMING_BOXES = frozenset({b"mdat", b"moov", b"moof", b"mfra", b"free", b"skip", b"meta", b"uuid"})


def _validate_iso_bmff(head: bytes, tail: bytes, size: int) -> str:
    """MP4/MOV/M4A: a chain of length-prefixed boxes with `ftyp` first.

    Every box declares its own size and the sizes have to tile the file exactly.
    A real container's media payload is high entropy - that is what compressed
    video is - but the frame around it is not, and the frame is what is checked.
    """
    if head[4:8] != b"ftyp":
        return FORGED

    offset = 0
    boxes = 0
    limit = min(len(head), MAX_WALK_BYTES)

    while offset + 8 <= limit and boxes < MAX_WALK_RECORDS:
        box_size = int.from_bytes(head[offset : offset + 4], "big")
        box_type = head[offset + 4 : offset + 8]
        if not _BOX_TYPE.fullmatch(box_type):
            return FORGED

        if box_size == 1:  # 64-bit size in the eight bytes that follow
            if offset + 16 > len(head):
                return INCOMPLETE
            box_size = int.from_bytes(head[offset + 8 : offset + 16], "big")
        elif box_size == 0:  # runs to end of file; only legal for the last box
            return VALID if boxes >= 1 else FORGED

        if box_size < 8:
            return FORGED
        if offset + box_size > size:
            # The chain is sound up to a box that has not finished landing.
            return INCOMPLETE if box_type in _BMFF_STREAMING_BOXES else FORGED

        offset += box_size
        boxes += 1
        if offset == size:
            return VALID if boxes >= 2 else FORGED

    # Ran out of sampled head with the chain still intact. `ftyp` plus at least
    # one more box that tiles correctly is as much as a bounded read can see.
    return VALID if boxes >= 2 else FORGED


# -------------------------------------------------------------------- dispatch

_VALIDATORS = {
    "zip": _validate_zip,
    "gzip": _validate_gzip,
    "png": _validate_png,
    "jpeg": _validate_jpeg,
    "pdf": _validate_pdf,
    "iso-bmff": _validate_iso_bmff,
}

# The formats a FORGED can be returned for. Exposed so callers - and the
# write-up - can state exactly which containers are decided and which are taken
# on trust, rather than implying the check is universal.
VALIDATED_FORMATS = frozenset(_VALIDATORS)


def container_status(
    head: bytes, tail: bytes, container: str | None, size: int | None = None
) -> str:
    """VALID / FORGED / INCOMPLETE / UNVALIDATED / UNREADABLE for one file.

    `head` is the leading sample the detector already read; `tail` must be a
    suffix of the same file (pass `head` itself when the file is small enough
    that the head *is* the whole file). `size` is the file's real length, which
    ZIP's offset arithmetic and ISO-BMFF's box tiling both need; it defaults to
    the larger sample, which is correct exactly when the file fits in one.
    """
    validator = _VALIDATORS.get(container or "")
    if validator is None:
        return UNVALIDATED
    if not head:
        # No bytes to judge. A locked or empty file is not a forged one, and
        # answering FORGED here would flag every file the reader lost a race with.
        return UNREADABLE
    if size is None:
        size = max(len(head), len(tail))

    try:
        return validator(head, tail, size)
    except (struct.error, ValueError, IndexError, zlib.error):
        # A structure that cannot be parsed at all has failed, and failing is
        # the answer - not an exception escaping onto the detection path.
        return FORGED


def validate_container(
    head: bytes, tail: bytes, container: str | None, size: int | None = None
) -> bool | None:
    """`container_status` as the tri-state the detector consumes.

    True is VALID, False is FORGED, and None is everything else - no validator,
    still being written, or nothing readable. None means "no verdict", and the
    caller must keep whatever behaviour it had without this check.
    """
    status = container_status(head, tail, container, size)
    if status == VALID:
        return True
    if status == FORGED:
        return False
    return None


# --------------------------------------------------- declared compression yield

# The high-entropy container exemption rests on a premise: the format explains
# the randomness. For the two general-purpose compressors that have validators
# here, that premise is checkable against the container's own declarations. If
# the archive stored its payload verbatim, or ran a compressor over it that
# achieved nothing, then the container transformed nothing - and whatever made
# the bytes random was there before the container was.
#
# This is deliberately not a new structural validator. Chapter 9 §9.13 rules
# those out for the eleven unvalidated formats, and nothing here validates
# anything: it reads sizes a valid archive has already declared about itself.

_ZIP_CENTRAL_SIZE = 46
_ZIP64_SENTINEL = 0xFFFFFFFF
_ZIP_STORED = 0
_ZIP_MAX_MEMBERS = 256

# 0.95 rather than 1.0. Deflate over incompressible input still emits stored
# blocks with a five-byte header every 65535 bytes, and a small archive pays a
# fixed central-directory cost - both put a genuinely-uncompressed ratio either
# side of 1.0. Anything that compressed even five percent is credited.
COMPRESSION_YIELD_THRESHOLD = 0.95

# Formats this is measured for. Deliberately only the general-purpose
# compressors: a noisy photograph is genuinely explained by JPEG, and a PNG of
# noise is a real PNG whose deflate could not help it. Holding those to a
# compression ratio would call the format a liar for doing its job.
COMPRESSION_MEASURED_FORMATS = frozenset({"zip", "gzip"})


def _zip_declared_sizes(tail: bytes) -> tuple[int, int, bool, int]:
    """Sum the central directory's declared sizes.

    Returns `(compressed, uncompressed, any_method_declared, members_read)`.
    The central directory sits at the end of the archive, so `tail` is where it
    is; a member whose sizes are the ZIP64 sentinel keeps its real sizes in an
    extra field and is skipped rather than guessed at.
    """
    compressed = uncompressed = members = 0
    declares = False
    index = tail.find(_ZIP_CENTRAL_HEADER)
    while index >= 0 and members < _ZIP_MAX_MEMBERS:
        record = tail[index : index + _ZIP_CENTRAL_SIZE]
        if len(record) < _ZIP_CENTRAL_SIZE:
            break
        (method,) = struct.unpack("<H", record[10:12])
        csize, usize = struct.unpack("<II", record[20:28])
        if method != _ZIP_STORED:
            declares = True
        if csize != _ZIP64_SENTINEL and usize != _ZIP64_SENTINEL and usize > 0:
            compressed += csize
            uncompressed += usize
            members += 1
        index = tail.find(_ZIP_CENTRAL_HEADER, index + 1)
    return compressed, uncompressed, declares, members


def _gzip_yield(head: bytes) -> tuple[float | None, str]:
    """Bytes produced per byte consumed by a bounded inflate of the head.

    `_validate_gzip` already runs this inflate to prove the stream is real; this
    reads the same operation for a second fact. Deflate over ciphertext emits
    stored blocks, so it returns very close to one byte out per byte in. Deflate
    over anything compressible returns several.
    """
    consumed_input = head[:_GZIP_PROBE_BYTES]
    if len(consumed_input) < 18:
        return None, "member shorter than a gzip header and trailer"
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    produced = decompressor.decompress(consumed_input, _GZIP_PROBE_OUTPUT)
    consumed = len(consumed_input) - len(decompressor.unconsumed_tail)
    if consumed <= 0 or not produced:
        return None, "inflate produced nothing measurable"
    return len(produced) / consumed, (
        f"bounded inflate: {len(produced)} bytes out of {consumed} in"
    )


def compression_evidence(
    head: bytes, tail: bytes, container: str | None, size: int | None = None
) -> dict | None:
    """Did this container actually compress what it carries?

    Returns None for every format outside COMPRESSION_MEASURED_FORMATS - the
    question is not asked there, and an absent answer must never read as a
    negative one. Otherwise:

        ratio       compressed bytes per uncompressed byte, or None when the
                    archive did not declare enough to say
        compressed  ratio <= COMPRESSION_YIELD_THRESHOLD, or None when unknown
        declares_compression
                    whether any member declares a compression method at all

    `compressed is None` means the measurement could not be taken, and callers
    must treat that as "no finding" rather than as "did not compress". A policy
    that flags on missing evidence flags on ZIP64 archives and truncated reads.
    """
    if container not in COMPRESSION_MEASURED_FORMATS:
        return None
    if not head:
        return None

    evidence = {
        "format": container,
        "declares_compression": None,
        "ratio": None,
        "compressed": None,
        "basis": "",
    }

    try:
        if container == "zip":
            csize, usize, declares, members = _zip_declared_sizes(tail or head)
            evidence["declares_compression"] = declares
            evidence["members_read"] = members
            if members and usize > 0:
                ratio = csize / usize
                evidence["ratio"] = round(ratio, 4)
                evidence["compressed"] = ratio <= COMPRESSION_YIELD_THRESHOLD
                evidence["basis"] = (
                    f"central directory: {csize} compressed / {usize} uncompressed "
                    f"over {members} member(s)"
                )
            else:
                evidence["basis"] = (
                    "no member declared usable sizes (empty, ZIP64, or the central "
                    "directory was past the tail sample)"
                )
        else:  # gzip
            expansion, basis = _gzip_yield(head)
            evidence["declares_compression"] = True  # deflate is gzip's only method
            evidence["basis"] = basis
            if expansion:
                ratio = 1.0 / expansion
                evidence["ratio"] = round(ratio, 4)
                evidence["compressed"] = ratio <= COMPRESSION_YIELD_THRESHOLD
    except (struct.error, ValueError, IndexError, zlib.error) as error:
        # Same posture as container_status: nothing escapes onto the detection
        # path. Unlike there, the answer is "unknown", not "failed" - a parse
        # error here is a measurement that did not happen, and D5's tolerance is
        # spent on files that were measured.
        evidence["basis"] = f"unreadable declaration ({type(error).__name__})"

    return evidence
