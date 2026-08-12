"""Detection primitives for the Monitor service - AS.

Shannon entropy on its own flags every compressed archive as an attack: a ZIP
and an AES-encrypted document both sit near 8.0 bits/byte. The magic-byte check
below is the false-positive mitigation named in the design doc - a file that is
high entropy *and* declares a known compressed/media container is legitimate
compression, not encryption.
"""

import hashlib
import math
import os
import time
from collections import Counter

# Entropy at or above this is "encrypted-looking". 7.5 bits/byte is the usual
# operating point: plain text sits ~4.5, office documents ~6, and both ciphertext
# and compressed data land above 7.9.
DEFAULT_ENTROPY_THRESHOLD = 7.5

# Read caps. Entropy over the first megabyte tracks the whole-file value closely
# enough to classify with, and keeps per-event work bounded on large files.
ENTROPY_SAMPLE_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAGIC_BYTES_READ = 16

# Windows holds files open with deny-share far more often than POSIX does: the
# encrypting process itself, Defender scanning the newly written bytes, and the
# search indexer all take a handle at exactly the moment the watchdog event
# fires. The lock clears in milliseconds, so a short retry recovers the read
# rather than losing the event - measured on Windows 11, an unretried read of a
# file under active write fails with PermissionError roughly once per few
# hundred events.
#
# The wait is bounded by a time budget rather than an attempt count, because the
# attempt count is the thing a caller cannot reason about: three attempts at
# 50ms of backoff is 150ms per open, and handle_event opens the same file twice,
# which put a locked file at 303ms against the 100ms detection target (measured,
# Windows 11 build 26200). A budget caps the worst case at a number that visibly
# fits inside that target.
READ_RETRY_BUDGET_SECONDS = float(os.getenv("READ_RETRY_BUDGET_SECONDS", "0.04"))
READ_RETRY_BACKOFF_SECONDS = float(os.getenv("READ_RETRY_BACKOFF_SECONDS", "0.005"))

# Formats that are high entropy *by design*. A hit here is the difference
# between "someone zipped their photos" and "someone encrypted them".
_CONTAINER_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\xfd7zXZ", "xz"),
    (b"BZh", "bzip2"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF", "pdf"),
    (b"ID3", "mp3"),
    (b"\xff\xfb", "mp3"),
    (b"OggS", "ogg"),
    (b"fLaC", "flac"),
    (b"RIFF", "riff"),  # wav/avi/webp
)

# ISO base media (mp4/mov/m4a) puts its brand at offset 4, not 0.
_FTYP_OFFSET = 4
_FTYP_MAGIC = b"ftyp"

# Extensions ransomware families append to what they encrypt. A secondary
# signal only - families rename constantly, so this never decides on its own.
RANSOM_EXTENSIONS = frozenset(
    {
        ".encrypted", ".enc", ".locked", ".crypt", ".crypto", ".cryp1", ".crypz",
        ".wannacry", ".wncry", ".wcry", ".locky", ".zepto", ".odin", ".thor",
        ".cerber", ".cerber3", ".zzz", ".xxx", ".ttt", ".micro", ".ecc",
        ".ezz", ".exx", ".r5a", ".vvv", ".ccc", ".petya", ".ryk", ".ryuk",
        ".conti", ".lockbit", ".revil", ".sodinokibi", ".darkside", ".maze",
        ".pay", ".payment", ".ransom", ".readme", ".hostage",
    }
)


def open_for_read(file_path: str, retry: bool = True):
    """Open a file, retrying briefly while another process holds a lock on it.

    Only PermissionError is retried: a file that does not exist will not start
    existing, but a locked one almost always frees within milliseconds.

    Python's `open` goes through the CRT on Windows, which sets errno but not
    winerror, so a sharing violation and a directory are both PermissionError
    with errno 13 and cannot be told apart from the exception. A directory will
    never become readable, so it is excluded explicitly rather than waiting out
    the full budget for it.

    `retry=False` skips the wait entirely. A caller that has already established
    the file is locked passes it, so one event pays the budget once rather than
    once per read.
    """
    deadline = time.monotonic() + (READ_RETRY_BUDGET_SECONDS if retry else 0.0)
    delay = READ_RETRY_BACKOFF_SECONDS

    while True:
        try:
            return open(file_path, "rb")
        except PermissionError:
            if os.path.isdir(file_path):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(delay, remaining))
            delay *= 2


def looks_unreadable(magic: bytes, size: int) -> bool:
    """True when a file has bytes but we got none of them.

    A locked file yields an empty read, which is indistinguishable from an
    empty file unless the size is checked too. Without this, `classify` scores
    the file as entropy 0.0 and calls it benign - the encryption is missed
    silently, which is the worst possible failure for a detector.
    """
    return not magic and size > 0


def read_sample(file_path: str, retry: bool = True) -> bytes:
    """The leading bytes that both entropy and the byte statistics score.

    Split out so one event can read a file once and derive both. Reading it
    twice was the old behaviour and it bought nothing - the two measurements
    are taken over exactly the same prefix.
    """
    try:
        with open_for_read(file_path, retry=retry) as handle:
            return handle.read(ENTROPY_SAMPLE_BYTES)
    except (OSError, ValueError):
        return b""


def calculate_entropy(file_path: str, retry: bool = True) -> float:
    """Shannon entropy in bits/byte over the first ENTROPY_SAMPLE_BYTES.

    Returns 0.0 for an unreadable file. Callers that act on the verdict must
    pair this with `looks_unreadable`, because a locked file and a file of
    zeroes both score 0.0 here.
    """
    return entropy_of(read_sample(file_path, retry=retry))


def entropy_of(data: bytes) -> float:
    """Entropy of an in-memory buffer. Split out so tests need no file I/O."""
    return _entropy_from(Counter(data), len(data))


def _entropy_from(counts: Counter, total: int) -> float:
    if not total:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(entropy, 2)


def measure(data: bytes) -> tuple[float, dict]:
    """Entropy and byte statistics from one pass over the buffer.

    Both measurements are a function of the same byte histogram, so counting
    once and deriving both halves the per-event cost. Building the histogram
    twice put detection latency at 62ms p95 where sharing it holds ~30ms
    (measured over 40 files, 4KB-2MB, on Windows 11 build 26200) - still inside
    the 100ms target either way, but the target is not the reason to pay double.
    """
    counts = Counter(data)
    total = len(data)
    return _entropy_from(counts, total), _statistics_from(counts, total)


def byte_statistics(file_path: str, retry: bool = True) -> dict:
    """Byte-distribution stats the ML engine's behavioural model consumes.

    Measured here because the Monitor has already read the file. Without them
    the ML service has to estimate all three from entropy alone, which is much
    weaker on the cases that matter - header-spoofed ciphertext and partially
    encrypted files both sit in the middle of that estimate.
    """
    return statistics_of(read_sample(file_path, retry=retry))


def statistics_of(data: bytes) -> dict:
    """Byte statistics of an in-memory buffer.

    Note that uniform random bytes are ~37% printable ASCII (95 of the 256 byte
    values), so a *low* printable ratio means text, not ciphertext.
    """
    return _statistics_from(Counter(data), len(data))


def _statistics_from(counts: Counter, total: int) -> dict:
    if not total:
        return {"printable_ratio": 0.0, "byte_value_std": 0.0, "chi_square_uniformity": 0.0}

    printable = sum(count for value, count in counts.items() if 32 <= value < 127) / total
    mean = sum(value * count for value, count in counts.items()) / total
    variance = sum(count * (value - mean) ** 2 for value, count in counts.items()) / total
    expected = total / 256
    chi_square = sum((counts.get(value, 0) - expected) ** 2 for value in range(256)) / expected

    return {
        "printable_ratio": round(printable, 4),
        "byte_value_std": round(math.sqrt(variance), 4),
        # Normalised so file size does not dominate the statistic.
        "chi_square_uniformity": round(chi_square / total, 4),
    }


def read_magic(file_path: str, retry: bool = True) -> bytes:
    try:
        with open_for_read(file_path, retry=retry) as handle:
            return handle.read(MAGIC_BYTES_READ)
    except (OSError, ValueError):
        return b""


def get_magic_bytes(file_path: str) -> str:
    """First four bytes as uppercase hex - the shape the API contract returns."""
    magic = read_magic(file_path)[:4]
    return magic.hex().upper() if magic else "UNKNOWN"


def identify_container(magic: bytes) -> str | None:
    """Name the compressed/media container a header declares, if any."""
    if not magic:
        return None

    for signature, name in _CONTAINER_SIGNATURES:
        if magic.startswith(signature):
            return name

    if magic[_FTYP_OFFSET : _FTYP_OFFSET + len(_FTYP_MAGIC)] == _FTYP_MAGIC:
        return "iso-bmff"

    return None


def sha256_file(file_path: str, retry: bool = True) -> str | None:
    """SHA-256 of a file. This is the `file_hash` the ledger event carries."""
    digest = hashlib.sha256()
    try:
        with open_for_read(file_path, retry=retry) as handle:
            for chunk in iter(lambda: handle.read(HASH_CHUNK_BYTES), b""):
                digest.update(chunk)
    except (OSError, ValueError):
        return None
    return digest.hexdigest()


def has_ransom_extension(file_path: str) -> bool:
    return os.path.splitext(file_path)[1].lower() in RANSOM_EXTENSIONS


def classify(
    file_path: str,
    entropy: float,
    magic: bytes,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    readable: bool = True,
) -> dict:
    """Decide whether a file event looks like encryption.

    Returns the verdict plus the reason for it, so the ledger entry records why
    something was flagged rather than just that it was.

    `readable=False` means the bytes could not be obtained at all. That is a
    third outcome, not a benign one: no measurement was taken, so none is
    reported. Saying "benign" here would be a claim the evidence does not
    support, and on Windows locked files are common enough that folding them
    into "benign" hides real encryption.
    """
    container = identify_container(magic)
    ransom_ext = has_ransom_extension(file_path)
    high_entropy = entropy >= threshold

    if not readable:
        # A ransomware extension is still a signal even with no bytes to score.
        return {
            "suspicious": ransom_ext,
            "verdict": "suspicious_extension" if ransom_ext else "unreadable",
            "reason": (
                "file could not be read (locked by another process); "
                + (
                    "flagged on its known ransomware extension alone"
                    if ransom_ext
                    else "no entropy verdict was possible"
                )
            ),
            "entropy": None,
            "container_format": None,
            "ransom_extension": ransom_ext,
        }

    if high_entropy and container and not ransom_ext:
        # The false-positive mitigation: high entropy explained by the format.
        return {
            "suspicious": False,
            "verdict": "benign_compressed",
            "reason": f"entropy {entropy} explained by {container} container",
            "entropy": entropy,
            "container_format": container,
            "ransom_extension": False,
        }

    if high_entropy:
        reason = f"entropy {entropy} >= {threshold} with no recognised container header"
        if ransom_ext:
            reason += " and a known ransomware extension"
        return {
            "suspicious": True,
            "verdict": "suspected_encryption",
            "reason": reason,
            "entropy": entropy,
            "container_format": container,
            "ransom_extension": ransom_ext,
        }

    if ransom_ext:
        return {
            "suspicious": True,
            "verdict": "suspicious_extension",
            "reason": f"known ransomware extension on a low-entropy file (entropy {entropy})",
            "entropy": entropy,
            "container_format": container,
            "ransom_extension": True,
        }

    return {
        "suspicious": False,
        "verdict": "benign",
        "reason": f"entropy {entropy} below threshold {threshold}",
        "entropy": entropy,
        "container_format": container,
        "ransom_extension": False,
    }
