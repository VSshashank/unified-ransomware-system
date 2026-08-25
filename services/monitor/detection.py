"""Detection primitives for the Monitor service - AS.

Shannon entropy on its own flags every compressed archive as an attack: a ZIP
and an AES-encrypted document both sit near 8.0 bits/byte. Two checks separate
the two, and the design doc names them as separate deliverables:

* Magic-byte verification, below: high entropy that a declared compressed or
  media container explains is compression, not encryption.
* Differential entropy analysis (spec 1.4, "entropy patterns over time"):
  entropy tracked per path across a file's create -> modify sequence. A single
  reading cannot tell an archive from ciphertext, but a *rise* can - a document
  that was 4.5 bits/byte and is now 7.9 was encrypted in place, which is the
  ransomware pattern. Magic bytes alone miss that when the encryptor writes a
  container header over the ciphertext; the rise still shows.

Two more, added after a sweep of the simulator families measured what the first
two miss (reports/simulator_families.json: `spoofer` 0/8, `partial` 0/8):

* Structural container validation (services/monitor/containers.py): the magic
  byte says what a file claims to be; the structure says whether it is. This is
  what closes the exemption `spoofer` was walking through with four bytes.
* Block-entropy profiling, below: whole-file entropy is an average, and an
  average hides a file that is 25% ciphertext and 75% untouched. Intermittent
  encryptors - LockBit 3.0, BlackCat - are built around exactly that arithmetic.
"""

import hashlib
import math
import os
import threading
import time
from collections import Counter, OrderedDict, deque

# Only the read size is needed here; the structural verdict itself is taken by
# the caller and handed to `classify`, so this module stays free of the parsing.
from containers import CONTAINER_TAIL_BYTES

# Entropy at or above this is "encrypted-looking". 7.5 bits/byte is the usual
# operating point: plain text sits ~4.5, office documents ~6, and both ciphertext
# and compressed data land above 7.9.
DEFAULT_ENTROPY_THRESHOLD = 7.5

# Read caps. Entropy over the first megabyte tracks the whole-file value closely
# enough to classify with, and keeps per-event work bounded on large files.
ENTROPY_SAMPLE_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAGIC_BYTES_READ = 16

# ------------------------------------------------------- block-entropy profile
#
# Whole-file entropy is a mean, and a mean is exactly the wrong statistic for
# intermittent encryption. `partial` in the simulator scrambles the leading
# quarter of each file and leaves the rest: the ciphertext is at 7.99 and the
# untouched tail at 4.65, so the file averages 5.22 and walks past a 7.5
# threshold untouched. Measured, 0 of 8 flagged.
#
# Scoring 4KB blocks separately puts the two regions back on either side of the
# line. 4096 is the smallest block that still measures entropy meaningfully -
# below roughly 2KB the estimate is dominated by the fact that a short sample
# cannot fill 256 bins, and every block starts to look non-uniform.
ENTROPY_BLOCK_BYTES = int(os.getenv("ENTROPY_BLOCK_BYTES", str(4096)))
MIN_ENTROPY_BLOCK_BYTES = 2048

# A block at or above this is ciphertext-or-compressed. Higher than the
# whole-file threshold on purpose: a 4KB window of genuinely random bytes lands
# at ~7.95, and demanding 7.9 keeps ordinary high-entropy *content* - a JPEG's
# scan data inside a larger file - from counting toward a partial-encryption
# verdict on its own.
HIGH_ENTROPY_BLOCK = float(os.getenv("HIGH_ENTROPY_BLOCK", "7.9"))

# What it takes to call a file partially encrypted. All three must hold:
#
#   * enough blocks to have a profile at all - two blocks is a coincidence
#   * a substantial *run* of them at ciphertext entropy, not one stray block
#   * a wide spread, meaning the file contains both encrypted-looking and
#     ordinary regions. A uniformly high-entropy file has no spread and is
#     already caught by the plain threshold; requiring spread here is what keeps
#     this rule from double-counting the case above it.
MIN_PROFILE_BLOCKS = int(os.getenv("MIN_PROFILE_BLOCKS", "4"))
PARTIAL_BLOCK_FRACTION = float(os.getenv("PARTIAL_BLOCK_FRACTION", "0.15"))
PARTIAL_BLOCK_SPREAD = float(os.getenv("PARTIAL_BLOCK_SPREAD", "2.0"))

# ---------------------------------------------- differential entropy analysis
#
# A rise this large means the content was replaced rather than edited. Ordinary
# editing moves entropy by tenths: appending a paragraph to a document, or
# adding a file to an archive, does not move the distribution of an entire
# megabyte. 2.0 bits/byte is comfortably above that and comfortably below the
# ~3.5 a text file gains when it is encrypted.
ENTROPY_RISE_THRESHOLD = float(os.getenv("ENTROPY_RISE_THRESHOLD", "2.0"))

# A rise only means something if it ends somewhere encrypted-looking. Slightly
# below DEFAULT_ENTROPY_THRESHOLD on purpose: this is what lets the rise catch
# encryption that lands just under the static cut-off, which is the case a
# single reading cannot see at all.
ENTROPY_RISE_FLOOR = float(os.getenv("ENTROPY_RISE_FLOOR", "7.0"))

# A reading only becomes a baseline once the file has real content in it.
# Watchdog reports a creation the moment the file exists, usually at zero bytes,
# and every file that has ever been written therefore "rose" from 0.0. Without
# this floor, creating any archive would look like encrypting one.
MIN_BASELINE_BYTES = int(os.getenv("MIN_BASELINE_BYTES", "1024"))

# Readings kept per path, and paths kept overall. Both bounded: a long-running
# watch over a busy tree must not grow an entry per file forever.
ENTROPY_HISTORY_WINDOW = int(os.getenv("ENTROPY_HISTORY_WINDOW", "5"))
ENTROPY_HISTORY_PATHS = int(os.getenv("ENTROPY_HISTORY_PATHS", "4096"))

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


def read_tail(file_path: str, size: int, retry: bool = True) -> bytes:
    """The trailing CONTAINER_TAIL_BYTES, for the structural checks.

    ZIP's central directory, PNG's IEND, JPEG's EOI and PDF's `%%EOF` all live
    at the *end* of a file, and `read_sample` only ever sees the front. This is
    a second seek on the detection path, so it is only paid when it can tell us
    something new: a file that fits inside the leading sample is already
    entirely in hand, and `sample_file` returns that sample as its own tail
    rather than opening it twice.
    """
    if size <= 0:
        return b""
    try:
        with open_for_read(file_path, retry=retry) as handle:
            if size > CONTAINER_TAIL_BYTES:
                handle.seek(size - CONTAINER_TAIL_BYTES)
            return handle.read(CONTAINER_TAIL_BYTES)
    except (OSError, ValueError):
        return b""


def sample_file(file_path: str, size: int, retry: bool = True) -> tuple[bytes, bytes]:
    """The leading sample and a trailing sample, in as few reads as possible.

    Returns `(head, tail)` where `tail` is a genuine suffix of the file - which
    is what `containers.container_status` requires to do offset arithmetic. For
    a file at or under ENTROPY_SAMPLE_BYTES the head *is* the whole file, so it
    is returned as both and no second read happens. That covers the great
    majority of events; only files over a megabyte pay for the tail.
    """
    head = read_sample(file_path, retry=retry)
    if size <= len(head):
        return head, head
    return head, read_tail(file_path, size, retry=retry)


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


def block_entropy_profile(data: bytes, block: int = ENTROPY_BLOCK_BYTES) -> list[float]:
    """Entropy of each `block`-sized window, in order.

    Split out from `measure` so tests and analysis scripts can look at the shape
    of a file directly. The detector itself goes through `measure`, which
    derives this and the whole-file figures from the same single pass.
    """
    return _profile(data, block)[2]


def _profile(data: bytes, block: int) -> tuple[Counter, int, list[float]]:
    """One pass: per-block entropies and the histogram of the whole buffer.

    The whole-file histogram is the sum of the per-block ones, so the block
    profile costs a dictionary merge per block rather than a second walk over
    the bytes. A trailing block shorter than MIN_ENTROPY_BLOCK_BYTES is counted
    into the total but left out of the profile - too few bytes to fill 256 bins
    is measured as low entropy no matter what is in it, and a short tail block
    would drag `entropy_block_spread` down on every file.
    """
    totals: Counter = Counter()
    blocks: list[float] = []

    for start in range(0, len(data), block):
        chunk = data[start : start + block]
        counts = Counter(chunk)
        totals.update(counts)
        if len(chunk) >= MIN_ENTROPY_BLOCK_BYTES:
            blocks.append(_entropy_from(counts, len(chunk)))

    return totals, len(data), blocks


def _block_scalars(blocks: list[float]) -> dict:
    """The three numbers the verdict and the ML feature vector read.

    Reported as 0.0 rather than None for a file with no measurable blocks. The
    model needs a number in every column, and "no high-entropy blocks were
    found" and "there were no blocks to look at" both mean the same thing to
    every rule that consumes these.
    """
    if not blocks:
        return {
            "entropy_max_block": 0.0,
            "entropy_block_spread": 0.0,
            "high_entropy_block_fraction": 0.0,
            "entropy_blocks": 0,
        }

    high = sum(1 for value in blocks if value >= HIGH_ENTROPY_BLOCK)
    return {
        "entropy_max_block": round(max(blocks), 2),
        "entropy_block_spread": round(max(blocks) - min(blocks), 2),
        "high_entropy_block_fraction": round(high / len(blocks), 4),
        "entropy_blocks": len(blocks),
    }


def looks_partially_encrypted(statistics: dict) -> bool:
    """Ciphertext in part of a file whose average hides it.

    Deliberately not applied to a structurally valid container - `classify` gates
    on that, and it is the difference between this rule and a false-positive
    generator. A PDF with an embedded JPEG, a .docx, an MP4 and a ZIP of photos
    all have exactly this profile by design: high-entropy regions inside a
    low-entropy frame. What separates them from a partially encrypted document is
    that they are still the format they claim to be.
    """
    return (
        statistics.get("entropy_blocks", 0) >= MIN_PROFILE_BLOCKS
        and statistics.get("high_entropy_block_fraction", 0.0) >= PARTIAL_BLOCK_FRACTION
        and statistics.get("entropy_block_spread", 0.0) >= PARTIAL_BLOCK_SPREAD
    )


def measure(data: bytes) -> tuple[float, dict]:
    """Entropy, byte statistics and the block profile from one pass over the buffer.

    All three are a function of the same byte histograms, so counting once and
    deriving them together is what keeps the per-event cost flat. Building the
    histogram twice put detection latency at 62ms p95 where sharing it holds
    ~30ms (measured over 40 files, 4KB-2MB, on Windows 11 build 26200) - still
    inside the 100ms target either way, but the target is not the reason to pay
    double. The block profile was added under the same discipline: it is derived
    from the per-block histograms that the whole-file histogram is summed from,
    not from a second walk.
    """
    counts, total, blocks = _profile(data, ENTROPY_BLOCK_BYTES)
    statistics = _statistics_from(counts, total)
    statistics.update(_block_scalars(blocks))
    return _entropy_from(counts, total), statistics


def byte_statistics(file_path: str, retry: bool = True) -> dict:
    """Byte-distribution stats the ML engine's behavioural model consumes.

    Measured here because the Monitor has already read the file. Without them
    the ML service has to estimate all three from entropy alone, which is much
    weaker on the cases that matter - header-spoofed ciphertext and partially
    encrypted files both sit in the middle of that estimate.
    """
    return statistics_of(read_sample(file_path, retry=retry))


def statistics_of(data: bytes) -> dict:
    """Byte statistics and block-entropy scalars of an in-memory buffer.

    Note that uniform random bytes are ~37% printable ASCII (95 of the 256 byte
    values), so a *low* printable ratio means text, not ciphertext.

    Returns exactly the same keys `measure` puts in its second slot. It has to:
    `/features` reaches the feature dict through here and `handle_event` reaches
    it through `measure`, and a consumer that got different columns depending on
    which door it came in by would be scoring two different models.
    """
    return measure(data)[1]


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


class _PathHistory:
    """One path's readings, plus the floor they can never rise above again.

    `readings` is the bounded window; `minimum` is the lowest substantive
    reading ever taken on this path in this session, and it is not in the window
    and cannot be evicted from it. See `EntropyHistory.observe`.
    """

    __slots__ = ("readings", "minimum")

    def __init__(self, window: int, first: float):
        self.readings: deque = deque([first], maxlen=window)
        self.minimum: float = first

    def record(self, entropy: float) -> None:
        self.readings.append(entropy)
        if entropy < self.minimum:
            self.minimum = entropy


class EntropyHistory:
    """Entropy readings per path - the "over time" half of the detection.

    One reading says how random a file looks. A sequence says whether it *became*
    that way, which is the difference between an archive someone created and a
    document someone encrypted. Ransomware overwrites existing files, so the
    signature is a large rise on a path that already existed.

    The baseline is a floor, not a recent value
    -------------------------------------------
    Taking the previous reading lets a multi-pass encryptor walk the entropy up
    in steps too small for any single delta to be a rise, which is what the
    `staged` family does. Taking the minimum of a bounded window fixes that, and
    was what this class did - but a window is still a thing an attacker can
    empty. With ENTROPY_HISTORY_WINDOW at 5, five writes at any entropy below the
    rise floor push the original 4.65 reading out of the deque, and the sixth
    write can be ciphertext: the rise is measured against the warm-up writes
    instead of against the document, comes out under ENTROPY_RISE_THRESHOLD, and
    a ZIP magic over the top then collects the container exemption as well. Both
    of Table 5.7's built mitigations, defeated by six writes. That is the
    `grinder` family in scripts/ransomware_simulator.py, and it is why the
    minimum is now kept separately from the window and never evicted from it.

    Every substantive reading updates the minimum, including - especially -
    readings below the rise floor. Those are exactly the writes an attacker uses
    to flush the window, and a floor that ignored them would be flushable in the
    same way.

    The cost of this is a detector that grows more sensitive on a long-lived
    path: a file that legitimately spends time at low entropy and later holds
    compressed content will read as a rise. That is a real false-positive
    source, and it is bounded the same way everything else here is - the minimum
    lives inside the per-path record, so the 4096-path eviction and `forget()`
    on delete both drop it, and a monitor restart clears it entirely.

    Bounded in both directions - readings per path, and paths overall, evicted
    oldest-first. Watchdog threads share one instance, so it takes a lock.
    """

    def __init__(
        self,
        window: int = ENTROPY_HISTORY_WINDOW,
        max_paths: int = ENTROPY_HISTORY_PATHS,
        min_baseline_bytes: int = MIN_BASELINE_BYTES,
    ):
        self._window = window
        self._max_paths = max_paths
        self._min_baseline_bytes = min_baseline_bytes
        self._readings: OrderedDict[str, _PathHistory] = OrderedDict()
        self._lock = threading.Lock()

    def observe(self, file_path: str, entropy: float, size: int) -> float | None:
        """Record a reading and return the rise over the floor established before it.

        Returns None when there is no baseline to compare against - a file seen
        for the first time, or one that has only ever been too small to measure
        meaningfully. None means "no evidence", which is not the same as 0.0.
        """
        substantive = size >= self._min_baseline_bytes and entropy > 0.0

        with self._lock:
            history = self._readings.get(file_path)
            baseline = history.minimum if history is not None else None

            if substantive:
                if history is None:
                    self._readings[file_path] = _PathHistory(self._window, entropy)
                else:
                    history.record(entropy)
                self._readings.move_to_end(file_path)
                while len(self._readings) > self._max_paths:
                    self._readings.popitem(last=False)

        if baseline is None:
            return None
        return round(entropy - baseline, 2)

    def baseline(self, file_path: str) -> float | None:
        """The floor a rise on this path is currently measured against."""
        with self._lock:
            history = self._readings.get(file_path)
            return history.minimum if history is not None else None

    def forget(self, file_path: str) -> None:
        """Drop a path's history. A deleted file's readings describe nothing."""
        with self._lock:
            self._readings.pop(file_path, None)

    def clear(self) -> None:
        with self._lock:
            self._readings.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._readings)


def classify(
    file_path: str,
    entropy: float,
    magic: bytes,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    readable: bool = True,
    entropy_delta: float | None = None,
    container_valid: bool | None = None,
    statistics: dict | None = None,
) -> dict:
    """Decide whether a file event looks like encryption.

    Returns the verdict plus the reason for it, so the ledger entry records why
    something was flagged rather than just that it was, and a `signal` naming
    which of the four detections fired. The signal is what
    services/monitor/admissibility.py adjudicates against: the rules differ in
    how much it costs an attacker to avoid them, so a suppression that may
    cancel one may not be allowed to cancel another, and "suspected_encryption"
    on its own does not say which one this was.

    `readable=False` means the bytes could not be obtained at all. That is a
    third outcome, not a benign one: no measurement was taken, so none is
    reported. Saying "benign" here would be a claim the evidence does not
    support, and on Windows locked files are common enough that folding them
    into "benign" hides real encryption.

    `container_valid` is `containers.validate_container`'s tri-state: True the
    structure holds, False the header is forged, None no opinion (no validator,
    or a file still being written). None keeps the behaviour this function had
    before structural validation existed, which is why it is the default - a
    caller that cannot supply it is not silently opted in to a stricter rule.

    `statistics` is `measure`'s second return value; the block-entropy scalars in
    it are what catch intermittent encryption. Omitting it disables that rule
    rather than guessing at it.
    """
    container = identify_container(magic)
    ransom_ext = has_ransom_extension(file_path)
    high_entropy = entropy >= threshold
    statistics = statistics or {}
    partial = looks_partially_encrypted(statistics)

    def verdict_of(suspicious: bool, verdict: str, reason: str, signal: str | None) -> dict:
        return {
            "suspicious": suspicious,
            "verdict": verdict,
            "reason": reason,
            "signal": signal,
            "entropy": entropy if readable else None,
            "container_format": container if readable else None,
            "container_valid": container_valid,
            "ransom_extension": ransom_ext,
            "entropy_delta": entropy_delta,
        }

    if not readable:
        # A ransomware extension is still a signal even with no bytes to score.
        return verdict_of(
            ransom_ext,
            "suspicious_extension" if ransom_ext else "unreadable",
            "file could not be read (locked by another process); "
            + (
                "flagged on its known ransomware extension alone"
                if ransom_ext
                else "no entropy verdict was possible"
            ),
            "ransom_extension" if ransom_ext else None,
        )

    # Differential entropy, checked before everything else because it is the
    # signal that survives a spoofed header *and* a forged structure: an
    # encryptor can write "PK\x03\x04" over its ciphertext and can even emit a
    # real archive around it, but it cannot make the file look like it was
    # always that random. A rise this size on a path already measured means the
    # content was replaced, not edited.
    if entropy_delta is not None and entropy_delta >= ENTROPY_RISE_THRESHOLD and entropy >= ENTROPY_RISE_FLOOR:
        reason = (
            f"entropy rose {entropy_delta} to {entropy} on a file already being watched, "
            "which is replacement rather than editing"
        )
        if container:
            reason += f"; the {container} header does not explain a rise this large"
        return verdict_of(True, "suspected_encryption", reason, "entropy_rise")

    # Structural validation. The container exemption below is what makes a
    # legitimate archive benign, and until this check existed it could be
    # borrowed for the price of four bytes - `spoofer` in the simulator does
    # exactly that and went undetected 8 times out of 8. A header whose format
    # is not there behind it is evidence, not an explanation.
    if container and container_valid is False and (high_entropy or partial):
        return verdict_of(
            True,
            "suspected_encryption",
            f"the file declares a {container} container but the {container} structure is not "
            f"there behind it, and the content is high entropy ({entropy})",
            "structural_mismatch",
        )

    # Intermittent encryption. Whole-file entropy is under the threshold, but a
    # substantial run of blocks is at ciphertext entropy and the rest is not -
    # which is an average hiding a file that is part ciphertext, not a file that
    # is uniformly ordinary. Gated on the container *not* being structurally
    # valid: a real PDF with an embedded JPEG, and every .docx, has this profile
    # by design.
    if not high_entropy and partial and container_valid is not True:
        return verdict_of(
            True,
            "suspected_encryption",
            f"whole-file entropy {entropy} is below {threshold}, but "
            f"{statistics['high_entropy_block_fraction']:.0%} of its "
            f"{statistics['entropy_blocks']} blocks are at or above {HIGH_ENTROPY_BLOCK} "
            f"with a spread of {statistics['entropy_block_spread']} - part of this file was "
            "replaced with ciphertext and the rest was left alone",
            "partial_entropy",
        )

    if high_entropy and container and container_valid is not False and not ransom_ext:
        # The false-positive mitigation: high entropy explained by the format.
        explanation = {
            True: f"a structurally valid {container} container",
            None: f"a {container} header (this format has no structural validator)",
        }[container_valid]
        return verdict_of(
            False, "benign_compressed", f"entropy {entropy} explained by {explanation}", None
        )

    if high_entropy:
        reason = f"entropy {entropy} >= {threshold} with no recognised container header"
        if ransom_ext:
            reason += " and a known ransomware extension"
        return verdict_of(True, "suspected_encryption", reason, "static_entropy")

    if ransom_ext:
        return verdict_of(
            True,
            "suspicious_extension",
            f"known ransomware extension on a low-entropy file (entropy {entropy})",
            "ransom_extension",
        )

    return verdict_of(False, "benign", f"entropy {entropy} below threshold {threshold}", None)
