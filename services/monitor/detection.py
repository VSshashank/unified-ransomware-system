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


def calculate_entropy(file_path: str) -> float:
    """Shannon entropy in bits/byte over the first ENTROPY_SAMPLE_BYTES."""
    try:
        with open(file_path, "rb") as handle:
            data = handle.read(ENTROPY_SAMPLE_BYTES)
    except (OSError, ValueError):
        return 0.0

    return entropy_of(data)


def entropy_of(data: bytes) -> float:
    """Entropy of an in-memory buffer. Split out so tests need no file I/O."""
    if not data:
        return 0.0

    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(entropy, 2)


def byte_statistics(file_path: str) -> dict:
    """Byte-distribution stats the ML engine's behavioural model consumes.

    Measured here because the Monitor has already read the file. Without them
    the ML service has to estimate all three from entropy alone, which is much
    weaker on the cases that matter - header-spoofed ciphertext and partially
    encrypted files both sit in the middle of that estimate.

    Note that uniform random bytes are ~37% printable ASCII (95 of the 256 byte
    values), so a *low* printable ratio means text, not ciphertext.
    """
    try:
        with open(file_path, "rb") as handle:
            data = handle.read(ENTROPY_SAMPLE_BYTES)
    except (OSError, ValueError):
        data = b""

    total = len(data)
    if not total:
        return {"printable_ratio": 0.0, "byte_value_std": 0.0, "chi_square_uniformity": 0.0}

    counts = Counter(data)
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


def read_magic(file_path: str) -> bytes:
    try:
        with open(file_path, "rb") as handle:
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


def sha256_file(file_path: str) -> str | None:
    """SHA-256 of a file. This is the `file_hash` the ledger event carries."""
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as handle:
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
) -> dict:
    """Decide whether a file event looks like encryption.

    Returns the verdict plus the reason for it, so the ledger entry records why
    something was flagged rather than just that it was.
    """
    container = identify_container(magic)
    ransom_ext = has_ransom_extension(file_path)
    high_entropy = entropy >= threshold

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
