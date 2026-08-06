"""Feature-dict -> model-vector mapping for the behavioural classifier - NI.

Kept as its own module because both the training script and the service have to
agree on the feature order exactly. A mismatch here does not raise; it silently
scores the wrong columns, which is the worst kind of bug to have in a detector.
"""

import math

# Must match FEATURE_NAMES in src/train_behavioral_model.py, in order.
FEATURE_ORDER = [
    "shannon_entropy",
    "log_file_size",
    "has_container_header",
    "ransom_extension",
    "printable_ratio",
    "byte_value_std",
    "chi_square_uniformity",
]

CONTAINER_SIGNATURES = [
    b"PK\x03\x04", b"\x1f\x8b", b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c", b"\xfd7zXZ",
    b"BZh", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"%PDF",
    b"ID3", b"OggS", b"fLaC", b"RIFF", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18",
]


def _has_container_header(payload: dict) -> float:
    if payload.get("container_format"):
        return 1.0
    magic_hex = payload.get("magic_bytes")
    if not magic_hex or magic_hex == "UNKNOWN":
        return 0.0
    try:
        magic = bytes.fromhex(str(magic_hex))
    except ValueError:
        return 0.0
    if any(magic.startswith(signature) for signature in CONTAINER_SIGNATURES):
        return 1.0
    return 1.0 if magic[4:8] == b"ftyp" else 0.0


def features_to_vector(payload: dict) -> list[float]:
    """Build the model's input row from whatever the Monitor sent.

    The Monitor measures the byte statistics directly and sends them. Older
    callers (and the gateway's /analyze passthrough) may not, so those three are
    interpolated between the two ends measured on the training corpus:

        uniform random bytes  printable 0.371, std 73.9, chi-square ~0.00
        English text          printable 1.000, std 28.0, chi-square ~18.2

    Note 0.371, not ~0: 95 of the 256 byte values are printable ASCII, so a
    third of a ciphertext's bytes land in that range. Assuming ciphertext is
    "unprintable" inverts the feature and the classifier with it.
    """
    entropy = float(payload.get("shannon_entropy", payload.get("entropy", 0.0)) or 0.0)
    size = float(payload.get("file_size", 0) or 0)
    uniformity = min(max(entropy / 8.0, 0.0), 1.0)

    return [
        entropy,
        math.log10(max(size, 1.0)),
        _has_container_header(payload),
        1.0 if payload.get("ransom_extension") else 0.0,
        float(payload.get("printable_ratio", 1.0 - 0.629 * uniformity)),
        float(payload.get("byte_value_std", 28.0 + 45.9 * uniformity)),
        float(payload.get("chi_square_uniformity", 18.2 * (1.0 - uniformity) ** 2)),
    ]
