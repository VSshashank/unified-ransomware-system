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
    "container_structurally_valid",
    "ransom_extension",
    "printable_ratio",
    "byte_value_std",
    "chi_square_uniformity",
    "entropy_max_block",
    "entropy_block_spread",
    "high_entropy_block_fraction",
]

# Keys the caller may legitimately send that this model does not score, and the
# reason for each. Listing 3.5 sends both; section 1.4 claims "behavioral
# profiles ... based on API call sequences" and section 2.3 says CryptEncrypt,
# WriteFile and MoveFile are "integrated into the feature vector for the ML
# engine". Listing 3.22's own error example names these two as the features whose
# absence causes a prediction to fail - so a caller has every reason to expect
# them to matter, and until now /predict accepted them and threw them away
# without a word.
#
# They are not scored *by this model*, and cannot honestly be:
#
#   * The behavioural model's corpus (src/train_behavioral_model.py) is file
#     content - documents, archives, images and the same content encrypted. None
#     of it is a Portable Executable, so every sample in both classes has an
#     import count of 0 and an empty API list. Adding the columns would train two
#     features that are constant across the corpus: zero information, zero
#     importance, and a feature list that looks like it means something. That is
#     the same lie as dropping them, with more moving parts.
#   * Fabricating plausible import counts per synthetic sample would be inventing
#     dataset rows to support a claim, which is worse.
#
# PE import structure *is* scored, by the EMBER classifier on the `ember_vector`
# path - EMBER's 2381 dimensions include hashed import tables - so section 2.3's
# claim holds for the primary model. The honest thing at this endpoint is to say
# which model ran and which of the supplied features it read.
UNSCORED_FEATURES = {
    "pe_imports_count": (
        "PE-structural; the behavioural model is trained on file content, not "
        "executables. Send an ember_vector to score PE structure."
    ),
    "api_calls": (
        "PE-structural; the behavioural model is trained on file content, not "
        "executables. Send an ember_vector to score PE structure."
    ),
}


# Request keys `features_to_vector` below actually reads. Deliberately not
# FEATURE_ORDER: the model's columns are derived, not copied. `file_size` becomes
# `log_file_size`, and `has_container_header` is decided from `container_format`
# or `magic_bytes`. Reporting the column names as though they were request keys
# would tell a caller it had sent fields it never sent.
SCORED_INPUT_KEYS = (
    "shannon_entropy",
    "entropy",
    "file_size",
    "container_format",
    "container_valid",
    "magic_bytes",
    "ransom_extension",
    "printable_ratio",
    "byte_value_std",
    "chi_square_uniformity",
    "entropy_max_block",
    "entropy_block_spread",
    "high_entropy_block_fraction",
)


def partition(payload: dict) -> tuple[list[str], dict[str, str]]:
    """Split what the caller sent into what is scored and what is not.

    Returned on every prediction so a caller can see that a feature it supplied
    had no effect on the answer, rather than having to read this source file.

    An unscored feature is only reported when it carries something. The Monitor
    sends `pe_imports_count: 0` and `api_calls: []` for every non-PE file it
    sees - an honest "there were none", not an expectation that was disappointed.
    Flagging those on every ordinary document would put a warning on almost every
    prediction, which is how operators learn to ignore warnings.
    """
    used = [name for name in SCORED_INPUT_KEYS if payload.get(name) is not None]
    ignored = {
        name: reason
        for name, reason in UNSCORED_FEATURES.items()
        if payload.get(name)
    }
    return used, ignored

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


def _structural_validity(payload: dict) -> float:
    """The Monitor's tri-state container check as the ordinal the model was fitted on.

        +1.0  the declared format's structure is there
         0.0  nothing was checked - no validator for this format, a file still
              being written, or a caller that predates the field
        -1.0  the header is a forgery

    Absent has to map to 0.0 and not to -1.0. An older caller that never sends
    the field would otherwise have every one of its files scored as though its
    container had been examined and found fake, which is the single highest-
    importance feature in the model saying the opposite of the truth.
    """
    value = payload.get("container_valid")
    if value is True:
        return 1.0
    if value is False:
        return -1.0
    return 0.0


def features_to_vector(payload: dict) -> list[float]:
    """Build the model's input row from whatever the Monitor sent.

    The Monitor measures the byte statistics and the block profile directly and
    sends them. Older callers (and the gateway's /analyze passthrough) may not,
    so those are interpolated rather than zeroed.

    The byte statistics interpolate between the two ends measured on the
    training corpus:

        uniform random bytes  printable 0.371, std 73.9, chi-square ~0.00
        English text          printable 1.000, std 28.0, chi-square ~18.2

    Note 0.371, not ~0: 95 of the 256 byte values are printable ASCII, so a
    third of a ciphertext's bytes land in that range. Assuming ciphertext is
    "unprintable" inverts the feature and the classifier with it.

    The block scalars interpolate under a uniformity assumption: with no profile
    to go on, the best available guess is that every block looks like the file
    as a whole, so the maximum block equals the file's entropy and the spread is
    zero. That is deliberately the *least* alarming shape those three can take -
    a file whose blocks vary is what the partial-encryption signal keys on, and
    inventing variation for a caller that measured none would manufacture the
    evidence. A caller that wants that signal has to send the measurement.
    """
    entropy = float(payload.get("shannon_entropy", payload.get("entropy", 0.0)) or 0.0)
    size = float(payload.get("file_size", 0) or 0)
    uniformity = min(max(entropy / 8.0, 0.0), 1.0)

    return [
        entropy,
        math.log10(max(size, 1.0)),
        _has_container_header(payload),
        _structural_validity(payload),
        1.0 if payload.get("ransom_extension") else 0.0,
        float(payload.get("printable_ratio", 1.0 - 0.629 * uniformity)),
        float(payload.get("byte_value_std", 28.0 + 45.9 * uniformity)),
        float(payload.get("chi_square_uniformity", 18.2 * (1.0 - uniformity) ** 2)),
        float(payload.get("entropy_max_block", entropy)),
        float(payload.get("entropy_block_spread", 0.0)),
        float(payload.get("high_entropy_block_fraction", 1.0 if entropy >= 7.9 else 0.0)),
    ]
