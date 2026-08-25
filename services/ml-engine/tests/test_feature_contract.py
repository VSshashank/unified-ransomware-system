"""The feature contract, asserted in one place because it lives in five.

`features.py`'s own docstring says it: a mismatch between the training column
order and the serving column order does not raise, it silently scores the wrong
columns. That is the worst failure mode a detector can have - it keeps
answering, confidently, about a different file.

Five files have to move together whenever the vector changes:

    src/train_behavioral_model.py     FEATURE_NAMES, featurise()
    services/ml-engine/features.py    FEATURE_ORDER, SCORED_INPUT_KEYS,
                                      features_to_vector()
    services/monitor/app.py           extract_features() -> /features
    services/monitor/app.py           the pipeline handoff in handle_event()
    services/dashboard/app.py         the /predict call behind the banner

The first two are checked here against the model artefact itself, which is the
only one of the five that cannot be talked out of the truth: whatever columns
the model was fitted on are recorded in it. The remaining three are producers of
the request dict rather than of the vector, and are checked by
`test_every_scored_key_has_a_producer` below plus the monitor's own suite.
"""

import json
import os
from pathlib import Path

import joblib
import pytest

from features import FEATURE_ORDER, SCORED_INPUT_KEYS, features_to_vector

REPO_ROOT = Path(__file__).resolve().parents[3]
BEHAVIORAL_MODEL = Path(os.environ["BEHAVIORAL_MODEL_PATH"])
METRICS = REPO_ROOT / "models" / "behavioral_model_metrics.json"

needs_behavioral = pytest.mark.skipif(
    not BEHAVIORAL_MODEL.is_file(),
    reason=f"no behavioural model at {BEHAVIORAL_MODEL}; run src/train_behavioral_model.py",
)

# A ZIP the Monitor checked and found structurally sound.
VALID_ARCHIVE = {
    "shannon_entropy": 7.999,
    "file_size": 262144,
    "magic_bytes": "504B0304",
    "container_format": "zip",
    "container_valid": True,
    "ransom_extension": False,
    "printable_ratio": 0.371,
    "byte_value_std": 73.98,
    "chi_square_uniformity": 0.001,
    "entropy_max_block": 7.99,
    "entropy_block_spread": 0.02,
    "high_entropy_block_fraction": 1.0,
}

# The same header with nothing behind it - what `spoofer` writes.
FORGED_ARCHIVE = dict(VALID_ARCHIVE, container_valid=False)

# Intermittent encryption: the average is unremarkable, the profile is not.
PARTIALLY_ENCRYPTED = {
    "shannon_entropy": 5.22,
    "file_size": 34000,
    "magic_bytes": "55524453",
    "container_format": None,
    "container_valid": None,
    "ransom_extension": False,
    "printable_ratio": 0.72,
    "byte_value_std": 52.0,
    "chi_square_uniformity": 6.4,
    "entropy_max_block": 7.95,
    "entropy_block_spread": 4.61,
    "high_entropy_block_fraction": 0.38,
}


# ------------------------------------------------------- order and arity


@needs_behavioral
def test_the_served_column_order_is_the_one_the_model_was_fitted_on():
    """The check that would have caught a five-file edit that missed one."""
    model = joblib.load(BEHAVIORAL_MODEL)
    assert model.n_features_in_ == len(FEATURE_ORDER), (
        f"the model takes {model.n_features_in_} columns and features.py builds "
        f"{len(FEATURE_ORDER)}. Retrain, or finish the edit."
    )


@needs_behavioral
def test_the_recorded_feature_names_match_features_py_exactly():
    """Names *and* order. A permutation has the right length and is still wrong."""
    recorded = json.loads(METRICS.read_text())["feature_names"]
    assert recorded == FEATURE_ORDER, (
        "src/train_behavioral_model.py and services/ml-engine/features.py "
        f"disagree:\n  trained: {recorded}\n  served:  {FEATURE_ORDER}"
    )


def test_every_vector_position_is_a_finite_number():
    for payload in (VALID_ARCHIVE, FORGED_ARCHIVE, PARTIALLY_ENCRYPTED):
        vector = features_to_vector(payload)
        assert len(vector) == len(FEATURE_ORDER)
        assert all(value == value and abs(value) != float("inf") for value in vector)


# ------------------------------------------ the tri-state, kept tri-state


def test_structural_validity_maps_to_three_distinct_values():
    position = FEATURE_ORDER.index("container_structurally_valid")
    assert features_to_vector(VALID_ARCHIVE)[position] == 1.0
    assert features_to_vector(FORGED_ARCHIVE)[position] == -1.0
    assert features_to_vector(dict(VALID_ARCHIVE, container_valid=None))[position] == 0.0


def test_an_absent_structural_check_is_unknown_and_not_forged():
    """The highest-importance column must not default to an accusation.

    A caller that predates this field - the gateway's /analyze passthrough, an
    older dashboard - sends no `container_valid`. Mapping that to -1.0 would
    tell the model every one of its files had been examined and found fake.
    """
    position = FEATURE_ORDER.index("container_structurally_valid")
    payload = {key: value for key, value in VALID_ARCHIVE.items() if key != "container_valid"}
    assert features_to_vector(payload)[position] == 0.0


# ----------------------------------------------------- the block profile


def test_block_scalars_are_read_from_the_payload_when_sent():
    vector = features_to_vector(PARTIALLY_ENCRYPTED)
    assert vector[FEATURE_ORDER.index("entropy_max_block")] == 7.95
    assert vector[FEATURE_ORDER.index("entropy_block_spread")] == 4.61
    assert vector[FEATURE_ORDER.index("high_entropy_block_fraction")] == 0.38


def test_absent_block_scalars_interpolate_to_a_uniform_file():
    """Not to zeros, and not to variation nobody measured.

    Zeroing `entropy_max_block` would say a file's busiest block is emptier than
    the file as a whole, which is arithmetically impossible. Inventing a spread
    would manufacture the exact evidence the partial-encryption signal keys on.
    """
    payload = {"shannon_entropy": 7.99, "file_size": 100000}
    vector = features_to_vector(payload)
    assert vector[FEATURE_ORDER.index("entropy_max_block")] == pytest.approx(7.99)
    assert vector[FEATURE_ORDER.index("entropy_block_spread")] == 0.0
    assert vector[FEATURE_ORDER.index("high_entropy_block_fraction")] == 1.0

    quiet = features_to_vector({"shannon_entropy": 4.0, "file_size": 100000})
    assert quiet[FEATURE_ORDER.index("high_entropy_block_fraction")] == 0.0


# ------------------------------------------------------ what it changes


@needs_behavioral
def test_a_forged_container_scores_as_ransomware_where_a_real_one_does_not():
    """The whole point of the new column, end to end through the model.

    These two payloads differ in exactly one field. Before structural
    validation existed there was no field to differ in, and the model - like
    the detector - had to call them both benign.
    """
    model = joblib.load(BEHAVIORAL_MODEL)
    valid = model.predict([features_to_vector(VALID_ARCHIVE)])[0]
    forged = model.predict([features_to_vector(FORGED_ARCHIVE)])[0]

    assert valid == 0, "a structurally sound archive is not an attack"
    assert forged == 1, "a forged container header is"


@needs_behavioral
def test_intermittent_encryption_scores_as_ransomware_despite_a_quiet_average():
    model = joblib.load(BEHAVIORAL_MODEL)
    assert model.predict([features_to_vector(PARTIALLY_ENCRYPTED)])[0] == 1


@needs_behavioral
def test_an_unvalidatable_container_is_still_benign():
    """bzip2 and XZ have no validator, so `container_valid` is null for them.

    The detector's answer there is "no opinion, the container exemption still
    applies", and the model has to give the same answer or the two halves of
    the system disagree about the same file. This case is in the training
    corpus for that reason - see the bzip2/xz kinds in
    src/train_behavioral_model.py.
    """
    model = joblib.load(BEHAVIORAL_MODEL)
    unvalidated = dict(
        VALID_ARCHIVE, container_format="bzip2", container_valid=None, magic_bytes="425A6839"
    )
    assert model.predict([features_to_vector(unvalidated)])[0] == 0


# ------------------------------------------------------------- reporting


# Each scored key, paired with a value that must move the vector, and with any
# keys that have to be absent for it to be reachable. Two of them are only read
# as fallbacks - `entropy` behind `shannon_entropy`, `magic_bytes` behind
# `container_format` - so removing them while their primary is present proves
# nothing, and perturbing them does.
PERTURBATIONS = {
    "shannon_entropy": (3.0, ()),
    "entropy": (3.0, ("shannon_entropy",)),
    "file_size": (17.0, ()),
    "container_format": (None, ("magic_bytes",)),
    "container_valid": (False, ()),
    "magic_bytes": ("A3F19C42", ("container_format",)),
    "ransom_extension": (True, ()),
    "printable_ratio": (0.99, ()),
    "byte_value_std": (12.0, ()),
    "chi_square_uniformity": (9.9, ()),
    "entropy_max_block": (2.0, ()),
    "entropy_block_spread": (3.3, ()),
    "high_entropy_block_fraction": (0.11, ()),
}


def test_every_scored_key_is_actually_read():
    """SCORED_INPUT_KEYS is reported back to callers, so it has to be true.

    `partition()` tells a caller which of the fields it sent were read. A key
    listed there that nothing reads would be a claim the endpoint cannot back
    up - and this endpoint has already shipped that bug once, with
    `pe_imports_count` and `api_calls` accepted and discarded in silence.

    Perturbation rather than removal: several of these have fallbacks, so
    dropping one can leave the vector identical while the key is read perfectly
    well. Changing its value cannot.
    """
    everything = dict(VALID_ARCHIVE, entropy=7.999)

    assert set(PERTURBATIONS) == set(SCORED_INPUT_KEYS), (
        "a scored key was added or removed without a case here: "
        f"{sorted(set(PERTURBATIONS) ^ set(SCORED_INPUT_KEYS))}"
    )

    unread = []
    for key, (value, must_be_absent) in PERTURBATIONS.items():
        payload = {
            name: content
            for name, content in everything.items()
            if name not in must_be_absent
        }
        before = features_to_vector(payload)
        after = features_to_vector({**payload, key: value})
        if before == after:
            unread.append(key)

    assert unread == [], f"listed as scored but never read: {unread}"
