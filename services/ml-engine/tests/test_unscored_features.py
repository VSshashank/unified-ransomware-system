"""Documented features that this model does not score must say so - NI (A6).

Listing 3.5's `/predict` request carries `pe_imports_count` and `api_calls`.
Listing 3.22's error example names those same two as the features whose absence
makes a prediction fail. Section 1.4 claims behavioural profiles are built "based
on API call sequences" and section 2.3 says `CryptEncrypt`, `WriteFile` and
`MoveFile` are "integrated into the feature vector for the ML engine".

A caller reading any of that expects those fields to influence the answer. Until
this change the behavioural model's seven-element FEATURE_ORDER contained
neither, so `/predict` accepted both and discarded them in silence - the one
outcome that is indefensible, because a caller cannot tell it from the feature
working.

These tests pin the contract that replaced it: the response states which of the
supplied features were read and which were not, with the reason. See
features.UNSCORED_FEATURES for why they cannot honestly be trained in.
"""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app as ml_app
from features import FEATURE_ORDER, SCORED_INPUT_KEYS, UNSCORED_FEATURES, partition

BEHAVIORAL_MODEL = Path(os.environ["BEHAVIORAL_MODEL_PATH"])

needs_behavioral = pytest.mark.skipif(
    not BEHAVIORAL_MODEL.is_file(),
    reason=f"no behavioural model at {BEHAVIORAL_MODEL}; run src/train_behavioral_model.py",
)

# Listing 3.5, verbatim.
LISTING_3_5 = {
    "shannon_entropy": 7.89,
    "file_size": 1048576,
    "magic_bytes": "4D5A",
    "modification_rate": 0.85,
    "pe_imports_count": 45,
    "api_calls": ["CreateFile", "WriteFile", "CryptEncrypt"],
}


@pytest.fixture(scope="module")
def client():
    with TestClient(ml_app.app) as test_client:
        yield test_client


def test_the_two_documented_pe_features_are_still_absent_from_the_model():
    """If either is ever trained in, this test should be deleted, not adjusted."""
    assert "pe_imports_count" not in FEATURE_ORDER
    assert "api_calls" not in FEATURE_ORDER
    assert set(UNSCORED_FEATURES) == {"pe_imports_count", "api_calls"}


def test_every_unscored_feature_carries_a_reason():
    """A field listed as ignored without a reason is just a quieter silence."""
    for name, reason in UNSCORED_FEATURES.items():
        assert reason.strip(), f"{name} has no stated reason"
        assert "ember_vector" in reason, f"{name} does not point at the path that does score it"


def test_partition_reports_what_was_read_and_what_was_not():
    used, ignored = partition(LISTING_3_5)

    assert set(ignored) == {"pe_imports_count", "api_calls"}
    # Request keys, not model columns: `file_size` is sent, `log_file_size` is
    # what the model sees. Claiming the latter was "used" would name a field the
    # caller never sent.
    assert {"shannon_entropy", "file_size", "magic_bytes"} <= set(used)
    assert set(used) <= set(SCORED_INPUT_KEYS)
    assert not set(used) & set(UNSCORED_FEATURES)


def test_partition_stays_quiet_when_the_caller_sends_neither():
    """Most callers are the Monitor, which sends neither. No noise for them."""
    _, ignored = partition({"shannon_entropy": 7.9, "file_size": 1024})
    assert ignored == {}


def test_an_empty_api_call_list_is_not_reported_as_ignored():
    """The Monitor sends `api_calls: []` for every non-PE file it sees.

    That is an honest "there were none", not a feature the caller expected to
    matter, so reporting it as ignored on every ordinary document would train
    operators to disregard the field.
    """
    _, ignored = partition({"shannon_entropy": 7.9, "api_calls": [], "pe_imports_count": 0})
    assert ignored == {}


@needs_behavioral
def test_listing_3_5_gets_a_prediction_that_names_what_it_ignored(client):
    """The request from the document, sent verbatim, answered honestly."""
    response = client.post("/predict", json={"features": LISTING_3_5})
    assert response.status_code == 200, response.text

    body = response.json()
    # Listing 3.6's fields still hold - this adds to the contract, it does not
    # replace it.
    for field in ("prediction", "confidence", "model_version", "timestamp",
                  "threat_level", "features_importance"):
        assert field in body, f"Listing 3.6 field {field} disappeared"

    assert set(body["features_ignored"]) == {"pe_imports_count", "api_calls"}
    assert body["features_used"], "the response claims nothing was read"


@needs_behavioral
def test_the_ember_path_reports_no_ignored_features(client):
    """`ember_vector` is the path that *does* score PE structure.

    A response there claiming to have ignored PE features would be actively
    misleading, so the two lists are populated only where they apply.
    """
    response = client.post("/predict", json={"ember_vector": [0.0] * ml_app.EMBER_VECTOR_LENGTH})
    if response.status_code == 503:
        pytest.skip("no EMBER model on disk")

    body = response.json()
    assert body["features_ignored"] == {}
    assert body["features_used"] == []
