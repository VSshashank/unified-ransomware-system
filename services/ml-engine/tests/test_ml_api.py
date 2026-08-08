"""ML Engine contract, TC-06 and the inference latency target.

The EMBER model is gitignored (it is ~10MB of trained artifact), so the tests
that need it are marked and skipped when it is absent rather than failing on a
clean checkout. The behavioural model is what the Monitor actually talks to and
is exercised unconditionally.
"""

import json
import os
from pathlib import Path
from time import perf_counter

import numpy as np
import pytest
from fastapi.testclient import TestClient

import app as ml_app
from features import FEATURE_ORDER, features_to_vector

REPO_ROOT = Path(__file__).resolve().parents[3]
REPORTS = REPO_ROOT / "reports"
EMBER_MODEL = Path(os.environ["MODEL_PATH"])
BEHAVIORAL_MODEL = Path(os.environ["BEHAVIORAL_MODEL_PATH"])

INFERENCE_TARGET_MS = 100.0

needs_ember = pytest.mark.skipif(
    not EMBER_MODEL.is_file(), reason=f"no EMBER model at {EMBER_MODEL} (gitignored)"
)
needs_behavioral = pytest.mark.skipif(
    not BEHAVIORAL_MODEL.is_file(),
    reason=f"no behavioural model at {BEHAVIORAL_MODEL}; run src/train_behavioral_model.py",
)


@pytest.fixture(scope="module")
def client():
    with TestClient(ml_app.app) as test_client:
        yield test_client


# Byte statistics below are measured values, not guesses - see the table in
# features.py. In particular ciphertext is ~0.371 printable, not ~0: 95 of the
# 256 byte values are printable ASCII.
ENCRYPTED = {
    "shannon_entropy": 7.999,
    "file_size": 524288,
    "magic_bytes": "A3F19C42",
    "modification_rate": 0.99,
    "container_format": None,
    "ransom_extension": False,
    "printable_ratio": 0.371,
    "byte_value_std": 73.88,
    "chi_square_uniformity": 0.001,
}

BENIGN_TEXT = {
    "shannon_entropy": 4.046,
    "file_size": 200000,
    "magic_bytes": "74686520",
    "modification_rate": 0.51,
    "container_format": None,
    "ransom_extension": False,
    "printable_ratio": 1.0,
    "byte_value_std": 27.98,
    "chi_square_uniformity": 18.245,
}

BENIGN_ZIP = {
    "shannon_entropy": 7.999,
    "file_size": 262144,
    "magic_bytes": "504B0304",
    "modification_rate": 0.99,
    "container_format": "zip",
    "ransom_extension": False,
    "printable_ratio": 0.371,
    "byte_value_std": 73.98,
    "chi_square_uniformity": 0.001,
}


# ------------------------------------------------------------------ contract


def test_health_reports_which_models_are_loaded(client):
    body = client.get("/health").json()
    assert body["status"] == "healthy"
    assert body["service"] == "ml_engine"
    assert "ember_model_loaded" in body
    assert "behavioral_model_loaded" in body


def test_predict_without_a_payload_is_a_400_envelope(client):
    response = client.post("/predict", json={})
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "BAD_REQUEST"
    assert set(body["error"]) == {"code", "message", "timestamp", "request_id"}


@needs_behavioral
def test_predict_response_matches_the_documented_contract(client):
    body = client.post("/predict", json={"features": ENCRYPTED}).json()

    for field in ("prediction", "confidence", "model_version", "timestamp",
                  "threat_level", "features_importance"):
        assert field in body, f"contract field {field} missing"

    assert body["prediction"] in {"ransomware", "benign"}
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["threat_level"] in {"low", "medium", "high", "critical"}
    assert isinstance(body["features_importance"], dict)


# -------------------------------------------------------------------- TC-06


@needs_behavioral
def test_tc06_encrypted_file_is_classified_as_ransomware(client):
    body = client.post("/predict", json={"features": ENCRYPTED}).json()
    assert body["prediction"] == "ransomware"
    assert body["threat_level"] in {"high", "critical"}


@needs_behavioral
def test_tc06_plain_document_is_classified_benign(client):
    body = client.post("/predict", json={"features": BENIGN_TEXT}).json()
    assert body["prediction"] == "benign"
    assert body["threat_level"] == "low"


@needs_behavioral
def test_tc06_legitimate_archive_is_classified_benign(client):
    """The high-entropy false-positive case, end to end through the API."""
    body = client.post("/predict", json={"features": BENIGN_ZIP}).json()
    assert body["prediction"] == "benign"


@needs_behavioral
def test_the_features_path_is_implemented(client):
    """It used to return 501, which broke the Monitor -> ML hop entirely."""
    response = client.post("/predict", json={"features": ENCRYPTED})
    assert response.status_code == 200


# ----------------------------------------------------------- feature mapping


def test_feature_vector_length_matches_the_declared_order():
    assert len(features_to_vector(ENCRYPTED)) == len(FEATURE_ORDER)


def test_container_header_is_read_from_magic_bytes_when_format_is_absent():
    payload = dict(BENIGN_ZIP, container_format=None)
    vector = features_to_vector(payload)
    assert vector[FEATURE_ORDER.index("has_container_header")] == 1.0


def test_unknown_magic_bytes_do_not_count_as_a_container():
    vector = features_to_vector(ENCRYPTED)
    assert vector[FEATURE_ORDER.index("has_container_header")] == 0.0


def test_malformed_magic_bytes_do_not_raise():
    vector = features_to_vector(dict(ENCRYPTED, magic_bytes="not-hex"))
    assert vector[FEATURE_ORDER.index("has_container_header")] == 0.0


def test_missing_byte_statistics_are_estimated_not_zeroed():
    """Older callers send only entropy/size/magic; the row must still be sane."""
    minimal = {"shannon_entropy": 7.99, "file_size": 524288, "magic_bytes": "A3F19C42"}
    vector = features_to_vector(minimal)

    # Estimates should land near the measured ciphertext end of the range.
    assert vector[FEATURE_ORDER.index("byte_value_std")] == pytest.approx(73.9, abs=3.0)
    assert vector[FEATURE_ORDER.index("printable_ratio")] == pytest.approx(0.371, abs=0.05)
    assert vector[FEATURE_ORDER.index("chi_square_uniformity")] == pytest.approx(0.0, abs=0.2)


@needs_behavioral
def test_estimated_statistics_classify_the_same_way_as_measured_ones(client):
    """A caller that omits the byte stats must not get the opposite verdict."""
    measured = client.post("/predict", json={"features": ENCRYPTED}).json()
    minimal = {k: ENCRYPTED[k] for k in ("shannon_entropy", "file_size", "magic_bytes")}
    estimated = client.post("/predict", json={"features": minimal}).json()
    assert measured["prediction"] == estimated["prediction"]


# -------------------------------------------------------------------- EMBER


@needs_ember
def test_ember_vector_is_accepted(client):
    vector = np.zeros(2381, dtype=float).tolist()
    body = client.post("/predict", json={"ember_vector": vector}).json()
    assert body["model"] == "ember_xgboost"
    assert body["prediction"] in {"ransomware", "benign"}


def test_wrong_length_ember_vector_is_rejected(client):
    if not EMBER_MODEL.is_file():
        pytest.skip("no EMBER model")
    response = client.post("/predict", json={"ember_vector": [0.0] * 100})
    assert response.status_code == 400
    assert "2381" in response.json()["error"]["message"]


# ------------------------------------------------------------------ metrics


def test_model_metrics_reports_both_models(client):
    body = client.get("/model/metrics").json()
    assert "models" in body
    assert "ember_xgboost" in body["models"]
    assert "behavioral_xgboost" in body["models"]
    for key in ("accuracy", "precision", "recall", "f1_score", "roc_auc"):
        assert key in body


@needs_behavioral
def test_model_metrics_are_read_from_disk_not_hardcoded(client):
    """The stub returned a fixed 0.92 regardless of what was trained."""
    on_disk = json.loads((REPO_ROOT / "models" / "behavioral_model_metrics.json").read_text())
    body = client.get("/model/metrics").json()
    assert body["models"]["behavioral_xgboost"]["accuracy"] == on_disk["accuracy"]


@needs_behavioral
def test_reported_accuracy_meets_the_85_percent_target(client):
    body = client.get("/model/metrics").json()
    accuracy = body["models"]["behavioral_xgboost"]["accuracy"]
    print(f"\nbehavioural model accuracy: {accuracy:.4f} (target >0.85)")
    assert accuracy > 0.85


# ------------------------------------------------------------------ latency


@pytest.mark.benchmark
@needs_behavioral
def test_inference_latency_under_100ms(client):
    payloads = [ENCRYPTED, BENIGN_TEXT, BENIGN_ZIP]
    samples = []

    for _ in range(5):  # warm up
        client.post("/predict", json={"features": ENCRYPTED})

    for index in range(60):
        started = perf_counter()
        response = client.post("/predict", json={"features": payloads[index % len(payloads)]})
        samples.append((perf_counter() - started) * 1000)
        assert response.status_code == 200

    samples.sort()
    mean = sum(samples) / len(samples)
    p95 = samples[int(len(samples) * 0.95) - 1]
    model_only = response.json()["inference_time_ms"]

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "ni_inference_benchmark.json").write_text(
        json.dumps(
            {
                "samples": len(samples),
                "end_to_end_mean_ms": round(mean, 3),
                "end_to_end_p95_ms": round(p95, 3),
                "model_only_ms": model_only,
                "target_ms": INFERENCE_TARGET_MS,
            },
            indent=2,
        )
    )
    print(
        f"\ninference: mean={mean:.2f}ms p95={p95:.2f}ms end-to-end, "
        f"model-only={model_only:.3f}ms (target <100ms)"
    )

    assert p95 < INFERENCE_TARGET_MS
