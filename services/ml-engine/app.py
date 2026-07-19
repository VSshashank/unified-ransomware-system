from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel


# PLACEHOLDER STUB: NI owns the real ML Engine logic.
# This deterministic heuristic only supports SH gateway/dashboard integration.

app = FastAPI(title="URDS ML Engine Stub", version="0.1.0")


class PredictRequest(BaseModel):
    features: dict


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "ml_engine", "placeholder": True}


@app.post("/predict")
def predict(payload: PredictRequest) -> dict:
    features = payload.features
    entropy = float(features.get("shannon_entropy", features.get("entropy", 0)))
    modification_rate = float(features.get("modification_rate", 0))
    api_calls = features.get("api_calls", [])
    crypto_signal = any("Crypt" in call for call in api_calls)
    score = min(0.99, (entropy / 10) + (modification_rate * 0.25) + (0.15 if crypto_signal else 0))
    threat_level = "critical" if score >= 0.9 else "high" if score >= 0.75 else "medium" if score >= 0.5 else "low"
    prediction = "ransomware" if threat_level in {"high", "critical"} else "benign"
    return {
        "prediction": prediction,
        "confidence": round(score, 2),
        "model_version": "1.0.0",
        "timestamp": utc_now(),
        "threat_level": threat_level,
        "features_importance": {
            "shannon_entropy": 0.35,
            "modification_rate": 0.28,
            "api_calls": 0.22,
        },
    }


@app.get("/model/metrics")
def model_metrics() -> dict:
    return {
        "accuracy": 0.92,
        "precision": 0.91,
        "recall": 0.93,
        "f1_score": 0.92,
        "roc_auc": 0.95,
        "last_trained": "2026-01-30T14:00:00Z",
    }
