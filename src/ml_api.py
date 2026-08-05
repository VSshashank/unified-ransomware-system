"""
Phase 3 / Sprint 2: ML Engine API service
Unified Ransomware Detection & Recovery System
NI - Machine Learning Engineer

Implements the /predict, /model/metrics endpoints from Section 3.4.2 of the
project doc. Run this from your project's services/ml_engine/ folder (or
adjust MODEL_PATH / METRICS_PATH below).

Run:
    uvicorn ml_api:app --host 0.0.0.0 --port 8002 --reload

Test:
    curl -X POST http://localhost:8002/predict -H "Content-Type: application/json" \
      -d '{"features": {"shannon_entropy": 7.89, "file_size": 1048576, "modification_rate": 0.85}}'
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Ransomware ML Engine", version="1.0.0")

MODEL_PATH = os.environ.get("MODEL_PATH", "../models/xgboost_model.pkl")
METRICS_PATH = os.environ.get("METRICS_PATH", "../reports/model_metrics.json")
IMPORTANCE_PATH = os.environ.get("IMPORTANCE_PATH", "../reports/shap_feature_importance.json")
MODEL_VERSION = "1.0.0"

model = None
cached_metrics = {}
cached_importance = {}


@app.on_event("startup")
def load_artifacts():
    global model, cached_metrics, cached_importance
    model = joblib.load(MODEL_PATH)
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH) as f:
            cached_metrics = json.load(f)
    if os.path.exists(IMPORTANCE_PATH):
        with open(IMPORTANCE_PATH) as f:
            cached_importance = json.load(f)


class PredictRequest(BaseModel):
    # NOTE: the EMBER-trained model expects the full 2381-length feature
    # vector. This "features" dict form (matching the doc's example
    # request) is a convenience wrapper for the Monitor Service - in
    # production the Monitor Service should send the full precomputed
    # EMBER vector under "ember_vector" instead. Both are supported below.
    features: Optional[dict] = None
    ember_vector: Optional[list] = None


class PredictResponse(BaseModel):
    prediction: str
    confidence: float
    model_version: str
    timestamp: str
    threat_level: str
    features_importance: dict


def threat_level_from_confidence(confidence: float) -> str:
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    if req.ember_vector is not None:
        if len(req.ember_vector) != 2381:
            raise HTTPException(
                status_code=400,
                detail=f"ember_vector must have 2381 values, got {len(req.ember_vector)}",
            )
        X = np.array(req.ember_vector, dtype=np.float32).reshape(1, -1)
    elif req.features is not None:
        # Placeholder path for lightweight feature dicts from the Monitor
        # Service. Replace this with real mapping once the Monitor
        # Service's feature extraction is finalized (Sprint 1 deliverable).
        raise HTTPException(
            status_code=501,
            detail="Lightweight 'features' dict prediction not yet implemented. "
                   "Send the full 'ember_vector' (2381 floats) for now.",
        )
    else:
        raise HTTPException(status_code=400, detail="Provide 'ember_vector' or 'features'")

    proba = model.predict_proba(X)[0]
    pred_class = int(np.argmax(proba))
    confidence = float(proba[pred_class])
    prediction = "ransomware" if pred_class == 1 else "benign"

    return PredictResponse(
        prediction=prediction,
        confidence=confidence,
        model_version=MODEL_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        threat_level=threat_level_from_confidence(confidence) if prediction == "ransomware" else "low",
        features_importance=cached_importance,
    )


@app.get("/model/metrics")
def model_metrics():
    if not cached_metrics:
        raise HTTPException(status_code=404, detail="Metrics not found. Run train_ember_model.py first.")
    return {
        **cached_metrics,
        "model_version": MODEL_VERSION,
        "last_trained": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": model is not None}
