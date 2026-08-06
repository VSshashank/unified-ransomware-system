"""URDS ML Engine service (port 8002) - NI.

    POST /predict         classify a file
    GET  /model/metrics   held-out test-set metrics for the loaded models
    GET  /health          liveness for docker-compose and the gateway

Two models sit behind /predict because two different callers ask two different
questions:

  * `ember_vector` - 2381 precomputed EMBER static-PE features. The primary
    classifier (train_ember_model.py).
  * `features` - the signals the Monitor can measure from a file it just saw
    change: entropy, size, magic bytes, extension. Scored by the behavioural
    model (train_behavioral_model.py). The EMBER model cannot read this shape,
    which is why this path used to return 501 and Monitor -> ML never worked.

A model that is not on disk is reported as not loaded rather than faked - a
prediction from a missing classifier would be worse than a 503.
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from uuid import uuid4

import joblib
import numpy as np
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from features import features_to_vector

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("ml_engine")


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_artifacts()
    yield


app = FastAPI(title="URDS ML Engine", version="1.0.0", lifespan=lifespan)

MODEL_DIR = Path(os.getenv("MODEL_DIR", "/models"))
EMBER_MODEL_PATH = Path(os.getenv("MODEL_PATH", str(MODEL_DIR / "xgboost_model.pkl")))
BEHAVIORAL_MODEL_PATH = Path(os.getenv("BEHAVIORAL_MODEL_PATH", str(MODEL_DIR / "behavioral_model.pkl")))
MODEL_VERSION = os.getenv("MODEL_VERSION", "1.0.0")

EMBER_VECTOR_LENGTH = 2381

_ember_model = None
_behavioral_model = None
_metrics: dict = {}
_feature_order: list[str] = []


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_error(code: str, message: str, details: dict | None = None) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "timestamp": utc_now(),
            "request_id": f"req_{uuid4().hex[:12]}",
        },
        "details": details or {},
    }


def _load_json(*candidates: Path) -> dict:
    for candidate in candidates:
        if candidate.is_file():
            try:
                return json.loads(candidate.read_text())
            except ValueError:
                logger.warning("could not parse %s", candidate)
    return {}


def load_artifacts() -> None:
    """Load whatever is present. A missing model degrades that one path only."""
    global _ember_model, _behavioral_model, _metrics, _feature_order

    reports = Path(__file__).resolve().parents[2] / "reports"

    if EMBER_MODEL_PATH.is_file():
        try:
            _ember_model = joblib.load(EMBER_MODEL_PATH)
            logger.info("loaded EMBER model from %s", EMBER_MODEL_PATH)
        except Exception:
            logger.exception("failed to load EMBER model from %s", EMBER_MODEL_PATH)
    else:
        logger.warning("no EMBER model at %s; /predict ember_vector will 503", EMBER_MODEL_PATH)

    if BEHAVIORAL_MODEL_PATH.is_file():
        try:
            _behavioral_model = joblib.load(BEHAVIORAL_MODEL_PATH)
            logger.info("loaded behavioural model from %s", BEHAVIORAL_MODEL_PATH)
        except Exception:
            logger.exception("failed to load behavioural model from %s", BEHAVIORAL_MODEL_PATH)
    else:
        logger.warning("no behavioural model at %s; /predict features will 503", BEHAVIORAL_MODEL_PATH)

    _metrics = {
        "ember": _load_json(MODEL_DIR / "model_metrics.json", reports / "model_metrics.json"),
        "behavioral": _load_json(
            MODEL_DIR / "behavioral_model_metrics.json", reports / "behavioral_model_metrics.json"
        ),
    }
    _feature_order = _metrics.get("behavioral", {}).get("feature_names", [])


class PredictRequest(BaseModel):
    features: dict | None = None
    ember_vector: list[float] | None = None


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content=build_error("BAD_REQUEST", "Request validation failed", {"errors": exc.errors()}),
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 500: "INTERNAL_SERVER_ERROR"}.get(
        exc.status_code, "REQUEST_FAILED"
    )
    return JSONResponse(status_code=exc.status_code, content=build_error(code, str(exc.detail)))


def threat_level_from(confidence: float, prediction: str) -> str:
    if prediction != "ransomware":
        return "low"
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"


def _importance(model, names: list[str]) -> dict:
    try:
        values = model.feature_importances_
    except AttributeError:
        return {}
    if names and len(names) == len(values):
        pairs = zip(names, (float(v) for v in values))
    else:
        pairs = ((f"f{i}", float(v)) for i, v in enumerate(values))
    top = sorted(pairs, key=lambda kv: kv[1], reverse=True)[:10]
    return {name: round(value, 4) for name, value in top}


@app.get("/health")
def health() -> dict:
    return {
        "status": "healthy",
        "service": "ml_engine",
        "ember_model_loaded": _ember_model is not None,
        "behavioral_model_loaded": _behavioral_model is not None,
    }


@app.post("/predict")
def predict(payload: PredictRequest) -> JSONResponse:
    started = perf_counter()

    if payload.ember_vector is not None:
        if _ember_model is None:
            return JSONResponse(
                status_code=503,
                content=build_error(
                    "MODEL_NOT_LOADED",
                    f"No EMBER model available at {EMBER_MODEL_PATH}. Run src/train_ember_model.py.",
                ),
            )
        if len(payload.ember_vector) != EMBER_VECTOR_LENGTH:
            return JSONResponse(
                status_code=400,
                content=build_error(
                    "BAD_REQUEST",
                    f"ember_vector must have {EMBER_VECTOR_LENGTH} values, got {len(payload.ember_vector)}",
                ),
            )
        vector = np.asarray(payload.ember_vector, dtype=np.float32).reshape(1, -1)
        model, model_name, names = _ember_model, "ember_xgboost", []

    elif payload.features is not None:
        if _behavioral_model is None:
            return JSONResponse(
                status_code=503,
                content=build_error(
                    "MODEL_NOT_LOADED",
                    f"No behavioural model available at {BEHAVIORAL_MODEL_PATH}. "
                    "Run src/train_behavioral_model.py.",
                ),
            )
        try:
            vector = np.asarray(
                [features_to_vector(payload.features)], dtype=np.float32
            )
        except (TypeError, ValueError) as exc:
            return JSONResponse(
                status_code=400,
                content=build_error("BAD_REQUEST", f"Could not read features: {exc}"),
            )
        model, model_name, names = _behavioral_model, "behavioral_xgboost", _feature_order

    else:
        return JSONResponse(
            status_code=400,
            content=build_error("BAD_REQUEST", "Provide either 'features' or 'ember_vector'"),
        )

    proba = model.predict_proba(vector)[0]
    predicted_class = int(np.argmax(proba))
    confidence = float(proba[predicted_class])
    prediction = "ransomware" if predicted_class == 1 else "benign"

    return JSONResponse(
        content={
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "model_version": MODEL_VERSION,
            "model": model_name,
            "timestamp": utc_now(),
            "threat_level": threat_level_from(confidence, prediction),
            "features_importance": _importance(model, names),
            "inference_time_ms": round((perf_counter() - started) * 1000, 3),
        }
    )


@app.get("/model/metrics")
def model_metrics() -> JSONResponse:
    ember = _metrics.get("ember", {})
    behavioral = _metrics.get("behavioral", {})

    if not ember and not behavioral:
        return JSONResponse(
            status_code=404,
            content=build_error(
                "METRICS_NOT_FOUND",
                "No metrics on disk. Run src/train_ember_model.py and src/train_behavioral_model.py.",
            ),
        )

    # The dashboard and the gateway contract read the top-level keys, so the
    # primary model's numbers stay flat and both are also reported in full.
    primary = ember or behavioral
    return JSONResponse(
        content={
            "accuracy": primary.get("accuracy"),
            "precision": primary.get("precision"),
            "recall": primary.get("recall"),
            "f1_score": primary.get("f1_score"),
            "roc_auc": primary.get("roc_auc"),
            "model_version": MODEL_VERSION,
            "last_trained": primary.get("trained_at", "unknown"),
            "models": {
                "ember_xgboost": {**ember, "loaded": _ember_model is not None},
                "behavioral_xgboost": {**behavioral, "loaded": _behavioral_model is not None},
            },
        }
    )
