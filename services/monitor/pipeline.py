"""Downstream fan-out for a suspicious file event - AS.

The Monitor is what notices an attack, so it is what drives the rest of the
chain: ML classification, ledger entry, then response. Each hop is best-effort
and independently reported - a ledger that is briefly down must not stop a
process from being killed, and a failed kill must still leave an audit trail.

Every ledger event carries `file_hash` in `event_data`. SI's recovery integrity
check reads that field back to decide whether a restored file matches what was
last seen, so it is not optional metadata.
"""

import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

LEDGER_URL = os.getenv("LEDGER_URL", "http://ledger:8003").rstrip("/")
ML_URL = os.getenv("ML_URL", "http://ml_engine:8002").rstrip("/")
RESPONSE_URL = os.getenv("RESPONSE_URL", "http://response:8004").rstrip("/")

# Short: this runs on the detection path, where the target is sub-100ms to
# decide and a couple of seconds to act.
DOWNSTREAM_TIMEOUT = float(os.getenv("DOWNSTREAM_TIMEOUT", "3.0"))

# Threat levels that justify killing a process.
ACTIONABLE_THREAT_LEVELS = {"high", "critical"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class PipelineResult(dict):
    """Plain dict; named so logs and tests read clearly."""


def _post(client: httpx.Client, base_url: str, path: str, payload: dict) -> dict | None:
    try:
        response = client.post(f"{base_url}{path}", json=payload, timeout=DOWNSTREAM_TIMEOUT)
        if response.status_code >= 400:
            logger.warning("%s%s returned %s: %s", base_url, path, response.status_code, response.text[:200])
            return None
        return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("%s%s unreachable: %s", base_url, path, exc)
        return None


def log_to_ledger(client: httpx.Client, event_type: str, event_data: dict) -> dict | None:
    """Append one event. `event_data` must already contain file_hash when known."""
    return _post(client, LEDGER_URL, "/ledger/log", {"event_type": event_type, "event_data": event_data})


def predict(client: httpx.Client, features: dict) -> dict | None:
    return _post(client, ML_URL, "/predict", {"features": features})


def trigger_response(
    client: httpx.Client, incident_id: str, process_id: int | None, threat_level: str
) -> dict | None:
    """Ask the Response service to act on one incident.

    Termination is only requested when the offending PID is actually known.
    Watchdog cannot attribute a file event to a process, so for a filesystem
    detection it is not - asking for a kill anyway would name some unrelated
    process in the Response container's PID namespace.
    """
    return _post(
        client,
        RESPONSE_URL,
        "/response/trigger",
        {
            "incident_id": incident_id,
            "process_id": process_id or 0,
            "threat_level": threat_level,
            "action_required": "terminate_process" if process_id else "isolate_and_log",
        },
    )


def run(event: dict, features: dict, verdict: dict, client: httpx.Client | None = None) -> PipelineResult:
    """ML -> ledger -> response for one detected event.

    Returns what each hop did so `/monitor/events` can show the chain and the
    integration test can assert on it.
    """
    owns_client = client is None
    client = client or httpx.Client(timeout=DOWNSTREAM_TIMEOUT)
    result = PipelineResult(
        {"prediction": None, "ledger_block": None, "response": None, "stages": []}
    )

    try:
        file_hash = event.get("file_hash")

        prediction = predict(client, features)
        if prediction:
            result["prediction"] = prediction
            result["stages"].append("ml_predicted")

        threat_level = (prediction or {}).get("threat_level", "high" if verdict["suspicious"] else "low")
        label = (prediction or {}).get("prediction", "ransomware" if verdict["suspicious"] else "benign")

        # file_hash is the field SI's recovery integrity check depends on.
        event_data = {
            "file_path": event.get("file_path"),
            "file_hash": file_hash,
            "event_type": event.get("event_type"),
            "entropy": verdict.get("entropy"),
            "verdict": verdict.get("verdict"),
            "reason": verdict.get("reason"),
            "container_format": verdict.get("container_format"),
            "detection_latency_ms": event.get("detection_latency_ms"),
            "process_id": event.get("process_id"),
            "prediction": label,
            "confidence": (prediction or {}).get("confidence"),
            "threat_level": threat_level,
        }

        block = log_to_ledger(client, "file_event", event_data)
        if block:
            result["ledger_block"] = block
            result["stages"].append("ledger_logged")

        if threat_level in ACTIONABLE_THREAT_LEVELS:
            incident_id = f"inc_{(block or {}).get('block_id', 'na')}_{event.get('event_id', 'na')}"
            response = trigger_response(client, incident_id, event.get("process_id"), threat_level)
            if response:
                result["response"] = response
                result["stages"].append("response_triggered")
                log_to_ledger(
                    client,
                    "response_action",
                    {
                        "file_path": event.get("file_path"),
                        "file_hash": file_hash,
                        "incident_id": incident_id,
                        "threat_level": threat_level,
                        "actions_taken": response.get("actions_taken", []),
                        "timestamp": utc_now(),
                    },
                )
        return result
    finally:
        if owns_client:
            client.close()
