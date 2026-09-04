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

# Ascending severity. Anything unrecognised ranks lowest.
THREAT_LEVEL_ORDER = ("low", "medium", "high", "critical")


def _rank(threat_level: str) -> int:
    try:
        return THREAT_LEVEL_ORDER.index(threat_level)
    except ValueError:
        return 0


def effective_threat_level(model_threat_level: str | None, suspicious: bool) -> str:
    """Combine the model's score with the Monitor's own verdict, taking the higher.

    The ML engine refines the Monitor's verdict; it does not overrule it. The
    behavioural classifier's operating point needs Shannon entropy of roughly
    7.995 before it calls something ransomware with confidence, and ciphertext
    under about 40KB cannot reach that through sampling noise alone. So a small
    file encrypted in place scored "low" here while the Monitor had already
    classified it `suspected_encryption` - and because the response gate read
    only the model's answer, nothing acted on it. Measured on this machine, that
    was every trial at 4KB, 8KB and 32KB.

    Treating the Monitor as a floor rather than a fallback keeps one detector
    from silently cancelling the other, and keeps the level coherent downstream:
    the Response service runs network isolation on `high`/`critical` only, so
    forwarding "low" for a file we are confident is encrypted would trigger a
    response that then declined to do most of its job.
    """
    monitor_threat_level = "high" if suspicious else "low"
    model_threat_level = model_threat_level or "low"
    return max(model_threat_level, monitor_threat_level, key=_rank)


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


def log_baseline(client: httpx.Client, event: dict) -> dict | None:
    """Record what a file hashed to while it was still known-good.

    `file_baseline` is one of the three event types
    services/response/recovery/ledger_client.py will accept as a reference for
    an integrity check, and until this existed nothing in the running system
    wrote any of them. The Monitor reached the ledger only for suspicious
    events, so the newest hash on an attacked path was the attacker's - which
    made "does the restored file match the ledger" a test that passed only if
    recovery handed back the ciphertext. The recovery client refuses to trust
    that hash, correctly, and the result was a verification step that could
    never verify anything.

    Written once per path per monitor run, for a file the detector found benign
    the first time it saw it. That is the strongest claim available without a
    trusted installer manifest, and the claim is exactly what it says: this is
    what the file hashed to when this monitor first saw it and had no reason to
    think it had been touched.
    """
    return log_to_ledger(
        client,
        "file_baseline",
        {
            "file_path": event.get("file_path"),
            "file_hash": event.get("file_hash"),
            "file_size": event.get("file_size"),
            "entropy": event.get("entropy"),
            "verdict": event.get("verdict"),
            "event_type": event.get("event_type"),
            "observed_at": event.get("timestamp") or utc_now(),
        },
    )


def log_governance_decision(client: httpx.Client, event: dict) -> dict | None:
    """Chain a suppression that *cancelled* an alert.

    P5.1 row M-16 and Table 9.8 row 7: an admitted suppression stops the event
    at `app.handle_event`'s fan-out gate, so the one decision an auditor most
    needs to see - the one that made a detection disappear - was the only one
    the chain never held. Coverage measured at 50.0% before this existed.

    This is not the pipeline. There is no prediction and no response, because
    the alert was cancelled and acting on it would defeat the operator's own
    rule. What is written is the decision and its two costs, so the chain shows
    that a detection existed, which rule removed it, and what that rule would
    have cost to forge against what the signal cost to avoid.
    """
    admissibility = event.get("admissibility")
    if not admissibility:
        return None
    return log_to_ledger(
        client,
        "suppression_decision",
        {
            "file_path": event.get("file_path"),
            "file_hash": event.get("file_hash"),
            "event_type": event.get("event_type"),
            "entropy": event.get("entropy"),
            # The verdict as the detector reached it, before the rule applied.
            # Without this the entry says a rule fired and not what it silenced.
            "verdict": event.get("verdict"),
            "reason": event.get("reason"),
            "signal": admissibility.get("signal"),
            "admissibility": admissibility,
            "outcome": admissibility.get("outcome"),
            # The two fields NOVELTY_PROOF_PLAN.md §9 row 10 requires and this
            # block did not have. `admissibility` already carries the mitigation
            # identifier, both capability levels and the reason; these say what
            # the validator concluded and under which policy it was read.
            "validation_state": event.get("validation_state"),
            "policy_version": event.get("policy_version"),
            "suppressed_by": event.get("suppressed_by"),
            "detection_latency_ms": event.get("detection_latency_ms"),
            "observed_at": event.get("timestamp") or utc_now(),
        },
    )


def predict(client: httpx.Client, features: dict) -> dict | None:
    return _post(client, ML_URL, "/predict", {"features": features})


def trigger_response(
    client: httpx.Client,
    incident_id: str,
    process_id: int | None,
    threat_level: str,
    admissibility: dict | None = None,
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
            # The governance record travels with the incident. An operator rule
            # that was consulted and outranked is why this response is firing at
            # all, and the Response service's own ledger entry should say so
            # rather than making an auditor join two chains on a timestamp.
            "admissibility": admissibility,
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

        model_threat_level = (prediction or {}).get("threat_level")
        threat_level = effective_threat_level(model_threat_level, verdict["suspicious"])
        label = (prediction or {}).get("prediction", "ransomware" if verdict["suspicious"] else "benign")

        # file_hash is the field SI's recovery integrity check depends on.
        event_data = {
            "file_path": event.get("file_path"),
            "file_hash": file_hash,
            "event_type": event.get("event_type"),
            "entropy": verdict.get("entropy"),
            # Differential entropy - the rise that made this suspicious, when a
            # rise is what did. Null for a file seen only once.
            "entropy_delta": verdict.get("entropy_delta"),
            "verdict": verdict.get("verdict"),
            "reason": verdict.get("reason"),
            # Which detection fired, and whether any operator rule tried to
            # cancel it. An outranked suppression is recorded here with both
            # costs, so the chain shows a rule that was consulted and lost
            # rather than leaving the operator to wonder why theirs did nothing.
            "signal": verdict.get("signal"),
            "admissibility": event.get("admissibility"),
            "container_format": verdict.get("container_format"),
            "container_valid": verdict.get("container_valid"),
            # An *attenuated* decision is chained here rather than as a
            # `suppression_decision`, because the alert stood and the event went
            # through the pipeline. TC-23 asks for the same five fields on it as
            # on a cancelled one, so both blocks carry them.
            "validation_state": verdict.get("validation_state"),
            "policy_version": verdict.get("policy"),
            "detection_latency_ms": event.get("detection_latency_ms"),
            "process_id": event.get("process_id"),
            "prediction": label,
            "confidence": (prediction or {}).get("confidence"),
            "threat_level": threat_level,
            # What the model said before the Monitor's verdict was applied as a
            # floor. Recorded so an escalated entry ("prediction": "benign",
            # "threat_level": "high") reads as a deliberate override with both
            # inputs visible, rather than as two fields contradicting each other.
            "model_threat_level": model_threat_level,
        }

        block = log_to_ledger(client, "file_event", event_data)
        if block:
            result["ledger_block"] = block
            result["stages"].append("ledger_logged")

        if threat_level in ACTIONABLE_THREAT_LEVELS:
            incident_id = f"inc_{(block or {}).get('block_id', 'na')}_{event.get('event_id', 'na')}"
            response = trigger_response(
                client,
                incident_id,
                event.get("process_id"),
                threat_level,
                admissibility=event.get("admissibility"),
            )
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
                        "admissibility": event.get("admissibility"),
                        # The third block that can hold an adjudication, and so
                        # the third that TC-23 reads. An attenuated decision is
                        # chained here as well as on the `file_event`; a record
                        # complete on one and truncated on the other is not a
                        # complete record.
                        "validation_state": verdict.get("validation_state"),
                        "policy_version": verdict.get("policy"),
                        "timestamp": utc_now(),
                    },
                )
        return result
    finally:
        if owns_client:
            client.close()
