"""Every console page renders from gateway data (defect 13).

These run the real scripts with Streamlit's AppTest against a stubbed gateway
and look at what they drew. The refresh timing itself - that a timed rerun no
longer cancels the run in progress - cannot be shown here: AppTest has no
browser and no timer; that half was checked live on the Windows test VM
(FIXES.md, defect 13).
"""

from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app.py"
VIEWS = ROOT / "views"
PAGES = ("overview.py", "events.py", "ledger.py", "response.py", "model.py")

EVENT = {
    "event_id": "evt_1",
    "timestamp": "2026-10-04T10:00:00Z",
    "event_type": "modified",
    "file_path": r"C:\watch\report.docx",
    "entropy": 7.99,
    "file_size": 32768,
    "magic_bytes": "UNKNOWN",
    "process_id": 4512,
    "process_image": r"C:\Python313\python.exe",
    "attribution_confidence": "certain",
    "user": "urds",
    "suspicious": True,
    "verdict": "suspected_encryption",
    "block_id": 42,
    "pipeline": {"stages": ["ml_predicted", "ledger_logged", "response_triggered"]},
    "attribution_escalation": {"result": "terminated"},
}
BENIGN = dict(EVENT, event_id="evt_2", file_path=r"C:\watch\notes.txt", entropy=4.1, suspicious=False,
              verdict="benign", block_id=None, pipeline=None, attribution_escalation=None, process_id=None)


def block(i: int, event_type: str = "file_event", **data) -> dict:
    return {
        "block_id": i, "timestamp": "2026-10-04T10:00:01Z", "event_type": event_type,
        "event_data": {"file_path": r"C:\watch\report.docx", "verdict": "suspected_encryption", **data},
        "previous_hash": f"{i - 1:064x}", "current_hash": f"{i:064x}",
    }


BLOCKS = [block(i) for i in range(42, 0, -1)]

GATEWAY = {
    "/health": {
        "status": "healthy",
        "services": {
            "gateway": {"status": "healthy"},
            "monitor": {"status": "healthy", "service": "monitor", "watching": True},
            "ml_engine": {"status": "healthy", "service": "ml-engine"},
            "ledger": {"status": "healthy", "service": "ledger"},
            "response": {"status": "healthy", "service": "response"},
        },
    },
    "/monitor/status": {"status": "active", "watch_path": r"C:\watch", "files_monitored": 241,
                        "events_captured": 500, "uptime_seconds": 60, "attribution_available": True,
                        "attribution_source": "security_log"},
    "/monitor/events": {"events": [EVENT, BENIGN]},
    "/model/metrics": {"accuracy": 0.92, "precision": 0.91, "recall": 0.93, "f1_score": 0.92, "roc_auc": 0.95,
                       "last_trained": "2026-10-04", "model_version": "1.0.0",
                       "models": {"behavioral_xgboost": {"accuracy": 0.99, "loaded": True, "test_samples": 870}}},
    "/ledger/entries": {"entries": BLOCKS[:8]},
    "/ledger/verify": {"valid": True, "blocks_checked": 42, "invalid_block_id": None, "verification_time_ms": 1.2},
    "/response/leases": {"leases": []},
    "/predict": {"prediction": "ransomware", "confidence": 0.94, "threat_level": "high",
                 "features_importance": {"shannon_entropy": 0.35}},
}


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload
        self.status_code = 200
        self.text = ""

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._payload


def blocks_answer(params: dict | None) -> dict:
    """/ledger/blocks honouring offset, limit, newest_first and event_type."""
    params = params or {}
    rows = [b for b in BLOCKS if not params.get("event_type") or b["event_type"] == params["event_type"]]
    if str(params.get("newest_first", "false")).lower() != "true":
        rows = list(reversed(rows))
    offset, limit = int(params.get("offset", 0)), int(params.get("limit", 50))
    return {"blocks": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit}


@pytest.fixture
def gateway(monkeypatch):
    calls = []

    def answer(url, params=None, **_):
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1]
        calls.append(path)
        if path == "/ledger/blocks":
            return FakeResponse(blocks_answer(params))
        if path == "/monitor/attribution":
            return FakeResponse({"available": True, "source": "security_log"})
        if path == "/monitor/whitelist":
            return FakeResponse({"whitelist": {"paths": [], "hashes": []}, "entries": 0})
        return FakeResponse(GATEWAY[path])

    monkeypatch.setattr(requests, "get", answer)
    monkeypatch.setattr(requests, "post", answer)
    return calls


def run(script: Path) -> AppTest:
    app = AppTest.from_file(str(script), default_timeout=60)
    app.run()
    assert not app.exception, [e.value for e in app.exception]
    return app


def run_dashboard() -> AppTest:
    return run(APP)


def markdown(app: AppTest) -> str:
    return "\n".join(block.value for block in app.markdown)


def test_the_console_opens_on_the_overview(gateway):
    page = markdown(run_dashboard())
    assert "<h1>Overview</h1>" in page
    for service in ("Gateway", "Monitor", "ML engine", "Ledger", "Response"):
        assert service in page
    assert "Files watched" in page and "241" in page
    assert "Chain integrity" in page and "Valid" in page


def test_the_overview_follows_the_latest_alert_end_to_end(gateway):
    page = markdown(run(VIEWS / "overview.py"))
    assert "Latest alert" in page
    assert r"C:\watch\report.docx" in page
    # Monitor and model together decide the status (pipeline.py's rule).
    assert "High" in page
    assert "Suspected encryption" in page and "Block #42" in page and "Terminated" in page
    assert "python.exe · PID 4512 · certain" in page


def test_one_overview_refresh_makes_the_calls_it_needs(gateway):
    run(VIEWS / "overview.py")
    assert sorted(gateway) == sorted(["/health", "/monitor/status", "/monitor/events", "/ledger/verify",
                                      "/ledger/entries", "/predict"])


def test_the_ledger_page_lists_every_block_and_inspects_one(gateway):
    app = run(VIEWS / "ledger.py")
    page = markdown(app)
    assert "<h1>Ledger</h1>" in page
    table = next(frame.value for frame in app.dataframe if "Previous hash" in frame.value.columns)
    assert len(table) == 42
    assert set(table["Link"]) <= {"Linked", ""}
    assert "Block #42" in page and f"{42:064x}" in page and "Linked to #41" in page


def test_the_ledger_page_names_the_broken_block(gateway, monkeypatch):
    monkeypatch.setitem(GATEWAY, "/ledger/verify",
                        {"valid": False, "blocks_checked": 42, "invalid_block_id": 17, "verification_time_ms": 1.0})
    page = markdown(run(VIEWS / "ledger.py"))
    assert "Broken" in page and "first bad block #17" in page
    assert "Block #17" in page and "Fails verification" in page


def test_the_events_page_shows_the_alert_in_full(gateway):
    app = run(VIEWS / "events.py")
    table = next(frame.value for frame in app.dataframe if "Verdict" in frame.value.columns)
    assert list(table["File"]) == ["report.docx", "notes.txt"]
    page = markdown(app)
    assert "Suspected encryption" in page and "Terminated" in page


@pytest.mark.parametrize("script", ["response.py", "model.py"])
def test_the_other_pages_render(gateway, script):
    assert "<h1>" in markdown(run(VIEWS / script))


def test_no_table_needs_streamlits_arrow_fallback(gateway, monkeypatch):
    """Tables hold text, not a mix pyarrow cannot store.

    With a path, an entropy, a PID and a boolean in one Value column, every
    refresh made Streamlit catch an ArrowTypeError, log it, and convert the
    column itself (reports/VM_TEST_REPORT_2026-10-04.md, "After the test").
    `fix_arrow_incompatible_column_types` runs only after that failure, so
    counting its calls counts the failures. The event carries an adjudication,
    so the Events page draws its Field / Value table.
    """
    import streamlit.dataframe_util as dataframe_util

    fallbacks = []
    real = dataframe_util.fix_arrow_incompatible_column_types

    def counting(df, *args, **kwargs):
        fallbacks.append(list(df.columns))
        return real(df, *args, **kwargs)

    monkeypatch.setattr(dataframe_util, "fix_arrow_incompatible_column_types", counting)
    adjudicated = dict(EVENT, admissibility={
        "rule": "path", "value": r"C:\watch\*", "signal": "static_entropy", "forgery_cost": "low",
        "avoidance_cost": "negligible", "outcome": "attenuated", "reason": "test", "admitted": False,
    })
    monkeypatch.setitem(GATEWAY, "/monitor/events", {"events": [adjudicated, BENIGN]})

    for script in PAGES:
        run(VIEWS / script)
    assert fallbacks == [], f"tables pyarrow could not store: {fallbacks}"


def test_an_unreachable_gateway_says_so_and_draws_nothing_else(monkeypatch):
    def refuse(url, **_):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(requests, "post", refuse)
    for script in PAGES:
        app = run(VIEWS / script)
        assert app.error[0].value.startswith("Gateway data unavailable"), script
        assert not app.dataframe, script
