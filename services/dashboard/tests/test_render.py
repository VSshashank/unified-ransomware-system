"""The dashboard renders its panels from gateway data (defect 13).

The live checks used to fetch the dashboard's HTML shell and its health
endpoint, both of which a page showing nothing but its title passes. These run
the real script with Streamlit's AppTest against a stubbed gateway and look at
what it drew.

What they cannot show is the refresh timing itself - that a timed rerun no
longer cancels the run in progress. AppTest has no browser and no timer; that
half was checked live on the Windows test VM (FIXES.md, defect 13).
"""

from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest


APP = Path(__file__).resolve().parents[1] / "app.py"

EVENT = {
    "event_id": "evt_1",
    "timestamp": "2026-10-04T10:00:00Z",
    "event_type": "modified",
    "file_path": r"C:\watch\report.docx",
    "entropy": 7.99,
    "file_size": 32768,
    "magic_bytes": "UNKNOWN",
    "process_id": 4512,
    "user": "urds",
    "suspicious": True,
    "verdict": "suspicious",
}

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
    "/monitor/status": {"status": "active", "files_monitored": 241, "events_captured": 500, "uptime_seconds": 60},
    "/monitor/events": {"events": [EVENT]},
    "/model/metrics": {"accuracy": 0.92, "precision": 0.91, "recall": 0.93, "f1_score": 0.92, "roc_auc": 0.95, "last_trained": "2026-10-04"},
    "/ledger/entries": {"entries": [{"block_id": 42, "current_hash": "c" * 64, "previous_hash": "d" * 64, "timestamp": "2026-10-04T10:00:01Z", "tamper_proof": True}]},
    "/predict": {"prediction": "ransomware", "confidence": 0.94, "threat_level": "high", "features_importance": {"shannon_entropy": 0.35}},
}

PANELS = {
    "End-to-End Pipeline",
    "Current Event Under Review",
    "Model Decision",
    "Entropy Trend",
    "Ledger Evidence",
    "Service Health",
    "Recent File Events",
    "Model Quality",
}


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._payload


@pytest.fixture
def gateway(monkeypatch):
    calls = []

    def answer(url, **_):
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1]
        calls.append(path)
        return FakeResponse(GATEWAY[path])

    monkeypatch.setattr(requests, "get", answer)
    monkeypatch.setattr(requests, "post", answer)
    return calls


def run_dashboard() -> AppTest:
    app = AppTest.from_file(str(APP), default_timeout=60)
    app.run()
    assert not app.exception, [e.value for e in app.exception]
    return app


def test_every_panel_renders_from_gateway_data(gateway):
    app = run_dashboard()

    assert app.title[0].value == "URDS Operations Dashboard"
    assert PANELS <= {header.value for header in app.subheader}
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Files Watched"] == "241"
    assert metrics["Events Captured"] == "500"
    assert metrics["Prediction"] == "Ransomware"
    assert any("Threat Detected" in block.value for block in app.markdown)
    assert not app.error


def test_one_refresh_makes_the_six_gateway_calls_it_did_before(gateway):
    run_dashboard()
    assert sorted(gateway) == sorted(["/health", "/monitor/status", "/monitor/events", "/model/metrics", "/ledger/entries", "/predict"])


def test_an_unreachable_gateway_says_so_and_draws_nothing_else(monkeypatch):
    def refuse(url, **_):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(requests, "post", refuse)
    app = run_dashboard()

    assert app.title[0].value == "URDS Operations Dashboard"
    assert app.error[0].value.startswith("Gateway data unavailable")
    assert not PANELS & {header.value for header in app.subheader}
