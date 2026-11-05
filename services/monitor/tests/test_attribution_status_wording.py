"""Defect 8 of the Windows integration test: /monitor/attribution before the watch starts.

The module-level attributor is built at import and gets its real source from
POST /monitor/start. Until then the endpoint said "no attribution source
configured" - a configuration fault, on a host that was configured correctly
and simply not watching yet.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
from attribution import Attributor  # noqa: E402


def test_a_fresh_attributor_says_correlation_starts_with_monitoring():
    status = Attributor().status()

    assert status["available"] is False
    assert status["error"] == attribution.NOT_STARTED
    assert "POST /monitor/start" in status["error"]
    assert "configured" not in status["error"]


def test_the_endpoint_says_so_before_the_watch_starts(monkeypatch):
    monkeypatch.setattr(monitor_app, "attributor", Attributor())

    with TestClient(monitor_app.app) as client:
        body = client.get("/monitor/attribution").json()

    assert body["error"] == attribution.NOT_STARTED


def test_a_source_that_failed_still_says_why():
    """The new wording is for 'not started', not a blanket replacement."""
    log = attribution.WriteLog()
    at = Attributor(log=log, source=attribution.NullSource(log, "Security channel unavailable"))

    assert at.status()["error"] == "Security channel unavailable"
