"""Response API contract: terminate, isolate, trigger.

The ledger is unreachable in these tests, which is deliberate - an action that
succeeded must still be reported as succeeded when the audit write fails.
"""

import subprocess
import sys

import psutil
import pytest
from fastapi.testclient import TestClient

import actions
import app as response_app


@pytest.fixture
def client(monkeypatch):
    # Never let a unit test shell out to a firewall.
    monkeypatch.setattr(actions, "ISOLATION_ENABLED", False)
    with TestClient(response_app.app) as test_client:
        yield test_client


@pytest.fixture
def victim():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    yield process
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)


def test_health_is_no_longer_flagged_as_a_placeholder(client):
    body = client.get("/health").json()
    assert body["status"] == "healthy"
    assert body["service"] == "response"
    assert "placeholder" not in body


# ------------------------------------------------------------------ terminate


def test_terminate_kills_a_real_process(client, victim):
    body = client.post(
        "/response/terminate",
        json={"process_id": victim.pid, "incident_id": "inc-1", "reason": "ransomware", "force": True},
    ).json()

    assert body["status"] == "terminated"
    assert body["process_id"] == victim.pid
    assert body["incident_id"] == "inc-1"
    assert body["termination_time_ms"] < 2000
    victim.wait(timeout=5)


def test_terminate_refusal_uses_the_error_envelope(client):
    response = client.post(
        "/response/terminate",
        json={"process_id": 1, "incident_id": "inc-2", "reason": "test", "force": True},
    )
    assert response.status_code == 409
    body = response.json()
    assert body["error"]["code"] == "TERMINATION_REFUSED"
    assert set(body["error"]) == {"code", "message", "timestamp", "request_id"}


def test_terminate_reports_success_even_when_the_ledger_is_down(client, victim):
    """The ledger host does not resolve in this test; the kill still happened."""
    response = client.post(
        "/response/terminate",
        json={"process_id": victim.pid, "incident_id": "inc-3", "reason": "test", "force": True},
    )
    assert response.status_code == 200
    assert not psutil.pid_exists(victim.pid) or psutil.Process(victim.pid).status() == psutil.STATUS_ZOMBIE


# -------------------------------------------------------------------- isolate


def test_isolate_reports_that_it_did_not_enforce(client):
    body = client.post(
        "/response/isolate",
        json={"isolation_level": "full", "duration_seconds": 300, "allow_localhost": True},
    ).json()

    assert body["enforced"] is False
    assert body["status"] == "simulated"
    assert body["isolation_level"] == "full"
    assert isinstance(body["planned_rules"], list)


# -------------------------------------------------------------------- trigger


def test_trigger_terminates_and_plans_isolation_for_a_critical_threat(client, victim):
    body = client.post(
        "/response/trigger",
        json={
            "incident_id": "inc-4",
            "process_id": victim.pid,
            "threat_level": "critical",
            "action_required": "terminate_process",
        },
    ).json()

    assert body["status"] == "success"
    assert "process_terminated" in body["actions_taken"]
    assert "network_isolation_planned" in body["actions_taken"]
    assert "admin_notified" in body["actions_taken"]
    assert body["details"]["terminate"]["status"] == "terminated"
    victim.wait(timeout=5)


def test_trigger_on_a_low_threat_does_not_isolate(client):
    body = client.post(
        "/response/trigger",
        json={
            "incident_id": "inc-5",
            "process_id": 0,
            "threat_level": "low",
            "action_required": "log_only",
        },
    ).json()

    assert body["actions_taken"] == ["admin_notified"]


def test_trigger_records_a_refused_kill_instead_of_claiming_it_worked(client):
    body = client.post(
        "/response/trigger",
        json={
            "incident_id": "inc-6",
            "process_id": 1,
            "threat_level": "critical",
            "action_required": "terminate_process",
        },
    ).json()

    assert "process_terminated" not in body["actions_taken"]
    assert body["details"]["terminate"]["status"] == "refused"


def test_trigger_validation_error_uses_the_shared_envelope(client):
    response = client.post("/response/trigger", json={"incident_id": "x"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "BAD_REQUEST"
