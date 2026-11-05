"""`/response/suspend`, `/resume`, `/leases` and the lease on `/terminate`, on real processes.

Defect 26 (F2b, Response side). Before this, `POST /response/suspend` was a
404 (VM test 2026-10-05). Every test here suspends a real child it started (see
conftest.py) and judges "frozen" by its heartbeat, so on Windows this is
`NtSuspendProcess` itself, nesting included.

The ledger is replaced by a list, so the blocks can be checked: suspend and
resume blocks name the PID *together with* the gate that allowed it (C-16).
"""

from __future__ import annotations

import os
import sys

import psutil
import pytest
from fastapi.testclient import TestClient

import actions
import app as response_app


class Clock:
    def __init__(self) -> None:
        self.now = 50_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def blocks(monkeypatch):
    recorded: list[tuple[str, dict]] = []
    monkeypatch.setattr(actions, "ISOLATION_ENABLED", False)
    monkeypatch.setattr(
        response_app, "log_action",
        lambda event_type, event_data: recorded.append((event_type, event_data)) or {"block_id": len(recorded)},
    )
    monkeypatch.delenv("URDS_MONITOR_PID", raising=False)
    monkeypatch.delenv("RESPONSE_PID_NAMESPACE", raising=False)
    return recorded


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def table(monkeypatch, clock, blocks):
    """A fresh table per test: injected clock, no watchdog child (see test_lease_watchdog.py).

    On a tree without leases (base dc089ff) there is nothing to replace and the
    tests run against the app as it is - where /response/suspend is a 404.
    """
    builder = getattr(response_app, "build_lease_table", None)
    if builder is None:
        return None
    table = builder(watchdog=None, clock=clock)
    monkeypatch.setattr(response_app, "LEASES", table)
    return table


@pytest.fixture
def client(table):
    with TestClient(response_app.app) as test_client:
        yield test_client


def body_for(child, **overrides):
    body = {
        "process_id": child.pid,
        "incident_id": "inc-s1",
        "lease_seconds": 2.0,
        "reason": "sole writer of report.docx",
        "attribution_confidence": "probable",
        "attribution_source": "windows-security-4663",
        "attribution_reason": "one writer so far (pending)",
        "image": child.image,
        "started_at": child.started_at,
    }
    body.update(overrides)
    return body


def of_type(blocks, event_type):
    return [data for kind, data in blocks if kind == event_type]


GATE = ("attribution_confidence", "attribution_source", "attribution_reason")


def assert_caller_claim(block):
    """Review follow-up R8c: the gate is the caller's claim, never Response's verdict."""
    assert block["attribution_supplied_by"] == "caller"
    assert block["gate"] is None
    assert block["gate_verified"] is False
    assert block["gate_reason"] == "no gate supplied (operator request)"


# ---------------------------------------------------------------- the happy path


def test_suspend_freezes_and_resume_unfreezes_a_real_process(client, child, blocks):
    response = client.post("/response/suspend", json=body_for(child))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["suspended"] is True
    assert body["already_held"] is False
    assert body["process_id"] == child.pid
    assert body["lease_id"].startswith("lease_")
    assert body["expires_at"].endswith("Z")
    assert child.is_frozen()

    listing = client.get("/response/leases").json()
    assert listing == [{"lease_id": body["lease_id"], "process_id": child.pid, "incident_id": "inc-s1",
                        "expires_at": body["expires_at"], "state": "held"}]

    resumed = client.post("/response/resume", json={"lease_id": body["lease_id"], "incident_id": "inc-s1",
                                                    "reason": "a second writer appeared"})
    assert resumed.status_code == 200
    assert resumed.json()["resumed"] is True
    assert resumed.json()["reason"] == "a second writer appeared"
    assert child.is_running()

    (suspended,) = of_type(blocks, "process_suspended")
    (resumed_block,) = of_type(blocks, "process_resumed")
    for block in (suspended, resumed_block):
        assert block["process_id"] == child.pid
        assert block["lease_id"] == body["lease_id"]
        assert block["incident_id"] == "inc-s1"
        assert_caller_claim(block)
        assert block["attribution_confidence"] == "probable"
        assert block["attribution_source"] == "windows-security-4663"
        assert block["attribution_reason"] == "one writer so far (pending)"
    assert suspended["outcome"] == "suspended" and suspended["suspended"] is True
    assert resumed_block["resumed"] is True
    assert resumed_block["reason"] == "a second writer appeared"
    assert resumed_block["requested_by"] == "caller"


def test_resume_by_process_id(client, child):
    client.post("/response/suspend", json=body_for(child))
    assert child.is_frozen()
    response = client.post("/response/resume", json={"process_id": child.pid, "incident_id": "inc-s1",
                                                     "reason": "released"})
    assert response.json()["resumed"] is True
    assert child.is_running()


def test_a_second_suspend_is_a_no_op_and_one_resume_unfreezes(client, child, blocks):
    """Suspension nests on Windows: had the second call suspended again, the
    single resume below would leave the child frozen."""
    first = client.post("/response/suspend", json=body_for(child)).json()
    second = client.post("/response/suspend", json=body_for(child, incident_id="inc-s2")).json()
    assert second["already_held"] is True
    assert second["lease_id"] == first["lease_id"]
    assert second["incident_id"] == "inc-s1"
    assert len(of_type(blocks, "process_suspended")) == 1

    client.post("/response/resume", json={"lease_id": first["lease_id"], "incident_id": "inc-s1",
                                          "reason": "released"})
    assert child.is_running()


def test_resume_is_idempotent(client, child, blocks):
    lease_id = client.post("/response/suspend", json=body_for(child)).json()["lease_id"]
    resume = {"lease_id": lease_id, "incident_id": "inc-s1", "reason": "released"}
    assert client.post("/response/resume", json=resume).json()["resumed"] is True
    again = client.post("/response/resume", json=resume)
    assert again.status_code == 200
    assert again.json()["resumed"] is False
    assert again.json()["state"] == "resumed"
    assert len(of_type(blocks, "process_resumed")) == 1
    assert child.is_running()


def test_resuming_a_process_never_suspended_is_a_no_op(client, child):
    response = client.post("/response/resume", json={"process_id": child.pid, "incident_id": "x", "reason": "r"})
    assert response.status_code == 200
    assert response.json()["resumed"] is False


# ---------------------------------------------------------------- leases end


def test_an_expired_lease_resumes_the_process(client, child, table, clock, blocks):
    lease_id = client.post("/response/suspend", json=body_for(child, lease_seconds=1.5)).json()["lease_id"]
    assert child.is_frozen()
    clock.now += 1.5
    table.reap()
    assert child.is_running()
    assert table.drain()  # blocks are written off the reaper's thread
    (block,) = of_type(blocks, "process_resumed")
    assert block["lease_id"] == lease_id
    assert block["reason"] == "lease_expired"
    assert block["requested_by"] == "lease_expiry"
    assert_caller_claim(block)
    assert client.get("/response/leases").json()[0]["state"] == "resumed"


def test_response_shutdown_resumes_every_held_lease(table, blocks, make_child):
    children = [make_child(), make_child()]
    with TestClient(response_app.app) as client:
        for n, child in enumerate(children):
            assert client.post("/response/suspend", json=body_for(child, incident_id=f"inc-{n}")).status_code == 200
        assert all(child.is_frozen() for child in children)
    # Leaving the context runs the lifespan's shutdown.
    assert all(child.is_running() for child in children)
    reasons = {block["reason"] for block in of_type(blocks, "process_resumed")}
    assert reasons == {"response_shutdown"}


def test_terminate_with_a_lease_releases_it(client, child, blocks):
    lease_id = client.post("/response/suspend", json=body_for(child)).json()["lease_id"]
    assert child.is_frozen()
    response = client.post("/response/terminate", json={
        "process_id": child.pid, "incident_id": "inc-s1", "reason": "killed at the horizon", "force": True,
        "attribution_confidence": "certain", "attribution_source": "windows-security-4663",
        "lease_id": lease_id,
    })
    assert response.status_code == 200, response.text
    assert response.json()["lease_id"] == lease_id
    assert response.json()["lease_released"] is True
    try:
        psutil.Process(child.pid).wait(timeout=5)
    except psutil.NoSuchProcess:
        pass
    assert not psutil.pid_exists(child.pid)

    assert client.get("/response/leases").json()[0]["state"] == "terminated"
    (kill,) = [b for t, b in blocks if t == "response_action" and b["action"] == "terminate"]
    assert kill["lease_id"] == lease_id
    assert kill["incident_id"] == "inc-s1"
    assert of_type(blocks, "process_resumed") == []
    # Idempotent after a kill too.
    again = client.post("/response/resume", json={"lease_id": lease_id, "incident_id": "inc-s1", "reason": "r"})
    assert again.json()["resumed"] is False


def test_terminate_after_the_lease_expired_says_so(client, child, table, clock, blocks):
    """The kill still happens (its gate is the Monitor's); the response says the lease was over."""
    lease_id = client.post("/response/suspend", json=body_for(child, lease_seconds=1.5)).json()["lease_id"]
    clock.now += 1.5
    table.reap()
    response = client.post("/response/terminate", json={
        "process_id": child.pid, "incident_id": "inc-s1", "reason": "late kill", "force": True,
        "lease_id": lease_id,
    })
    assert response.status_code == 200
    assert response.json()["lease_released"] is False
    assert "already ended resumed" in response.json()["lease_note"]


def test_terminate_without_a_lease_is_unchanged(client, child, blocks):
    response = client.post("/response/terminate", json={
        "process_id": child.pid, "incident_id": "inc-t", "reason": "ransomware", "force": True,
    })
    assert response.status_code == 200
    assert response.json()["status"] == "terminated"
    assert response.json()["lease_released"] is False
    (kill,) = of_type(blocks, "response_action")
    assert kill["lease_id"] is None


# ---------------------------------------------------------------- refusals


def refused(response, code):
    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == code
    assert body["error"]["code"] == code
    assert body["message"] == body["error"]["message"]
    return body


def assert_refusal_recorded(blocks, child, code):
    (block,) = of_type(blocks, "process_suspended")
    assert block["outcome"] == "refused"
    assert block["suspended"] is False
    assert block["code"] == code
    assert block["process_id"] == child.pid
    assert all(block[key] for key in GATE)
    assert_caller_claim(block)


def test_a_reused_pid_wrong_started_at_is_refused(client, child, blocks):
    """The number belongs to a process created after the one attribution named."""
    response = client.post("/response/suspend", json=body_for(child, started_at=child.started_at - 30.0))
    refused(response, "PID_REUSED")
    assert child.is_running()
    assert_refusal_recorded(blocks, child, "PID_REUSED")
    assert client.get("/response/leases").json() == []


def test_started_at_may_be_iso_8601(client, child):
    from datetime import datetime, timezone

    iso = datetime.fromtimestamp(child.started_at, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    assert client.post("/response/suspend", json=body_for(child, started_at=iso)).status_code == 200
    assert child.is_frozen()


def test_a_reused_pid_wrong_image_is_refused(client, child, blocks):
    other = os.path.join(os.path.dirname(child.image), "not-the-writer.exe")
    refused(client.post("/response/suspend", json=body_for(child, image=other)), "PID_REUSED")
    assert child.is_running()


def test_no_identity_no_suspend(client, child, blocks):
    response = client.post("/response/suspend", json=body_for(child, image=None, started_at=None))
    refused(response, "IDENTITY_UNPROVEN")
    assert child.is_running()


def test_a_system_image_is_refused(client, child, blocks, monkeypatch):
    """Through the kill gate's own `_guard_image_path`; the image is faked as in TC-26."""
    protected_exe = os.path.join(actions.PROTECTED_IMAGE_ROOTS[0], "System32", "fontdrvhost.exe")
    real_exe = psutil.Process.exe
    monkeypatch.setattr(psutil.Process, "exe",
                        lambda self: protected_exe if self.pid == child.pid else real_exe(self))
    refused(client.post("/response/suspend", json=body_for(child, image=protected_exe)), "SYSTEM_PROCESS")
    assert child.is_running()
    assert_refusal_recorded(blocks, child, "SYSTEM_PROCESS")


def test_this_service_and_its_ancestors_are_refused(client, blocks):
    me = psutil.Process()
    for pid in [me.pid] + [p.pid for p in me.parents()][:2]:
        response = client.post("/response/suspend", json={
            "process_id": pid, "incident_id": "inc-self", "lease_seconds": 2, "reason": "r",
            "attribution_confidence": "probable", "attribution_source": "windows-security-4663",
            "attribution_reason": "r", "started_at": psutil.Process(pid).create_time(),
        })
        refused(response, "RESPONSE_OR_ANCESTOR")


def test_the_monitor_is_refused(client, child, blocks, monkeypatch):
    monkeypatch.setenv("URDS_MONITOR_PID", str(child.pid))
    refused(client.post("/response/suspend", json=body_for(child)), "MONITOR_OR_ANCESTOR")
    assert child.is_running()
    assert_refusal_recorded(blocks, child, "MONITOR_OR_ANCESTOR")


SPAWNER_SOURCE = (
    "import os, subprocess, sys, time\n"
    "grandchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
    "out = open(sys.argv[1], 'ab', buffering=0)\n"
    "print(os.getpid(), grandchild.pid, flush=True)\n"
    "deadline = time.monotonic() + 60\n"
    "while time.monotonic() < deadline:\n"
    "    out.write(b'.')\n"
    "    time.sleep(0.01)\n"
)


def test_an_ancestor_of_the_monitor_is_refused(client, make_child, blocks, monkeypatch):
    """The 'Monitor' is a grandchild; suspending its parent would freeze it with it."""
    parent = make_child(source=SPAWNER_SOURCE)
    monitor_pid = int(parent.line.split()[1])
    try:
        monkeypatch.setenv("URDS_MONITOR_PID", str(monitor_pid))
        refused(client.post("/response/suspend", json=body_for(parent)), "MONITOR_OR_ANCESTOR")
        assert parent.is_running()
    finally:
        for pid in {monitor_pid} | {p.pid for p in psutil.Process(parent.pid).children(recursive=True)}:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass


def test_a_pid_that_does_not_exist_is_refused(client, blocks):
    ghost = 999_999
    while psutil.pid_exists(ghost):
        ghost += 1
    refused(client.post("/response/suspend", json={
        "process_id": ghost, "incident_id": "inc-g", "lease_seconds": 2, "reason": "r",
        "attribution_confidence": "probable", "attribution_source": "windows-security-4663",
        "attribution_reason": "r", "started_at": 1.0,
    }), "PID_GONE")


def test_an_unattributed_suspend_is_refused(client, child, blocks):
    refused(client.post("/response/suspend", json=body_for(child, attribution_confidence="unknown")),
            "NOT_ATTRIBUTED")
    assert child.is_running()


def test_the_gate_is_required(client, child, blocks):
    """No block may name the PID without what allowed it, so the request must carry it."""
    for missing in ("attribution_confidence", "attribution_source", "attribution_reason"):
        body = body_for(child)
        del body[missing]
        response = client.post("/response/suspend", json=body)
        assert response.status_code == 400, missing
    assert child.is_running()
    assert blocks == []


def test_a_container_pid_namespace_refuses_explicitly_and_records_it(client, child, blocks, monkeypatch):
    """In Compose, Response cannot suspend a host PID. It says so; it does not try."""
    monkeypatch.setenv("RESPONSE_PID_NAMESPACE", "container")
    body = refused(client.post("/response/suspend", json=body_for(child)), "PID_NAMESPACE_ISOLATED")
    assert "PID namespace" in body["message"]
    assert child.is_running()
    assert_refusal_recorded(blocks, child, "PID_NAMESPACE_ISOLATED")


def test_the_lease_watchdog_itself_is_refused(table, child, blocks, monkeypatch):
    monkeypatch.setattr(table, "protected_pids", lambda: {child.pid})
    with TestClient(response_app.app) as client:
        refused(client.post("/response/suspend", json=body_for(child)), "LEASE_WATCHDOG")
    assert child.is_running()


def test_resume_needs_a_lease_or_a_pid(client):
    assert client.post("/response/resume", json={"incident_id": "x", "reason": "r"}).status_code == 400
