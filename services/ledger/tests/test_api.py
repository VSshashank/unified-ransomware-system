"""API tests for the ledger service, including TC-05 end to end."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

import main
from hash_chain import HashChainLedger


@pytest.fixture
def ledger(tmp_path):
    chain = HashChainLedger(str(tmp_path / "ledger.db"))
    yield chain
    chain.close()


@pytest.fixture
def client(ledger):
    main.app.dependency_overrides[main.get_ledger] = lambda: ledger
    with TestClient(main.app) as test_client:
        yield test_client
    main.app.dependency_overrides.clear()


def log(client, event_type="file_encrypted", **event_data):
    payload = event_data or {"file_path": "/a.doc", "process_id": 1234, "user": "admin", "entropy": 7.89}
    return client.post("/ledger/log", json={"event_type": event_type, "event_data": payload})


# ----------------------------------------------------------------------- health


def test_health_reports_healthy(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["service"] == "ledger"


# ------------------------------------------------------------------ POST /log


def test_log_returns_the_contract_shape(client):
    response = log(client)
    # 201, per Table 3.2, which names a ledger entry as its Created example.
    assert response.status_code == 201

    body = response.json()
    assert set(body) == {"block_id", "current_hash", "previous_hash", "timestamp", "tamper_proof"}
    assert body["block_id"] == 1
    assert body["tamper_proof"] is True
    assert body["previous_hash"] == "0" * 64
    assert len(body["current_hash"]) == 64


def test_log_chains_successive_blocks(client):
    first = log(client, file_path="/a.doc").json()
    second = log(client, file_path="/b.doc").json()

    assert second["block_id"] == 2
    assert second["previous_hash"] == first["current_hash"]


def test_log_accepts_the_gateways_nested_analysis_payload(client):
    """Matches what gateway /analyze already sends."""
    response = client.post(
        "/ledger/log",
        json={
            "event_type": "analysis",
            "event_data": {
                "file_path": "/data/a.doc",
                "features": {"entropy": 7.9, "size": 2048},
                "result": {"prediction": "ransomware", "confidence": 0.97},
                "request_id": "req_abc123",
            },
        },
    )
    assert response.status_code == 201
    assert client.get("/ledger/verify").json()["valid"] is True


def test_log_rejects_a_missing_event_type(client):
    response = client.post("/ledger/log", json={"event_data": {}})
    assert response.status_code == 400

    body = response.json()
    assert set(body) == {"error", "details"}
    assert set(body["error"]) == {"code", "message", "timestamp", "request_id"}
    assert body["error"]["code"] == "BAD_REQUEST"


def test_errors_echo_the_gateways_request_id(client):
    response = client.post("/ledger/log", json={}, headers={"X-Request-ID": "req_from_gateway"})
    assert response.json()["error"]["request_id"] == "req_from_gateway"


# --------------------------------------------------------------- GET /verify


def test_verify_on_an_empty_chain(client):
    body = client.get("/ledger/verify").json()
    assert body["valid"] is True
    assert body["blocks_checked"] == 0
    assert body["invalid_block_id"] is None


def test_verify_reports_a_healthy_chain(client):
    for _ in range(5):
        log(client)

    body = client.get("/ledger/verify").json()
    assert body["valid"] is True
    assert body["blocks_checked"] == 5
    assert body["verification_time_ms"] < 50


def test_tc05_tampered_row_is_caught(client, ledger):
    """TC-05: edit the SQLite file directly, then ask the API."""
    log(client, file_path="/a.doc")
    log(client, file_path="/b.doc")
    log(client, file_path="/c.doc")
    assert client.get("/ledger/verify").json()["valid"] is True

    conn = sqlite3.connect(ledger.db_path)
    conn.execute("UPDATE blocks SET event_data = ? WHERE id = 2", ('{"file_path":"/innocent.txt"}',))
    conn.commit()
    conn.close()

    body = client.get("/ledger/verify").json()
    assert body["valid"] is False
    assert body["invalid_block_id"] == 2


# --------------------------------------------------------------- GET /blocks


def test_blocks_are_paginated(client):
    for n in range(10):
        log(client, n=n)

    body = client.get("/ledger/blocks", params={"offset": 2, "limit": 3}).json()
    assert body["total"] == 10
    assert body["offset"] == 2
    assert body["limit"] == 3
    assert [b["block_id"] for b in body["blocks"]] == [3, 4, 5]


def test_blocks_expose_the_full_block_shape(client):
    log(client)
    block = client.get("/ledger/blocks").json()["blocks"][0]
    assert set(block) == {
        "block_id",
        "timestamp",
        "event_type",
        "event_data",
        "previous_hash",
        "current_hash",
        "blockchain_anchor",
    }
    assert block["blockchain_anchor"] is None


def test_blocks_can_be_filtered_by_path(client):
    log(client, file_path="/data/a.doc")
    log(client, file_path="/data/b.doc")

    body = client.get("/ledger/blocks", params={"file_path": "/data/b.doc"}).json()
    assert [b["event_data"]["file_path"] for b in body["blocks"]] == ["/data/b.doc"]


def test_blocks_rejects_an_out_of_range_limit(client):
    assert client.get("/ledger/blocks", params={"limit": 0}).status_code == 400
    assert client.get("/ledger/blocks", params={"limit": 5000}).status_code == 400


# -------------------------------------------------------------- GET /entries


def test_entries_keeps_the_dashboard_contract(client):
    """SH's dashboard reads entries[0] and expects these keys."""
    log(client, file_path="/a.doc")
    log(client, file_path="/b.doc")

    body = client.get("/ledger/entries", params={"limit": 10}).json()
    assert "entries" in body

    latest = body["entries"][0]
    assert latest["block_id"] == 2  # newest first
    for field in ("block_id", "current_hash", "previous_hash", "tamper_proof", "timestamp"):
        assert field in latest, f"dashboard reads {field}"
    assert latest["tamper_proof"] is True


def test_entries_on_an_empty_chain_is_empty(client):
    """The stub used to invent a block here; a real audit log must not."""
    assert client.get("/ledger/entries").json()["entries"] == []
