import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main
import rate_limit
import routers.proxy as proxy
from auth import create_access_token


@pytest.fixture(autouse=True)
def reset_limits():
    rate_limit.reset_rate_limits()
    yield
    rate_limit.reset_rate_limits()


@pytest.fixture
def client(monkeypatch):
    calls = []

    async def fake_call_downstream(method, base_url, path, json_body=None, params=None):
        calls.append({"method": method, "base_url": base_url, "path": path, "json": json_body, "params": params})
        if path == "/health":
            return httpx.Response(200, json={"status": "healthy", "service": base_url.rsplit("/", 1)[-1] or "stub"})
        if path == "/monitor/status":
            return httpx.Response(200, json={"status": "active", "files_monitored": 1523, "events_captured": 45, "uptime_seconds": 3600})
        if path == "/monitor/start":
            return httpx.Response(200, json={"status": "monitoring", "monitor_id": "mon_123abc", "start_time": "2026-01-31T10:00:00Z"})
        if path == "/monitor/events":
            return httpx.Response(200, json={"events": [{"event_id": "evt_1", "file_path": "/watch/file.doc", "event_type": "modified", "entropy": 7.89, "timestamp": "2026-01-31T10:00:00Z"}]})
        if path == "/features":
            return httpx.Response(
                200,
                json={
                    "shannon_entropy": 7.89,
                    "file_size": 1048576,
                    "magic_bytes": "4D5A",
                    "modification_rate": 0.85,
                    "pe_imports_count": 45,
                    "api_calls": ["CreateFile", "WriteFile", "CryptEncrypt"],
                },
            )
        if path == "/predict":
            return httpx.Response(
                200,
                json={
                    "prediction": "ransomware",
                    "confidence": 0.94,
                    "model_version": "1.0.0",
                    "timestamp": "2026-01-31T10:01:05Z",
                    "threat_level": "high",
                    "features_importance": {"shannon_entropy": 0.35, "modification_rate": 0.28, "api_calls": 0.22},
                },
            )
        if path == "/model/metrics":
            return httpx.Response(200, json={"accuracy": 0.92, "precision": 0.91, "recall": 0.93, "f1_score": 0.92, "roc_auc": 0.95, "last_trained": "2026-01-30T14:00:00Z"})
        if path == "/ledger/log":
            return httpx.Response(200, json={"block_id": 42, "current_hash": "abc123", "previous_hash": "def456", "timestamp": "2026-01-31T10:01:10Z", "tamper_proof": True})
        if path == "/ledger/entries":
            return httpx.Response(200, json={"entries": [{"block_id": 42, "current_hash": "abc123", "previous_hash": "def456", "timestamp": "2026-01-31T10:01:10Z", "tamper_proof": True}]})
        if path == "/ledger/verify":
            return httpx.Response(200, json={"valid": True, "blocks_checked": 128, "invalid_block_id": None, "verification_time_ms": 3.7})
        if path == "/ledger/blocks":
            return httpx.Response(
                200,
                json={
                    "blocks": [
                        {
                            "block_id": 42,
                            "timestamp": "2026-01-31T10:01:10Z",
                            "event_type": "file_event",
                            "event_data": {"file_path": "/watch/file.doc", "file_hash": "a" * 64},
                            "previous_hash": "d" * 64,
                            "current_hash": "c" * 64,
                            "blockchain_anchor": None,
                        }
                    ],
                    "total": 1,
                    "offset": 0,
                    "limit": 50,
                },
            )
        if path == "/response/terminate":
            return httpx.Response(200, json={"status": "terminated", "process_id": 4512, "timestamp": "2026-01-31T10:02:40Z", "exit_code": 0})
        if path == "/response/isolate":
            return httpx.Response(200, json={"status": "simulated", "enforced": False, "isolation_level": "full", "timestamp": "2026-01-31T10:02:41Z"})
        if path == "/response/recover":
            return httpx.Response(200, json={"status": "success", "files_recovered": 1, "integrity_verified": True, "timestamp": "2026-01-31T10:03:00Z"})
        if path == "/monitor/stop":
            return httpx.Response(200, json={"status": "stopped", "stop_time": "2026-01-31T10:05:00Z"})
        if path == "/response/trigger":
            return httpx.Response(200, json={"status": "success", "actions_taken": ["process_terminated", "network_isolated", "admin_notified"], "timestamp": "2026-01-31T10:02:45Z"})
        return httpx.Response(404, json={"message": f"Unhandled test path: {path}"})

    monkeypatch.setattr(proxy, "call_downstream", fake_call_downstream)
    monkeypatch.setattr(main, "call_downstream", fake_call_downstream)
    test_client = TestClient(main.app)
    test_client.calls = calls
    return test_client


def auth_headers(role="admin", tier="enterprise"):
    token = create_access_token("test_user", role=role, tier=tier)
    return {"Authorization": f"Bearer {token}"}


def test_health_is_unauthenticated(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert "gateway" in body["services"]
    assert "monitor" in body["services"]


def test_protected_route_rejects_missing_token(client):
    response = client.get("/monitor/status")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["error"]["request_id"].startswith("req_")


def test_dev_token_can_access_monitor_status(client):
    token_response = client.post("/auth/token", json={"sub": "user_id_123", "role": "admin", "tier": "enterprise"})
    assert token_response.status_code == 200
    token = token_response.json()["access_token"]
    response = client.get("/monitor/status", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["files_monitored"] == 1523


def test_predict_contract_shape(client):
    payload = {
        "features": {
            "shannon_entropy": 7.89,
            "file_size": 1048576,
            "magic_bytes": "4D5A",
            "modification_rate": 0.85,
            "pe_imports_count": 45,
            "api_calls": ["CreateFile", "WriteFile", "CryptEncrypt"],
        }
    }
    response = client.post("/predict", json=payload, headers=auth_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] == "ransomware"
    assert body["threat_level"] == "high"
    assert "features_importance" in body


def test_analyze_calls_monitor_ml_and_ledger_in_order(client):
    response = client.post("/analyze", json={"file_path": "/watch/file.doc"}, headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["prediction"] == "ransomware"
    paths = [call["path"] for call in client.calls]
    assert paths[-3:] == ["/features", "/predict", "/ledger/log"]
    assert client.calls[-1]["json"]["event_type"] == "analysis"


def test_response_trigger_proxy_supports_full_flow(client):
    payload = {
        "incident_id": "inc_998877",
        "process_id": 4512,
        "threat_level": "critical",
        "action_required": "terminate_process",
    }
    response = client.post("/response/trigger", json=payload, headers=auth_headers())
    assert response.status_code == 200
    assert "process_terminated" in response.json()["actions_taken"]


def test_rate_limit_returns_standard_429(client, monkeypatch):
    monkeypatch.setitem(rate_limit.RATE_LIMITS, "free", {"requests_per_minute": 1, "burst": 1})
    headers = auth_headers(role="free", tier="free")
    assert client.get("/monitor/status", headers=headers).status_code == 200
    response = client.get("/monitor/status", headers=headers)
    assert response.status_code == 429
    body = response.json()
    assert body["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert body["details"]["tier"] == "free"


# ------------------------------------------------------------- ledger proxies


def test_ledger_verify_is_reachable_through_the_gateway(client):
    """SI's chain verification had no gateway route, so 8000 could not reach it."""
    response = client.get("/ledger/verify", headers=auth_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["blocks_checked"] == 128
    assert client.calls[-1]["path"] == "/ledger/verify"


def test_ledger_blocks_is_reachable_through_the_gateway(client):
    response = client.get("/ledger/blocks", headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert client.calls[-1]["path"] == "/ledger/blocks"


def test_ledger_blocks_forwards_its_query_parameters(client):
    """offset/limit/event_type/file_path/newest_first have to reach the ledger."""
    client.get(
        "/ledger/blocks",
        params={"offset": "10", "limit": "5", "event_type": "file_event",
                "file_path": "/watch/a.doc", "newest_first": "true"},
        headers=auth_headers(),
    )
    params = client.calls[-1]["params"]
    assert params["offset"] == "10"
    assert params["limit"] == "5"
    assert params["event_type"] == "file_event"
    assert params["file_path"] == "/watch/a.doc"
    assert params["newest_first"] == "true"


def test_ledger_routes_require_a_token(client):
    for path in ("/ledger/verify", "/ledger/blocks"):
        assert client.get(path).status_code == 401, path


def test_full_64_character_hashes_survive_the_proxy(client):
    """Ledger hashes are full SHA-256 now, not the old stub's truncated 32."""
    block = client.get("/ledger/blocks", headers=auth_headers()).json()["blocks"][0]
    assert len(block["current_hash"]) == 64
    assert len(block["previous_hash"]) == 64
    assert len(block["event_data"]["file_hash"]) == 64


# ------------------------------------------------------------ TC-10 auth


def test_malformed_token_is_rejected(client):
    response = client.get("/monitor/status", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_token_signed_with_the_wrong_secret_is_rejected(client):
    from jose import jwt

    forged = jwt.encode(
        {"sub": "attacker", "role": "admin", "tier": "enterprise", "exp": 9_999_999_999},
        "not-the-real-secret",
        algorithm="HS256",
    )
    response = client.get("/monitor/status", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_expired_token_is_rejected(client):
    from datetime import datetime, timedelta, timezone

    from jose import jwt

    import auth as gateway_auth

    expired = jwt.encode(
        {
            "sub": "u",
            "role": "admin",
            "tier": "enterprise",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
        },
        gateway_auth.JWT_SECRET,
        algorithm=gateway_auth.JWT_ALGORITHM,
    )
    response = client.get("/monitor/status", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


# ------------------------------------------------- spec / implementation parity


def test_every_documented_path_is_implemented():
    """The contract is only useful if 8000 actually serves what it promises."""
    from openapi_spec_validator.readers import read_from_filename

    spec_path = Path(__file__).resolve().parents[3] / "docs" / "openapi" / "gateway.yaml"
    spec, _ = read_from_filename(str(spec_path))

    documented = {
        (path, method.upper())
        for path, operations in spec["paths"].items()
        for method in operations
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }
    implemented = {
        (route.path, method)
        for route in main.app.routes
        if getattr(route, "methods", None)
        for method in route.methods
        if method not in {"HEAD", "OPTIONS"}
    }

    missing = documented - implemented
    assert not missing, f"documented in gateway.yaml but not implemented: {sorted(missing)}"


def test_every_implemented_route_is_documented():
    from openapi_spec_validator.readers import read_from_filename

    spec_path = Path(__file__).resolve().parents[3] / "docs" / "openapi" / "gateway.yaml"
    spec, _ = read_from_filename(str(spec_path))

    documented = {
        (path, method.upper())
        for path, operations in spec["paths"].items()
        for method in operations
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }
    ignored = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
    implemented = {
        (route.path, method)
        for route in main.app.routes
        if getattr(route, "methods", None) and route.path not in ignored
        for method in route.methods
        if method not in {"HEAD", "OPTIONS"}
    }

    undocumented = implemented - documented
    assert not undocumented, f"served by the gateway but absent from gateway.yaml: {sorted(undocumented)}"
