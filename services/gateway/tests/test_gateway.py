import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main
import rate_limit
from auth import create_access_token

# `client` and `reset_limits` live in conftest.py so test_authz.py can use them too.


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
    """Updated in place: this used to request role=admin with no credentials.

    /auth/token no longer hands out admin to an anonymous caller - that was the
    Phase 1 finding. The behaviour this test exists to pin is that a token from
    the dev endpoint reaches a protected read, so it now asks for the free token
    an anonymous caller can actually get. The admin path is covered in
    test_authz.py::test_requesting_admin_with_the_bootstrap_secret_succeeds.
    """
    token_response = client.post("/auth/token", json={"sub": "user_id_123", "role": "free", "tier": "free"})
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


def test_ledger_log_returns_201_through_the_gateway(client):
    """Table 3.2 names a ledger entry as its 201 Created example, and the proxy
    has to pass the downstream code through rather than flattening it to 200."""
    response = client.post(
        "/ledger/log",
        json={"event_type": "file_event", "event_data": {"file_path": "/watch/a.doc"}},
        headers=auth_headers(),
    )
    assert response.status_code == 201
    assert response.json()["block_id"] == 42


def test_monitor_stop_forwards_the_monitor_id(client):
    """The gateway used to send {} regardless, so a monitor_id the caller
    supplied never reached the service that validates it."""
    client.post("/monitor/stop", json={"monitor_id": "mon_a1b2c3"}, headers=auth_headers())

    stop_call = client.calls[-1]
    assert stop_call["path"] == "/monitor/stop"
    assert stop_call["json"]["monitor_id"] == "mon_a1b2c3"


def test_monitor_stop_still_works_with_no_body(client):
    assert client.post("/monitor/stop", headers=auth_headers()).status_code == 200


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
