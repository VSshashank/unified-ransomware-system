"""Phase 1 security regressions: authorization, token issuance, and secret hygiene.

Before these fixes the gateway authenticated but never authorized. A `free`
token minted from an empty POST to /auth/token could terminate processes and
isolate the network, because `get_current_user` read the role and threw it away
and `TokenRequest.role` defaulted to "admin". Nothing in the project ever
raised 403.

Each test names the behaviour it pins rather than the code it touches, so a
future refactor that quietly drops a check fails here.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auth as gateway_auth
import main
from auth import create_access_token


BOOTSTRAP_HEADER = "X-Bootstrap-Secret"


def headers_for(role: str, tier: str | None = None) -> dict[str, str]:
    token = create_access_token("test_user", role=role, tier=tier or role)
    return {"Authorization": f"Bearer {token}"}


TERMINATE_BODY = {"process_id": 4512, "incident_id": "inc_1", "reason": "ransomware_detected", "force": True}
ISOLATE_BODY = {"isolation_level": "full", "duration_seconds": 300, "allow_localhost": True}
RECOVER_BODY = {"snapshot_id": "vss_1", "files": ["/watch/a.doc"], "verify_integrity": True}
TRIGGER_BODY = {"incident_id": "inc_1", "process_id": 4512, "threat_level": "critical", "action_required": "terminate_process"}
START_BODY = {"watch_path": "/watch", "recursive": True, "file_patterns": ["*.doc"]}
LEDGER_BODY = {"event_type": "file_event", "event_data": {"file_path": "/watch/a.doc"}}


# ------------------------------------------------------- 1.2 role enforcement


@pytest.mark.parametrize(
    "path,body",
    [
        ("/response/terminate", TERMINATE_BODY),
        ("/response/isolate", ISOLATE_BODY),
        ("/response/recover", RECOVER_BODY),
        ("/response/trigger", TRIGGER_BODY),
    ],
)
def test_free_role_cannot_reach_any_response_action(client, path, body):
    """The verified finding: a free token could terminate and isolate."""
    response = client.post(path, json=body, headers=headers_for("free"))
    assert response.status_code == 403, f"{path} allowed a free token: {response.status_code}"


@pytest.mark.parametrize(
    "path,body",
    [
        ("/response/terminate", TERMINATE_BODY),
        ("/response/isolate", ISOLATE_BODY),
        ("/response/recover", RECOVER_BODY),
        ("/response/trigger", TRIGGER_BODY),
    ],
)
def test_admin_role_still_reaches_every_response_action(client, path, body):
    response = client.post(path, json=body, headers=headers_for("admin", "enterprise"))
    assert response.status_code == 200, f"{path} refused an admin token: {response.text}"


def test_enterprise_role_cannot_reach_response_actions(client):
    """Response is admin-only; enterprise is deliberately not enough."""
    response = client.post("/response/isolate", json=ISOLATE_BODY, headers=headers_for("enterprise"))
    assert response.status_code == 403


def test_free_role_cannot_stop_the_monitor(client):
    """Stopping the monitor blinds detection, so it sits with the response actions."""
    response = client.post("/monitor/stop", headers=headers_for("free"))
    assert response.status_code == 403


def test_enterprise_role_cannot_stop_the_monitor(client):
    response = client.post("/monitor/stop", headers=headers_for("enterprise"))
    assert response.status_code == 403


def test_admin_can_stop_the_monitor(client):
    response = client.post("/monitor/stop", headers=headers_for("admin", "enterprise"))
    assert response.status_code == 200


@pytest.mark.parametrize(
    "path,body",
    [
        ("/monitor/start", START_BODY),
        ("/analyze", {"file_path": "/watch/a.doc"}),
        ("/ledger/log", LEDGER_BODY),
        ("/predict", {"features": {"shannon_entropy": 7.9, "file_size": 1024, "magic_bytes": "4D5A", "modification_rate": 0.8, "pe_imports_count": 4, "api_calls": ["WriteFile"]}}),
    ],
)
def test_free_role_cannot_reach_operator_writes(client, path, body):
    response = client.post(path, json=body, headers=headers_for("free"))
    assert response.status_code == 403, f"{path} allowed a free token"


@pytest.mark.parametrize(
    "role,tier",
    [("admin", "enterprise"), ("enterprise", "enterprise")],
)
@pytest.mark.parametrize(
    "path,body",
    [
        ("/monitor/start", START_BODY),
        ("/analyze", {"file_path": "/watch/a.doc"}),
        ("/ledger/log", LEDGER_BODY),
    ],
)
def test_admin_and_enterprise_reach_operator_writes(client, role, tier, path, body):
    response = client.post(path, json=body, headers=headers_for(role, tier))
    assert response.status_code == 200, f"{path} refused {role}: {response.text}"


@pytest.mark.parametrize(
    "path",
    ["/monitor/status", "/monitor/events", "/model/metrics", "/ledger/entries", "/ledger/verify", "/ledger/blocks"],
)
def test_every_get_route_is_open_to_any_authenticated_role(client, path):
    """Reads stay available to every role - only writes and actions are gated."""
    response = client.get(path, headers=headers_for("free"))
    assert response.status_code == 200, f"{path} refused a free token: {response.text}"


def test_forbidden_uses_the_project_error_envelope(client):
    response = client.post("/response/terminate", json=TERMINATE_BODY, headers=headers_for("free"))
    assert response.status_code == 403
    body = response.json()
    assert set(body) == {"error", "details"}
    assert set(body["error"]) == {"code", "message", "timestamp", "request_id"}
    assert body["error"]["code"] == "FORBIDDEN"
    assert body["error"]["request_id"].startswith("req_")
    assert body["error"]["timestamp"].endswith("Z")


def test_missing_token_is_still_401_not_403(client):
    """401 and 403 answer different questions; the role check must not shadow auth."""
    assert client.post("/response/terminate", json=TERMINATE_BODY).status_code == 401


# ------------------------------------------------------ 1.3 token issuance


def test_empty_post_issues_a_free_token(client):
    """The verified finding: an empty POST returned a working admin token."""
    response = client.post("/auth/token")
    assert response.status_code == 200
    claims = gateway_auth.decode_token(response.json()["access_token"])
    assert claims.role == "free"
    assert claims.tier == "free"


def test_free_token_from_the_endpoint_cannot_terminate(client):
    """End to end: what an anonymous caller can actually mint must not act."""
    token = client.post("/auth/token").json()["access_token"]
    response = client.post("/response/terminate", json=TERMINATE_BODY, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_requesting_admin_without_the_bootstrap_secret_is_forbidden(client, monkeypatch):
    monkeypatch.setenv("DEV_TOKEN_BOOTSTRAP_SECRET", "s3cret")
    response = client.post("/auth/token", json={"sub": "u", "role": "admin", "tier": "enterprise"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_requesting_admin_with_the_bootstrap_secret_succeeds(client, monkeypatch):
    monkeypatch.setenv("DEV_TOKEN_BOOTSTRAP_SECRET", "s3cret")
    response = client.post(
        "/auth/token",
        json={"sub": "u", "role": "admin", "tier": "enterprise"},
        headers={BOOTSTRAP_HEADER: "s3cret"},
    )
    assert response.status_code == 200
    claims = gateway_auth.decode_token(response.json()["access_token"])
    assert claims.role == "admin"


def test_a_wrong_bootstrap_secret_is_forbidden(client, monkeypatch):
    monkeypatch.setenv("DEV_TOKEN_BOOTSTRAP_SECRET", "s3cret")
    response = client.post(
        "/auth/token",
        json={"sub": "u", "role": "admin", "tier": "enterprise"},
        headers={BOOTSTRAP_HEADER: "wrong"},
    )
    assert response.status_code == 403


def test_an_unset_bootstrap_secret_cannot_be_matched_by_an_empty_header(client, monkeypatch):
    """An unconfigured secret must fail closed, not match "" and hand out admin."""
    monkeypatch.delenv("DEV_TOKEN_BOOTSTRAP_SECRET", raising=False)
    response = client.post(
        "/auth/token",
        json={"sub": "u", "role": "admin", "tier": "enterprise"},
        headers={BOOTSTRAP_HEADER: ""},
    )
    assert response.status_code == 403


def test_an_elevated_tier_also_needs_the_secret(client, monkeypatch):
    """tier outranks role in resolve_tier, so free+enterprise buys 1000 rpm."""
    monkeypatch.setenv("DEV_TOKEN_BOOTSTRAP_SECRET", "s3cret")
    response = client.post("/auth/token", json={"sub": "u", "role": "free", "tier": "enterprise"})
    assert response.status_code == 403


def test_the_endpoint_can_be_switched_off_entirely(client, monkeypatch):
    monkeypatch.setenv("ALLOW_DEV_TOKENS", "false")
    response = client.post("/auth/token")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "DEV_TOKENS_DISABLED"


def test_dev_tokens_are_allowed_by_default(client, monkeypatch):
    monkeypatch.delenv("ALLOW_DEV_TOKENS", raising=False)
    assert client.post("/auth/token").status_code == 200


# --------------------------------------------------- 1.4 JWT secret hygiene


def test_default_secret_refuses_to_start_in_production(monkeypatch):
    monkeypatch.setattr(gateway_auth, "JWT_SECRET", gateway_auth.DEFAULT_JWT_SECRET)
    monkeypatch.setenv("URDS_ENV", "production")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        gateway_auth.verify_jwt_secret_configuration()


def test_default_secret_only_warns_in_development(monkeypatch, caplog):
    monkeypatch.setattr(gateway_auth, "JWT_SECRET", gateway_auth.DEFAULT_JWT_SECRET)
    monkeypatch.setenv("URDS_ENV", "development")
    with caplog.at_level("WARNING"):
        gateway_auth.verify_jwt_secret_configuration()
    assert "JWT_SECRET" in caplog.text


def test_an_overridden_secret_is_accepted_in_production(monkeypatch, caplog):
    monkeypatch.setattr(gateway_auth, "JWT_SECRET", "a-real-secret")
    monkeypatch.setenv("URDS_ENV", "production")
    with caplog.at_level("WARNING"):
        gateway_auth.verify_jwt_secret_configuration()
    assert "JWT_SECRET" not in caplog.text


def test_app_startup_runs_the_secret_check(monkeypatch):
    """Wiring test: the check is worthless if nothing calls it on boot."""
    monkeypatch.setattr(gateway_auth, "JWT_SECRET", gateway_auth.DEFAULT_JWT_SECRET)
    monkeypatch.setenv("URDS_ENV", "production")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        with TestClient(main.app):
            pass
