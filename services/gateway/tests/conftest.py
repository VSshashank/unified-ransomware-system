"""Shared gateway test fixtures.

`client` and `reset_limits` started out in test_gateway.py. They moved here when
test_authz.py needed the same stubbed downstream, so both suites drive one
fixture instead of two copies that can drift apart.
"""

import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main
import rate_limit
import routers.proxy as proxy


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
            # 201, matching the real ledger - an append creates a block.
            return httpx.Response(201, json={"block_id": 42, "current_hash": "abc123", "previous_hash": "def456", "timestamp": "2026-01-31T10:01:10Z", "tamper_proof": True})
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
