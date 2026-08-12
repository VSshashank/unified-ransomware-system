"""Numeric targets for the Gateway - Table 5.9, "API Response Time (p95) <200ms".

Measured over the gateway's own work: routing, auth, role check, rate-limit
accounting and envelope construction. Downstream services are stubbed by the
shared `client` fixture, so what this reports is the overhead the gateway adds,
not the latency of whatever it proxies to. That is the honest thing to measure
here - a slow ML model is not a slow gateway, and the two would be
indistinguishable if the real services were in the path.

Measurements are written to reports/gateway_benchmarks.json.
"""

import json
from pathlib import Path
from time import perf_counter

import pytest

REPORTS = Path(__file__).resolve().parents[3] / "reports"
MEASUREMENTS: dict = {}

API_P95_TARGET_MS = 200.0
SAMPLES = 200


@pytest.fixture(scope="module", autouse=True)
def write_measurements():
    yield
    if MEASUREMENTS:
        REPORTS.mkdir(exist_ok=True)
        (REPORTS / "gateway_benchmarks.json").write_text(json.dumps(MEASUREMENTS, indent=2))


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, int(len(ordered) * fraction) - 1)]


def _measure(client, method: str, path: str, headers: dict, json_body=None) -> list[float]:
    samples = []
    for _ in range(SAMPLES):
        started = perf_counter()
        response = client.request(method, path, headers=headers, json=json_body)
        samples.append((perf_counter() - started) * 1000)
        assert response.status_code == 200, response.text
    return samples


@pytest.mark.benchmark
def test_api_response_time_p95_under_200ms(client):
    """Table 5.9: p95 of API requests under 200ms."""
    from auth import create_access_token

    headers = {"Authorization": f"Bearer {create_access_token('bench', role='admin', tier='enterprise')}"}

    routes = {
        "GET /monitor/status": ("GET", "/monitor/status", None),
        "GET /ledger/blocks": ("GET", "/ledger/blocks", None),
        "GET /model/metrics": ("GET", "/model/metrics", None),
        "POST /ledger/log": ("POST", "/ledger/log", {"event_type": "bench", "event_data": {}}),
        "POST /analyze": ("POST", "/analyze", {"file_path": "/watch/bench.doc"}),
    }

    everything: list[float] = []
    per_route = {}

    for label, (method, path, body) in routes.items():
        samples = _measure(client, method, path, headers, body)
        everything.extend(samples)
        per_route[label] = {
            "samples": len(samples),
            "mean_ms": round(sum(samples) / len(samples), 3),
            "p95_ms": round(_percentile(samples, 0.95), 3),
        }
        print(f"  {label:22s} mean {per_route[label]['mean_ms']:6.2f}ms  p95 {per_route[label]['p95_ms']:6.2f}ms")

    overall_p95 = _percentile(everything, 0.95)
    MEASUREMENTS["api_response_time_ms"] = {
        "samples": len(everything),
        "mean": round(sum(everything) / len(everything), 3),
        "p95": round(overall_p95, 3),
        "max": round(max(everything), 3),
        "target": API_P95_TARGET_MS,
        "per_route": per_route,
        "note": "downstream services stubbed; this is gateway overhead only",
    }
    print(f"\napi response time: p95={overall_p95:.2f}ms over {len(everything)} requests (target <200ms)")

    assert overall_p95 < API_P95_TARGET_MS, f"p95 API response time {overall_p95:.2f}ms exceeds 200ms"


@pytest.mark.benchmark
def test_rejected_requests_are_also_fast(client):
    """A 401 now writes an audit block (TC-10). That must not make rejection
    slower than acceptance - if it did, the audit trail would be a usable
    timing oracle and a cheap way to load the gateway."""
    samples = []
    for _ in range(SAMPLES):
        started = perf_counter()
        response = client.get("/monitor/status")
        samples.append((perf_counter() - started) * 1000)
        assert response.status_code == 401

    p95 = _percentile(samples, 0.95)
    MEASUREMENTS["rejected_request_time_ms"] = {
        "samples": len(samples),
        "mean": round(sum(samples) / len(samples), 3),
        "p95": round(p95, 3),
        "target": API_P95_TARGET_MS,
    }
    print(f"\nrejected (401 + audit write): p95={p95:.2f}ms (target <200ms)")

    assert p95 < API_P95_TARGET_MS, f"p95 rejection time {p95:.2f}ms exceeds 200ms"
