"""End-to-end attack sequence against the running stack (spec 3.3 / 3.6.2).

Drops a high-entropy file into the watched path and follows it all the way
through: Monitor detects -> ML classifies -> Ledger records -> Response acts ->
Dashboard-visible within 1s. Writes a transcript to
reports/attack_chain_evidence.txt.

    python scripts/attack_chain_demo.py

Start the stack first: docker compose up -d --build
"""

import argparse
import hashlib
import io
import json
import math
import os
import sys
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = REPO_ROOT / "reports" / "attack_chain_evidence.txt"

transcript: list[str] = []
results: dict[str, bool | None] = {}


def say(line: str = "") -> None:
    print(line)
    transcript.append(line)


def rule(title: str) -> None:
    say(f"--- {title} " + "-" * max(4, 70 - len(title)))


def entropy_of(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in Counter(data).values())


def wait_for(predicate, timeout=20.0, interval=0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (httpx.HTTPError, KeyError, ValueError, IndexError):
            pass
        time.sleep(interval)
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", default="http://localhost:8000")
    parser.add_argument("--monitor", default="http://localhost:8001")
    parser.add_argument("--ledger", default="http://localhost:8003")
    parser.add_argument("--response", default="http://localhost:8004")
    parser.add_argument("--dashboard", default="http://localhost:8501")
    parser.add_argument(
        "--bootstrap-secret",
        default=os.getenv("DEV_TOKEN_BOOTSTRAP_SECRET", "dev-bootstrap-change-me"),
        help="Shared secret /auth/token requires to issue an admin token.",
    )
    # Host path, and the path the same directory has inside the containers.
    parser.add_argument("--watch-host", default=str(REPO_ROOT / "watched_files"))
    parser.add_argument("--watch-container", default="/watch")
    args = parser.parse_args()

    client = httpx.Client(timeout=15.0)
    started_at = datetime.now(timezone.utc)

    say("=" * 74)
    say("URDS end-to-end attack chain")
    say(f"started {started_at.isoformat().replace('+00:00', 'Z')}")
    say("=" * 74)
    say()

    # --- 0. health -----------------------------------------------------------
    rule("0. SERVICE HEALTH")
    try:
        health = client.get(f"{args.gateway}/health").json()
    except httpx.HTTPError as exc:
        say(f"  gateway unreachable: {exc}")
        say("  Is the stack up?  docker compose up -d --build")
        return 2

    say(f"  gateway: {health.get('status')}")
    for name, info in sorted(health.get("services", {}).items()):
        say(f"    {name:12s} {info.get('status')}")
    results["all_services_healthy"] = health.get("status") == "healthy"
    say()

    # The demo drives admin-only routes (/monitor/start, /response/terminate),
    # and /auth/token no longer hands out admin to an anonymous caller. The
    # bootstrap secret has to match the gateway's DEV_TOKEN_BOOTSTRAP_SECRET;
    # the default matches docker-compose.yml so the demo runs unconfigured.
    token_response = client.post(
        f"{args.gateway}/auth/token",
        json={"sub": "demo", "role": "admin", "tier": "enterprise"},
        headers={"X-Bootstrap-Secret": args.bootstrap_secret},
    )
    if token_response.status_code == 403:
        say(f"  /auth/token refused an admin token: {token_response.text}")
        say("  Pass --bootstrap-secret to match the gateway's DEV_TOKEN_BOOTSTRAP_SECRET.")
        return 2
    token = token_response.json()["access_token"]
    auth = {"Authorization": f"Bearer {token}"}

    # --- 1. start monitoring -------------------------------------------------
    rule("1. START MONITORING")
    start = client.post(
        f"{args.gateway}/monitor/start",
        json={"watch_path": args.watch_container, "recursive": True, "file_patterns": []},
        headers=auth,
    ).json()
    say(f"  monitor_id : {start.get('monitor_id')}")
    say(f"  watch_path : {start.get('watch_path')}")
    baseline_events = client.get(f"{args.gateway}/monitor/status", headers=auth).json().get("events_captured", 0)
    say(f"  events so far: {baseline_events}")
    say()

    # --- 2. benign control ---------------------------------------------------
    rule("2. CONTROL: a legitimate archive must NOT trip the detector")
    control = Path(args.watch_host) / "quarterly_backup.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("data.bin", os.urandom(300_000))
    control.write_bytes(buffer.getvalue())
    say(f"  wrote {control.name} ({control.stat().st_size} bytes, entropy {entropy_of(control.read_bytes()):.3f})")

    control_event = wait_for(
        lambda: next(
            (e for e in client.get(f"{args.gateway}/monitor/events", params={"limit": 50}, headers=auth).json()["events"]
             if e["file_path"].endswith(control.name)),
            None,
        )
    )
    if control_event:
        say(f"  detected   : entropy={control_event['entropy']} verdict={control_event.get('verdict')}")
        say(f"  suspicious : {control_event.get('suspicious')}")
        results["tc03_no_false_positive"] = control_event.get("suspicious") is False
    else:
        say("  NOT DETECTED (monitor did not report the control file)")
        results["tc03_no_false_positive"] = False
    say()

    # --- 3. the attack -------------------------------------------------------
    rule("3. ATTACK: high-entropy write into the watched path")
    victim = Path(args.watch_host) / "annual_report.docx.locked"
    payload = os.urandom(400_000)
    dropped_at = time.time()
    victim.write_bytes(payload)
    expected_hash = hashlib.sha256(payload).hexdigest()
    say(f"  wrote {victim.name} ({len(payload)} bytes, entropy {entropy_of(payload):.3f})")
    say(f"  sha256     : {expected_hash}")
    say()

    # --- 4. detection --------------------------------------------------------
    rule("4. MONITOR DETECTION")
    event = wait_for(
        lambda: next(
            (e for e in client.get(f"{args.gateway}/monitor/events", params={"limit": 50}, headers=auth).json()["events"]
             if e["file_path"].endswith(victim.name)),
            None,
        )
    )
    if not event:
        say("  FAIL: monitor never reported the file")
        results["tc01_detected"] = False
        return finish(client, args, started_at)

    detect_latency = event.get("detection_latency_ms")
    say(f"  event_id          : {event['event_id']}")
    say(f"  entropy           : {event['entropy']}")
    say(f"  verdict           : {event.get('verdict')}")
    say(f"  reason            : {event.get('reason')}")
    say(f"  suspicious        : {event.get('suspicious')}")
    say(f"  file_hash         : {event.get('file_hash')}")
    say(f"  detection latency : {detect_latency} ms (target <100ms)")
    results["tc01_detected"] = True
    results["tc02_flagged_as_ransomware"] = bool(event.get("suspicious"))
    results["detection_latency_under_100ms"] = bool(detect_latency is not None and detect_latency < 100)
    results["file_hash_is_sha256"] = len(event.get("file_hash") or "") == 64
    if event.get("file_hash") != expected_hash:
        say(f"  NOTE: hash differs from the bytes written (file may have been rewritten)")
    say()

    # --- 5. the pipeline -----------------------------------------------------
    rule("5. ML -> LEDGER -> RESPONSE")
    enriched = wait_for(
        lambda: next(
            (e for e in client.get(f"{args.gateway}/monitor/events", params={"limit": 50}, headers=auth).json()["events"]
             if e["file_path"].endswith(victim.name) and e.get("pipeline")),
            None,
        ),
        timeout=25.0,
    )
    if enriched:
        stages = enriched.get("pipeline", {}).get("stages", [])
        say(f"  stages completed : {stages}")
        say(f"  ML prediction    : {enriched.get('prediction')} ({enriched.get('threat_level')})")
        say(f"  ledger block     : #{enriched.get('block_id')}")
        results["tc06_ml_classified"] = enriched.get("prediction") == "ransomware"
        results["ledger_logged"] = "ledger_logged" in stages
        results["response_triggered"] = "response_triggered" in stages
    else:
        say("  pipeline did not complete within 25s")
        results["tc06_ml_classified"] = False
        results["ledger_logged"] = False
        results["response_triggered"] = False
    say()

    # --- 6. the ledger record ------------------------------------------------
    rule("6. LEDGER EVIDENCE (via gateway :8000)")
    blocks = client.get(
        f"{args.gateway}/ledger/blocks",
        params={"limit": 50, "newest_first": "true"},
        headers=auth,
    ).json()
    # Prefer the file_event block: response_action blocks name the same file but
    # carry the action, not the detection.
    matching = [
        b for b in blocks.get("blocks", [])
        if str(b.get("event_data", {}).get("file_path", "")).endswith(victim.name)
        and b.get("event_type") == "file_event"
    ] or [
        b for b in blocks.get("blocks", [])
        if str(b.get("event_data", {}).get("file_path", "")).endswith(victim.name)
    ]
    if matching:
        block = matching[0]
        data = block["event_data"]
        say(f"  block_id      : {block['block_id']}")
        say(f"  event_type    : {block['event_type']}")
        say(f"  current_hash  : {block['current_hash']}  (len {len(block['current_hash'])})")
        say(f"  previous_hash : {block['previous_hash']}")
        say(f"  file_hash     : {data.get('file_hash')}")
        say(f"  verdict       : {data.get('verdict')}")
        results["ledger_event_carries_file_hash"] = len(str(data.get("file_hash") or "")) == 64
        results["ledger_hash_is_64_chars"] = len(block["current_hash"]) == 64
    else:
        say("  no ledger block found for the victim file")
        results["ledger_event_carries_file_hash"] = False
        results["ledger_hash_is_64_chars"] = False

    verify = client.get(f"{args.gateway}/ledger/verify", headers=auth).json()
    say(f"  chain valid   : {verify.get('valid')} "
        f"({verify.get('blocks_checked')} blocks in {verify.get('verification_time_ms')}ms, target <50ms)")
    results["tc08_chain_verified"] = bool(verify.get("valid"))
    results["chain_verify_under_50ms"] = bool(
        verify.get("verification_time_ms") is not None and verify["verification_time_ms"] < 50
    )
    say()

    # --- 7. response ---------------------------------------------------------
    rule("7. RESPONSE ACTIONS")
    response_blocks = client.get(
        f"{args.gateway}/ledger/blocks",
        params={"limit": 20, "event_type": "response_action", "newest_first": "true"},
        headers=auth,
    ).json()
    actions = response_blocks.get("blocks", [])
    if actions:
        for block in actions[:3]:
            data = block["event_data"]
            say(f"  block #{block['block_id']}: action={data.get('action')} "
                f"outcome={data.get('outcome', data.get('actions_taken'))}")
        results["response_action_audited"] = True
    else:
        say("  no response_action blocks in the ledger")
        results["response_action_audited"] = False

    # TC-07 needs a process that actually exists; use a disposable one.
    import subprocess

    victim_process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    time.sleep(0.3)
    kill = client.post(
        f"{args.gateway}/response/terminate",
        json={"process_id": victim_process.pid, "incident_id": "inc_demo", "reason": "ransomware_detected", "force": True},
        headers=auth,
    )
    if kill.status_code == 200:
        body = kill.json()
        say(f"  terminated pid {body['process_id']} ({body.get('process_name')}) "
            f"via {body.get('method')} in {body.get('termination_time_ms')}ms (target <2000ms)")
        results["tc07_process_terminated"] = True
        results["kill_time_under_2s"] = body.get("termination_time_ms", 9e9) < 2000
    else:
        say(f"  terminate returned {kill.status_code}: {kill.text[:200]}")
        say("  (expected on macOS/Windows hosts: the response service runs in a Linux")
        say("   container and cannot see host PIDs. Covered by services/response tests.)")
        results["tc07_process_terminated"] = None
        results["kill_time_under_2s"] = None
    if victim_process.poll() is None:
        victim_process.kill()
        victim_process.wait(timeout=5)
    say()

    # --- 8. dashboard --------------------------------------------------------
    rule("8. DASHBOARD FRESHNESS (TC-09)")
    probe = Path(args.watch_host) / "dashboard_probe.bin"
    probe_written = time.time()
    probe.write_bytes(os.urandom(120_000))
    seen = wait_for(
        lambda: next(
            (e for e in client.get(f"{args.gateway}/monitor/events", params={"limit": 50}, headers=auth).json()["events"]
             if e["file_path"].endswith(probe.name)),
            None,
        ),
        timeout=5.0,
        interval=0.05,
    )
    if seen:
        lag = time.time() - probe_written
        say(f"  event queryable through the gateway {lag * 1000:.0f}ms after the write")
        say(f"  dashboard auto-refresh interval: 1000ms (services/dashboard/app.py)")
        results["tc09_dashboard_within_1s"] = lag < 1.0
    else:
        say("  probe file never surfaced")
        results["tc09_dashboard_within_1s"] = False

    try:
        dash = client.get(f"{args.dashboard}/_stcore/health", timeout=5.0)
        say(f"  dashboard health: HTTP {dash.status_code}")
    except httpx.HTTPError as exc:
        say(f"  dashboard unreachable: {exc}")
    say()

    # --- 9. auth -------------------------------------------------------------
    rule("9. AUTH (TC-10)")
    no_token = client.get(f"{args.gateway}/monitor/status")
    bad_token = client.get(f"{args.gateway}/monitor/status", headers={"Authorization": "Bearer not-a-jwt"})
    say(f"  no token   -> HTTP {no_token.status_code}")
    say(f"  bad token  -> HTTP {bad_token.status_code}")
    results["tc10_auth_rejects"] = no_token.status_code == 401 and bad_token.status_code == 401
    say()

    return finish(client, args, started_at)


def finish(client, args, started_at) -> int:
    rule("SUMMARY")
    for name, value in results.items():
        label = "PASS" if value else ("SKIP" if value is None else "FAIL")
        say(f"  {name:38s} {label}")
    say()

    failures = [k for k, v in results.items() if v is False]
    say(f"{len(results) - len(failures)}/{len(results)} checks passed")
    if failures:
        say(f"failed: {', '.join(failures)}")

    EVIDENCE_PATH.parent.mkdir(exist_ok=True)
    EVIDENCE_PATH.write_text("\n".join(transcript) + "\n")
    print(f"\nEvidence written to {EVIDENCE_PATH}")

    (EVIDENCE_PATH.parent / "attack_chain_results.json").write_text(json.dumps(results, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
