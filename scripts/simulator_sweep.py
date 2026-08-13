"""Run every simulated ransomware family past a live Monitor and measure it - AS.

Section 6.4.1 reads: *"we executed 10 different ransomware simulators (e.g.,
RanSim). Measured Result Placeholder: The system successfully detected and
terminated 10/10 instances within 2 seconds. (To be replaced with real
evidence)"*. This script is that replacement. It reports what actually happens,
including the families that are not caught.

Why a live observer rather than classifying the files afterwards
----------------------------------------------------------------
Differential entropy analysis compares a file against the lowest reading
previously taken *on that path*. A sweep that only classified the finished
ciphertext would give every family a blank history, which silently disables half
the detector - `headerspoof` writes a valid ZIP header over its ciphertext and
is benign-looking without a baseline to rise from. So the observer is started
first, the simulator creates its decoys, and the 0.5s settle in the simulator
lets the watcher take that baseline before any of them are rewritten. That is
the same ordering as production, and it is the only ordering under which the
measurement means anything.

What is measured, per family
----------------------------
* files flagged / files the family encrypted
* seconds from the first encryption to the first flag, end to end: file write ->
  watchdog -> entropy + statistics -> verdict visible on the event buffer
* whether `--restore` returned every decoy byte for byte

    python scripts/simulator_sweep.py
    python scripts/simulator_sweep.py --files 8 --family headerspoof

Writes reports/simulator_families.json when URDS_WRITE_REPORTS=1, per the
repository's rule that a test run never rewrites committed evidence by accident.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SIMULATOR = REPO_ROOT / "scripts" / "ransomware_simulator.py"
MONITOR_DIR = REPO_ROOT / "services" / "monitor"
REPORTS_DIR = REPO_ROOT / "reports"

# The pipeline fans out to the ML engine, ledger and response services over
# HTTP. This sweep measures the detector, not the stack, and those services are
# not necessarily up - so the fan-out is off and every number below is the
# Monitor's own work.
os.environ["PIPELINE_ENABLED"] = "false"
sys.path.insert(0, str(MONITOR_DIR))

import app as monitor_app  # noqa: E402
from watchdog.observers import Observer  # noqa: E402

# TC-01's bound is "<5 files encrypted"; section 6.4.1's is "within 2 seconds".
# Both are recorded against every family rather than only the ones that pass.
DETECTION_DEADLINE_SECONDS = 2.0

MARKER = b"URDS-TC01-DECOY"


def _families() -> list[str]:
    """Read the family list from the simulator itself, so the two cannot drift."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("ransomware_simulator", SIMULATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return sorted(module.FAMILIES)


def _reset_monitor_state() -> None:
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def _first_flag_time(deadline: float) -> float | None:
    """Poll the event buffer until something is flagged, or `deadline` passes.

    Polled rather than hooked because this measures what an operator would see:
    the moment a suspicious verdict is readable on /monitor/events, not the
    moment a function returned inside the watcher thread.

    This runs *while the simulator is still encrypting*. An earlier version
    waited for the process to exit first and then looked, which timed how long
    the simulator took to finish rather than how long detection took - it
    reported ~1.0s for families that are in fact caught on the first file, and
    reported nothing at all for `slowburn`, whose 800ms pace puts its exit past
    the 2s deadline.
    """
    while time.monotonic() < deadline:
        with monitor_app._LOCK:
            events = list(monitor_app.EVENTS)
        if any(event.get("suspicious") for event in events):
            return time.monotonic()
        time.sleep(0.002)
    return None


def run_family(family: str, files: int, settle_seconds: float) -> dict:
    """One family, start to finish, in its own directory."""
    workdir = Path(tempfile.mkdtemp(prefix=f"urds_sweep_{family}_"))
    _reset_monitor_state()

    observer = Observer()
    observer.schedule(monitor_app.MonitorHandler(), str(workdir), recursive=True)
    observer.start()

    first_write: list[float] = []

    process = subprocess.Popen(
        [sys.executable, str(SIMULATOR), "--target-dir", str(workdir),
         "--files", str(files), "--family", family],
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    def read_stdout() -> None:
        for line in process.stdout:
            if line.startswith("ENCRYPTED 1 ") and not first_write:
                first_write.append(time.monotonic())

    reader = threading.Thread(target=read_stdout, daemon=True)
    reader.start()

    # Wait for the first encryption to be announced before starting the clock;
    # otherwise the decoy-creation phase and the simulator's own settle would be
    # counted as detection latency.
    while not first_write and process.poll() is None:
        time.sleep(0.002)

    started = first_write[0] if first_write else time.monotonic()
    flagged_at = _first_flag_time(started + DETECTION_DEADLINE_SECONDS)

    reader.join(timeout=180)
    process.wait(timeout=180)

    # Whether or not something was flagged, let the remaining events land before
    # counting them - a per-file rate taken mid-flight understates every family.
    time.sleep(settle_seconds)
    observer.stop()
    observer.join(timeout=10)

    with monitor_app._LOCK:
        events = list(monitor_app.EVENTS)

    # One verdict per path, the last one taken: `staged` writes each file twice
    # and it is the finished state that says whether the family was caught.
    latest: dict[str, dict] = {}
    for event in events:
        if event["event_type"] == "deleted":
            continue
        latest[event["file_path"]] = event

    # Only the files the family produced count toward the rate. Its ransom note
    # is a real event and is deliberately expected *not* to be flagged, so
    # counting it as a miss would penalise the detector for being right.
    manifest = json.loads((workdir / ".simulator_manifest.json").read_text())
    produced = {entry["encrypted"] for entry in manifest["entries"]}
    targets = {p: e for p, e in latest.items() if Path(p).name in produced}

    flagged = [p for p, e in targets.items() if e["suspicious"]]
    note_events = [e for p, e in latest.items() if Path(p).name not in produced]

    restored = _restore_and_verify(workdir, files)
    shutil.rmtree(workdir, ignore_errors=True)

    detection_seconds = round(flagged_at - started, 3) if flagged_at else None
    return {
        "family": family,
        "files_encrypted": len(targets),
        "files_flagged": len(flagged),
        "detected": bool(flagged),
        "detection_seconds": detection_seconds,
        "within_2s": detection_seconds is not None and detection_seconds <= DETECTION_DEADLINE_SECONDS,
        "verdicts": sorted({e["verdict"] for e in targets.values()}),
        "reason_sample": next(iter(targets.values()))["reason"] if targets else None,
        "mean_entropy": (
            round(sum(e["entropy"] for e in targets.values() if e["entropy"] is not None)
                  / max(len([e for e in targets.values() if e["entropy"] is not None]), 1), 3)
            if targets else None
        ),
        "collateral_events_flagged": sum(1 for e in note_events if e["suspicious"]),
        "restore_round_trips": restored,
    }


def _restore_and_verify(workdir: Path, files: int) -> bool:
    """`--restore` must return every decoy byte for byte, for every family."""
    subprocess.run(
        [sys.executable, str(SIMULATOR), "--target-dir", str(workdir), "--restore"],
        check=True, capture_output=True, text=True, timeout=120,
    )
    restored = sorted(p for p in workdir.glob("quarterly_report_*") if p.is_file())
    return len(restored) == files and all(p.read_bytes().startswith(MARKER) for p in restored)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files", type=int, default=8, help="decoy documents per family")
    parser.add_argument("--family", action="append", help="run only these (repeatable)")
    parser.add_argument("--settle", type=float, default=2.0, help="seconds to let events land")
    args = parser.parse_args()

    families = args.family or _families()
    results = []
    for family in families:
        print(f"--- {family}", flush=True)
        result = run_family(family, args.files, args.settle)
        results.append(result)
        print(
            f"    {result['files_flagged']}/{result['files_encrypted']} flagged"
            f"   first flag: {result['detection_seconds']}s"
            f"   entropy {result['mean_entropy']}"
            f"   restore {'ok' if result['restore_round_trips'] else 'FAILED'}",
            flush=True,
        )

    detected = [r for r in results if r["detected"]]
    within = [r for r in detected if r["within_2s"]]
    # A family can be flagged without a latency: the flag may land after the 2s
    # deadline the clock stops at. Those are real detections and belong in
    # `detected`, but they have no number to aggregate.
    latencies = [r["detection_seconds"] for r in detected if r["detection_seconds"] is not None]

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "spec_reference": "section 6.4.1, Scenario A",
        "files_per_family": args.files,
        "families_run": len(results),
        "families_detected": len(detected),
        "families_detected_within_2s": len(within),
        "slowest_detection_seconds": max(latencies) if latencies else None,
        "fastest_detection_seconds": min(latencies) if latencies else None,
        "all_restore_round_trips": all(r["restore_round_trips"] for r in results),
        "results": results,
    }

    print("=" * 72)
    print(f"detected {len(detected)}/{len(results)} families, "
          f"{len(within)} of them within {DETECTION_DEADLINE_SECONDS}s")
    missed = [r["family"] for r in results if not r["detected"]]
    if missed:
        print(f"not detected: {', '.join(missed)}")

    if os.getenv("URDS_WRITE_REPORTS") == "1":
        REPORTS_DIR.mkdir(exist_ok=True)
        path = REPORTS_DIR / "simulator_families.json"
        path.write_text(json.dumps(payload, indent=2))
        print(f"wrote {path}")
    else:
        print("set URDS_WRITE_REPORTS=1 to record this to reports/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
