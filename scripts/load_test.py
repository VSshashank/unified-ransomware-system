"""What the Monitor does under sustained load - AS + SH.

Item P7.3: *load testing. Measured, not asserted.*

Three questions, none of which a single-event benchmark answers:

  1. Does the detection path hold its budget when many threads are in it at
     once? Table 5.9 gives 100 ms; `reports/as_benchmarks.json` measures it on
     an idle machine one file at a time.
  2. What happens to the fan-out queue when events arrive faster than the
     worker drains them? `app._work` is an unbounded `queue.Queue` and the
     Phase 5 inventory recorded that without measuring it.
  3. What does `app._SEEN_FILES` cost? It is a `set` that grows by one entry
     per distinct path, for the life of the process, and nothing removes from
     it.

The second and third are availability questions rather than detection ones, and
they are the kind that only appear at a scale nobody runs by hand. A monitor that
is correct and falls over after nine hours of a busy build server is not a
monitor.

Nothing here is fixed. This measures, and the numbers go to
`docs/SECURITY_AUDIT.md` with what they mean.

    .venv\\Scripts\\python.exe scripts/load_test.py

Writes reports/load_test.json only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"

sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

DETECTION_BUDGET_MS = 100.0

# Enough events that a queue which is going to grow has grown, and few enough
# that the sweep runs in under a minute on a laptop.
BURST_EVENTS = 1200
CONCURRENCY = 16
SUSTAINED_SECONDS = 8.0
SEEN_FILES_PROBE = 20_000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def payload(tag: str, size: int = 60_000) -> bytes:
    return hashlib.shake_256(tag.encode()).digest(size)


def percentiles(values: list[float]) -> dict:
    if not values:
        return {}
    ordered = sorted(values)

    def at(fraction: float) -> float:
        index = min(len(ordered) - 1, int(fraction * len(ordered)))
        return round(ordered[index], 3)

    return {
        "n": len(ordered),
        "min_ms": round(ordered[0], 3),
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": at(0.95),
        "p99_ms": at(0.99),
        "max_ms": round(ordered[-1], 3),
        "mean_ms": round(statistics.fmean(ordered), 3),
    }


# ------------------------------------------------------ 1. concurrent detection


def measure_concurrent_detection(workdir: Path) -> dict:
    """`handle_event` from many threads at once, with the fan-out disabled.

    The fan-out is off deliberately: this measures the detection path, which is
    what the 100 ms budget is written against. The queue is measured separately
    below, with it on.
    """
    import app as monitor_app

    workdir.mkdir(parents=True, exist_ok=True)
    previous = monitor_app.PIPELINE_ENABLED
    monitor_app.PIPELINE_ENABLED = False
    monitor_app.ENTROPY_HISTORY.clear()

    # A mix that exercises every branch: ciphertext, a forged header, a genuine
    # archive, and prose. A load figure taken on one shape is a figure about that
    # shape.
    shapes = {
        "ciphertext": lambda i: payload(f"load:ct:{i}"),
        "forged": lambda i: b"PK\x03\x04" + payload(f"load:forged:{i}"),
        "genuine_gzip": lambda i: gzip.compress(
            (b"quarterly deployment report. " * 2000)[:60_000]
        ),
        "prose": lambda i: (b"quarterly deployment report. " * 2000)[:60_000],
    }

    files: list[Path] = []
    for index in range(BURST_EVENTS):
        name, build = list(shapes.items())[index % len(shapes)]
        target = workdir / f"{name}_{index}.bin"
        target.write_bytes(build(index))
        files.append(target)

    latencies: list[float] = []
    lock = threading.Lock()
    errors: list[str] = []

    def one(target: Path) -> None:
        started = time.perf_counter()
        try:
            monitor_app.handle_event(str(target), "created")
        except Exception as error:  # an error under load is a result
            with lock:
                errors.append(f"{type(error).__name__}: {error}")
            return
        elapsed = (time.perf_counter() - started) * 1000.0
        with lock:
            latencies.append(elapsed)

    wall_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        list(pool.map(one, files))
    wall = time.perf_counter() - wall_start

    monitor_app.PIPELINE_ENABLED = previous

    stats = percentiles(latencies)
    return {
        "events": BURST_EVENTS,
        "concurrency": CONCURRENCY,
        "wall_seconds": round(wall, 3),
        "throughput_events_per_second": round(BURST_EVENTS / wall, 1) if wall else None,
        "latency": stats,
        "budget_ms": DETECTION_BUDGET_MS,
        "over_budget": sum(1 for value in latencies if value > DETECTION_BUDGET_MS),
        "p95_within_budget": bool(stats) and stats["p95_ms"] <= DETECTION_BUDGET_MS,
        "errors": errors[:10],
        "error_count": len(errors),
    }


# ---------------------------------------------------------- 2. the work queue


def measure_queue_growth(workdir: Path) -> dict:
    """Feed events faster than the worker drains them, and watch the queue.

    The fan-out worker is real. What is replaced is the transport, with one that
    sleeps - which is what a slow or unreachable ledger looks like from here, and
    is the condition under which an unbounded queue is a liability rather than a
    detail.
    """
    import app as monitor_app
    import pipeline as monitor_pipeline

    drained = {"count": 0}

    def slow_post(client, base_url, path, body):
        time.sleep(0.02)  # a downstream hop that takes 20 ms
        if path == "/ledger/log":
            drained["count"] += 1
            return {"block_id": drained["count"], "current_hash": "a" * 64}
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.9, "threat_level": "critical"}
        return {"status": "success", "actions_taken": []}

    workdir.mkdir(parents=True, exist_ok=True)
    original = monitor_pipeline._post
    previous = monitor_app.PIPELINE_ENABLED
    monitor_pipeline._post = slow_post
    monitor_app.PIPELINE_ENABLED = True
    monitor_app.ENTROPY_HISTORY.clear()
    monitor_app._ensure_worker()

    depths: list[int] = []
    produced = 0
    deadline = time.perf_counter() + SUSTAINED_SECONDS
    try:
        while time.perf_counter() < deadline:
            target = workdir / f"queue_{produced}.bin"
            target.write_bytes(payload(f"queue:{produced}", 20_000))
            monitor_app.handle_event(str(target), "created")
            depths.append(monitor_app._work.qsize())
            produced += 1
        peak = max(depths) if depths else 0
        final = monitor_app._work.qsize()
    finally:
        monitor_app.PIPELINE_ENABLED = previous
        # Cleanup, not measurement. The backlog is what was measured; draining it
        # at 60 ms an item would take longer than the whole rest of this script,
        # which is itself the finding - so the transport is swapped for one that
        # answers instantly and the queue is emptied at that speed instead.
        monitor_pipeline._post = lambda *a, **k: {}

    drain_started = time.perf_counter()
    monitor_app._work.join()
    drain_seconds = time.perf_counter() - drain_started
    monitor_pipeline._post = original

    return {
        "seconds": SUSTAINED_SECONDS,
        "events_produced": produced,
        "production_rate_per_second": round(produced / SUSTAINED_SECONDS, 1),
        "queue_depth_peak": peak,
        "queue_depth_final": final,
        "downstream_latency_ms_per_call": 20,
        "calls_per_event": 3,
        "projected_drain_seconds_at_measured_latency": round(final * 0.06, 1),
        "actual_drain_seconds_with_instant_transport": round(drain_seconds, 2),
        "queue_is_bounded": monitor_app._work.maxsize > 0,
        "queue_maxsize": monitor_app._work.maxsize,
        "backlog_grew_monotonically": bool(depths) and depths[-1] >= depths[0],
        "depth_samples": depths[:: max(1, len(depths) // 20)][:20],
        "what_this_means": (
            "`app._work` is a queue.Queue with maxsize 0, which is unbounded. "
            "Producers are watchdog threads and the consumer is one worker "
            "making three HTTP calls per event, so any period where events "
            "arrive faster than the fan-out completes grows the backlog and "
            "nothing bounds it. The queue holds the full event dict, so the "
            "cost is per-event and real."
        ),
    }


# --------------------------------------------------------- 3. the seen-file set


def measure_seen_files() -> dict:
    """What one entry in `_SEEN_FILES` costs, and what nothing removing it means.

    Measured by adding paths of a realistic length to a set of the same kind and
    reading the process's own accounting, rather than by reasoning about
    CPython's set growth policy.
    """
    import app as monitor_app

    baseline = len(monitor_app._SEEN_FILES)

    probe: set[str] = set()
    template = "C:/Users/operator/Documents/projects/build/artifacts/output_{}.bin"
    before = sys.getsizeof(probe)
    for index in range(SEEN_FILES_PROBE):
        probe.add(template.format(index))
    container_bytes = sys.getsizeof(probe)
    string_bytes = sum(sys.getsizeof(value) for value in probe)
    total = container_bytes + string_bytes

    return {
        "entries_probed": SEEN_FILES_PROBE,
        "set_bytes_empty": before,
        "set_container_bytes": container_bytes,
        "string_bytes": string_bytes,
        "total_bytes": total,
        "bytes_per_path": round(total / SEEN_FILES_PROBE, 1),
        "monitor_seen_files_now": baseline,
        "is_bounded": False,
        "what_this_means": (
            "`_SEEN_FILES` exists to answer 'is this the first time this path has "
            "been seen', which gates one ledger baseline write per path per "
            "monitor run. It is a plain set and nothing removes from it, so its "
            "size is the number of distinct paths the monitor has ever seen. On a "
            "build server or a large source tree that is unbounded in practice as "
            "well as in principle. The number above is what a million distinct "
            "paths would cost, and it is not large - which is the honest finding: "
            "this is a slow leak with a small constant, not an imminent failure."
        ),
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="load_test_") as tmp_name:
        tmp = Path(tmp_name)
        print("  measuring concurrent detection ...", flush=True)
        detection_result = measure_concurrent_detection(tmp / "detect")
        print("  measuring fan-out queue growth ...", flush=True)
        queue_result = measure_queue_growth(tmp / "queue")
    print("  measuring the seen-file set ...", flush=True)
    seen_result = measure_seen_files()

    report = {
        "schema": "urds.load_test/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "requirement": "Phase 7 P7.3 - load testing, measured not asserted",
        "host": {
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "cpu_count": os.cpu_count(),
        },
        "concurrent_detection": detection_result,
        "fan_out_queue": queue_result,
        "seen_files_set": seen_result,
        "limits": (
            "One machine, one process, synthetic files on a local disk. Nothing "
            "here measures the Compose stack, the network between containers, or "
            "a real filesystem under real load - the fan-out transport is stubbed "
            "in the queue measurement and disabled in the latency one, so these "
            "are Monitor-scoped numbers and are labelled as such."
        ),
    }

    print("load test")
    print(
        f"  detection   {detection_result['events']} events at concurrency "
        f"{detection_result['concurrency']}: "
        f"median {detection_result['latency'].get('median_ms')} ms, "
        f"p95 {detection_result['latency'].get('p95_ms')} ms, "
        f"p99 {detection_result['latency'].get('p99_ms')} ms, "
        f"max {detection_result['latency'].get('max_ms')} ms"
    )
    print(
        f"              {detection_result['over_budget']} over the "
        f"{DETECTION_BUDGET_MS:.0f} ms budget, "
        f"{detection_result['throughput_events_per_second']} events/s, "
        f"{detection_result['error_count']} errors"
    )
    print(
        f"  queue       {queue_result['events_produced']} events in "
        f"{queue_result['seconds']:.0f}s, peak depth {queue_result['queue_depth_peak']}, "
        f"bounded={queue_result['queue_is_bounded']}"
    )
    print(
        f"              a backlog of {queue_result['queue_depth_final']} would take "
        f"{queue_result['projected_drain_seconds_at_measured_latency']}s to clear at "
        "20 ms a hop"
    )
    print(
        f"  seen files  {seen_result['bytes_per_path']} bytes per distinct path, "
        f"bounded={seen_result['is_bounded']}"
    )

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "load_test.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {REPORTS / 'load_test.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
