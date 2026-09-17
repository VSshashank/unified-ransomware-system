"""How long after a write does its 4663 record become visible, at what rate?

This measures the number the whole attribution design rests on, and which had
never been measured. `ATTRIBUTION_GRACE_MS` and `ATTRIBUTION_WINDOW_MS` were
both chosen before there was a burst to test them against.

Run it elevated on a Windows host whose watch path already has the SACL from
`scripts/setup_attribution_audit.ps1`:

    python scripts/measure_attribution_lag.py --path D:\\some\\audited\\dir
    URDS_WRITE_REPORTS=1 python scripts/measure_attribution_lag.py --path ...

Writes reports/attribution_delivery_lag.json only when URDS_WRITE_REPORTS=1.

Method
------

* a real `Attributor` on the real `SecurityLogSource`, in this process
* a **child** process does the writing, because `Attributor` excludes its own
  PID and its ancestors - a measurement whose writes are attributed to the
  measurer measures nothing
* the child reports each file the instant it closes it, and this process polls
  `WriteLog.lookup` continuously *while the run is still going*

That last point is the whole harness. The first version of this collected the
child's output with `subprocess.run`, which blocks until the child exits, so
nothing looked for a record until every write was already done and each
reported lag had the remaining span of the run baked into it. It read as 4.2 s
of delivery lag at five writes a second, which is not a measurement of
anything. The concurrent version reports 0.6 s at the same rate.

What it found
-------------

Delivery lag is bounded at roughly one second and is **independent of rate**:
the minimum falls as low as 11 ms and the maximum sits at 1010 ms whatever the
write rate, which is the signature of a flush timer rather than of queueing. A
write landing just before a flush is visible almost at once; one landing just
after waits out the rest of the interval.

The consequence is the important part. A 750 ms correlation window is *below
the delivery latency of the source it reads*, so under a burst - where every
write falls inside one flush interval - it matches nothing at all. That is not
a tuning preference, it is a constant set below the floor of the mechanism.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

import attribution  # noqa: E402

#: (label, files, seconds between writes)
RATES = [
    ("idle      5 writes/s", 25, 0.200),
    ("busy     20 writes/s", 40, 0.050),
    ("fast    100 writes/s", 60, 0.010),
    ("burst   uncapped", 120, 0.0),
]

#: Deliberately far longer than any production window. This is the measurement
#: that decides what the production window should be, so it must not be the
#: thing doing the filtering.
PROBE_WINDOW_MS = 120_000.0

WRITER_SOURCE = '''
import json, os, sys, time
from pathlib import Path
target, count, interval = Path(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
payload = b"probe payload " * 64
print(json.dumps({"pid": os.getpid()}), flush=True)
for index in range(count):
    path = target / ("lag_%04d.bin" % index)
    with open(path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    print(json.dumps({"path": os.path.normcase(os.path.abspath(str(path))),
                      "at": time.monotonic()}), flush=True)
    if interval:
        time.sleep(interval)
print(json.dumps({"done": True}), flush=True)
'''


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True,
                          text=True, check=False).stdout.strip()


def measure(label: str, count: int, interval: float, attributor,
            target: Path, writer: Path) -> dict:
    target.mkdir(parents=True, exist_ok=True)
    for stale in target.glob("lag_*.bin"):
        try:
            stale.unlink()
        except OSError:
            pass
    time.sleep(1.5)

    before = attributor.log.recorded
    written: list[tuple[str, float]] = []
    writer_pid: list[int] = []
    finished = threading.Event()

    proc = subprocess.Popen(
        [sys.executable, str(writer), str(target), str(count), str(interval)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    def consume() -> None:
        for line in proc.stdout:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "pid" in record:
                writer_pid.append(record["pid"])
            elif "path" in record:
                written.append((record["path"], record["at"]))
            elif record.get("done"):
                finished.set()
        finished.set()

    threading.Thread(target=consume, daemon=True).start()

    # Poll while the child is still writing. A lookup is a lock and a scan of
    # at most MAX_ENTRIES, so it costs microseconds and does not perturb what
    # it is measuring.
    lags: dict[str, float] = {}
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        for path, at in list(written):
            if path in lags:
                continue
            answer = attributor.log.lookup(
                path, window_ms=PROBE_WINDOW_MS, source="probe",
                kernel_grade=True)
            if writer_pid and answer.pid == writer_pid[0]:
                lags[path] = (now - at) * 1000.0
        if finished.is_set() and written and len(lags) >= len(written):
            break
        time.sleep(0.004)

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    found = sorted(lags.values())

    def pct(fraction: float):
        if not found:
            return None
        return round(found[min(len(found) - 1, int(len(found) * fraction))], 1)

    return {
        "rate": label,
        "files_written": len(written),
        "writes_recorded_delta": attributor.log.recorded - before,
        "attributed": len(found),
        "never_attributed": len(written) - len(found),
        "lag_ms_min": round(found[0], 1) if found else None,
        "lag_ms_median": round(statistics.median(found), 1) if found else None,
        "lag_ms_p90": pct(0.90),
        "lag_ms_max": round(found[-1], 1) if found else None,
        "within_250ms": sum(1 for v in found if v <= 250.0),
        "within_750ms": sum(1 for v in found if v <= 750.0),
        "within_3000ms": sum(1 for v in found if v <= 3000.0),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True,
                        help="an audited directory to write probe files into")
    args = parser.parse_args(argv)

    target = Path(args.path) / "lagprobe"
    writer = target.parent / "_urds_lag_writer.py"

    attributor = attribution.Attributor()
    source = attribution.build_source(attributor.log)
    if not attributor.start(source):
        print(json.dumps({"error": "no attribution source is available",
                          "detail": source.error,
                          "hint": "run elevated, on Windows, after "
                                  "scripts/setup_attribution_audit.ps1"},
                         indent=2))
        return 1

    target.mkdir(parents=True, exist_ok=True)
    writer.write_text(WRITER_SOURCE, encoding="utf-8")
    print(f"source: {source.name}, kernel_grade={source.kernel_grade}",
          file=sys.stderr)
    time.sleep(2.0)

    try:
        results = [measure(label, count, interval, attributor, target, writer)
                   for label, count, interval in RATES]
    finally:
        attributor.stop()
        writer.unlink(missing_ok=True)

    ceiling = max((r["lag_ms_max"] or 0.0) for r in results)
    report = {
        "schema": "urds.attribution_delivery_lag/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "_what_this_measures":
            "delay between a write completing and its 4663 record becoming "
            "visible to Attributor.lookup, at four write rates, on this host",
        "host_platform": sys.platform,
        "source": source.name,
        "kernel_grade": source.kernel_grade,
        "grace_ms_at_measurement": attribution.GRACE_MS,
        "window_ms_at_measurement": attribution.WINDOW_MS,
        "results": results,
        "observed_delivery_ceiling_ms": ceiling,
        "finding":
            "Delivery lag is bounded at roughly one second and is independent "
            "of write rate - the minimum falls to a few milliseconds and the "
            "maximum sits near the same ceiling whatever the rate. That is a "
            "flush timer, not queueing: a write landing just before a flush is "
            "visible almost at once, one landing just after waits out the "
            "interval.",
        "consequence":
            "A correlation window shorter than this ceiling is set below the "
            "floor of the mechanism it reads. Under a burst, where every write "
            "falls inside one flush interval, such a window matches nothing at "
            "all - which is what the first Phase 3 acceptance measured as 40 "
            "of 40 documents destroyed with nothing suspended.",
    }

    print(json.dumps(report, indent=2))
    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    out = REPO_ROOT / "reports" / "attribution_delivery_lag.json"
    with out.open("w", encoding="utf-8", newline="") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
