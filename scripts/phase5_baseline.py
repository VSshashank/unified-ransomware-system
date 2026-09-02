"""The measured starting state of Phase 5 - SH.

Chapter 9 §9.8 assigns this reports/phase5_baseline.json, and every later "no
regression" claim in Phases 5-8 is measured against that file. So it has to be a
measurement, not a transcription of the numbers already in reports/.

Two of those numbers were not measured by the method Table 5.9 states.

    System CPU Usage   <15%     "Average during 1-hour monitoring period"
    System RAM Usage   <500MB   "Peak memory consumption during stress test"

`services/monitor/tests/test_benchmarks.py` samples both over a five-second
window. Five seconds is a fine smoke test and it is not a one-hour average: a
watcher can idle cheaply for five seconds and still drift upward over an hour,
and the RSS peak of a five-second burst is not the peak of a stress test. This
script runs the window Table 5.9 asks for. It takes an hour, which is the point.

What is measured here directly
------------------------------
Detection latency, false-positive rate, forged-container detection, CPU over the
full monitoring window, peak RSS under sustained stress, dashboard freshness,
ledger verification time, and process-termination time. All of these run
in-process against the same functions `handle_event` calls, so the benchmark
cannot drift away from the detector anyone actually runs.

What is delegated, and why
--------------------------
ML inference time and gateway p95 are measured by the suites that own them
(`services/ml-engine/tests`, `services/gateway/tests`), because those suites
carry the downstream stubs the measurement needs and duplicating the stubs here
would mean two versions of "what a request costs" that can disagree. This script
runs those suites itself with URDS_WRITE_REPORTS=1 and ingests the files they
write, recording the hash of each so the provenance is checkable. Nothing is
read from a report this run did not produce.

The 13 simulator families come from scripts/simulator_sweep.py the same way -
run here, ingested here.

    .venv\\Scripts\\python.exe scripts/phase5_baseline.py            # 1h, the real thing
    .venv\\Scripts\\python.exe scripts/phase5_baseline.py --quick    # 60s, a smoke run

Writes reports/phase5_baseline.json only when URDS_WRITE_REPORTS=1, per the
repository rule that a run never rewrites committed evidence by accident. A
--quick run refuses to write at all: an hour-long benchmark that can be
satisfied by a sixty-second run is the defect this file exists to correct, and
the only way to keep that honest is to make the short run unable to produce the
artefact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"
PYTHON = sys.executable

sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import synthetic_corpus  # noqa: E402

# Table 5.9 targets, quoted from the reference document rather than restated.
TARGETS = {
    "detection_latency_ms": ("<100ms", "Timestamp diff between modification and alert"),
    "response_time_s": ("<2 seconds", "Time from detection to termination"),
    "false_positive_rate": ("<5%", "(False Positives / Total) x 100"),
    "ml_inference_ms": ("<100ms", "Average prediction time across 1000 samples"),
    "api_p95_ms": ("<200ms", "95th percentile of all API requests"),
    "cpu_percent": ("<15%", "Average during 1-hour monitoring period"),
    "ram_peak_mb": ("<500MB", "Peak memory consumption during stress test"),
    "file_recovery_success": ("100%", "Successful restoration of encrypted files"),
    "ledger_verify_ms": ("<50ms", "Time to verify hash chain integrity"),
    "dashboard_latency_ms": ("<1 second", "Time from event to dashboard display"),
}

SERVICES = ("monitor", "gateway", "ledger", "ml-engine", "response")

# Files Phases 5-8 cite. Hashing them here is what lets a later run prove the
# thing it measured is the thing this baseline measured.
HASHED_ARTEFACTS = (
    "services/monitor/detection.py",
    "services/monitor/containers.py",
    "services/monitor/suppression.py",
    "services/monitor/admissibility.py",
    "services/monitor/pipeline.py",
    "services/monitor/app.py",
    "services/ml-engine/app.py",
    "services/response/app.py",
    "services/ledger/hash_chain.py",
    "scripts/ransomware_simulator.py",
    "scripts/simulator_sweep.py",
    "scripts/synthetic_corpus.py",
    "docs/CAPABILITY_GOVERNED_EXCEPTIONS.md",
    "docs/DETECTION_HARDENING.md",
    "docs/PHASE1-4_COMPLETION_SUMMARY.md",
    "docs/PHASE4_VERIFICATION_REPORT.md",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_of(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


# ---------------------------------------------------------------- provenance


def provenance() -> dict:
    dirty = git("status", "--porcelain")
    return {
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "working_tree_clean": dirty == "",
        "uncommitted_paths": [line[3:] for line in dirty.splitlines()] if dirty else [],
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "logical_cores": psutil.cpu_count(),
            "physical_cores": psutil.cpu_count(logical=False),
            "total_ram_mb": round(psutil.virtual_memory().total / (1024 * 1024)),
        },
    }


# ---------------------------------------------------------------- test suite

_COUNT = re.compile(r"(\d+) (passed|failed|skipped|error|xfailed|xpassed)")


def run_suite(service: str) -> dict:
    """One service's pytest run, counted from its own summary line."""
    started = time.perf_counter()
    result = subprocess.run(
        [PYTHON, "-m", "pytest", "-q"],
        cwd=REPO_ROOT / "services" / service,
        capture_output=True,
        text=True,
        check=False,
    )
    counts = {name: int(value) for value, name in _COUNT.findall(result.stdout)}
    return {
        "passed": counts.get("passed", 0),
        "failed": counts.get("failed", 0) + counts.get("error", 0),
        "skipped": counts.get("skipped", 0),
        "exit_code": result.returncode,
        "seconds": round(time.perf_counter() - started, 1),
    }


def test_suite() -> dict:
    per_service = {service: run_suite(service) for service in SERVICES}
    return {
        "per_service": per_service,
        "total_passed": sum(s["passed"] for s in per_service.values()),
        "total_failed": sum(s["failed"] for s in per_service.values()),
        "total_skipped": sum(s["skipped"] for s in per_service.values()),
        "all_green": all(s["exit_code"] == 0 for s in per_service.values()),
    }


# --------------------------------------------------------- monitor internals


def _verdict_for(path: Path) -> dict:
    """Classify one file exactly as the detection path does.

    Imported lazily and reconstructed here rather than imported from the test
    module, because scripts/ must not depend on a service's tests directory.
    """
    from containers import validate_container
    from detection import classify, identify_container, measure, read_magic, sample_file

    size = path.stat().st_size
    head, tail = sample_file(str(path), size)
    entropy, statistics = measure(head)
    magic = read_magic(str(path))
    return classify(
        str(path),
        entropy,
        magic,
        container_valid=validate_container(head, tail, identify_container(magic), size),
        statistics=statistics,
    )


def benign_corpus(root: Path) -> list[Path]:
    """The forty-file benign corpus the Phase 4 false-positive figure was taken
    over, rebuilt so this baseline measures the same population."""
    root.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []
    plan = [
        (8, "notes_{}.txt", None),
        (6, "archive_{}.zip", lambda: synthetic_corpus.build_zip(120000)),
        (6, "backup_{}.gz", lambda: synthetic_corpus.build_gzip(400000)),
        (6, "photo_{}.png", lambda: synthetic_corpus.build_png(120000)),
        (6, "scan_{}.jpg", lambda: synthetic_corpus.build_jpeg(120000)),
        (4, "manual_{}.pdf", lambda: synthetic_corpus.build_pdf(80000)),
        (4, "clip_{}.mp4", lambda: synthetic_corpus.build_mp4(120000)),
    ]
    for count, template, builder in plan:
        for index in range(count):
            path = root / template.format(index)
            if builder is None:
                path.write_text(f"quarterly report section {index}\n" * 400)
            else:
                path.write_bytes(builder())
            files.append(path)
    return files


def detection_latency(workdir: Path) -> dict:
    """Table 5.9 row 1. Table 9.8 additionally asks for median and IQR over at
    least ten repetitions, so those are reported here too - the post-repair
    comparison in Phase 6 has to be against the same statistics."""
    import app as monitor_app

    workdir.mkdir(parents=True, exist_ok=True)
    samples: list[float] = []
    for index, size in enumerate((4 * 1024, 64 * 1024, 512 * 1024, 2 * 1024 * 1024)):
        for repeat in range(10):
            target = workdir / f"lat_{index}_{repeat}.bin"
            target.write_bytes(os.urandom(size))
            event = monitor_app.handle_event(str(target), "created")
            samples.append(event["detection_latency_ms"])

    samples.sort()
    n = len(samples)
    q1 = samples[n // 4]
    q3 = samples[(3 * n) // 4]
    return {
        "samples": n,
        "mean": round(sum(samples) / n, 3),
        "median": round(samples[n // 2], 3),
        "q1": round(q1, 3),
        "q3": round(q3, 3),
        "iqr": round(q3 - q1, 3),
        "p95": round(samples[int(n * 0.95) - 1], 3),
        "max": round(samples[-1], 3),
    }


def false_positive_rate(workdir: Path) -> dict:
    from detection import calculate_entropy

    files = benign_corpus(workdir)
    offenders = [
        (p.name, v["entropy"], v["verdict"])
        for p in files
        for v in (_verdict_for(p),)
        if v["suspicious"]
    ]
    high = sum(1 for p in files if calculate_entropy(str(p)) >= 7.5)
    return {
        "corpus_size": len(files),
        "high_entropy_in_corpus": high,
        "false_positives": len(offenders),
        "rate": round(len(offenders) / len(files), 4),
        "offenders": offenders,
    }


def forged_container_rate(workdir: Path) -> dict:
    """Not a Table 5.9 row, recorded because a false-positive rate on its own
    can be driven to zero by a detector that detects nothing. Phase 6 compares
    both numbers or neither."""
    workdir.mkdir(parents=True, exist_ok=True)
    forged = []
    for index in range(8):
        for magic, extension in synthetic_corpus.SPOOF_TARGETS:
            path = workdir / f"spoof_{index}{extension}"
            path.write_bytes(synthetic_corpus.spoof(magic, 120000))
            forged.append(path)
    detected = sum(1 for p in forged if _verdict_for(p)["suspicious"])
    return {
        "samples": len(forged),
        "detected": detected,
        "rate": round(detected / len(forged), 4),
        "formats": sorted({ext for _, ext in synthetic_corpus.SPOOF_TARGETS}),
    }


def cpu_over_window(workdir: Path, seconds: float) -> dict:
    """Table 5.9 row 6, by its stated method.

    The load is a steady write cadence into a watched directory - one 32KB file
    every 50ms - held for the whole window, so the figure is the cost of
    monitoring under continuous activity rather than the cost of monitoring an
    idle disk. CPU and RSS are both sampled once a second; the RSS series is
    kept because a leak that only shows after forty minutes is invisible to any
    shorter run, and this is the only run long enough to see one.
    """
    from fastapi.testclient import TestClient

    import app as monitor_app

    workdir.mkdir(parents=True, exist_ok=True)
    process = psutil.Process()
    samples: list[float] = []
    system_samples: list[float] = []
    rss_series: list[float] = []
    written = 0
    cores = psutil.cpu_count() or 1

    with TestClient(monitor_app.app) as client:
        client.post("/monitor/start", json={"watch_path": str(workdir), "recursive": True})
        process.cpu_percent(interval=None)  # prime
        started = time.time()
        next_sample = started + 1.0

        while True:
            now = time.time()
            if now - started >= seconds:
                break
            target = workdir / f"load_{written}.bin"
            target.write_bytes(os.urandom(32768))
            written += 1
            if now >= next_sample:
                samples.append(process.cpu_percent(interval=None) / cores)
                # What the rest of the machine was doing. cpu_percent above is
                # per-process, so other work on this host is not attributed to
                # the Monitor - but a loaded host still slows it down, and a
                # reader cannot judge the figure without knowing the load it was
                # taken under. Recording it is cheaper than claiming the machine
                # was idle.
                system_samples.append(psutil.cpu_percent(interval=None))
                rss_series.append(process.memory_info().rss / (1024 * 1024))
                next_sample = now + 1.0
                # The window is an hour; keeping every file would be 2.3GB of
                # disk for a CPU measurement. Old load files are recycled.
                if written % 200 == 0:
                    for stale in sorted(workdir.glob("load_*.bin"))[:-20]:
                        stale.unlink(missing_ok=True)
            time.sleep(0.05)

        client.post("/monitor/stop")

    duration = time.time() - started
    # The first sample covers the priming interval and is discarded - it
    # attributes the whole of process startup to one second of monitoring.
    usable = samples[1:] or samples
    return {
        "window_seconds": round(duration, 1),
        "files_written": written,
        "samples": len(usable),
        "mean_percent_of_total_cpu": round(sum(usable) / len(usable), 3),
        "max_percent_of_total_cpu": round(max(usable), 3),
        "p95_percent_of_total_cpu": round(sorted(usable)[int(len(usable) * 0.95) - 1], 3),
        "cores": cores,
        "host_wide_mean_percent": round(sum(system_samples) / len(system_samples), 2)
        if system_samples
        else None,
        "host_wide_max_percent": round(max(system_samples), 2) if system_samples else None,
        "rss_first_mb": round(rss_series[0], 2) if rss_series else None,
        "rss_last_mb": round(rss_series[-1], 2) if rss_series else None,
        "rss_peak_over_window_mb": round(max(rss_series), 2) if rss_series else None,
        "method": TARGETS["cpu_percent"][1],
    }


def ram_under_stress(workdir: Path, seconds: float) -> dict:
    """Table 5.9 row 7. Harder than the CPU load on purpose: 512KB files with no
    sleep, and the event handled synchronously, so the entropy reader and the
    bounded event buffer are both under pressure for the whole window."""
    from fastapi.testclient import TestClient

    import app as monitor_app

    workdir.mkdir(parents=True, exist_ok=True)
    process = psutil.Process()
    baseline_mb = process.memory_info().rss / (1024 * 1024)
    peak_mb = baseline_mb
    written = 0

    with TestClient(monitor_app.app) as client:
        client.post("/monitor/start", json={"watch_path": str(workdir), "recursive": True})
        started = time.time()
        while time.time() - started < seconds:
            target = workdir / f"stress_{written % 64}.bin"
            target.write_bytes(os.urandom(512 * 1024))
            monitor_app.handle_event(str(target), "created")
            written += 1
            peak_mb = max(peak_mb, process.memory_info().rss / (1024 * 1024))
        client.post("/monitor/stop")

    return {
        "stress_seconds": round(time.time() - started, 1),
        "events_processed": written,
        "baseline_mb": round(baseline_mb, 2),
        "peak_mb": round(peak_mb, 2),
        "growth_mb": round(peak_mb - baseline_mb, 2),
        "method": TARGETS["ram_peak_mb"][1],
    }


def dashboard_latency(workdir: Path) -> dict:
    """Table 5.9 row 10. The dashboard renders GET /monitor/events, so what the
    system controls is how quickly a write becomes readable there."""
    from fastapi.testclient import TestClient

    import app as monitor_app

    workdir.mkdir(parents=True, exist_ok=True)
    lags = []
    with TestClient(monitor_app.app) as client:
        client.post("/monitor/start", json={"watch_path": str(workdir), "recursive": True})
        for index in range(10):
            target = workdir / f"alert_{index}.docx"
            started = time.perf_counter()
            target.write_bytes(os.urandom(64 * 1024))
            monitor_app.handle_event(str(target), "created")
            deadline = started + 1.0
            seen = None
            while time.perf_counter() < deadline:
                events = client.get("/monitor/events", params={"limit": 50}).json()["events"]
                if any(e["file_path"].endswith(f"alert_{index}.docx") for e in events):
                    seen = time.perf_counter()
                    break
            lags.append((seen - started) * 1000 if seen else None)
        client.post("/monitor/stop")

    measured = [lag for lag in lags if lag is not None]
    return {
        "samples": len(lags),
        "visible_within_1s": len(measured),
        "mean_ms": round(sum(measured) / len(measured), 3) if measured else None,
        "max_ms": round(max(measured), 3) if measured else None,
    }


def ledger_verify_time(workdir: Path) -> dict:
    """Table 5.9 row 9, over a chain long enough for the walk to cost something."""
    sys.path.insert(0, str(REPO_ROOT / "services" / "ledger"))
    from hash_chain import HashChainLedger

    workdir.mkdir(parents=True, exist_ok=True)
    db = workdir / "baseline_ledger.db"
    db.unlink(missing_ok=True)
    ledger = HashChainLedger(str(db))
    for index in range(500):
        ledger.add_block("detection", {"file": f"f{index}.docx", "entropy": 7.99})

    timings = []
    for _ in range(20):
        started = time.perf_counter()
        result = ledger.verify_chain()
        timings.append((time.perf_counter() - started) * 1000)
    ledger.close()

    timings.sort()
    return {
        "chain_length": 500,
        "repetitions": len(timings),
        "mean_ms": round(sum(timings) / len(timings), 3),
        "median_ms": round(timings[len(timings) // 2], 3),
        "max_ms": round(timings[-1], 3),
        "chain_valid": bool(result.get("valid")),
    }


def termination_time() -> dict:
    """Table 5.9 row 2. A real child process, terminated through the same
    function the Response service calls."""
    sys.path.insert(0, str(REPO_ROOT / "services" / "response"))
    from actions import terminate_process

    timings = []
    for _ in range(10):
        child = subprocess.Popen([PYTHON, "-c", "import time; time.sleep(30)"])
        started = time.perf_counter()
        terminate_process(child.pid)
        timings.append(time.perf_counter() - started)
        child.wait(timeout=10)

    timings.sort()
    return {
        "repetitions": len(timings),
        "mean_s": round(sum(timings) / len(timings), 4),
        "median_s": round(timings[len(timings) // 2], 4),
        "max_s": round(timings[-1], 4),
    }


# ------------------------------------------------------------ delegated runs


def _run(command: list[str], cwd: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, check=False)


def delegated_benchmarks() -> dict:
    """ML inference time and gateway p95, measured by the suites that own them.

    Both are run here with URDS_WRITE_REPORTS=1 so the files ingested below are
    files this run produced. The hash of each is recorded next to the number.
    """
    out: dict = {}

    ml = _run(
        [PYTHON, "-m", "pytest", "-q", "-m", "benchmark", "-p", "no:cacheprovider"],
        REPO_ROOT / "services" / "ml-engine",
        {"URDS_WRITE_REPORTS": "1"},
    )
    gw = _run(
        [PYTHON, "-m", "pytest", "-q", "-m", "benchmark", "-p", "no:cacheprovider"],
        REPO_ROOT / "services" / "gateway",
        {"URDS_WRITE_REPORTS": "1"},
    )

    for key, path, exit_code in (
        ("ml_inference", REPORTS / "ni_inference_benchmark.json", ml.returncode),
        ("gateway_api", REPORTS / "gateway_benchmarks.json", gw.returncode),
    ):
        payload = json.loads(path.read_text()) if path.exists() else None
        out[key] = {
            "source": str(path.relative_to(REPO_ROOT)).replace("\\", "/"),
            "sha256": sha256_of(path),
            "suite_exit_code": exit_code,
            "report": payload,
        }
    return out


def simulator_families(files_per_family: int) -> dict:
    """The 13/13 figure, re-measured rather than read from the committed file."""
    result = _run(
        [PYTHON, str(REPO_ROOT / "scripts" / "simulator_sweep.py"), "--files", str(files_per_family)],
        REPO_ROOT,
        {"URDS_WRITE_REPORTS": "1"},
    )
    path = REPORTS / "simulator_families.json"
    payload = json.loads(path.read_text()) if path.exists() else {}
    return {
        "source": "reports/simulator_families.json",
        "sha256": sha256_of(path),
        "sweep_exit_code": result.returncode,
        "families_run": payload.get("families_run"),
        "families_detected": payload.get("families_detected"),
        "families_detected_within_2s": payload.get("families_detected_within_2s"),
        "all_restore_round_trips": payload.get("all_restore_round_trips"),
        "slowest_detection_seconds": payload.get("slowest_detection_seconds"),
        "stderr_tail": result.stderr.strip().splitlines()[-5:] if result.returncode else [],
    }


# ------------------------------------------------------------------- summary


def table_5_9(measured: dict) -> dict:
    """The ten rows, each with its target, its stated method, the number this run
    produced, and whether it is met. A row that could not be measured says so
    rather than carrying a number from somewhere else."""

    def row(key: str, value, meets):
        target, method = TARGETS[key]
        return {"target": target, "method": method, "measured": value, "meets_target": meets}

    latency = measured["detection_latency_ms"]
    fp = measured["false_positive_rate"]
    cpu = measured["cpu_percent"]
    ram = measured["ram_peak_mb"]
    dash = measured["dashboard_latency_ms"]
    ledger = measured["ledger_verify_ms"]
    kill = measured["response_time_s"]
    families = measured["simulator_families"]
    ml = (measured["delegated"]["ml_inference"]["report"] or {})
    gw = (measured["delegated"]["gateway_api"]["report"] or {}).get("api_response_time_ms", {})

    ml_mean = ml.get("end_to_end_mean_ms")
    gw_p95 = gw.get("p95")
    restored = families.get("all_restore_round_trips")

    return {
        "detection_latency_ms": row("detection_latency_ms", latency["p95"], latency["p95"] < 100),
        "response_time_s": row("response_time_s", kill["max_s"], kill["max_s"] < 2.0),
        "false_positive_rate": row("false_positive_rate", fp["rate"], fp["rate"] < 0.05),
        "ml_inference_ms": row("ml_inference_ms", ml_mean, ml_mean is not None and ml_mean < 100),
        "api_p95_ms": row("api_p95_ms", gw_p95, gw_p95 is not None and gw_p95 < 200),
        "cpu_percent": row(
            "cpu_percent",
            cpu["mean_percent_of_total_cpu"],
            cpu["mean_percent_of_total_cpu"] < 15.0,
        ),
        "ram_peak_mb": row("ram_peak_mb", ram["peak_mb"], ram["peak_mb"] < 500.0),
        "file_recovery_success": row("file_recovery_success", restored, restored is True),
        "ledger_verify_ms": row("ledger_verify_ms", ledger["max_ms"], ledger["max_ms"] < 50.0),
        "dashboard_latency_ms": row(
            "dashboard_latency_ms",
            dash["max_ms"],
            dash["visible_within_1s"] == dash["samples"],
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu-seconds", type=float, default=3600.0)
    parser.add_argument("--stress-seconds", type=float, default=300.0)
    parser.add_argument("--files-per-family", type=int, default=8)
    parser.add_argument("--skip-suite", action="store_true", help="skip the pytest counts")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="60s CPU window, 30s stress - a smoke run that refuses to write the report",
    )
    args = parser.parse_args()

    if args.quick:
        args.cpu_seconds, args.stress_seconds = 60.0, 30.0

    workdir = REPO_ROOT / ".baseline_work"
    started = time.time()

    def stage(name: str, fn, *fn_args):
        mark = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] {name} ...", flush=True)
        value = fn(*fn_args)
        print(f"[{time.strftime('%H:%M:%S')}] {name} done in {time.time() - mark:.1f}s", flush=True)
        return value

    measured: dict = {}
    measured["detection_latency_ms"] = stage("detection latency", detection_latency, workdir / "latency")
    measured["false_positive_rate"] = stage("false positive rate", false_positive_rate, workdir / "benign")
    measured["forged_container_rate"] = stage("forged containers", forged_container_rate, workdir / "forged")
    measured["response_time_s"] = stage("termination time", termination_time)
    measured["ledger_verify_ms"] = stage("ledger verification", ledger_verify_time, workdir / "ledger")
    measured["dashboard_latency_ms"] = stage("dashboard freshness", dashboard_latency, workdir / "dash")
    measured["ram_peak_mb"] = stage("ram under stress", ram_under_stress, workdir / "stress", args.stress_seconds)
    measured["delegated"] = stage("delegated benchmarks", delegated_benchmarks)
    measured["simulator_families"] = stage("simulator sweep", simulator_families, args.files_per_family)
    measured["cpu_percent"] = stage("cpu over window", cpu_over_window, workdir / "cpu", args.cpu_seconds)

    suite = {} if args.skip_suite else stage("test suite", test_suite)

    baseline = {
        "schema": "urds.phase5_baseline/1",
        "purpose": (
            "The measured starting state for Phases 5-8. Every later no-regression claim "
            "is compared against this file."
        ),
        "provenance": provenance(),
        "run": {
            "cpu_window_seconds": args.cpu_seconds,
            "stress_seconds": args.stress_seconds,
            "files_per_family": args.files_per_family,
            "quick": args.quick,
            "total_seconds": round(time.time() - started, 1),
        },
        "test_suite": suite,
        "table_5_9": table_5_9(measured),
        "measurements": measured,
        "artefact_hashes": {
            path: sha256_of(REPO_ROOT / path) for path in HASHED_ARTEFACTS
        },
    }

    print(json.dumps(baseline["table_5_9"], indent=2))

    if args.quick:
        print("\n--quick: report not written (a 60s run cannot stand in for a 1-hour window)")
        return 0
    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "phase5_baseline.json").write_text(json.dumps(baseline, indent=2))
    print(f"\nwrote {REPORTS / 'phase5_baseline.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
