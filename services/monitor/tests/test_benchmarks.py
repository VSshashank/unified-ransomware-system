"""Numeric targets for the Monitor - detection latency, false positives, CPU.

Each test asserts the spec target and prints the measured value, so a run of
`pytest -m benchmark -s` is the evidence for the status report. Measurements are
also written to reports/as_benchmarks.json.
"""

import io
import json
import os
import gzip
import time
import zipfile
from pathlib import Path

import psutil
import pytest
from fastapi.testclient import TestClient

import app as monitor_app
from detection import calculate_entropy, classify, read_magic

REPORTS = Path(__file__).resolve().parents[3] / "reports"
MEASUREMENTS: dict = {}

DETECTION_LATENCY_TARGET_MS = 100.0
FALSE_POSITIVE_TARGET = 0.05
CPU_TARGET_PERCENT = 15.0
# Table 5.8 TC-08 pairs this with the CPU target; Table 5.9 defines it as peak
# memory during a stress test, which is what the test below measures.
MEMORY_TARGET_MB = 500.0


@pytest.fixture(scope="module", autouse=True)
def write_measurements():
    """Merge, do not overwrite.

    as_benchmarks.json is AS's evidence file and two suites write to it: this
    one and services/response/tests/test_actions.py, which contributes
    process_kill_time_s. This used to replace the whole file, so running the
    Monitor benchmarks on their own silently deleted the Response measurement.
    It only looked harmless because the documented run order puts monitor before
    response, which rewrote its key afterwards.
    """
    yield
    REPORTS.mkdir(exist_ok=True)
    path = REPORTS / "as_benchmarks.json"
    existing = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except (OSError, ValueError):
            existing = {}
    existing.update(MEASUREMENTS)
    path.write_text(json.dumps(existing, indent=2))


# ------------------------------------------------------- detection latency


@pytest.mark.benchmark
def test_detection_latency_under_100ms(tmp_path):
    """Time from a file event arriving to a verdict existing. Target: <100ms."""
    sizes = [4 * 1024, 64 * 1024, 512 * 1024, 2 * 1024 * 1024]
    samples = []

    for index, size in enumerate(sizes):
        for repeat in range(10):
            target = tmp_path / f"sample_{index}_{repeat}.bin"
            target.write_bytes(os.urandom(size))
            event = monitor_app.handle_event(str(target), "created")
            assert event is not None
            samples.append(event["detection_latency_ms"])

    samples.sort()
    mean = sum(samples) / len(samples)
    p95 = samples[int(len(samples) * 0.95) - 1]
    worst = samples[-1]

    MEASUREMENTS["detection_latency_ms"] = {
        "samples": len(samples),
        "mean": round(mean, 3),
        "p95": round(p95, 3),
        "max": round(worst, 3),
        "target": DETECTION_LATENCY_TARGET_MS,
    }
    print(f"\ndetection latency: mean={mean:.2f}ms p95={p95:.2f}ms max={worst:.2f}ms (target <100ms)")

    assert p95 < DETECTION_LATENCY_TARGET_MS, f"p95 detection latency {p95:.2f}ms exceeds 100ms"


# ------------------------------------------------------- false positive rate


def _benign_corpus(root: Path) -> list[Path]:
    """Legitimate files a normal user has, including high-entropy ones."""
    files = []

    for index in range(8):
        path = root / f"notes_{index}.txt"
        path.write_text(f"quarterly report section {index}\n" * 400)
        files.append(path)

    for index in range(6):
        path = root / f"archive_{index}.zip"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("data.bin", os.urandom(120000))
        path.write_bytes(buffer.getvalue())
        files.append(path)

    for index in range(6):
        path = root / f"backup_{index}.gz"
        path.write_bytes(gzip.compress(os.urandom(120000)))
        files.append(path)

    for index in range(6):
        path = root / f"photo_{index}.png"
        path.write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(120000))
        files.append(path)

    for index in range(6):
        path = root / f"scan_{index}.jpg"
        path.write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(120000))
        files.append(path)

    for index in range(4):
        path = root / f"manual_{index}.pdf"
        path.write_bytes(b"%PDF-1.7\n" + os.urandom(80000))
        files.append(path)

    for index in range(4):
        path = root / f"clip_{index}.mp4"
        path.write_bytes(b"\x00\x00\x00\x18ftypmp42" + os.urandom(120000))
        files.append(path)

    return files


@pytest.mark.benchmark
def test_false_positive_rate_under_5_percent(tmp_path):
    """Legitimate files - most of them deliberately high entropy - must not be
    flagged. This is the check raw entropy alone fails."""
    files = _benign_corpus(tmp_path)
    false_positives = []

    for path in files:
        entropy = calculate_entropy(str(path))
        verdict = classify(str(path), entropy, read_magic(str(path)))
        if verdict["suspicious"]:
            false_positives.append((path.name, entropy, verdict["verdict"]))

    rate = len(false_positives) / len(files)
    high_entropy = sum(1 for p in files if calculate_entropy(str(p)) >= 7.5)

    MEASUREMENTS["false_positive_rate"] = {
        "corpus_size": len(files),
        "high_entropy_in_corpus": high_entropy,
        "false_positives": len(false_positives),
        "rate": round(rate, 4),
        "target": FALSE_POSITIVE_TARGET,
        "offenders": false_positives,
    }
    print(
        f"\nfalse positives: {len(false_positives)}/{len(files)} = {rate:.1%} "
        f"({high_entropy} of the corpus is high-entropy) (target <5%)"
    )

    assert rate < FALSE_POSITIVE_TARGET, f"false positive rate {rate:.1%} exceeds 5%: {false_positives}"


@pytest.mark.benchmark
def test_true_positive_rate_on_encrypted_corpus(tmp_path):
    """The mitigation must not be so lenient that it misses actual encryption."""
    detected = 0
    total = 30
    for index in range(total):
        path = tmp_path / f"victim_{index}.docx"
        path.write_bytes(os.urandom(120000))
        entropy = calculate_entropy(str(path))
        if classify(str(path), entropy, read_magic(str(path)))["suspicious"]:
            detected += 1

    rate = detected / total
    MEASUREMENTS["true_positive_rate"] = {"samples": total, "detected": detected, "rate": rate}
    print(f"\ntrue positives: {detected}/{total} = {rate:.1%}")

    assert rate == 1.0, f"missed {total - detected} encrypted files"


# --------------------------------------------------------------------- CPU


@pytest.mark.benchmark
def test_cpu_usage_under_15_percent_while_monitoring(tmp_path):
    """CPU attributable to this process while the watcher runs. Target: <15%."""
    process = psutil.Process()

    with TestClient(monitor_app.app) as client:
        client.post("/monitor/start", json={"watch_path": str(tmp_path), "recursive": True})

        process.cpu_percent(interval=None)  # prime the counter
        started = time.time()
        written = 0

        # A steady, realistic write load for the sampling window.
        while time.time() - started < 5.0:
            target = tmp_path / f"load_{written}.bin"
            target.write_bytes(os.urandom(32768))
            written += 1
            time.sleep(0.05)

        cpu = process.cpu_percent(interval=None)
        normalised = cpu / (psutil.cpu_count() or 1)
        client.post("/monitor/stop")

    MEASUREMENTS["cpu_percent"] = {
        "files_written": written,
        "raw_percent_of_one_core": round(cpu, 2),
        "percent_of_total_cpu": round(normalised, 2),
        "cores": psutil.cpu_count(),
        "target": CPU_TARGET_PERCENT,
    }
    print(
        f"\ncpu while monitoring {written} writes over 5s: {cpu:.1f}% of one core, "
        f"{normalised:.1f}% of {psutil.cpu_count()} cores (target <15%)"
    )

    assert normalised < CPU_TARGET_PERCENT, f"CPU {normalised:.1f}% exceeds 15%"


# ------------------------------------------------------------------ memory


@pytest.mark.benchmark
def test_memory_usage_under_500mb_during_stress(tmp_path):
    """TC-08's other half. Target: peak RSS <500MB during a stress test.

    Stressed deliberately harder than the CPU test: larger files and no sleep,
    so the entropy reader and the bounded event buffer are both under pressure.
    A leak in either - the buffer used to grow without limit - shows up here as
    RSS that climbs with the file count instead of levelling off.
    """
    process = psutil.Process()
    baseline_mb = process.memory_info().rss / (1024 * 1024)
    peak_mb = baseline_mb

    with TestClient(monitor_app.app) as client:
        client.post("/monitor/start", json={"watch_path": str(tmp_path), "recursive": True})

        written = 0
        started = time.time()
        while time.time() - started < 5.0:
            target = tmp_path / f"stress_{written}.bin"
            target.write_bytes(os.urandom(512 * 1024))
            monitor_app.handle_event(str(target), "created")
            written += 1
            peak_mb = max(peak_mb, process.memory_info().rss / (1024 * 1024))

        client.post("/monitor/stop")

    MEASUREMENTS["memory_mb"] = {
        "files_processed": written,
        "baseline_mb": round(baseline_mb, 2),
        "peak_mb": round(peak_mb, 2),
        "growth_mb": round(peak_mb - baseline_mb, 2),
        "target": MEMORY_TARGET_MB,
    }
    print(
        f"\nmemory over {written} x 512KB events: baseline {baseline_mb:.1f}MB, "
        f"peak {peak_mb:.1f}MB (+{peak_mb - baseline_mb:.1f}MB) (target <500MB)"
    )

    assert peak_mb < MEMORY_TARGET_MB, f"peak RSS {peak_mb:.1f}MB exceeds 500MB"
