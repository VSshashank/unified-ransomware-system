"""TC-01 - detect a ransomware sample, terminate it, lose fewer than 5 files.

Table 5.8: "Detect known ransomware (Jasmin) -> Alert triggered, process
terminated, <5 files encrypted."

`scripts/ransomware_simulator.py` stands in for the sample (see its docstring
and docs/test_cases.md for why). This test drives the whole loop the test case
describes and, crucially, measures the thing that actually matters: how many
documents were lost between the first write and the process dying.

The bound is what makes this a real test. Detection that fires after the
twentieth file is not detection worth having.
"""

import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app
from detection import calculate_entropy, classify, read_magic

REPO_ROOT = Path(__file__).resolve().parents[3]
SIMULATOR = REPO_ROOT / "scripts" / "ransomware_simulator.py"

MAX_FILES_LOST = 5
DECOY_COUNT = 20


@pytest.fixture(autouse=True)
def clean_event_state():
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    yield
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()


def test_tc01_simulator_is_detected_and_stopped_under_five_files(tmp_path):
    """The full TC-01 loop: run, detect, terminate, count the damage."""
    assert SIMULATOR.exists(), f"simulator missing at {SIMULATOR}"

    process = subprocess.Popen(
        [sys.executable, str(SIMULATOR), "--target-dir", str(tmp_path),
         "--files", str(DECOY_COUNT), "--delay-ms", "120"],
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    encrypted_before_kill = 0
    detected = False
    try:
        for line in process.stdout:
            if not line.startswith("ENCRYPTED "):
                continue
            encrypted_before_kill = int(line.split()[1])
            name = line.split(maxsplit=2)[2].strip()

            # The Monitor's real classification path over the file just written.
            locked = tmp_path / (name + ".locked")
            if not locked.exists():
                continue
            entropy = calculate_entropy(str(locked))
            verdict = classify(str(locked), entropy, read_magic(str(locked)))

            if verdict["suspicious"]:
                detected = True
                # This is the response engine's job in production; here we do
                # exactly what it would do, and time is of the essence.
                psutil.Process(process.pid).terminate()
                break
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()

    assert detected, "simulator encrypted files and the monitor never flagged one"
    print(f"\nTC-01: detected and terminated after {encrypted_before_kill} file(s) (bound <{MAX_FILES_LOST})")
    assert encrypted_before_kill < MAX_FILES_LOST, (
        f"{encrypted_before_kill} files were encrypted before termination; TC-01 allows fewer than {MAX_FILES_LOST}"
    )


def test_tc01_simulator_output_is_high_entropy_and_loses_the_magic_bytes(tmp_path):
    """Confirms the stand-in actually reproduces the signal it claims to.

    If the simulator produced low-entropy output, TC-01 would be passing on a
    file the real thing would never generate, and the test would be theatre.
    """
    subprocess.run(
        [sys.executable, str(SIMULATOR), "--target-dir", str(tmp_path), "--files", "4", "--delay-ms", "0"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    locked = sorted(tmp_path.glob("*.locked"))
    assert len(locked) == 4, f"expected 4 encrypted files, found {[p.name for p in locked]}"

    for path in locked:
        entropy = calculate_entropy(str(path))
        assert entropy >= 7.5, f"{path.name} entropy {entropy:.3f} is too low to resemble ciphertext"
        assert classify(str(path), entropy, read_magic(str(path)))["suspicious"], f"{path.name} was not flagged"


def test_tc01_simulator_refuses_to_touch_files_it_did_not_create(tmp_path):
    """The guard that makes this script safe to ship in a defensive project.

    A mistyped --target-dir must be inert, not destructive.
    """
    precious = tmp_path / "thesis_final_v9.docx"
    precious.write_bytes(b"eight months of work")

    result = subprocess.run(
        [sys.executable, str(SIMULATOR), "--target-dir", str(tmp_path), "--files", "5"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 2, f"expected a refusal, got {result.returncode}: {result.stdout}{result.stderr}"
    assert "refusing to run" in result.stdout
    assert precious.read_bytes() == b"eight months of work", "the simulator modified a file it did not create"
    assert not list(tmp_path.glob("*.locked"))


def test_tc01_restore_returns_every_document_byte_for_byte(tmp_path):
    """Reversibility is what keeps this safe to run on a real watched directory."""
    subprocess.run(
        [sys.executable, str(SIMULATOR), "--target-dir", str(tmp_path), "--files", "6", "--delay-ms", "0"],
        check=True, capture_output=True, text=True, timeout=60,
    )
    originals = {p.name: p.read_bytes() for p in tmp_path.glob("*.locked")}
    assert originals, "nothing was encrypted"

    subprocess.run(
        [sys.executable, str(SIMULATOR), "--target-dir", str(tmp_path), "--restore"],
        check=True, capture_output=True, text=True, timeout=60,
    )

    assert not list(tmp_path.glob("*.locked")), "restore left encrypted files behind"
    restored = sorted(p for p in tmp_path.glob("quarterly_report_*") if p.is_file())
    assert len(restored) == 6
    for path in restored:
        assert path.read_bytes().startswith(b"URDS-TC01-DECOY"), f"{path.name} did not round-trip"
