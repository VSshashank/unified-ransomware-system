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
import ransomware_simulator
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
            # The simulator reports the name now on disk, so this works for every
            # family rather than only the ones that append a known extension.
            written = tmp_path / name
            if not written.exists():
                continue
            entropy = calculate_entropy(str(written))
            verdict = classify(str(written), entropy, read_magic(str(written)))

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


# ------------------------------------------------- multiple simulator families
#
# Section 5.6.2 asks the system to detect "3+ different ransomware simulators".
# These are distinct behaviours, not distinct payloads: what differs is the shape
# of what the watcher sees, which is what a detector either handles or does not.
#
# The simulator imitates thirteen families in total; section 6.4.1's full sweep
# of all of them, against a live observer, is TC-13 in
# test_tc13_simulator_families.py. The
# subset here is the 5.6.2 criterion and is classified without an observer, so it
# deliberately exercises only the families that need no entropy history.


def run_family(tmp_path, family: str, files: int = 6) -> list[dict]:
    """Run one family end to end and classify everything it left behind."""
    subprocess.run(
        [sys.executable, str(SIMULATOR), "--target-dir", str(tmp_path), "--files", str(files),
         "--delay-ms", "0", "--family", family],
        check=True, capture_output=True, text=True, timeout=120,
    )
    events = []
    for path in sorted(tmp_path.iterdir()):
        if path.name.startswith(".") or not path.is_file():
            continue
        event = monitor_app.handle_event(str(path), "modified")
        if event is not None:
            events.append(event)
    return events


@pytest.mark.parametrize("family", ["locker", "silent", "copycat"])
def test_every_detected_family_is_caught_on_every_file(tmp_path, family):
    """Three distinct families, all caught. This is the 5.6.2 criterion.

    locker  - rewrite in place, append .locked (entropy and extension both fire)
    silent  - rewrite in place, keep the name (no extension to help)
    copycat - write a new file, delete the original (created + deleted, not modified)
    """
    events = run_family(tmp_path, family)

    assert events, f"{family} produced no events"
    missed = [e["file_path"] for e in events if not e["suspicious"]]
    assert not missed, f"{family} was not detected on {len(missed)} file(s): {missed}"
    assert all(e["verdict"] == "suspected_encryption" for e in events)


def test_silent_family_is_caught_without_any_extension_signal(tmp_path):
    """The point of `silent`: entropy carries the decision alone.

    If this ever passes only because of a rename, the family has stopped
    testing what it exists to test.
    """
    events = run_family(tmp_path, "silent")

    assert events
    assert all(e["ransom_extension"] is False for e in events), "silent renamed something"
    assert all(e["suspicious"] for e in events)


@pytest.mark.parametrize("family", ["partial", "strider"])
def test_intermittent_encryption_is_caught_below_the_entropy_threshold(tmp_path, family):
    """This test used to assert the opposite, and said so on purpose.

    Intermittent encryption (LockBit 3, BlackCat) scrambles a fraction of each
    file, so whole-file entropy lands between the plaintext and ciphertext
    values - measured at ~5.2 bits/byte for `partial` and ~5.9 for `strider`,
    against a 7.5 threshold. An entropy *average* reads that as an ordinary
    edit, which is what it did: 0 of 8 flagged in the recorded sweep.

    What catches it is scoring 4KB blocks separately. The concern that kept this
    a blind spot was that a .docx or PDF carries compressed blocks with the same
    profile - which is true, and is why the rule is gated on the file not being
    a structurally valid container. Both halves are measured: the false-positive
    benchmark still reads 0/40, and both families are caught here on every file.
    """
    events = run_family(tmp_path, family)

    assert events, f"{family} produced no events"
    entropies = [e["entropy"] for e in events]
    mean_entropy = sum(entropies) / len(entropies)

    assert 4.0 < mean_entropy < 7.5, (
        f"{family}'s entropy is {mean_entropy}; this test only means something "
        "while whole-file entropy stays under the threshold"
    )
    missed = [e["file_path"] for e in events if not e["suspicious"]]
    assert not missed, f"{family} was missed on {len(missed)} file(s)"
    assert all(e["signal"] == "partial_entropy" for e in events), (
        f"caught, but not by the block profile: {sorted({e['signal'] for e in events})}"
    )


def test_grinder_cannot_flush_the_entropy_baseline(tmp_path):
    """D4: five sub-floor writes must not move the floor the rise is measured from.

    `grinder` rewrites the file five times at ~6.5 bits/byte before writing its
    ciphertext. Five is the size of the differential-entropy window, so those
    writes used to evict the document's own 4.65 reading and the rise was then
    measured from 6.5 - a delta of about 1.5, under the 2.0 threshold - after
    which a ZIP header over the ciphertext collected the container exemption as
    well. Six writes, both of Table 5.7's built mitigations.

    Driven write by write rather than through `run_family`, which only ever sees
    a family's finished output: the warm-up writes *are* the attack, and a
    detector that never saw them has nothing to be fooled by.

    Asserted on the entropy delta rather than on `suspicious`, because structural
    validation catches this file anyway. That is defence in depth working, and it
    is also exactly how a regression in the floor would hide.
    """
    monitor_app.ENTROPY_HISTORY.clear()
    target = tmp_path / "quarterly_report.docx"
    original = ransomware_simulator.MARKER + b"\n" + (b"decoy document 0 " * 2000)

    target.write_bytes(original)
    baseline = monitor_app.handle_event(str(target), "created")
    assert baseline["entropy"] < 5.0, "the document has to start at document entropy"

    for index in range(ransomware_simulator.GRINDER_WARMUP_WRITES):
        filler = ransomware_simulator.keystream(b"seed" + b"warmup" + bytes([index]), len(original))
        target.write_bytes(
            bytes(b % ransomware_simulator.GRINDER_WARMUP_ALPHABET + 32 for b in filler)
        )
        warmup = monitor_app.handle_event(str(target), "modified")
        assert warmup["suspicious"] is False, "a warm-up write must not alert on its own"

    target.write_bytes(ransomware_simulator.ZIP_MAGIC + ransomware_simulator._xor(original, b"seed"))
    final = monitor_app.handle_event(str(target), "modified")

    assert final["entropy_delta"] >= 2.0, (
        f"the baseline was flushed: rise of {final['entropy_delta']} measured "
        "against the warm-up writes rather than against the document"
    )
    assert final["signal"] == "entropy_rise"
    assert final["suspicious"] is True


@pytest.mark.parametrize("family", ["locker", "silent", "copycat", "partial"])
def test_every_family_round_trips_through_restore(tmp_path, family):
    """Reversibility is what makes any of these safe to run. All four, not just
    the default - a family that cannot be undone is not safe to ship."""
    subprocess.run(
        [sys.executable, str(SIMULATOR), "--target-dir", str(tmp_path), "--files", "4",
         "--delay-ms", "0", "--family", family],
        check=True, capture_output=True, text=True, timeout=120,
    )
    subprocess.run(
        [sys.executable, str(SIMULATOR), "--target-dir", str(tmp_path), "--restore"],
        check=True, capture_output=True, text=True, timeout=120,
    )

    restored = sorted(p for p in tmp_path.glob("quarterly_report_*") if p.is_file())
    assert len(restored) == 4, f"{family}: expected 4 restored files, got {len(restored)}"
    for path in restored:
        assert path.read_bytes().startswith(b"URDS-TC01-DECOY"), f"{family}: {path.name} did not round-trip"
    assert not list(tmp_path.glob("*.locked")), f"{family}: restore left .locked behind"
    assert not list(tmp_path.glob("*.enc")), f"{family}: restore left .enc behind"
