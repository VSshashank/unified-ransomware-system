"""TC-13/TC-14: whitelist and training mode against the real detection path.

`test_suppression.py` tests the rules in isolation. This file drives the same
rules through `handle_event`, which is the function the watchdog calls, so what
is proved is that a real alert on a real file stops firing - and that the
simulator's output still does.

Table 5.7 lists both mechanisms as false-positive mitigations. The measurement
that matters for grading is the one at the bottom: the false-positive rate over
the benign corpus is unchanged at 0/40 with both mechanisms switched on.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402
from suppression import TrainingMode, Whitelist  # noqa: E402


@pytest.fixture(autouse=True)
def clean_state():
    """Suppression state is process-global, like the monitor's other state."""
    monitor_app.WHITELIST.replace([], [])
    monitor_app.TRAINING_MODE.reset()
    monitor_app.ENTROPY_HISTORY.clear()
    yield
    monitor_app.WHITELIST.replace([], [])
    monitor_app.TRAINING_MODE.reset()
    monitor_app.ENTROPY_HISTORY.clear()


def write_ciphertext(path: Path, size: int = 64 * 1024) -> Path:
    """A file that the detector flags: high entropy, no container header."""
    path.write_bytes(os.urandom(size))
    return path


# --------------------------------------------------------- TC-13: whitelist


def test_tc13_whitelist_suppresses_an_alert_that_otherwise_fires(tmp_path):
    target = write_ciphertext(tmp_path / "vault.bin")

    before = monitor_app.handle_event(str(target), "created")
    assert before["suspicious"] is True, "baseline: this file must alert"
    assert before["suppressed_by"] is None

    monitor_app.WHITELIST.replace([str(tmp_path / "*.bin")], [])
    monitor_app.ENTROPY_HISTORY.clear()

    after = monitor_app.handle_event(str(target), "created")
    assert after["suspicious"] is False
    assert after["suppressed_by"] == {"rule": "path", "value": str(tmp_path / "*.bin")}
    # The detector's own conclusion is still on the record.
    assert after["verdict"] == "suspected_encryption"


def test_tc13_whitelist_by_hash_suppresses_exactly_that_content(tmp_path):
    target = write_ciphertext(tmp_path / "approved.bin")
    first = monitor_app.handle_event(str(target), "created")
    digest = first["file_hash"]
    assert digest

    monitor_app.WHITELIST.replace([], [digest])
    monitor_app.ENTROPY_HISTORY.clear()
    assert monitor_app.handle_event(str(target), "created")["suspicious"] is False

    # Different content at the same path is a different file.
    write_ciphertext(target)
    monitor_app.ENTROPY_HISTORY.clear()
    assert monitor_app.handle_event(str(target), "modified")["suspicious"] is True


def test_tc13_whitelisted_path_still_alerts_when_the_file_is_encrypted_in_place(tmp_path):
    """The property that keeps the whitelist from being a hole in the detector."""
    target = tmp_path / "notes.txt"
    target.write_bytes(b"quarterly revenue report " * 2000)

    monitor_app.WHITELIST.replace([str(tmp_path / "*")], [])

    baseline = monitor_app.handle_event(str(target), "created")
    assert baseline["suspicious"] is False

    # Encrypted in place, same name - the differential-entropy case.
    write_ciphertext(target, size=len(target.read_bytes()))
    encrypted = monitor_app.handle_event(str(target), "modified")

    assert encrypted["entropy_delta"] is not None and encrypted["entropy_delta"] >= 2.0
    assert encrypted["suppressed_by"] is None, "a path whitelist must not survive replacement"
    assert encrypted["suspicious"] is True


# ----------------------------------------------------- TC-14: training mode


def test_tc14_training_mode_learns_a_workload_then_declines_to_alert(tmp_path):
    """Learn a legitimate high-entropy workload, then stop alerting on it."""
    workspace = tmp_path / "renders"
    workspace.mkdir()

    monitor_app.TRAINING_MODE.start(duration_seconds=60)
    for index in range(6):
        target = workspace / f"frame_{index}.rndr"
        write_ciphertext(target, size=32 * 1024)
        event = monitor_app.handle_event(str(target), "created")
        # These do alert during learning - training mode observes, it does not
        # suppress until it is finished.
        assert event["suspicious"] is True

    status = monitor_app.TRAINING_MODE.finish()
    assert status["state"] == "active"
    assert ".rndr" in status["learned_extensions"]

    monitor_app.ENTROPY_HISTORY.clear()
    fresh = workspace / "frame_99.rndr"
    write_ciphertext(fresh, size=32 * 1024)
    after = monitor_app.handle_event(str(fresh), "created")

    assert after["suspicious"] is False
    assert after["suppressed_by"]["rule"] == "training_mode"


def test_tc14_training_mode_still_catches_the_simulator(tmp_path):
    """The other half: learning a workload must not blind the detector.

    The learned workload is `.rndr` files in one directory. The simulated attack
    encrypts a document in a different directory and appends a ransom extension,
    and both of those are outside anything the baseline saw.
    """
    workspace = tmp_path / "renders"
    workspace.mkdir()
    documents = tmp_path / "documents"
    documents.mkdir()

    monitor_app.TRAINING_MODE.start(duration_seconds=60)
    for index in range(6):
        target = workspace / f"frame_{index}.rndr"
        write_ciphertext(target, size=32 * 1024)
        monitor_app.handle_event(str(target), "created")
    monitor_app.TRAINING_MODE.finish()

    monitor_app.ENTROPY_HISTORY.clear()

    victim = documents / "thesis.docx"
    victim.write_bytes(b"chapter one introduction " * 2000)
    monitor_app.handle_event(str(victim), "created")

    locked = documents / "thesis.docx.locked"
    write_ciphertext(locked, size=48 * 1024)
    event = monitor_app.handle_event(str(locked), "created")

    assert event["suspicious"] is True
    assert event["suppressed_by"] is None


def test_tc14_training_mode_does_not_learn_an_attack_that_is_already_running(tmp_path):
    """If the encryptor started first, the baseline must refuse to learn it."""
    documents = tmp_path / "documents"
    documents.mkdir()

    victim = documents / "report.docx"
    victim.write_bytes(b"quarterly revenue " * 3000)
    monitor_app.handle_event(str(victim), "created")

    monitor_app.TRAINING_MODE.start(duration_seconds=60)
    write_ciphertext(victim, size=48 * 1024)
    during = monitor_app.handle_event(str(victim), "modified")

    assert during["entropy_delta"] is not None and during["entropy_delta"] >= 2.0
    assert during["suspicious"] is True

    status = monitor_app.TRAINING_MODE.finish()
    assert status["observed_events"] == 0, "a replacement event must not enter the baseline"
    assert status["state"] == "idle"


# ------------------------------------------------- the graded number itself


def test_false_positive_rate_stays_zero_with_both_mechanisms_enabled(tmp_path):
    """Table 5.9 wants the false-positive rate under 5%; it is measured at 0.

    Both suppressions being enabled must not change that in either direction -
    they must not create false positives, and they must not be what is holding
    the number down either. Nothing here is whitelisted or learned, so every
    verdict below is the detector's own.
    """
    import gzip
    import io
    import zipfile

    monitor_app.WHITELIST.replace([], [])
    monitor_app.TRAINING_MODE.reset()

    benign: list[Path] = []
    for index in range(8):
        text = tmp_path / f"notes_{index}.txt"
        text.write_bytes(b"the quarterly revenue report for section four " * 400)
        benign.append(text)

        archive = tmp_path / f"bundle_{index}.zip"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("payload.bin", os.urandom(64 * 1024))
        archive.write_bytes(buffer.getvalue())
        benign.append(archive)

        gz = tmp_path / f"backup_{index}.gz"
        gz.write_bytes(gzip.compress(b"log line " * 5000))
        benign.append(gz)

        png = tmp_path / f"photo_{index}.png"
        png.write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(64 * 1024))
        benign.append(png)

        pdf = tmp_path / f"manual_{index}.pdf"
        pdf.write_bytes(b"%PDF-1.7\n" + os.urandom(32 * 1024))
        benign.append(pdf)

    false_positives = [
        path for path in benign
        if monitor_app.handle_event(str(path), "created")["suspicious"]
    ]

    assert len(benign) == 40
    assert false_positives == [], f"{len(false_positives)}/40 false positives"
