"""Whitelist and training mode - Table 5.7's two remaining FP mitigations.

The tests that matter most here are the negative ones. A suppression mechanism
is easy to prove works; what has to be proved is that it *stops* working when
the file it is suppressing turns out to have been encrypted. Those are the
`_does_not_hide_` tests.
"""

import hashlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from suppression import TrainingMode, Whitelist  # noqa: E402


def verdict(
    name: str = "suspected_encryption",
    entropy: float = 7.99,
    delta: float | None = None,
    ransom_extension: bool = False,
) -> dict:
    return {
        "verdict": name,
        "entropy": entropy,
        "entropy_delta": delta,
        "ransom_extension": ransom_extension,
        "suspicious": name in {"suspected_encryption", "suspicious_extension"},
    }


# ------------------------------------------------------------------ whitelist


def test_whitelist_starts_empty_and_suppresses_nothing():
    whitelist = Whitelist()
    assert len(whitelist) == 0
    assert whitelist.match("/watch/report.docx", "ab" * 32, verdict()) is None


def test_path_rule_suppresses_a_matching_file():
    whitelist = Whitelist(paths=["/watch/backups/*.zip"])
    match = whitelist.match("/watch/backups/nightly.zip", None, verdict())
    assert match == {"rule": "path", "value": "/watch/backups/*.zip"}


def test_path_rule_ignores_a_file_outside_it():
    whitelist = Whitelist(paths=["/watch/backups/*.zip"])
    assert whitelist.match("/watch/documents/report.docx", None, verdict()) is None


def test_hash_rule_suppresses_exact_content():
    digest = hashlib.sha256(b"an approved payload").hexdigest()
    whitelist = Whitelist(hashes=[digest.upper()])
    match = whitelist.match("/watch/anywhere.bin", digest, verdict())
    assert match == {"rule": "hash", "value": digest}


def test_path_rule_does_not_hide_a_file_that_was_encrypted_in_place():
    """The safety property. An operator approving a location did not approve an
    encryptor writing into it, so replacement evidence overrides the rule."""
    whitelist = Whitelist(paths=["/watch/backups/*"])

    quiet = whitelist.match("/watch/backups/nightly.zip", None, verdict(delta=None))
    assert quiet is not None, "an ordinary event in an approved path is suppressed"

    replaced = whitelist.match(
        "/watch/backups/nightly.zip", None, verdict(entropy=7.99, delta=3.4)
    )
    assert replaced is None, "a large entropy rise must survive a path whitelist"


def test_hash_rule_survives_replacement_evidence_because_the_bytes_cannot_have_changed():
    digest = hashlib.sha256(b"an approved payload").hexdigest()
    whitelist = Whitelist(hashes=[digest])
    assert whitelist.match("/watch/x.bin", digest, verdict(delta=3.4)) is not None


def test_hash_rule_stops_matching_once_the_content_changes():
    approved = hashlib.sha256(b"original").hexdigest()
    encrypted = hashlib.sha256(b"ciphertext").hexdigest()
    whitelist = Whitelist(hashes=[approved])
    assert whitelist.match("/watch/x.bin", encrypted, verdict()) is None


def test_whitelist_round_trips_through_a_config_file(tmp_path):
    config = tmp_path / "whitelist.json"
    config.write_text('{"paths": ["/watch/*.zip"], "hashes": ["AB12"]}')
    whitelist = Whitelist.from_file(config)
    assert whitelist.to_dict() == {"paths": ["/watch/*.zip"], "hashes": ["ab12"]}


def test_unreadable_config_yields_an_empty_whitelist_not_a_permissive_one(tmp_path):
    config = tmp_path / "broken.json"
    config.write_text("{not json")
    assert len(Whitelist.from_file(config)) == 0


def test_missing_config_yields_an_empty_whitelist(tmp_path):
    assert len(Whitelist.from_file(tmp_path / "absent.json")) == 0


def test_replace_swaps_the_whole_list():
    whitelist = Whitelist(paths=["/a/*"], hashes=["ff"])
    whitelist.replace(["/b/*"], None)
    assert whitelist.to_dict() == {"paths": ["/b/*"], "hashes": []}


# -------------------------------------------------------------- training mode


def test_training_mode_is_idle_and_suppresses_nothing_until_started():
    training = TrainingMode()
    assert training.state == TrainingMode.IDLE
    assert training.match("/watch/a.docx", 6.0, verdict()) is None


def test_learning_records_extensions_and_directories():
    training = TrainingMode()
    training.start(duration_seconds=60)
    assert training.observe("/watch/docs/report.docx", 6.1, verdict("benign")) is True

    status = training.status()
    assert status["state"] == "learning"
    assert status["observed_events"] == 1
    assert status["learned_extensions"][".docx"]["entropy_ceiling"] == 6.1


def test_a_learned_pattern_is_suppressed_after_training_finishes():
    training = TrainingMode()
    training.start(duration_seconds=60)
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert training.state == TrainingMode.ACTIVE
    match = training.match("/watch/docs/other.docx", 6.0, verdict())
    assert match is not None and match["rule"] == "training_mode"


def test_training_mode_does_not_hide_encryption_of_a_learned_file_type():
    """The safety property. Learning that .docx files reach 6.1 bits/byte must
    not teach the detector to ignore a .docx at 7.99."""
    training = TrainingMode()
    training.start(duration_seconds=60)
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert training.match("/watch/docs/report.docx", 7.99, verdict()) is None


def test_training_mode_does_not_suppress_an_unlearned_directory():
    training = TrainingMode()
    training.start(duration_seconds=60)
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert training.match("/watch/elsewhere/report.docx", 6.0, verdict()) is None


def test_training_mode_does_not_suppress_a_ransom_extension():
    training = TrainingMode()
    training.start(duration_seconds=60)
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert (
        training.match("/watch/docs/report.locked", 5.0, verdict(ransom_extension=True))
        is None
    )


def test_training_mode_does_not_suppress_a_differential_entropy_rise():
    training = TrainingMode()
    training.start(duration_seconds=60)
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert training.match("/watch/docs/report.docx", 6.0, verdict(delta=2.5)) is None


def test_an_attack_running_during_training_is_refused_from_the_baseline():
    """Otherwise the one genuinely dangerous failure mode: start training while
    an encryptor is already working, and the attack becomes the baseline."""
    training = TrainingMode()
    training.start(duration_seconds=60)

    assert training.observe("/watch/docs/report.docx", 7.99, verdict(delta=3.4)) is False
    assert training.observe("/watch/docs/note.locked", 7.99, verdict(ransom_extension=True)) is False
    assert training.status()["observed_events"] == 0


def test_a_training_window_that_learned_nothing_returns_to_idle():
    training = TrainingMode()
    training.start(duration_seconds=60)
    training.finish()
    assert training.state == TrainingMode.IDLE


def test_training_window_expires_on_its_own():
    training = TrainingMode()
    training.start(duration_seconds=0.01)
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    # No sleep: the deadline is checked against the clock on every read, and
    # 0.01s has passed by the time the assertion runs.
    import time as _time

    _time.sleep(0.05)
    assert training.state == TrainingMode.ACTIVE


def test_reset_clears_the_baseline():
    training = TrainingMode()
    training.start(duration_seconds=60)
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()
    training.reset()

    assert training.state == TrainingMode.IDLE
    assert training.status()["learned_extensions"] == {}


def test_observe_ignores_events_with_no_entropy_reading():
    training = TrainingMode()
    training.start(duration_seconds=60)
    assert training.observe("/watch/locked.docx", None, verdict("unreadable")) is False


@pytest.mark.skipif(os.name != "nt", reason="path normalisation is case-insensitive on Windows only")
def test_windows_paths_match_case_insensitively():
    whitelist = Whitelist(paths=[r"C:\Watch\Backups\*.zip"])
    assert whitelist.match(r"c:\watch\backups\nightly.zip", None, verdict()) is not None
