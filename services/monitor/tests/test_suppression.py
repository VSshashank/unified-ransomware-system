"""Whitelist and training mode - Table 5.7's two remaining FP mitigations.

The tests that matter most here are the negative ones. A suppression mechanism
is easy to prove works; what has to be proved is that it *stops* working when
the file it is suppressing turns out to have been encrypted. Those are the
`_does_not_hide_` tests.

Two of them now assert through `admissibility.adjudicate` rather than through
`match` alone. That is where the decision moved: `match` answers "does this rule
describe this file", and adjudication answers "is this rule expensive enough to
fake to be allowed to cancel *this* detection". Asserting on `match` returning
None would now be asserting on the wrong half, and would pass while the
end-to-end property broke.
"""

import hashlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from admissibility import adjudicate  # noqa: E402
from suppression import TrainingMode, Whitelist  # noqa: E402


def verdict(
    name: str = "suspected_encryption",
    entropy: float = 7.99,
    delta: float | None = None,
    ransom_extension: bool = False,
    signal: str | None = None,
    container_format: str | None = None,
    container_valid: bool | None = None,
) -> dict:
    suspicious = name in {"suspected_encryption", "suspicious_extension"}
    if signal is None and suspicious:
        # What classify() would have set: a rise if there was one, otherwise the
        # static threshold. Spelled out so a test that cares can override it.
        signal = "entropy_rise" if (delta or 0) >= 2.0 else "static_entropy"
    return {
        "verdict": name,
        "entropy": entropy,
        "entropy_delta": delta,
        "ransom_extension": ransom_extension,
        "suspicious": suspicious,
        "signal": signal,
        "container_format": container_format,
        "container_valid": container_valid,
    }


def cancels(verdict_dict: dict, rule: dict | None) -> bool:
    """Does this matched rule actually remove the alert?"""
    decision = adjudicate(verdict_dict, rule)
    return bool(decision and decision["admitted"])


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
    encryptor writing into it, so replacement evidence outranks the rule."""
    whitelist = Whitelist(paths=["/watch/backups/*"])

    quiet = verdict(delta=None)
    assert cancels(quiet, whitelist.match("/watch/backups/nightly.zip", None, quiet)), (
        "an ordinary event in an approved path is suppressed"
    )

    replaced = verdict(entropy=7.99, delta=3.4)
    assert not cancels(replaced, whitelist.match("/watch/backups/nightly.zip", None, replaced)), (
        "a large entropy rise must survive a path whitelist"
    )


def test_an_outranked_path_rule_is_recorded_rather_than_dropped():
    """A rule an operator wrote and that then did nothing has to say so.

    The old implementation returned None here, which is indistinguishable on the
    event from "no rule matched" - so an operator whose whitelist was being
    overridden had no way to see it.
    """
    whitelist = Whitelist(paths=["/watch/backups/*"])
    replaced = verdict(entropy=7.99, delta=3.4)

    decision = adjudicate(replaced, whitelist.match("/watch/backups/nightly.zip", None, replaced))

    assert decision["rule"] == "path"
    assert decision["admitted"] is False
    assert decision["outcome"] == "attenuated"
    assert decision["forgery_cost"] == "low"
    assert decision["avoidance_cost"] == "moderate"


def test_hash_rule_survives_replacement_evidence_because_the_bytes_cannot_have_changed():
    digest = hashlib.sha256(b"an approved payload").hexdigest()
    whitelist = Whitelist(hashes=[digest])
    rose = verdict(delta=3.4)
    assert cancels(rose, whitelist.match("/watch/x.bin", digest, rose))


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


def learning(dwell: float = 0.0) -> TrainingMode:
    """A training window that is already learning.

    `dwell` defaults to 0 here because most of these tests are about what the
    baseline learns, not about how long a file has to persist first. The dwell
    requirement has its own tests below, and they set it explicitly.
    """
    training = TrainingMode(dwell_seconds=dwell)
    training.start(duration_seconds=60)
    return training


def test_training_mode_is_idle_and_suppresses_nothing_until_started():
    training = TrainingMode()
    assert training.state == TrainingMode.IDLE
    assert training.match("/watch/a.docx", 6.0, verdict()) is None


def test_learning_records_extensions_and_directories():
    training = learning()
    assert training.observe("/watch/docs/report.docx", 6.1, verdict("benign")) is True

    status = training.status()
    assert status["state"] == "learning"
    assert status["observed_events"] == 1
    assert status["learned_extensions"][".docx"]["entropy_ceiling"] == 6.1


def test_a_learned_pattern_is_suppressed_after_training_finishes():
    training = learning()
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert training.state == TrainingMode.ACTIVE
    match = training.match("/watch/docs/other.docx", 6.0, verdict())
    assert match is not None and match["rule"] == "training_mode"


def test_training_mode_does_not_hide_encryption_of_a_learned_file_type():
    """The safety property. Learning that .docx files reach 6.1 bits/byte must
    not teach the detector to ignore a .docx at 7.99."""
    training = learning()
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert training.match("/watch/docs/report.docx", 7.99, verdict()) is None


def test_training_mode_does_not_suppress_an_unlearned_directory():
    training = learning()
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert training.match("/watch/elsewhere/report.docx", 6.0, verdict()) is None


def test_training_mode_does_not_suppress_a_ransom_extension():
    training = learning()
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    assert (
        training.match("/watch/docs/report.locked", 5.0, verdict(ransom_extension=True))
        is None
    )


def test_training_mode_does_not_suppress_a_differential_entropy_rise():
    """Now decided by adjudication rather than by `match` refusing to answer.

    A learned ceiling costs an attacker one write to move; avoiding a
    differential-entropy rise costs them a file with no history. The rise wins,
    and the rule that lost is recorded on the event instead of vanishing.
    """
    training = learning()
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    rose = verdict(entropy=6.0, delta=2.5)
    assert not cancels(rose, training.match("/watch/docs/report.docx", 6.0, rose))


def test_training_mode_cannot_cancel_a_forged_container():
    """The case the hand-written rules missed.

    Nobody wrote a rule saying "a learned ceiling does not cover a file whose
    header is a forgery", because nobody had thought of forged headers when the
    ceiling was written. The cost comparison says it without being told:
    emitting a real archive costs an attacker an encoder, moving a ceiling costs
    them a write.
    """
    training = learning()
    training.observe("/watch/render/frame.rndr", 7.99, verdict("benign"))
    training.finish()

    forged = verdict(signal="structural_mismatch", container_format="zip", container_valid=False)
    assert not cancels(forged, training.match("/watch/render/frame.rndr", 7.5, forged))


def test_training_mode_cannot_cancel_intermittent_encryption():
    """The other case the hand-written rules missed, for the same reason."""
    training = learning()
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()

    partial = verdict(entropy=5.2, signal="partial_entropy")
    assert not cancels(partial, training.match("/watch/docs/report.docx", 5.2, partial))


def test_a_hash_rule_outranks_every_detection():
    """The other end of the scale, and the reason the scale is costs.

    A SHA-256 match is the most permissive suppression here and the only one an
    attacker cannot manufacture, so it is the only one allowed to cancel
    everything.
    """
    digest = hashlib.sha256(b"approved").hexdigest()
    whitelist = Whitelist(hashes=[digest])
    for signal in ("static_entropy", "entropy_rise", "structural_mismatch", "partial_entropy"):
        subject = verdict(signal=signal, delta=3.4)
        assert cancels(subject, whitelist.match("/watch/x.bin", digest, subject)), signal


def test_an_attack_running_during_training_is_refused_from_the_baseline():
    """Otherwise the one genuinely dangerous failure mode: start training while
    an encryptor is already working, and the attack becomes the baseline."""
    training = learning()

    assert training.observe("/watch/docs/report.docx", 7.99, verdict(delta=3.4)) is False
    assert training.observe("/watch/docs/note.locked", 7.99, verdict(ransom_extension=True)) is False
    assert training.status()["observed_events"] == 0


# ------------------------------------------------- poisoning the ceiling (D3)


def test_a_file_created_during_training_cannot_raise_a_ceiling_immediately():
    """The defect this class shipped with.

    `observe` refused events carrying an entropy rise, but a *created* file has
    no baseline to have risen from, so `entropy_delta` is None and there was
    nothing to refuse. Anyone able to write into the watched tree during a
    training window could write one file at 7.99 and lift the ceiling for that
    extension to 7.99 - after which real encryption at 7.98 was suppressed. The
    dwell requirement is what prices that.
    """
    training = TrainingMode(dwell_seconds=60)
    training.start(duration_seconds=60)

    assert training.observe("/watch/docs/poison.docx", 7.99, verdict("benign")) is True
    assert training.status()["learned_extensions"] == {}

    training.finish()
    assert training.state == TrainingMode.IDLE, "nothing dwelled, so nothing was learned"
    assert training.match("/watch/docs/victim.docx", 7.98, verdict()) is None


def test_a_file_that_has_dwelled_does_raise_a_ceiling():
    """The other half: the dwell must not stop the feature from working."""
    training = TrainingMode(dwell_seconds=0.05)
    training.start(duration_seconds=60)
    training.observe("/watch/render/frame.rndr", 7.9, verdict("benign"))

    import time as _time

    _time.sleep(0.08)
    training.finish()

    assert training.state == TrainingMode.ACTIVE
    assert training.match("/watch/render/other.rndr", 7.8, verdict()) is not None


def test_a_ceiling_learned_from_real_archives_does_not_cover_raw_ciphertext():
    """Structural class is part of the key, not just the extension.

    A poison file that *is* a real archive is indistinguishable from a
    legitimate one, so it can raise a ceiling. What it cannot do is spend that
    ceiling on a file with no container at all, which is what raw ciphertext is.
    """
    training = learning()
    training.observe(
        "/watch/docs/poison.docx",
        7.99,
        verdict("benign", container_format="zip", container_valid=True),
    )
    training.finish()

    plain = verdict()
    assert training.match("/watch/docs/victim.docx", 7.98, plain) is None

    archive = verdict(container_format="zip", container_valid=True)
    assert training.match("/watch/docs/victim.docx", 7.98, archive) is not None


def test_a_forged_container_never_enters_the_baseline():
    training = learning()
    forged = verdict("benign", container_format="png", container_valid=False)

    assert training.observe("/watch/img/fake.png", 7.99, forged) is False
    assert training.status()["observed_events"] == 0


def test_the_candidate_set_is_bounded_while_learning():
    """A training window over a busy tree must not grow an entry per file."""
    from suppression import MAX_CANDIDATE_PATHS

    training = learning()
    for index in range(MAX_CANDIDATE_PATHS * 3):
        training.observe(f"/watch/docs/file_{index}.docx", 5.0 + (index % 10) / 10, verdict("benign"))

    candidates = training._candidates[(".docx", "plain")]
    assert len(candidates) <= MAX_CANDIDATE_PATHS


def test_a_training_window_that_learned_nothing_returns_to_idle():
    training = learning()
    training.finish()
    assert training.state == TrainingMode.IDLE


def test_training_window_expires_on_its_own():
    training = TrainingMode(dwell_seconds=0.0)
    training.start(duration_seconds=0.01)
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    # No sleep before observing: the deadline is checked against the clock on
    # every read, and 0.01s has passed by the time the assertion runs.
    import time as _time

    _time.sleep(0.05)
    assert training.state == TrainingMode.ACTIVE


def test_reset_clears_the_baseline():
    training = learning()
    training.observe("/watch/docs/report.docx", 6.1, verdict("benign"))
    training.finish()
    training.reset()

    assert training.state == TrainingMode.IDLE
    assert training.status()["learned_extensions"] == {}


def test_observe_ignores_events_with_no_entropy_reading():
    training = learning()
    assert training.observe("/watch/locked.docx", None, verdict("unreadable")) is False



@pytest.mark.skipif(os.name != "nt", reason="path normalisation is case-insensitive on Windows only")
def test_windows_paths_match_case_insensitively():
    whitelist = Whitelist(paths=[r"C:\Watch\Backups\*.zip"])
    assert whitelist.match(r"c:\watch\backups\nightly.zip", None, verdict()) is not None
