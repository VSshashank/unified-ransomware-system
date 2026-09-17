"""The second axis: velocity, canaries, the ladder, and the shadow-copy guard.

These run without elevation and without suspending anything real. The decision
logic is what is under test - which signals fire, which corroborate, and what
the ladder does with two of them versus one - because that logic is what stands
between a suspended build and a killed one.
"""

from __future__ import annotations

import os
import sys
import time
import zipfile
from collections import Counter
from math import log2
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import agent as agent_module  # noqa: E402
from agent import config as agent_config  # noqa: E402
from agent import procmon  # noqa: E402
from agent.ledger import DirectLedger  # noqa: E402
from agent.canary import CanaryField  # noqa: E402
from agent.velocity import VelocityTracker  # noqa: E402


def _config(tmp_path, **overrides):
    payload = {
        "protected_paths": [str(tmp_path / "protected")],
        "data_dir": str(tmp_path / "data"),
    }
    payload.update(overrides)
    (tmp_path / "protected").mkdir(exist_ok=True)
    return agent_config.from_mapping(payload)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((n / total) * log2(n / total) for n in counts.values())


# ---------------------------------------------------------------- velocity

def test_an_unattributed_write_is_not_attributed_to_anyone():
    """A shared "unknown" bucket would invent a velocity signal out of nothing.

    Every unattributed write on the host would pool into one apparent process,
    and ordinary background activity would cross the threshold on its own.
    """
    tracker = VelocityTracker()
    for i in range(50):
        tracker.record(None, f"/docs/f{i}.txt", at=100.0 + i * 0.01)
    assert tracker.tracked_pids() == []


def test_extension_appending_counts_as_churn():
    """report.docx -> report.docx.locked, which is what families actually do."""
    tracker = VelocityTracker()
    for i in range(4):
        tracker.record(7, f"/d/r{i}.docx", at=100.0 + i * 0.01)
    for i in range(4):
        tracker.record(7, f"/d/r{i}.docx.locked", at=100.1 + i * 0.01)
    signals = tracker.signals(7, now=100.2)
    assert signals.extension_churn == 4
    assert "extension_churn" in signals.fired


def test_extension_replacement_counts_as_churn():
    """report.docx -> report.locked."""
    tracker = VelocityTracker()
    for i in range(4):
        tracker.record(7, f"/d/r{i}.docx", at=100.0 + i * 0.01)
    for i in range(4):
        tracker.record(7, f"/d/r{i}.locked", at=100.1 + i * 0.01)
    signals = tracker.signals(7, now=100.2)
    assert signals.extension_churn == 4


def test_ordinary_saving_is_not_churn():
    """Saving the same file repeatedly must not look like a rename campaign."""
    tracker = VelocityTracker()
    for i in range(8):
        tracker.record(7, "/d/report.docx", at=100.0 + i * 0.5)
    signals = tracker.signals(7, now=104.0)
    assert signals.extension_churn == 0
    assert "extension_churn" not in signals.fired


def test_entropy_delta_fires_against_the_ledgers_baseline():
    tracker = VelocityTracker()
    tracker.record(7, "/d/a.docx", entropy=7.99, baseline_entropy=4.1, at=100.0)
    signals = tracker.signals(7, now=100.1)
    assert signals.max_entropy_delta == pytest.approx(3.89, abs=1e-6)
    assert "entropy_delta" in signals.fired


def test_no_baseline_means_no_entropy_delta_signal():
    """An unknown reference is not a zero reference."""
    tracker = VelocityTracker()
    tracker.record(7, "/d/a.docx", entropy=7.99, baseline_entropy=None, at=100.0)
    signals = tracker.signals(7, now=100.1)
    assert signals.max_entropy_delta is None
    assert "entropy_delta" not in signals.fired


def test_directory_fanout_fires_on_breadth():
    tracker = VelocityTracker(fanout_threshold=3)
    for i in range(6):
        tracker.record(7, f"/d/sub{i}/a.docx", at=100.0 + i * 0.01)
    assert "directory_fanout" in tracker.signals(7, now=100.1).fired


def test_writes_outside_the_window_are_forgotten():
    tracker = VelocityTracker(window_s=10.0)
    for i in range(30):
        tracker.record(7, f"/d/f{i}.docx", at=100.0 + i)
    signals = tracker.signals(7, now=130.0)
    assert signals.writes <= 11, "the window is not being trimmed"


def test_a_fast_burst_of_a_few_files_is_not_a_velocity_signal():
    """Three files written in the same millisecond is an application saving.

    A document, its index and its temp file go out together. Dividing three by
    a sub-millisecond span gives thousands per second, which is arithmetic
    rather than evidence - so the rate term is floored on both the span and the
    count.
    """
    tracker = VelocityTracker(window_s=10.0, path_threshold=12)
    for i in range(3):
        tracker.record(9, f"/d/save{i}.tmp", at=100.0 + i * 0.0001)
    assert "path_velocity" not in tracker.signals(9, now=100.01).fired


def test_a_genuine_burst_still_fires():
    """Twenty files in half a second is not an application saving."""
    tracker = VelocityTracker(window_s=10.0, path_threshold=12)
    for i in range(20):
        tracker.record(9, f"/d/f{i}.locked", at=100.0 + i * 0.025)
    assert "path_velocity" in tracker.signals(9, now=100.6).fired


def test_a_single_slow_writer_trips_nothing():
    """One file every two seconds into one directory is a person working."""
    tracker = VelocityTracker(window_s=10.0, path_threshold=12, fanout_threshold=3)
    for i in range(5):
        tracker.record(7, f"/d/note{i}.txt", entropy=4.0,
                       baseline_entropy=4.0, at=100.0 + i * 2.0)
    assert tracker.signals(7, now=110.0).fired == ()


# ----------------------------------------------------------------- canaries

def test_canaries_are_valid_low_entropy_documents(tmp_path):
    field = CanaryField(_config(tmp_path, canaries_per_root=6))
    field.seed()
    for path in field.paths():
        assert zipfile.is_zipfile(path), f"{path} is not a valid package"
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            assert "[Content_Types].xml" in archive.namelist()
        data = Path(path).read_bytes()
        assert _entropy(data) < 7.0, (
            "a high-entropy canary is indistinguishable from an already "
            "encrypted file, and the detector would see twenty victims at boot")


def test_canaries_bracket_the_real_documents(tmp_path):
    """One decoy sorts before every real file and one sorts after every one.

    The naming is easy to get backwards - `~` is 0x7E and sorts *after* `z` -
    and getting it backwards puts the whole field at one end, leaving an
    ordinary forward traversal to reach every real document first.
    """
    config = _config(tmp_path, canaries_per_root=8)
    protected = Path(config.protected_paths[0])
    for name in ("annual_report.docx", "Budget 2026.xlsx", "0_agenda.docx",
                 "notes.txt", "zebra.docx", "Photo.jpg"):
        (protected / name).write_bytes(b"ordinary content\n" * 10)

    field = CanaryField(config)
    field.seed()

    listing = sorted(p.name for p in protected.iterdir())
    canaries = {n for n in listing if "urds_canary" in n}
    real = [n for n in listing if n not in canaries]

    assert listing[0] in canaries, "nothing sorts ahead of the real documents"
    assert listing[-1] in canaries, "nothing sorts behind the real documents"
    assert listing.index(real[0]) > 0
    assert listing.index(real[-1]) < len(listing) - 1


def test_seeding_is_idempotent(tmp_path):
    field = CanaryField(_config(tmp_path, canaries_per_root=4))
    first = field.seed()
    second = field.seed()
    assert len(first["created"]) == 4
    assert len(second["created"]) == 0
    assert len(second["existing"]) == 4


def test_a_write_to_a_canary_is_recorded_with_the_content_change(tmp_path):
    field = CanaryField(_config(tmp_path, canaries_per_root=2))
    field.seed()
    target = field.paths()[0]

    untouched = field.touched(target, pid=4242, image="x.exe")
    assert untouched is not None and untouched.changed is False

    Path(target).write_bytes(os.urandom(4096))
    rewritten = field.touched(target, pid=4242, image="x.exe")
    assert rewritten.changed is True
    assert field.hit_count(4242) == 2


def test_a_deleted_canary_is_a_hit_and_counts_as_changed(tmp_path):
    """The least ambiguous tripwire in the system, and it used to be skipped.

    A decoy that is gone cannot be hash-compared, which is true and beside the
    point. An attack that archives and unlinks rather than overwriting - `7z a
    -sdel`, or a loop around `openssl enc` - never writes a single byte to a
    decoy, so treating deletion as "not a hit" meant it walked through the
    whole field without setting anything off.
    """
    field = CanaryField(_config(tmp_path, canaries_per_root=2))
    field.seed()
    target = field.paths()[0]

    Path(target).unlink()
    hit = field.touched(target, pid=9624, image="7z.exe")

    assert hit is not None, "a deleted decoy must still be a hit"
    assert hit.deleted is True
    assert hit.changed is True, (
        "a file that is gone has certainly changed; recording it as unchanged "
        "makes the clearest possible hit the weakest kind")
    assert hit.as_dict()["deleted"] is True


def test_a_file_that_is_not_a_canary_is_not_a_hit(tmp_path):
    field = CanaryField(_config(tmp_path, canaries_per_root=2))
    field.seed()
    other = Path(field.config.protected_paths[0]) / "real.docx"
    other.write_bytes(b"content")
    assert field.is_canary(other) is False
    assert field.touched(str(other), 1, "x") is None


def test_the_canary_allowlist_is_empty_by_default(tmp_path):
    field = CanaryField(_config(tmp_path, canaries_per_root=2))
    assert field.allowlisted("C:\\Windows\\explorer.exe") is False
    assert field.allowlisted(None) is False


def test_canaries_survive_a_restart_via_the_manifest(tmp_path):
    config = _config(tmp_path, canaries_per_root=4)
    CanaryField(config).seed()
    reloaded = CanaryField(config)
    assert reloaded.load()["loaded"] == 4
    assert reloaded.is_canary(reloaded.paths()[0])


def test_removing_canaries_leaves_nothing_behind(tmp_path):
    config = _config(tmp_path, canaries_per_root=4)
    field = CanaryField(config)
    field.seed()
    protected = Path(config.protected_paths[0])
    assert len(list(protected.iterdir())) == 4
    field.remove()
    assert list(protected.iterdir()) == []


# --------------------------------------------------------- shadow-copy guard

@pytest.mark.parametrize("image,command,expected", [
    ("vssadmin.exe", r"vssadmin delete shadows /all /quiet", "vssadmin_delete_shadows"),
    ("vssadmin.exe", r"C:\Windows\System32\vssadmin.exe  Delete   Shadows /All", "vssadmin_delete_shadows"),
    ("wmic.exe", "wmic shadowcopy delete /nointeractive", "wmic_shadowcopy_delete"),
    ("wbadmin.exe", "wbadmin delete catalog -quiet", "wbadmin_delete_catalog"),
    ("bcdedit.exe", "bcdedit /set {default} recoveryenabled No", "bcdedit_disable_recovery"),
    ("cipher.exe", "cipher /w:C", "cipher_wipe_free_space"),
])
def test_the_destructive_commands_are_recognised(image, command, expected):
    found = procmon.classify(image, command)
    assert found is not None, f"{command!r} was not recognised"
    assert found.name == expected


@pytest.mark.parametrize("image,command", [
    ("vssadmin.exe", "vssadmin list shadows"),
    ("vssadmin.exe", "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10%"),
    ("wmic.exe", "wmic shadowcopy list brief"),
    ("wbadmin.exe", "wbadmin get status"),
    ("cipher.exe", "cipher /c somefile.txt"),
    ("notepad.exe", "notepad.exe shadows-delete-notes.txt"),
    ("python.exe", "python analyse.py --about 'delete shadows'"),
])
def test_ordinary_and_read_only_commands_are_not_recognised(image, command):
    assert procmon.classify(image, command) is None, (
        f"{command!r} must not be treated as an attempt to destroy recovery")


def test_a_command_line_merely_mentioning_the_words_does_not_match():
    """Otherwise this test file's own strings would trip the guard."""
    assert procmon.classify(
        "python.exe",
        "python -c \"print('vssadmin delete shadows')\"") is None


def test_the_guard_allowlist_is_empty_by_default(tmp_path):
    guard = procmon.ShadowCopyGuard(_config(tmp_path))
    assert guard.allowlisted("C:\\Windows\\System32\\vssadmin.exe") is False


def test_a_sighting_is_logged_even_when_nothing_can_be_suspended(tmp_path):
    guard = procmon.ShadowCopyGuard(_config(tmp_path), responder=None)
    sighting = guard.on_process(4242, "vssadmin.exe",
                                "vssadmin delete shadows /all /quiet", 111)
    assert sighting is not None
    assert sighting.action == "logged_only"
    assert sighting.parent_pid == 111
    assert "Shadow Copies" in sighting.why or "shadow" in sighting.why.lower()
    assert len(guard.recent()) == 1


def test_an_ordinary_process_creation_produces_no_sighting(tmp_path):
    guard = procmon.ShadowCopyGuard(_config(tmp_path))
    assert guard.on_process(1, "chrome.exe", "chrome.exe --type=renderer", 2) is None
    assert guard.recent() == []


# --------------------------------------------------------------- the ladder

def _responder(tmp_path, **kwargs):
    from agent.responder import Responder

    return Responder(_config(tmp_path), escalate=False, **kwargs)


def _suspicious(tmp_path, **overrides):
    event = {
        "event_id": "e1",
        "file_path": str(Path(tmp_path) / "protected" / "a.docx.locked"),
        "suspicious": True,
        "verdict": "suspected_encryption",
        "signal": "entropy_threshold",
        "entropy": 7.99,
        "process_id": 4242,
        "attribution_confidence": "certain",
    }
    event.update(overrides)
    return event


def test_the_entry_verdict_does_not_corroborate_itself(tmp_path):
    """The whole point of requiring two independent signals."""
    responder = _responder(tmp_path)
    evidence = responder._evidence(4242, "x.exe", _suspicious(tmp_path))
    assert evidence["entry_verdict"] == "suspected_encryption"
    assert evidence["corroborating_signals"] == []


def test_velocity_and_canary_together_corroborate(tmp_path):
    config = _config(tmp_path, canaries_per_root=2)
    field = CanaryField(config)
    field.seed()
    field.touched(field.paths()[0], 4242, "x.exe")

    tracker = VelocityTracker()
    for i in range(6):
        tracker.record(4242, f"/d/sub{i}/f.docx", entropy=7.9,
                       baseline_entropy=3.0)

    from agent.responder import Responder

    responder = Responder(config, velocity=tracker, canaries=field, escalate=False)
    signals = responder._evidence(4242, "x.exe", _suspicious(tmp_path))["corroborating_signals"]
    assert "canary" in signals
    assert len(signals) >= 2


def test_one_signal_alone_is_a_near_miss_and_resumes(tmp_path, monkeypatch):
    """A kill needs two. One resumes, and says exactly what it had."""
    # Spread over three seconds, so the rate term stays low and directory
    # fan-out is genuinely the only signal: six paths in 3s is 2/s against a
    # threshold of 12.
    #
    # Anchored to time.monotonic() rather than an arbitrary 100.0, because the
    # escalation reads signals() with no `now` and therefore at real monotonic
    # time. Writes stamped in some other epoch fall outside the window and the
    # test would pass for the wrong reason - no signals at all, rather than
    # exactly one.
    base = time.monotonic()
    tracker = VelocityTracker(fanout_threshold=3)
    for i in range(6):
        tracker.record(4242, f"/d/sub{i}/f.docx", at=base + i * 0.6)

    from agent.responder import Responder

    responder = Responder(_config(tmp_path), velocity=tracker, escalate=False)
    calls = {}
    monkeypatch.setattr(responder, "_snapshot", lambda: {"taken": False, "reason": "test"})
    monkeypatch.setattr(responder, "kill", lambda pid, why: calls.setdefault("kill", why))
    monkeypatch.setattr(responder, "resume", lambda pid, why: calls.setdefault("resume", why))

    record = responder._escalate(4242, "inc1", "x.exe", _suspicious(tmp_path))

    assert record["decision"] == "resume"
    assert "kill" not in calls
    assert "near miss" in calls["resume"]
    assert record["corroborating_signals"] == ["directory_fanout"]
    assert len(responder.near_misses) == 1


def test_two_signals_escalate_to_a_kill(tmp_path, monkeypatch):
    tracker = VelocityTracker(fanout_threshold=3)
    for i in range(6):
        tracker.record(4242, f"/d/sub{i}/f.docx", entropy=7.9, baseline_entropy=2.0)

    from agent.responder import Responder

    responder = Responder(_config(tmp_path), velocity=tracker, escalate=False)
    calls = {}
    monkeypatch.setattr(responder, "_snapshot", lambda: {"taken": True, "snapshot_id": "{x}"})
    monkeypatch.setattr(responder, "kill", lambda pid, why: calls.setdefault("kill", why))
    monkeypatch.setattr(responder, "resume", lambda pid, why: calls.setdefault("resume", why))

    record = responder._escalate(4242, "inc1", "x.exe", _suspicious(tmp_path))

    assert record["decision"] == "kill"
    assert "resume" not in calls
    assert len(record["corroborating_signals"]) >= 2
    assert record["snapshot"]["taken"] is True


def test_a_failed_escalation_still_resumes(tmp_path, monkeypatch):
    """A process must never stay frozen because the ladder raised."""
    from agent.responder import Responder

    responder = Responder(_config(tmp_path), escalate=False)
    calls = {}

    def boom():
        raise RuntimeError("snapshot subsystem exploded")

    monkeypatch.setattr(responder, "_snapshot", boom)
    monkeypatch.setattr(responder, "resume", lambda pid, why: calls.setdefault("resume", why))

    record = responder._escalate(4242, "inc1", "x.exe", _suspicious(tmp_path))

    assert record["decision"] == "resume_on_error"
    assert "snapshot subsystem exploded" in calls["resume"]


def test_a_snapshot_failure_does_not_block_the_decision(tmp_path, monkeypatch):
    """Losing the snapshot is bad; leaving the encryptor running is worse."""
    tracker = VelocityTracker(fanout_threshold=3)
    for i in range(6):
        tracker.record(4242, f"/d/sub{i}/f.docx", entropy=7.9, baseline_entropy=2.0)

    from agent.responder import Responder

    responder = Responder(_config(tmp_path), velocity=tracker, escalate=False)
    calls = {}
    monkeypatch.setattr(responder, "kill", lambda pid, why: calls.setdefault("kill", why))
    monkeypatch.setattr(responder, "resume", lambda pid, why: calls.setdefault("resume", why))
    # No VSS manager configured at all, which is the unelevated case.
    record = responder._escalate(4242, "inc1", "x.exe", _suspicious(tmp_path))

    assert record["snapshot"]["taken"] is False
    assert record["decision"] == "kill"


def test_a_canary_hit_without_certain_attribution_still_suspends_nothing(tmp_path):
    """The tripwire says something walked the directory, not which process."""
    responder = _responder(tmp_path)
    outcome = responder.respond(_suspicious(
        tmp_path, attribution_confidence="unknown", process_id=None,
        canary_hit=True))
    assert outcome.action == "isolate_and_log"
    assert outcome.suspended is False
    assert "canary" in outcome.reason.lower()


def test_two_behavioural_signals_alone_do_not_authorise_a_kill(tmp_path, monkeypatch):
    """The git-clone case, measured and then fixed.

    A clone into a protected folder fires path_velocity and directory_fanout
    together, and its objects are zlib-compressed so every one of them reads as
    suspected encryption. Under a rule of "any two signals" it would be killed.
    A compiler and an installer look the same. Speed is corroboration, never
    the discriminator.
    """
    base = time.monotonic()
    tracker = VelocityTracker(fanout_threshold=3, path_threshold=12)
    for i in range(20):
        # Many paths, many directories, and no baseline entropy anywhere -
        # which is exactly right, because a clone writes files that never
        # existed before and so have no known-good reading to fall from.
        tracker.record(4242, f"/repo/objects/{i:02d}/{i}.pack",
                       entropy=7.9, baseline_entropy=None, at=base + i * 0.02)

    from agent.responder import Responder

    responder = Responder(_config(tmp_path), velocity=tracker, escalate=False)
    calls = {}
    monkeypatch.setattr(responder, "_snapshot", lambda: {"taken": False, "reason": "test"})
    monkeypatch.setattr(responder, "kill", lambda pid, why: calls.setdefault("kill", why))
    monkeypatch.setattr(responder, "resume", lambda pid, why: calls.setdefault("resume", why))

    record = responder._escalate(4242, "inc1", "git.exe", _suspicious(tmp_path))

    assert len(record["corroborating_signals"]) >= 2, (
        "this test is only meaningful if both behavioural signals fired")
    assert record["discriminating_signals"] == []
    assert record["decision"] == "resume"
    assert "kill" not in calls
    assert "none of them discriminating" in calls["resume"]


def test_one_discriminating_signal_plus_one_behavioural_kills(tmp_path, monkeypatch):
    """The same speed, but now known-good content is being destroyed."""
    base = time.monotonic()
    tracker = VelocityTracker(fanout_threshold=3, path_threshold=12)
    for i in range(20):
        tracker.record(4242, f"/docs/{i:02d}/r{i}.docx",
                       entropy=7.9, baseline_entropy=3.1, at=base + i * 0.02)

    from agent.responder import Responder

    responder = Responder(_config(tmp_path), velocity=tracker, escalate=False)
    calls = {}
    monkeypatch.setattr(responder, "_snapshot", lambda: {"taken": True, "snapshot_id": "{x}"})
    monkeypatch.setattr(responder, "kill", lambda pid, why: calls.setdefault("kill", why))
    monkeypatch.setattr(responder, "resume", lambda pid, why: calls.setdefault("resume", why))

    record = responder._escalate(4242, "inc1", "x.exe", _suspicious(tmp_path))

    assert "entropy_delta" in record["discriminating_signals"]
    assert record["decision"] == "kill"
    assert "resume" not in calls


def test_a_config_with_a_utf8_bom_loads(tmp_path):
    """PowerShell 5.1 writes one, and install.ps1 writes this file with it.

    Read as plain utf-8 the BOM raises, the agent refuses to start, and the
    SCM reports only that the service stopped. That is how this was found.
    """
    import json as _json

    config_path = tmp_path / "agent.json"
    payload = {
        "protected_paths": [str(tmp_path / "protected")],
        "data_dir": str(tmp_path / "data"),
    }
    (tmp_path / "protected").mkdir()
    config_path.write_bytes(b"\xef\xbb\xbf" + _json.dumps(payload).encode("utf-8"))

    loaded = agent_config.load(config_path)
    assert loaded.protected_paths


def test_the_phase3_acceptance_artefact_agrees_with_its_own_verdict():
    """The acceptance artefact must not be able to claim more than it measured.

    This replaces a test that asserted the *previous* artefact - `result` was
    FAILED, both arms unsuspended, FEBR 40 - and which went red the moment that
    artefact was rewritten, in a commit whose message reported the suite green.
    See docs/CORRECTIONS.md correction 9.

    So this one does not pin a number. It pins the criterion, and it pins the
    relationship between the verdict and the runs behind it: a PASSED that any
    replicate contradicts is a failure of this test. The bounds are the two
    things that must never move, because moving either is how a failing phase
    becomes a passing one without anything being fixed.
    """
    import json as _json

    report = _json.loads(
        (ROOT / "reports" / "agent_phase3_acceptance.json").read_text(encoding="utf-8"))

    # The bounds. Not negotiable, and spelled out here so that changing them
    # means changing a test rather than editing a string in an artefact.
    assert "20 files" in report["criterion"]["attack"]
    assert "under 2 s" in report["criterion"]["attack"]

    arms = {arm["arm"].split()[0]: arm for arm in report["attack_arms"]}
    a2, a1 = arms["A2"], arms["A1"]

    # A verdict that the replicates do not support is the failure mode this
    # test exists for. Both directions: a PASSED nobody earned, and a FAILED
    # left in place after the runs stopped failing.
    within_files = int(a2["within_the_file_bound"].split()[0])
    within_time = int(a2["within_the_time_bound"].split()[0])
    replicates = a2["replicates"]
    assert replicates >= 3, (
        "the response's floor is a periodic timer about a second wide, so a "
        "single run measures one draw from a distribution wider than the bound")

    if report["result"] == "PASSED":
        assert within_files == replicates, (
            f"result is PASSED with {replicates - within_files} replicate(s) "
            f"outside the file bound")
        assert within_time == replicates
        assert a2["suspended_in"] == replicates
        assert a2["febr_files_encrypted_before_response"]["max"] <= 20
    else:
        assert within_files < replicates or within_time < replicates, (
            "result is FAILED but every replicate met both bounds")

    # A1 is not suspended and the artefact must keep saying so, with the reason
    # that was measured rather than either of the two that were guessed.
    assert a1["suspended"] is False
    assert a1["febr_files_encrypted_before_response"] == 500
    assert "encryptor_lifetime.json" in a1["why_it_is_missed"], (
        "A1's explanation must cite the lifetime measurement; the separability "
        "result and the -sdel claim were both the wrong reason")

    # The one harness change that helps the agent has to be measured, not
    # argued. Its absence would let a future run quietly depend on it.
    control = report["control_did_the_harness_change_do_this"]
    assert control["replicates"] >= 1, "the fixed-sleep control was not run"
    assert control["finding"]

    # A benign arm shorter than the audit delivery lag completes untouched
    # whatever the detector decided, so it cannot be quoted as specificity.
    ran = [arm for arm in report["benign_arms"] if arm.get("exit_code") is not None]
    assert ran, "no benign arm ran"
    for arm in ran:
        assert arm.get("suspended") is not True
        assert "outlived_the_delivery_lag" in arm, (
            f"{arm['arm']} does not record whether a response could have "
            f"reached it")


def test_a_removed_protected_root_drops_out_of_the_canary_manifest(tmp_path):
    """Changing protected_paths must not leave the old root's decoys counted.

    Otherwise the agent reports a field larger than the one that exists, which
    overstates the protection in place.
    """
    first = _config(tmp_path, canaries_per_root=4)
    field = CanaryField(first)
    field.seed()
    assert len(field.paths()) == 4

    second_root = tmp_path / "other"
    second_root.mkdir()
    second = agent_config.from_mapping({
        "protected_paths": [str(second_root)],
        "data_dir": str(tmp_path / "data"),
        "canaries_per_root": 4,
    })
    moved = CanaryField(second)
    moved.load()
    result = moved.seed()

    assert result["total"] == 4, "the old root's canaries are still counted"
    # paths() returns the manifest's keys, which are lowercased for
    # case-insensitive membership tests on Windows.
    assert all(str(second_root).lower() in path for path in moved.paths())


# ------------------------------------------- the baseline cache off the chain

class _CacheOnly:
    """Just enough of an Agent to exercise the two cache methods.

    A whole Agent needs the Monitor's app module, a watchdog observer and a
    Security-channel subscription. What is under test here is a dict and one
    query, and binding the unbound methods keeps the test hermetic without
    pretending the rest of the agent is present.
    """

    def __init__(self, ledger):
        self.ledger = ledger
        self._baseline_entropy = {}

    warm = agent_module.Agent._warm_baselines
    note = agent_module.Agent._note_block


def _ledger_with_baselines(tmp_path, entries):
    ledger = DirectLedger(tmp_path / "chain.db")
    for path, entropy in entries:
        ledger.chain.add_block("file_baseline",
                               {"file_path": path, "entropy": entropy})
    return ledger


def test_the_agent_never_reads_the_chain_to_find_a_baseline(tmp_path):
    """The single most expensive thing on the protection path, removed.

    `_baseline_for` used to query the chain on every cache miss, and every
    path the agent has not seen before is a miss. The filter has no index it
    can use - file_path lives inside the event_data JSON, so it is a LIKE with
    a leading wildcard - and it ran on a lane, on the one SQLite connection
    the fan-out thread was writing the next block through. Measured at 3300
    blocks it cost 4.4 ms against 2.5 ms for the whole of detection.
    """
    ledger = _ledger_with_baselines(tmp_path, [(r"C:\p\a.docx", 4.2)])
    stub = _CacheOnly(ledger)
    stub.warm()

    def explode(*args, **kwargs):
        raise AssertionError(
            "the protection path read the chain to answer a baseline lookup")

    ledger.chain.get_blocks = explode
    try:
        assert agent_module.Agent._baseline_for(stub, r"C:\p\a.docx") == 4.2
        assert agent_module.Agent._baseline_for(stub, r"C:\p\never.docx") is None
    finally:
        ledger.close()


def test_a_baseline_written_now_is_readable_without_a_query(tmp_path):
    """The agent is the process writing these. Reading them back was the long way."""
    ledger = _ledger_with_baselines(tmp_path, [])
    stub = _CacheOnly(ledger)
    stub.warm()
    assert agent_module.Agent._baseline_for(stub, r"C:\p\fresh.docx") is None

    stub.note("file_baseline", {"file_path": r"C:\p\fresh.docx", "entropy": 3.9})
    assert agent_module.Agent._baseline_for(stub, r"C:\p\fresh.docx") == 3.9
    ledger.close()


def test_warming_keeps_the_newest_reading_for_a_path(tmp_path):
    """Two baselines for one path: the later one is the one that counts.

    The query is newest-first, so an older block must not overwrite what a
    newer one already put in the cache. Getting this backwards would compare
    today's entropy against a reading from before the file was last rewritten.
    """
    ledger = _ledger_with_baselines(tmp_path, [
        (r"C:\p\twice.docx", 2.0),
        (r"C:\p\twice.docx", 6.5),
    ])
    stub = _CacheOnly(ledger)
    assert stub.warm() == 1
    assert agent_module.Agent._baseline_for(stub, r"C:\p\twice.docx") == 6.5
    ledger.close()


def test_a_baseline_lookup_is_case_insensitive_like_the_filesystem(tmp_path):
    ledger = _ledger_with_baselines(tmp_path, [(r"C:\Protected\Report.DOCX", 4.4)])
    stub = _CacheOnly(ledger)
    stub.warm()
    assert agent_module.Agent._baseline_for(stub, r"c:\protected\report.docx") == 4.4
    ledger.close()


def test_a_ledger_that_cannot_be_read_does_not_stop_the_agent_starting(tmp_path):
    """Starting without baselines is a weaker detector, not a dead one."""
    ledger = _ledger_with_baselines(tmp_path, [])

    def explode(*args, **kwargs):
        raise RuntimeError("chain unavailable")

    ledger.chain.get_blocks = explode
    stub = _CacheOnly(ledger)
    assert stub.warm() == 0
    assert agent_module.Agent._baseline_for(stub, r"C:\p\a.docx") is None
    ledger.close()


def test_a_failed_ledger_write_does_not_put_a_baseline_in_the_cache(tmp_path):
    """The cache must not claim a reading the chain does not hold.

    The hook runs from the transport after a block commits, so a write that
    raised never reaches it. That is the property under test: the agent's
    in-memory view of the chain cannot get ahead of the chain itself.
    """
    from agent import transport as transport_module

    ledger = _ledger_with_baselines(tmp_path, [])
    stub = _CacheOnly(ledger)
    seen = []

    class _Broken:
        class chain:
            @staticmethod
            def add_block(*args, **kwargs):
                raise RuntimeError("disk full")

    hop = transport_module.InProcessTransport(
        _Broken(), on_block=lambda kind, data: seen.append(kind))
    result = hop(None, "http://ledger", "/ledger/log", {
        "event_type": "file_baseline",
        "event_data": {"file_path": r"C:\p\lost.docx", "entropy": 4.0}})

    assert result is None
    assert seen == [], "the cache was told about a block that was never written"
    assert agent_module.Agent._baseline_for(stub, r"C:\p\lost.docx") is None
    ledger.close()
