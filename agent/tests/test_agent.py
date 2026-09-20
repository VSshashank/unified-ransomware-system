"""The agent's own regressions.

Everything here runs without elevation and without the Windows Service, which
is deliberate: the parts that decide whether to act on a process must be
testable on a machine that cannot act on one. The elevated end-to-end
measurement is `reports/agent_phase2_acceptance.json`.

The gating tests are the ones that matter. An agent that suspends the wrong
process, or a process outside its configured blast radius, is worse than no
agent, so each refusal has a test that fails if the refusal is ever relaxed.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import config as agent_config  # noqa: E402
from agent import imports  # noqa: E402


# ------------------------------------------------------------------ imports

def test_every_service_module_loads_from_the_service_that_owns_it():
    """The collision check. `app` exists in five services; this loads one."""
    loaded = imports.load_all()
    for name, module in loaded.items():
        owner = imports._OWNERS[name]
        expected = (imports.SERVICES / owner).resolve()
        actual = Path(module.__file__).resolve()
        assert actual.is_relative_to(expected), (
            f"{name} loaded from {actual}, not from {expected}")


def test_an_unlisted_module_is_refused():
    """An agent may not import a service module nobody vouched for."""
    with pytest.raises(imports.ServiceImportError):
        imports.load("models")


def test_the_monitor_app_is_the_one_that_loads():
    """`app` resolves to the Monitor's, not the gateway's or the ledger's."""
    app = imports.load("app")
    assert Path(app.__file__).parent.name == "monitor"
    assert hasattr(app, "handle_event"), "the measured detection path is missing"


# ------------------------------------------------------------------- config

def _base(tmp_path, **overrides):
    payload = {
        "protected_paths": [str(tmp_path / "protected")],
        "data_dir": str(tmp_path / "data"),
    }
    payload.update(overrides)
    return payload


def test_a_valid_config_loads(tmp_path):
    (tmp_path / "protected").mkdir()
    cfg = agent_config.from_mapping(_base(tmp_path))
    assert cfg.protects(tmp_path / "protected" / "a.docx")
    assert not cfg.protects(tmp_path / "elsewhere" / "a.docx")


def test_an_empty_protected_list_is_refused(tmp_path):
    """No roots means the agent watches nothing, not everything."""
    with pytest.raises(agent_config.ConfigError, match="non-empty"):
        agent_config.from_mapping(_base(tmp_path, protected_paths=[]))


@pytest.mark.skipif(os.name != "nt", reason="Windows system paths")
def test_protecting_the_windows_directory_is_refused(tmp_path):
    """The responder acts on writes inside a protected root. Never here."""
    system_root = os.getenv("SystemRoot", r"C:\Windows")
    with pytest.raises(agent_config.ConfigError, match="overlaps"):
        agent_config.from_mapping(_base(tmp_path, protected_paths=[system_root]))


def test_protecting_a_filesystem_root_is_refused(tmp_path):
    root = "C:\\" if os.name == "nt" else "/"
    with pytest.raises(agent_config.ConfigError, match="filesystem root|overlaps"):
        agent_config.from_mapping(_base(tmp_path, protected_paths=[root]))


def test_a_system_directory_is_refused_on_this_platform(tmp_path):
    """The refusal is not Windows-specific; the directory names are.

    Checked per-platform rather than with a Windows path on Linux, where
    ``Path(r"C:\\Program Files")`` is a one-component *relative* path and the
    assertion would pass or fail for reasons having nothing to do with the
    guard.
    """
    target = os.getenv("ProgramFiles", r"C:\Program Files") if os.name == "nt" else "/usr"
    with pytest.raises(agent_config.ConfigError, match="overlaps"):
        agent_config.from_mapping(_base(tmp_path, protected_paths=[target]))


def test_a_directory_containing_a_system_directory_is_refused(tmp_path):
    """Protecting a parent of the system directory is still protecting it."""
    if os.name == "nt":
        target = os.getenv("SystemDrive", "C:") + os.sep
        expected = "filesystem root|overlaps"
    else:
        target = "/"
        expected = "filesystem root|overlaps"
    with pytest.raises(agent_config.ConfigError, match=expected):
        agent_config.from_mapping(_base(tmp_path, protected_paths=[target]))


def test_the_shipped_default_config_is_valid_and_narrow():
    cfg = agent_config.load(agent_config.DEFAULT_CONFIG)
    assert cfg.protected_paths
    assert cfg.allowlist_images == (), (
        "the canary allowlist must ship empty; an allowlist with entries in it "
        "is one nobody has read")


# ------------------------------------------------------------------- ledger

def test_the_direct_ledger_chains_and_verifies(tmp_path):
    from agent.ledger import DirectLedger

    with DirectLedger(tmp_path / "ledger.db") as led:
        led.log_event("agent_started", {"host": "test"})
        led.log_event("file_event", {"file_path": "/x", "process_id": None})
        assert led.block_count() == 2
        assert led.verify_chain()["valid"] is True


def test_the_direct_ledger_keeps_the_services_integrity_rule(tmp_path):
    """`last_known_hash` must return the baseline, never the attacker's hash.

    This is the subtle rule in recovery/ledger_client.py: during an attack the
    newest hash on a path is the ciphertext's, and verifying a restored file
    against it passes only when recovery hands back the encrypted file. The
    agent reuses that code rather than reimplementing it, and this asserts the
    reuse actually happened.
    """
    from agent.ledger import DirectLedger

    clean = b"quarterly figures\n" * 10
    clean_hash = hashlib.sha256(clean).hexdigest()
    cipher_hash = hashlib.sha256(os.urandom(64)).hexdigest()

    with DirectLedger(tmp_path / "ledger.db") as led:
        led.log_event("file_baseline", {"file_path": "/x/r.docx", "file_hash": clean_hash})
        led.log_event("file_event", {"file_path": "/x/r.docx", "file_hash": cipher_hash})
        reference = led.last_known_hash("/x/r.docx")

    assert reference["file_hash"] == clean_hash
    assert reference["event_type"] == "file_baseline"


def test_an_unmapped_route_is_refused_rather_than_falling_back(tmp_path):
    from agent.ledger import DirectLedger, LedgerUnavailableError

    with DirectLedger(tmp_path / "ledger.db") as led:
        with pytest.raises(LedgerUnavailableError, match="not implemented"):
            led._request("DELETE", "/ledger/blocks/1")


# ---------------------------------------------------------------- responder

def _responder(tmp_path):
    from agent.responder import Responder

    (tmp_path / "protected").mkdir(exist_ok=True)
    return Responder(agent_config.from_mapping(_base(tmp_path)))


def _event(tmp_path, **overrides):
    event = {
        "event_id": "e1",
        "file_path": str(tmp_path / "protected" / "a.docx.locked"),
        "suspicious": True,
        "process_id": 999999,
        "attribution_confidence": "unknown",
        "attribution_reason": "no source",
    }
    event.update(overrides)
    return event


def test_an_unknown_attribution_suspends_nothing(tmp_path):
    outcome = _responder(tmp_path).respond(_event(tmp_path))
    assert outcome.action == "isolate_and_log"
    assert outcome.suspended is False


def test_a_probable_attribution_suspends_nothing(tmp_path):
    """PROBABLE is not kill-authorising, and it is not suspend-authorising."""
    outcome = _responder(tmp_path).respond(
        _event(tmp_path, attribution_confidence="probable"))
    assert outcome.action == "isolate_and_log"
    assert outcome.suspended is False


def test_a_path_outside_every_protected_root_is_ignored(tmp_path):
    """Certain attribution is not enough. The path gates first."""
    outcome = _responder(tmp_path).respond(_event(
        tmp_path,
        file_path=str(tmp_path / "elsewhere" / "a.docx.locked"),
        attribution_confidence="certain",
        process_id=os.getpid(),
    ))
    assert outcome.action == "ignored"
    assert outcome.suspended is False


def test_the_agents_own_process_is_refused(tmp_path):
    """`guard()` in the Response service refuses self and ancestors."""
    outcome = _responder(tmp_path).respond(_event(
        tmp_path, attribution_confidence="certain", process_id=os.getpid()))
    assert outcome.action == "refused"
    assert outcome.suspended is False


def test_a_certain_attribution_on_a_dead_pid_reports_gone(tmp_path):
    outcome = _responder(tmp_path).respond(_event(
        tmp_path, attribution_confidence="certain", process_id=999999))
    assert outcome.action in {"gone", "refused"}
    assert outcome.suspended is False


def test_the_outcome_is_recorded_for_the_ledger(tmp_path):
    responder = _responder(tmp_path)
    outcome = responder.respond(_event(tmp_path))
    recorded = responder.recorded(outcome.incident_id)
    assert recorded["action"] == "isolate_and_log"
    assert recorded["process_id"] is None or recorded["attribution_confidence"] != "certain"


# ------------------------------------------- what reaches the hash chain

class _RecordingLedger:
    """Stands in for the chain, and remembers what was asked of it."""

    def __init__(self) -> None:
        self.blocks: list[tuple[str, dict]] = []

    def try_log_event(self, event_type, event_data):
        self.blocks.append((event_type, event_data))
        return {"id": len(self.blocks)}


def _agent_shell(tmp_path):
    """An `Agent` with nothing started, for driving `_act` directly.

    `Agent.__init__` builds observers, a responder and a dispatcher and would
    need elevation and a Windows Security subscription to do anything; what is
    under test here is one method, so the object is made without running it.
    """
    from agent.agent import Agent

    agent = Agent.__new__(Agent)
    agent._lock = threading.Lock()
    agent._chained_decisions = set()
    agent.ledger = _RecordingLedger()
    return agent


class _Outcome:
    def __init__(self, action): self.action = action


def test_a_decision_the_pipeline_does_not_carry_still_reaches_the_chain(tmp_path):
    """The Phase 5 finding: 7-Zip deleted twenty decoys and the chain was silent.

    `app.handle_event` fans out to the ledger only for events it found
    suspicious, and returns before the fan-out entirely for a deletion. The
    agent responds to both. Without this the whole of an archive-and-delete
    attack - seen, attributed to `7z.exe`, responded to - existed only in a
    text log.
    """
    agent = _agent_shell(tmp_path)
    event = {"file_path": "C:\\p\\decoy.docx", "event_type": "deleted",
             "suspicious": False, "verdict": "deleted",
             "process_id": 5844, "process_image": r"C:\Program Files\7-Zip\7z.exe",
             "attribution_confidence": "certain", "canary_hit": True}

    agent._chain_unsuspicious_decision(event, event["file_path"],
                                       _Outcome("refused"))

    assert len(agent.ledger.blocks) == 1
    kind, data = agent.ledger.blocks[0]
    assert kind == "file_event"
    assert data["process_id"] == 5844
    assert data["attribution_confidence"] == "certain"
    assert data["canary_hit"] is True
    assert data["verdict"] == "deleted"


def test_a_suspicious_event_is_not_chained_twice(tmp_path):
    """The Monitor's pipeline already writes those, and two blocks is worse."""
    agent = _agent_shell(tmp_path)
    agent._chain_unsuspicious_decision(
        {"file_path": "C:\\p\\a.docx", "suspicious": True},
        "C:\\p\\a.docx", _Outcome("suspended"))
    assert agent.ledger.blocks == []


def test_one_decoy_touched_forty_times_is_one_block(tmp_path):
    """A chain that grows per watchdog event can be flooded into uselessness.

    That run produced forty-two log lines for a single decoy. The decision was
    one decision.
    """
    agent = _agent_shell(tmp_path)
    event = {"file_path": "C:\\p\\decoy.docx", "suspicious": False,
             "process_id": 5844, "verdict": "deleted"}
    for _ in range(42):
        agent._chain_unsuspicious_decision(event, event["file_path"],
                                           _Outcome("isolate_and_log"))
    assert len(agent.ledger.blocks) == 1


def test_a_different_decision_about_the_same_path_is_a_second_block(tmp_path):
    """`unknown -> isolate_and_log` then `certain -> suspended` is two facts."""
    agent = _agent_shell(tmp_path)
    path = "C:\\p\\decoy.docx"
    agent._chain_unsuspicious_decision(
        {"file_path": path, "suspicious": False, "process_id": None},
        path, _Outcome("isolate_and_log"))
    agent._chain_unsuspicious_decision(
        {"file_path": path, "suspicious": False, "process_id": 5844},
        path, _Outcome("suspended"))
    assert len(agent.ledger.blocks) == 2
    assert [b[1]["process_id"] for b in agent.ledger.blocks] == [None, 5844]


# ---------------------------------------------------------------- transport

def test_the_transport_routes_the_ledger_leg_to_sqlite(tmp_path):
    from agent.ledger import DirectLedger
    from agent.transport import InProcessTransport

    with DirectLedger(tmp_path / "ledger.db") as led:
        post = InProcessTransport(led)
        answer = post(None, "http://ledger:8003", "/ledger/log",
                      {"event_type": "file_event", "event_data": {"file_path": "/x"}})
        assert answer["block_id"] == 1
        assert led.block_count() == 1


def test_an_unrouted_leg_reports_unavailable_rather_than_dialling_out(tmp_path):
    """None is the pipeline's own word for "that hop did not happen"."""
    from agent.ledger import DirectLedger
    from agent.transport import InProcessTransport

    with DirectLedger(tmp_path / "ledger.db") as led:
        post = InProcessTransport(led)
        assert post(None, "http://ml:8002", "/something-else", {}) is None


def test_the_ml_leg_is_off_by_default(tmp_path):
    from agent.ledger import DirectLedger
    from agent.transport import InProcessTransport

    with DirectLedger(tmp_path / "ledger.db") as led:
        post = InProcessTransport(led)
        assert post(None, "http://ml:8002", "/predict", {"features": {}}) is None


def test_the_response_leg_reports_the_action_already_taken(tmp_path):
    from agent.ledger import DirectLedger
    from agent.transport import InProcessTransport

    responder = _responder(tmp_path)
    outcome = responder.respond(_event(tmp_path))
    with DirectLedger(tmp_path / "ledger.db") as led:
        post = InProcessTransport(led, responder)
        answer = post(None, "http://response:8004", "/response/trigger",
                      {"incident_id": outcome.incident_id,
                       "action_required": "isolate_and_log"})
    assert answer["action"] == "isolate_and_log"
    assert "performed in-process" in answer["note"]


# ------------------------------------------------------- attribution timing

def test_every_attribution_question_says_when_its_event_happened():
    """`event_at` is optional in the module and mandatory here.

    `WriteLog.lookup` keeps the old behaviour when the caller does not say when
    its event happened, because callers outside the agent - the Monitor's own
    watchdog handlers, the sweep scripts - ask about a write that has only just
    occurred. The agent is the caller that parks events and re-asks later, so
    it is the one for which the default is wrong: an unstamped question there
    can be answered with the path's previous writer. A call site that loses the
    argument is silent, correct-looking, and reintroduces the suspension of the
    wrong process, so it is asserted from the source rather than trusted.
    """
    source = (ROOT / "agent" / "agent.py").read_text(encoding="utf-8")

    for call in ("handle_event(", "_attribution_fields("):
        invocations = [
            block for block in source.split(call)[1:]
            # The def itself is not a call.
            if not block.startswith("self, path")
        ]
        assert invocations, f"no {call} call found in agent/agent.py"
        for block in invocations:
            head = block[:220]
            assert "event_at" in head or "queued.queued_at" in head or \
                   "queued_at)" in head, (
                f"a {call}...) in agent/agent.py does not pass the moment its "
                f"event was observed:\n{head.splitlines()[0]}")

    pending_source = (ROOT / "agent" / "pending.py").read_text(encoding="utf-8")
    assert "self._resolve(parked.path, parked.queued_at)" in pending_source, (
        "the sweep must re-ask with the moment the event was queued; stamping "
        "the re-ask with `now` rejects the very record it is waiting for")


def test_the_limitation_this_fixed_is_no_longer_described_as_unfixed():
    """docs/LIMITATIONS.md §3 deferred this to Phase 5. Phase 5 is where it lands."""
    text = (ROOT / "docs" / "LIMITATIONS.md").read_text(encoding="utf-8")
    assert "**Not fixed here.**" not in text, (
        "the confident-wrong-answer path is fixed; LIMITATIONS.md still says "
        "it is not")


# -------------------------------------------------------------- the evidence

def test_the_phase2_acceptance_evidence_states_what_it_does_not_show():
    """The FEBR number has to stay in the artefact, not just the passing flag."""
    report = json.loads(
        (ROOT / "reports" / "agent_phase2_acceptance.json").read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["service_suspends_a_real_writer"]["attribution_confidence"] == "certain"
    assert report["service_suspends_a_real_writer"]["ledger_names_the_real_writer"] is True
    assert report["service_suspends_a_real_writer"]["left_frozen_after_cleanup"] is False
    assert report["service_suspends_a_real_writer"]["febr_files_at_suspend"] is not None, (
        "the number of files encrypted before the response fired is the metric "
        "that matters, and it must not be droppable from the evidence")
    assert "_what_this_does_not_show" in report
