"""The attack demo's bookkeeping: whose PID, and whose events (R14(b), defect 23).

The 2026-10-05 VM run named and killed the right writer every time, and the demo
still failed TC-07, for two reasons of its own:

* `Writer.pid` was `Popen(...).pid`. From a venv `sys.executable` is a launcher
  (`.venv\\Scripts\\python.exe`) that starts the base interpreter as a child, so
  the PID the demo judged against was the launcher's, not the writer's.
* Events were found with `file_path.endswith(victim.name)`. Every run writes
  `annual_report.docx.locked`, so an earlier run's event for that name in
  another folder was judged as this run's.

Each test here fails on the code before the fix.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import textwrap
from pathlib import Path

import psutil
import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"urds_bk_{name}", SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


demo = _load("attack_chain_demo")

# A launcher in the way the Windows venv one is: it starts the real interpreter
# as a child, passes the arguments and the standard handles through, and waits.
LAUNCHER = textwrap.dedent(
    """
    import subprocess, sys
    raise SystemExit(subprocess.run([sys.executable] + sys.argv[1:]).returncode)
    """
)


@pytest.fixture
def fake_launcher(tmp_path):
    script = tmp_path / "launcher.py"
    script.write_text(LAUNCHER)
    return [sys.executable, str(script)]


def _reap(writer) -> None:
    """No test leaves a writer behind: kill whatever is still alive."""
    for pid in (getattr(writer, "pid", None), writer.process.pid):
        try:
            psutil.Process(pid).kill()
        except (psutil.Error, TypeError):
            pass
    try:
        writer.process.wait(timeout=5)
    except Exception:
        pass


def _is_leaf(pid: int) -> bool:
    return not psutil.Process(pid).children()


# ------------------------------------------------------------------ the PID


def test_writer_pid_is_the_process_that_ran_the_code_not_its_launcher(tmp_path, fake_launcher):
    writer = demo.Writer(tmp_path / "w.bin", 1000, 5.0, interpreter=fake_launcher)
    try:
        launcher_pid = writer.process.pid
        assert writer.pid != launcher_pid
        assert writer.pid in {c.pid for c in psutil.Process(launcher_pid).children(recursive=True)}
        assert _is_leaf(writer.pid)
    finally:
        _reap(writer)


def test_writer_run_by_the_base_interpreter_reports_the_popen_pid(tmp_path):
    """No launcher in the way: the reported PID and the handle's agree."""
    base = getattr(sys, "_base_executable", sys.executable)
    writer = demo.Writer(tmp_path / "w.bin", 1000, 5.0, interpreter=[base])
    try:
        assert writer.pid == writer.process.pid
    finally:
        _reap(writer)


@pytest.mark.skipif(
    sys.platform != "win32" or sys.prefix == sys.base_prefix,
    reason="needs a Windows venv, whose python.exe is a launcher for the base interpreter",
)
def test_writer_from_a_real_windows_venv_launcher_reports_the_leaf_pid(tmp_path):
    writer = demo.Writer(tmp_path / "w.bin", 1000, 5.0)  # the default: sys.executable
    try:
        assert _is_leaf(writer.pid), "the PID is the launcher's: it still has a child"
        assert writer.pid != writer.process.pid
    finally:
        _reap(writer)


def test_writer_line_carries_the_hash_and_the_pid(tmp_path, fake_launcher):
    path = tmp_path / "w.bin"
    writer = demo.Writer(path, 2000, 5.0, interpreter=fake_launcher)
    try:
        assert writer.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
        assert psutil.pid_exists(writer.pid)
    finally:
        _reap(writer)


def test_writer_exit_is_watched_through_the_popen_handle(tmp_path, fake_launcher):
    writer = demo.Writer(tmp_path / "w.bin", 1000, 0.2, interpreter=fake_launcher)
    try:
        assert writer.finish(timeout=5.0) is not None
        assert writer.exited_at is not None
    finally:
        _reap(writer)


# ------------------------------------------------------------- the matching


def test_an_event_for_the_same_name_in_another_folder_is_not_this_runs(tmp_path):
    this = tmp_path / "now" / "annual_report.docx.locked"
    other = tmp_path / "earlier" / "annual_report.docx.locked"
    assert demo.is_this_runs_event(str(this), None, str(this), None)
    assert not demo.is_this_runs_event(str(other), None, str(this), None)


def test_an_event_for_the_same_path_with_another_hash_is_not_this_runs(tmp_path):
    path = str(tmp_path / "annual_report.docx.locked")
    assert demo.is_this_runs_event(path, "aa" * 32, path, "aa" * 32)
    assert not demo.is_this_runs_event(path, "bb" * 32, path, "aa" * 32)


def test_an_event_with_no_hash_still_matches_on_the_path(tmp_path):
    path = str(tmp_path / "annual_report.docx.locked")
    assert demo.is_this_runs_event(path, None, path, "aa" * 32)
    assert demo.is_this_runs_event(path, "", path, "aa" * 32)


def test_the_path_is_compared_normalised_not_as_spelled(tmp_path):
    path = tmp_path / "a" / "file.bin"
    spelled = str(tmp_path / "a" / "." / "sub" / ".." / "file.bin")
    assert demo.is_this_runs_event(spelled, None, str(path), None)
    assert demo.is_this_runs_event(str(path).replace("\\", "/"), None, str(path), None)


@pytest.mark.skipif(sys.platform != "win32", reason="case is folded for Windows paths only")
def test_the_path_is_compared_case_insensitively_on_windows(tmp_path):
    path = str(tmp_path / "Annual_Report.docx.locked")
    assert demo.is_this_runs_event(path.upper(), None, path, None)


def test_a_name_that_merely_ends_the_same_way_is_not_a_match(tmp_path):
    path = str(tmp_path / "report.bin")
    assert not demo.is_this_runs_event(str(tmp_path / "old_report.bin"), None, path, None)


# ------------------------------------------- judge_tc07 judgements, unchanged

WRITER = 4242
OTHER = 1717


def _event(confidence, pid, result=None):
    event = {"attribution_confidence": confidence, "process_id": pid,
             "attribution_reason": "test", "attribution_source": "test"}
    if result is not None:
        event["attribution_escalation"] = {"result": result}
    return event


def test_the_five_judgements_and_both_exit_codes_are_unchanged():
    assert demo.judge_tc07([_event("unknown", None)], WRITER, False)[0] == {
        "tc07_attributed_pid_is_the_writer": None, "tc07_process_terminated": None}
    assert demo.judge_tc07([_event("probable", WRITER, "not_escalated")], WRITER, False)[0][
        "tc07_process_terminated"] is None
    assert demo.judge_tc07([_event("certain", WRITER, "terminated")], WRITER, True)[0] == {
        "tc07_attributed_pid_is_the_writer": True, "tc07_process_terminated": True}
    assert demo.judge_tc07([_event("certain", OTHER, "terminated")], WRITER, True)[0] == {
        "tc07_attributed_pid_is_the_writer": False, "tc07_process_terminated": False}
    assert demo.judge_tc07(
        [_event("certain", WRITER, "termination_refused_or_unreachable")], WRITER, False
    )[0]["tc07_process_terminated"] is False
    assert demo.exit_code({"a": True, "b": True}) == 0
    assert demo.exit_code({"a": True, "b": None}) == 1


# ----------------------------------- the whole demo, against a fake gateway


class _Response:
    def __init__(self, body=None, status=200):
        self._body, self.status_code, self.text = body, status, str(body)

    def json(self):
        return self._body


class FakeGateway:
    """Serves what the gateway would, from the files the demo really wrote.

    The system's own answers are right, as they were on the VM: it names the
    writer's real (leaf) PID `certain` and ends it, which the fake does by
    killing the process when the demo asks for the closed events. Beside them
    are the leftovers of earlier runs: the same file name in another folder, and
    the same path with another hash, each naming another process.
    """

    def __init__(self, watch: Path, writers: list):
        self.watch, self.writers = watch, writers
        self.victim_killed = False
        self.requests: list[tuple[str, str]] = []

    @staticmethod
    def _event(path, digest, event_id, *, suspicious, pid=None, result=None, **extra):
        event = {
            "event_id": event_id, "file_path": str(path), "file_hash": digest,
            "entropy": 7.99, "verdict": "x", "reason": "r", "suspicious": suspicious,
            "detection_latency_ms": 5, "process_id": pid,
            "attribution_confidence": "certain" if pid else "unknown",
            "attribution_reason": "test", "attribution_source": "test",
        }
        if result:
            event["attribution_escalation"] = {"result": result}
        event.update(extra)
        return event

    def _victim_writer(self):
        return next((w for w in self.writers if w.path.name == "annual_report.docx.locked"), None)

    def events(self, limit):
        out = []
        control = self.watch / "quarterly_backup.zip"
        older = self.watch.parent / "older" / "annual_report.docx.locked"
        if control.exists():
            out.append(self._event(self.watch.parent / "older" / "quarterly_backup.zip", "cc" * 32,
                                   "evt-old-control", suspicious=True))
            out.append(self._event(control, hashlib.sha256(control.read_bytes()).hexdigest(),
                                   "evt-control", suspicious=False))
        writer = self._victim_writer()
        if writer is not None:
            victim = writer.path
            staged = dict(prediction="ransomware", threat_level="high", block_id=1,
                          pipeline={"stages": ["ledger_logged", "response_triggered"]})
            out.append(self._event(older, "dd" * 32, "evt-old-folder", suspicious=True, pid=8240,
                                   result="terminated", **staged))
            out.append(self._event(victim, "ee" * 32, "evt-old-hash", suspicious=True, pid=8240,
                                   result="terminated", **staged))
            if limit == 200 and not self.victim_killed:
                # the system's termination of the writer it named
                psutil.Process(writer.pid).kill()
                writer.process.wait(timeout=5)
                self.victim_killed = True
            out.append(self._event(victim, writer.sha256, "evt-this", suspicious=True, pid=writer.pid,
                                   result="terminated", **staged))
        probe = next((w for w in self.writers if w.path.name == "dashboard_probe.bin"), None)
        if probe is not None:
            out.append(self._event(probe.path, probe.sha256, "evt-probe", suspicious=True))
        return out

    def get(self, url, params=None, headers=None, **_):
        params = params or {}
        route = url.split("://", 1)[-1].split("/", 1)[-1]
        self.requests.append(("GET", route))
        if route == "health":
            return _Response({"status": "healthy", "services": {"monitor": {"status": "ok"}}})
        if route == "monitor/status":
            if not (headers or {}).get("Authorization", "").startswith("Bearer ey"):
                return _Response({}, 401)
            return _Response({"events_captured": 0})
        if route == "monitor/events":
            return _Response({"events": self.events(params.get("limit", 50))})
        if route == "ledger/blocks":
            if params.get("event_type") == "response_action":
                return _Response({"blocks": [{"block_id": 3, "event_data": {"action": "alert", "outcome": "ok"}}]})
            writer = self._victim_writer()
            blocks = []
            if writer is not None:
                blocks.append({"block_id": 90, "event_type": "file_event", "current_hash": "1" * 64,
                               "previous_hash": "0" * 64,
                               "event_data": {"file_path": str(self.watch.parent / "older" / writer.path.name),
                                              "file_hash": "dd" * 32, "verdict": "old"}})
                blocks.append({"block_id": 91, "event_type": "file_event", "current_hash": "2" * 64,
                               "previous_hash": "1" * 64,
                               "event_data": {"file_path": str(writer.path), "file_hash": writer.sha256,
                                              "verdict": "this"}})
            return _Response({"blocks": blocks})
        if route == "ledger/verify":
            return _Response({"valid": True, "blocks_checked": 2, "verification_time_ms": 1})
        return _Response({}, 200)

    def post(self, url, json=None, headers=None, **_):
        route = url.split("://", 1)[-1].split("/", 1)[-1]
        self.requests.append(("POST", route))
        if route == "auth/token":
            return _Response({"access_token": "ey.fake.token"})
        if route == "monitor/start":
            return _Response({"monitor_id": "m1", "watch_path": json["watch_path"]})
        return _Response({}, 200)


@pytest.fixture
def run_demo(monkeypatch, tmp_path):
    watch = tmp_path / "watched"
    watch.mkdir()
    writers: list = []

    class RecordingWriter(demo.Writer):
        def __init__(self, path, size, hold, **kw):
            self.path = Path(path)
            super().__init__(path, size, hold, **kw)
            writers.append(self)

    gateway = FakeGateway(watch, writers)
    monkeypatch.setattr(demo, "Writer", RecordingWriter)
    monkeypatch.setattr(demo.httpx, "Client", lambda **kw: gateway)
    monkeypatch.setattr(demo, "transcript", [])
    monkeypatch.setattr(demo, "results", {})
    monkeypatch.setattr(sys, "argv", ["attack_chain_demo.py", "--watch-host", str(watch),
                                      "--watch-container", str(watch)])
    monkeypatch.delenv("URDS_WRITE_REPORTS", raising=False)
    try:
        yield gateway, writers
    finally:
        for writer in writers:
            _reap(writer)


def test_the_demo_judges_this_runs_writer_and_this_runs_events(run_demo, monkeypatch):
    gateway, writers = run_demo
    code = demo.main()
    text = "\n".join(demo.transcript)

    victim = next(w for w in writers if w.path.name == "annual_report.docx.locked")
    # it names the PID that ran the code, once, and not the earlier run's process
    assert f"writer pid {victim.pid} wrote" in text
    assert "8240" not in text
    assert "WRONG PROCESS" not in text
    # it read this run's event and this run's block, not the stale ones before them
    assert "event_id          : evt-this" in text
    assert "block_id      : 91" in text
    assert demo.results["tc03_no_false_positive"] is True
    assert demo.results["tc07_attributed_pid_is_the_writer"] is True
    assert demo.results["tc07_process_terminated"] is True
    assert [k for k, v in demo.results.items() if v is not True and k != "kill_time_under_2s"] == []
    # X1: the demo asked for no termination
    assert ("POST", "response/terminate") not in gateway.requests
    assert code == demo.exit_code(demo.results)
