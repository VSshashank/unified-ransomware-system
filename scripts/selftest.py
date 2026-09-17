r"""Does this installation actually do the thing? One run, PASS/FAIL per step.

`install.ps1` finishes by calling this, and treats a non-zero exit as a failed
installation. It is the difference between "the service is running" and "the
service caught something", and those are not the same sentence: an agent whose
auditing is misconfigured starts cleanly, reports `RUNNING`, watches the right
folder, and suspends nothing for ever, because without a kernel-grade source no
attribution reaches CERTAIN and it will not guess a PID. That failure is silent
by design. This is what makes it loud.

    .venv\Scripts\python.exe scripts/selftest.py
    .venv\Scripts\python.exe scripts/selftest.py --timeout 180 --keep

What it does, in order:

  1. resolve the configuration the *service* is using, not a default
  2. confirm the service is RUNNING and that auditing is set up on the root
  3. write a pristine, low-entropy file into the protected path, confirm the
     agent saw it - which proves the observers are alive before anything is
     asked of them - and then **wait for that write to age out of the
     attribution window**, so that this process is not a candidate writer when
     the attacker's write is judged
  4. take a VSS snapshot **before** the damage. A snapshot taken during an
     incident contains the encrypted file; restoring from it returns the
     ciphertext. Recovery depends on a snapshot that predates the write, and a
     self-test that snapshotted after it would round-trip a hash that proves
     nothing
  5. spawn `scripts/selftest_writer.py`, take the PID **it reports for itself**,
     and let it overwrite the file with 1 MiB of `os.urandom`. Not
     `Popen.pid`: the venv's `python.exe` is a launcher that starts the real
     interpreter as its own child, so the parent's idea of the child's PID is
     the launcher's. Measured - Popen.pid 28732, writer reports 9976 - after
     this test failed a correct agent for naming the right process
  6. read back, from the service's own hash-chained ledger, whether the agent
     named that PID, suspended it, took its own snapshot, and recorded it
  7. restore the file from the pre-damage snapshot and compare SHA-256

Every verdict in step 6 comes out of the ledger the service wrote. This process
does no detection and makes no judgement about the file; if it did, a green run
would only prove that this file agrees with itself.

Exit codes: 0 all PASS. 1 at least one FAIL. 2 could not run the test at all
(no configuration, not elevated, not Windows).

The report is written into the agent's data directory and deliberately **not**
into `reports/`. Everything in `reports/` carrying `generated_at` and `commit`
is checked by `scripts/claim_matrix.py` against the git history, and a file
generated on a user's machine at install time has no commit to be an ancestor
of. It is an installation record, not evidence for a claim.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# The recovery modules are laid out for their container, where `recovery` is a
# top-level package. Same import shape `scripts/verify_vss.py` uses.
RESPONSE_DIR = ROOT / "services" / "response"
if str(RESPONSE_DIR) not in sys.path:
    sys.path.insert(0, str(RESPONSE_DIR))
LEDGER_DIR = ROOT / "services" / "ledger"
if str(LEDGER_DIR) not in sys.path:
    sys.path.insert(0, str(LEDGER_DIR))

SERVICE_NAME = "URDSAgent"
WRITER = ROOT / "scripts" / "selftest_writer.py"
AUDIT_SCRIPT = ROOT / "scripts" / "setup_attribution_audit.ps1"

#: Bytes the child writes. One megabyte of `os.urandom` sits at 8.0 bits/byte
#: and carries no container header, which is the static-entropy path already
#: exercised on this machine. Not a threshold this test invented.
ATTACK_BYTES = 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def attribution_window_ms() -> float:
    """How far back the agent looks when asked who wrote a path.

    Taken from the agent's own module, not copied. A number typed in here would
    go stale the first time the window moved, and this test would go back to
    manufacturing the ambiguity it now avoids.
    """
    try:
        from agent import imports  # noqa: PLC0415

        return float(imports.load("attribution").WINDOW_MS)
    except Exception:  # noqa: BLE001
        # The agent could not be imported, which every check above would have
        # failed on already. Fall back to the documented default rather than to
        # zero: zero would skip the wait entirely.
        return float(os.getenv("ATTRIBUTION_WINDOW_MS", "3000"))


# --------------------------------------------------------------------- results


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    remediation: str = ""
    observed: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        payload = {"check": self.name, "result": "PASS" if self.ok else "FAIL",
                   "detail": self.detail, "remediation": self.remediation}
        if self.observed:
            payload["observed"] = self.observed
        return payload


class Report:
    """The checks, in the order they ran, and what they saw.

    A check that could not be attempted is a FAIL and not a silent gap. There
    is no `skip` here: the place this project has been bitten repeatedly is a
    harness that reported green because it could not report anything else.
    """

    def __init__(self) -> None:
        self.checks: list[Check] = []
        self.context: dict = {}

    def record(self, name: str, ok: bool, detail: str = "",
               remediation: str = "", **observed) -> bool:
        check = Check(name, bool(ok), detail, remediation, observed)
        self.checks.append(check)
        mark = "[ PASS ]" if check.ok else "[ FAIL ]"
        line = "{0} {1}".format(mark, name)
        if detail:
            line += "  -  " + detail
        print(line, flush=True)
        if not check.ok and remediation:
            for row in remediation.splitlines():
                print("         " + row, flush=True)
        return check.ok

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if not c.ok)

    def as_dict(self) -> dict:
        return {
            "self_test": "urds installation",
            "generated_at_local": utc_now(),
            "host": platform.node(),
            "platform": "{0} {1} {2}".format(platform.system(),
                                             platform.release(),
                                             platform.version()),
            "passed": sum(1 for c in self.checks if c.ok),
            "failed": self.failed,
            # No checks is not a pass. A report that ran nothing and said PASS
            # is the exact shape of every false green this project has had: the
            # suite runner that printed "0 passed, 0 failed" under five green
            # groups and exited 0, and the audit script that printed FAIL and
            # exited 0 before it. An empty result means the run fell over
            # before it measured anything.
            "result": "PASS" if (self.checks and self.failed == 0) else "FAIL",
            "context": self.context,
            "checks": [c.as_dict() for c in self.checks],
        }


# ----------------------------------------------------------------- environment


def is_elevated() -> bool:
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def parse_service_state(out: str) -> str:
    """Pull the state word out of `sc.exe query` output.

    Separate from the call so it can be tested without a service. The line
    looks like `        STATE              : 4  RUNNING`, and the interesting
    part is the last word, not the number - the number is stable and the word
    is what a reader recognises.
    """
    if "does not exist" in out or "1060" in out:
        return "absent"
    for line in out.splitlines():
        if "STATE" in line and ":" in line:
            tail = line.split(":", 1)[1].strip()
            if tail:
                return tail.split()[-1].strip()
    return "unknown"


def service_state(name: str = SERVICE_NAME) -> str:
    """What the SCM says, as a word. 'absent' if the service is not installed."""
    try:
        out = subprocess.run(["sc.exe", "query", name], capture_output=True,
                             text=True, check=False).stdout
    except OSError as exc:
        return "unqueryable: {0}".format(exc)
    return parse_service_state(out)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------- ledger reads


def read_only_connection(db: Path) -> sqlite3.Connection:
    """Open the service's ledger without becoming a second writer.

    The agent holds one connection to this file and it is deliberately not in
    WAL mode. A writer opened here would contend with the thing under test, and
    the first symptom would be the agent failing to record the very incident
    this test is waiting for. Read-only, so it cannot.
    """
    conn = sqlite3.connect("file:{0}?mode=ro".format(db.as_posix()),
                           uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def blocks_since(db: Path, after_id: int, event_type: str | None = None) -> list[dict]:
    conn = read_only_connection(db)
    try:
        sql = "SELECT id, timestamp, event_type, event_data FROM blocks WHERE id > ?"
        params: list = [after_id]
        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        rows = conn.execute(sql + " ORDER BY id ASC", params).fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        try:
            payload = json.loads(row["event_data"])
        except (TypeError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        out.append({"id": row["id"], "timestamp": row["timestamp"],
                    "event_type": row["event_type"], "data": payload})
    return out


def tip_id(db: Path) -> int:
    conn = read_only_connection(db)
    try:
        row = conn.execute("SELECT id FROM blocks ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    return int(row["id"]) if row else 0


def verify_chain(db: Path) -> dict:
    """Recompute every hash, using the ledger service's own hash function.

    The walk is here rather than a call to `HashChainLedger.verify_chain` for
    one reason: constructing that class opens a writable connection and runs
    `CREATE TABLE IF NOT EXISTS` against a database the service is using. The
    hash itself is imported, not reimplemented - a second implementation of the
    block hash would let this test certify a chain the service would reject.
    """
    from hash_chain import GENESIS_HASH, HashChainLedger  # noqa: PLC0415

    conn = read_only_connection(db)
    try:
        rows = conn.execute(
            "SELECT id, timestamp, event_type, event_data, previous_hash,"
            " current_hash FROM blocks ORDER BY id ASC").fetchall()
    finally:
        conn.close()

    expected_previous = GENESIS_HASH
    for row in rows:
        recomputed = HashChainLedger.compute_hash(
            row["timestamp"], row["event_type"], row["event_data"],
            row["previous_hash"])
        if recomputed != row["current_hash"] or row["previous_hash"] != expected_previous:
            return {"valid": False, "blocks_checked": len(rows),
                    "invalid_block_id": int(row["id"])}
        expected_previous = row["current_hash"]
    return {"valid": True, "blocks_checked": len(rows), "invalid_block_id": None}


def wait_for(predicate, timeout_s: float, interval_s: float = 0.25):
    """Poll until the predicate returns something truthy, or time runs out."""
    deadline = time.monotonic() + timeout_s
    while True:
        found = predicate()
        if found:
            return found
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


# ------------------------------------------------------------------- the test


def run(args: argparse.Namespace) -> int:
    report = Report()
    print()
    print("URDS installation self-test")
    print("=" * 62)

    if platform.system() != "Windows":
        print("This test needs Windows: the agent is a Windows Service and "
              "attribution is a Security-channel subscription.", file=sys.stderr)
        return 2
    if not is_elevated():
        print("Run this from an Administrator console. Creating a shadow copy "
              "and reading the Security log both need it.", file=sys.stderr)
        return 2

    # 1. the configuration the service resolved -----------------------------
    try:
        from agent import config as agent_config  # noqa: PLC0415

        config = agent_config.load()
    except Exception as exc:  # noqa: BLE001
        print("cannot load the agent configuration: {0}".format(exc),
              file=sys.stderr)
        return 2

    protected = Path(config.protected_paths[0])
    ledger_db = Path(config.ledger_db)
    report.context = {
        # This process's own PID, because it has been the answer before: the
        # agent named it, correctly, when this test left its own write inside
        # the attribution window.
        "selftest_pid": os.getpid(),
        "config_source": str(config.source),
        "protected_paths": [str(p) for p in config.protected_paths],
        "ledger_db": str(ledger_db),
        "attribution_timeout_ms": config.attribution_timeout_ms,
        "timeout_s": args.timeout,
    }
    report.record(
        "configuration resolved",
        ledger_db.is_file() and protected.is_dir(),
        "{0} -> protecting {1}".format(config.source, protected),
        remediation="Expected a ledger at {0} and a directory at {1}. Run "
                    "install.ps1, or start the service once.".format(
                        ledger_db, protected),
    )

    # 2. the service, and the auditing it depends on -------------------------
    state = service_state()
    report.record(
        "service is running", state == "RUNNING",
        "{0}: {1}".format(SERVICE_NAME, state),
        remediation="sc.exe start URDSAgent\n"
                    "If it stops immediately, read "
                    "%ProgramData%\\URDS\\agent.log.",
    )

    audit = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(AUDIT_SCRIPT), "-WatchPath", str(protected), "-Verify"],
        capture_output=True, text=True, check=False)
    report.record(
        "attribution is configured on the protected path",
        audit.returncode == 0,
        "setup_attribution_audit.ps1 -Verify exited {0}".format(audit.returncode),
        remediation='powershell -ExecutionPolicy Bypass -File "{0}" '
                    '-WatchPath "{1}"\n'
                    "Without it the agent detects and suspends nothing: no "
                    "attribution reaches CERTAIN and it does not guess a "
                    "PID.".format(AUDIT_SCRIPT, protected),
    )

    if report.failed:
        # Everything below writes into a protected folder and waits for a
        # response. With the service down or auditing off that is a guaranteed
        # timeout dressed up as a test.
        print()
        print("Stopping before the live test: the preconditions above are what "
              "it measures.")
        return finish(report, args, config)

    # 3. a pristine file the agent can see ----------------------------------
    tag = uuid.uuid4().hex[:8]
    victim = protected / "urds_selftest_{0}.txt".format(tag)
    pristine = ("URDS installation self-test {0}, written {1}.\n"
                "Low-entropy text, so that writing it is not itself "
                "suspicious.\n".format(tag, utc_now()).encode("utf-8") * 64)
    before_pristine = tip_id(ledger_db)
    victim.write_bytes(pristine)
    pristine_written_at = time.monotonic()
    pristine_hash = sha256_of(victim)

    seen = wait_for(
        lambda: [b for b in blocks_since(ledger_db, before_pristine)
                 if str(b["data"].get("file_path", "")).lower()
                 == str(victim).lower()],
        timeout_s=min(30.0, args.timeout))
    report.record(
        "the agent sees writes to the protected path",
        bool(seen),
        "{0} ledger block(s) name {1}".format(len(seen or []), victim.name)
        if seen else
        "no ledger block named {0} within 30s".format(victim.name),
        remediation="The observers are not delivering. Check "
                    "%ProgramData%\\URDS\\agent.log for the watchdog backend it "
                    "chose, and that the service is watching this path.",
        victim=str(victim), pristine_sha256=pristine_hash)

    # Wait for this process's own write to leave the attribution window.
    #
    # This is the whole reason the first two runs of this test failed an agent
    # that was working. The window is 3000 ms and the Security channel delivers
    # in 600-1010 ms, so at the moment the attacker's write is judged, the only
    # audited write on that path can still be *this* process's pristine one -
    # exactly one distinct PID, from a kernel-grade source, so CERTAIN - and the
    # agent suspends the self-test. It did. The chain says so:
    #
    #   file_event 16095 | verdict suspected_encryption | pid 27792 | certain
    #     reason: exactly one process wrote this path in the last 3000ms
    #
    # where 27792 was this script. Nothing was guessed and nothing was wrong
    # with the agent; the harness put a second writer in the window and then
    # complained about the answer. Same lesson as every previous harness defect
    # in this project: the thing doing the measuring must not also be a writer
    # in the protected path.
    #
    # The wait is derived from the agent's own constant rather than typed in, so
    # that changing the window cannot silently break this.
    settle_s = (attribution_window_ms() / 1000.0) + 1.5
    elapsed = time.monotonic() - pristine_written_at
    if elapsed < settle_s:
        remaining = settle_s - elapsed
        print("  waiting {0:.1f}s for this process's own write to age out of "
              "the {1:.0f}ms attribution window".format(
                  remaining, attribution_window_ms()))
        time.sleep(remaining)

    # 4. a snapshot that predates the damage --------------------------------
    snapshot_id = None
    try:
        from recovery.vss_manager import VSSManager  # noqa: PLC0415

        vss = VSSManager()
        volume = str(protected.anchor or "C:\\")
        started = time.perf_counter()
        snapshot_id = vss.create_snapshot(volume)
        took = time.perf_counter() - started
        report.record("pre-damage VSS snapshot", True,
                      "{0} of {1} in {2:.1f}s".format(snapshot_id, volume, took),
                      snapshot_id=snapshot_id, volume=volume,
                      seconds=round(took, 3))
    except Exception as exc:  # noqa: BLE001
        report.record(
            "pre-damage VSS snapshot", False,
            "{0}: {1}".format(type(exc).__name__, exc),
            remediation="vssadmin list shadowstorage /for=C:\n"
                        "A volume with no shadow storage, or a VSS writer in a "
                        "failed state, produces this. install.ps1 sets the "
                        "storage; `vssadmin list writers` finds the other case.")

    # 5. the child, and the PID it reports for itself -----------------------
    #
    # `Popen.pid` is not that PID, and assuming it was is how this test first
    # failed against an agent that had done everything right. Measured here:
    #
    #     Popen.pid      : 28732
    #     child reports  : {"self": 9976, "parent": 28732}
    #
    # `.venv\Scripts\python.exe` is a 255 KB launcher that starts the real
    # interpreter as its own child, so the process that opens the file is the
    # grandchild. The agent named the writer correctly; the test was watching
    # the launcher, and reported the agent as having failed to attribute
    # anything.
    #
    # There is a rule in this project against guessing a PID. It applies to the
    # thing doing the measuring too: the writer prints `os.getpid()` and that -
    # reported by the process that did the write - is what everything below
    # uses. If it never arrives, this check fails rather than falling back to
    # the number that was wrong the first time.
    before_attack = tip_id(ledger_db)
    child = subprocess.Popen(
        [sys.executable, str(WRITER), "--target", str(victim),
         "--bytes", str(ATTACK_BYTES), "--hold", str(args.hold)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    announced: dict = {}

    def read_announcement() -> None:
        try:
            line = child.stdout.readline() if child.stdout else ""
        except Exception:  # noqa: BLE001
            return
        try:
            announced.update(json.loads(line))
        except (TypeError, ValueError):
            announced["raw"] = line

    reader = threading.Thread(target=read_announcement, daemon=True)
    reader.start()
    reader.join(timeout=min(60.0, args.timeout))

    child_pid = announced.get("pid")
    report.record(
        "the writer announced its own PID",
        isinstance(child_pid, int),
        "pid {0} wrote {1} bytes (launcher was pid {2})".format(
            child_pid, announced.get("bytes"), child.pid)
        if isinstance(child_pid, int) else
        "scripts/selftest_writer.py printed nothing usable: "
        "{0!r}".format(announced.get("raw", "")),
        remediation="Run it by hand to see what it says:\n"
                    "  .venv\\Scripts\\python.exe scripts/selftest_writer.py "
                    "--target <a file> --hold 5")

    if not isinstance(child_pid, int):
        cleanup(child, child.pid, victim, args, snapshot_id)
        return finish(report, args, config)

    print()
    print("  pid {0} wrote {1} random bytes over {2}".format(
        child_pid, ATTACK_BYTES, victim.name))
    print()

    # Observed directly, not inferred. Polled fast because the freeze may be
    # short: the escalation snapshots, decides, and often resumes. This starts
    # after the writer has announced itself, which is after the write - so a
    # freeze that has already happened and ended is simply not seen, and is
    # reported as not seen rather than as not happened.
    frozen = False
    try:
        import psutil  # noqa: PLC0415

        deadline = time.monotonic() + min(20.0, args.timeout)
        while time.monotonic() < deadline and not frozen:
            try:
                if psutil.Process(child_pid).status() == psutil.STATUS_STOPPED:
                    frozen = True
            except psutil.NoSuchProcess:
                break
            time.sleep(0.005)
    except ImportError:
        pass

    # 6. what the service recorded ------------------------------------------
    escalation = wait_for(
        lambda: next((b for b in blocks_since(ledger_db, before_attack,
                                              "response_escalation")
                      if b["data"].get("process_id") == child_pid), None),
        timeout_s=args.timeout)

    report.record(
        "the agent attributed the write to that PID",
        escalation is not None,
        "response_escalation block #{0} names pid {1} ({2})".format(
            escalation["id"], child_pid,
            escalation["data"].get("process_image")) if escalation else
        "no response_escalation block named pid {0} within {1:.0f}s".format(
            child_pid, args.timeout),
        remediation="The write was seen but nobody was named, or nobody was "
                    "acted on. `python -m agent status` reports the "
                    "attribution source; if it says unavailable, auditing is "
                    "the cause.\n"
                    "If the agent instead named THIS process (pid {0}), the "
                    "wait above was too short and the window still held this "
                    "test's own write - that is a defect here, not in the "
                    "agent.".format(os.getpid()),
        child_pid=child_pid, selftest_pid=os.getpid(),
        other_escalations=[
            {"pid": b["data"].get("process_id"),
             "decision": b["data"].get("decision")}
            for b in blocks_since(ledger_db, before_attack, "response_escalation")
        ])

    # A `response_escalation` block exists only because the responder suspended
    # first: `_schedule_escalation` is called from the suspend path and from the
    # already-suspended path, and from nowhere else. That is the record. The
    # direct observation above is corroboration, and it is reported as observed
    # or not observed rather than being allowed to decide anything - the freeze
    # can be shorter than the window this process gets to look in.
    if escalation:
        result = escalation["data"].get("result") or {}
        decision = escalation["data"].get("decision")
        detail = "escalated after the suspend, then {0}".format(decision)
        if result.get("resumed"):
            detail += "; resumed after {0} call(s)".format(result.get("resume_calls"))
        detail += ("; directly observed STOPPED" if frozen else
                   "; the freeze was not caught in this process's polling window")
        report.record(
            "it suspended that process before deciding anything",
            decision in {"kill", "resume", "resume_on_error"},
            detail,
            remediation="An escalation with no decision means the responder "
                        "raised. %ProgramData%\\URDS\\agent.log has the "
                        "traceback.",
            directly_observed_stopped=frozen, decision=decision, result=result)

        snapshot = escalation["data"].get("snapshot") or {}
        report.record(
            "it took a VSS snapshot during the incident",
            bool(snapshot.get("taken")),
            "{0} in {1}s".format(snapshot.get("snapshot_id"),
                                 snapshot.get("elapsed_s"))
            if snapshot.get("taken") else
            "not taken: {0}".format(snapshot.get("reason")),
            remediation="The suspect stays frozen either way, but there is no "
                        "point-in-time copy of the damage. `vssadmin list "
                        "writers` from an elevated console.",
            snapshot=snapshot)
    else:
        report.record("it suspended that process before deciding anything",
                      False, "no escalation record to read it from")
        report.record("it took a VSS snapshot during the incident", False,
                      "no escalation record to read it from")

    # 7. the chain ----------------------------------------------------------
    chain = verify_chain(ledger_db)
    appended = tip_id(ledger_db) - before_attack
    report.record(
        "the ledger recorded it, and the chain verifies",
        bool(chain["valid"]) and appended > 0,
        "{0} blocks, valid={1}, {2} appended during this test".format(
            chain["blocks_checked"], chain["valid"], appended),
        remediation="An invalid chain names the first broken block. That is a "
                    "tamper finding, not an installation problem.",
        blocks_appended=appended, **chain)

    # 8. restore, and compare bytes -----------------------------------------
    if snapshot_id:
        try:
            from recovery.recovery import RecoveryManager  # noqa: PLC0415

            manager = RecoveryManager()
            snapshot_root = manager.resolve_snapshot_root(snapshot_id)
            restored_hash = manager.restore_file(snapshot_root, str(victim))
            report.record(
                "restore round-trips the hash",
                restored_hash == pristine_hash,
                "{0}... == {1}...".format(restored_hash[:16], pristine_hash[:16])
                if restored_hash == pristine_hash else
                "restored {0}... but the original was {1}...".format(
                    restored_hash[:16], pristine_hash[:16]),
                remediation="The file came back from the snapshot with "
                            "different bytes. Check that the snapshot predates "
                            "the write - a snapshot taken during an incident "
                            "contains the damage.",
                snapshot_id=snapshot_id, snapshot_root=snapshot_root,
                restored_sha256=restored_hash, original_sha256=pristine_hash)
        except Exception as exc:  # noqa: BLE001
            report.record(
                "restore round-trips the hash", False,
                "{0}: {1}".format(type(exc).__name__, exc),
                remediation="`vssadmin list shadows` shows whether the "
                            "snapshot is still there. A shadow copy can be "
                            "deleted by Disk Cleanup between the two halves of "
                            "this test.")
    else:
        report.record("restore round-trips the hash", False,
                      "there was no pre-damage snapshot to restore from")

    cleanup(child, child_pid, victim, args, snapshot_id)
    return finish(report, args, config)


def cleanup(child: subprocess.Popen, pid: int, victim: Path,
            args: argparse.Namespace, snapshot_id: str | None) -> None:
    """Leave the machine as it was found, except for the shadow copy.

    The shadow copy stays. Deleting it means `vssadmin delete shadows`, and the
    agent's own guard watches for exactly that command line and treats it as an
    attack on the means of recovery - correctly. A self-test that ended by
    setting off the alarm it had just tested would be its own last incident.
    """
    print()
    try:
        import psutil  # noqa: PLC0415

        process = psutil.Process(pid)
        if process.status() == psutil.STATUS_STOPPED:
            # Never leave a frozen process behind, whoever froze it.
            process.resume()
        process.terminate()
        process.wait(timeout=10)
        print("  cleaned up: child pid {0} is gone".format(pid))
    except Exception as exc:  # noqa: BLE001
        print("  cleanup: child pid {0}: {1}: {2}".format(
            pid, type(exc).__name__, exc))
    finally:
        try:
            child.kill()
        except Exception:  # noqa: BLE001
            pass

    if args.keep:
        print("  kept: {0}".format(victim))
    else:
        try:
            victim.unlink(missing_ok=True)
            print("  cleaned up: {0}".format(victim.name))
        except OSError as exc:
            print("  cleanup: {0}: {1}".format(victim, exc))

    if snapshot_id:
        print("  left in place: shadow copy {0}".format(snapshot_id))
        print("    remove it with Disk Cleanup, or from an elevated console:")
        print("      vssadmin delete shadows /shadow={0}".format(snapshot_id))


def finish(report: Report, args: argparse.Namespace, config) -> int:
    payload = report.as_dict()

    destination = (Path(args.json) if args.json
                   else Path(config.data_dir) / "selftest.json")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(payload, indent=2, default=str),
                               encoding="utf-8")
        written = str(destination)
    except OSError as exc:
        written = "could not write {0}: {1}".format(destination, exc)

    print()
    print("=" * 62)
    print("  {0} passed, {1} failed".format(payload["passed"], payload["failed"]))
    print("  report: {0}".format(written))
    if payload["failed"]:
        print()
        print("  FAILED. This installation does not do what it claims to do.")
        print("  Each failure above prints what to run next.")
        return 1
    print()
    print("  PASS. The agent named a real PID, froze it, snapshotted, recorded")
    print("  it in the chain, and the file came back byte-identical.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="seconds to wait for the agent to respond "
                             "(default 120; the escalation alone allows 45 for "
                             "a snapshot)")
    parser.add_argument("--hold", type=float, default=90.0,
                        help="seconds the child stays alive after writing")
    parser.add_argument("--keep", action="store_true",
                        help="leave the test file in the protected path")
    parser.add_argument("--json", help="where to write the report")
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
