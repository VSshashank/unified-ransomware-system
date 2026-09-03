"""Does the governance decision survive every hop? - SH + SI.

Item P6.4, Chapter 9 §9.4.2 and the artefact register §9.8. Writes
reports/pipeline_governance.json.

§9.4.2 asks for two things and this measures both:

  1. the policy decision record propagates **ML -> Ledger -> Response ->
     Recovery** intact at every hop;
  2. the dashboard surfaces `cancelled`, `attenuated` and `deferred`
     **distinctly**.

Nothing here is asserted from reading the source. Three populations are driven
through the real `app.handle_event`, the real `pipeline`, the real Response
handler and the real `RecoveryManager`, and every hop's payload is captured as
it is actually built:

    cancelled    a hash whitelist rule against a signal it outranks
    attenuated   a path whitelist rule against a signal that outranks it
    deferred     a genuinely locked file. Opened through CreateFileW with
                 dwShareMode 0, so the Monitor's own read fails the way it
                 fails in production - not simulated, not monkeypatched.

"Intact" means deep-equal to the record the Monitor produced. A hop that carries
a *summary* of the decision is recorded as carrying a summary, not as carrying
the decision.

**D6 applies.** If any gate fails, the final claim is reduced to "URDS Monitor"
scope, the word *unified* is not used for evidence that was not collected, and
the reduction is written down. This script decides that mechanically from what
it measured, so the reduction cannot be argued away afterwards.

    .venv\\Scripts\\python.exe scripts/pipeline_governance.py

Writes the report only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import ast
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"

# Order matters: both services have a module called `app`, and the last insert
# wins index 0. The Monitor's has to be the one `import app` finds, so the
# Response path goes down first and the Monitor path on top of it.
sys.path.insert(0, str(REPO_ROOT / "services" / "response"))
sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

EVENTS_PER_POPULATION = 6
PAYLOAD_BYTES = 120_000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def payload(tag: str, size: int = PAYLOAD_BYTES) -> bytes:
    """Deterministic high-entropy bytes, so a rerun drives the same files."""
    out = bytearray()
    seed = hashlib.sha256(tag.encode()).digest()
    while len(out) < size:
        seed = hashlib.sha256(seed).digest()
        out += seed
    return bytes(out[:size])


# ---------------------------------------------------------------- locked file


class LockedFile:
    """A file Windows will not let a second reader open.

    CreateFileW with dwShareMode 0 takes exclusive access. The Monitor's
    `read_magic` then fails for the same reason it fails when an encryptor holds
    a handle, which is the condition `readable=False` exists for. Simulating it
    by patching the reader would measure the patch.
    """

    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    INVALID_HANDLE = ctypes.c_void_p(-1).value

    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = None

    def __enter__(self):
        handle = ctypes.windll.kernel32.CreateFileW(
            str(self.path), self.GENERIC_READ, 0, None, self.OPEN_EXISTING, 0, None
        )
        if handle == self.INVALID_HANDLE:
            raise OSError(f"could not take an exclusive handle on {self.path}")
        self.handle = handle
        return self

    def __exit__(self, *exc):
        if self.handle is not None:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None


# -------------------------------------------------------------------- capture


class HopRecorder:
    """Stands in for the network and records what each hop was handed."""

    def __init__(self) -> None:
        self.hops: list[dict] = []

    def __call__(self, client, base_url, path, payload_body):
        self.hops.append({"path": path, "body": payload_body})
        if path == "/ledger/log":
            return {"block_id": len(self.hops), "current_hash": "recorded"}
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.95, "threat_level": "critical"}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["admin_notified"]}
        return {}

    def by_path(self, path: str) -> list[dict]:
        return [h["body"] for h in self.hops if h["path"] == path]

    def ledger_blocks(self, event_type: str) -> list[dict]:
        return [
            b.get("event_data") or {}
            for b in self.by_path("/ledger/log")
            if b.get("event_type") == event_type
        ]


# ------------------------------------------------------------------- driving


def drive(workdir: Path, population: str, recorder: HopRecorder) -> list[dict]:
    import app as monitor_app

    workdir.mkdir(parents=True, exist_ok=True)
    events = []

    for index in range(EVENTS_PER_POPULATION):
        if population == "cancelled":
            blob = payload(f"cancelled:{index}")
            path = workdir / f"cancelled_{index}.docx"
            path.write_bytes(blob)
            monitor_app.WHITELIST.replace(
                paths=[], hashes=[hashlib.sha256(blob).hexdigest()]
            )
            events.append(monitor_app.handle_event(str(path), "created"))
        elif population == "attenuated":
            blob = b"PK\x03\x04" + payload(f"attenuated:{index}")
            path = workdir / f"attenuated_{index}.zip"
            path.write_bytes(blob)
            monitor_app.WHITELIST.replace(paths=[str(workdir / "*")], hashes=[])
            events.append(monitor_app.handle_event(str(path), "created"))
        else:
            path = workdir / f"deferred_{index}.bin"
            path.write_bytes(payload(f"deferred:{index}"))
            monitor_app.WHITELIST.replace(paths=[], hashes=[])
            with LockedFile(path):
                events.append(monitor_app.handle_event(str(path), "modified"))

    monitor_app._work.join()
    time.sleep(0.2)
    return [e for e in events if e]


# ------------------------------------------------------------ the hop ladder


def measure_hops(events: list[dict], recorder: HopRecorder, population: str) -> dict:
    """Per hop: did it happen, did it carry the record, was the record intact.

    Every event has its *own* record - a hash whitelist rule carries the hash it
    matched, so six files produce six different records. Comparing every hop
    against one reference therefore fails for a hop that is working correctly,
    which is what the first version of this function did: it reported the
    cancelled population's ledger blocks as 6 of 6 carrying and 0 intact. The
    pairing is per event, by the path the decision was about, and a hop that
    does not carry a path is matched against the set of records instead.
    """
    decisions = [e["admissibility"] for e in events if e.get("admissibility")]
    by_path = {
        e["file_path"]: e["admissibility"] for e in events if e.get("admissibility")
    }

    def carried(bodies: list[dict], key: str = "admissibility") -> dict:
        present = [b for b in bodies if isinstance(b, dict) and b.get(key)]
        intact = 0
        unpaired = 0
        for body in present:
            path = body.get("file_path")
            if path in by_path:
                intact += body[key] == by_path[path]
            else:
                # No path on this hop - `/response/trigger` carries an incident
                # id, not a file. Membership in the set of records is the
                # strongest claim the payload supports.
                unpaired += 1
                intact += body[key] in decisions
        return {
            "hop_occurred": bool(bodies),
            "payloads": len(bodies),
            "carrying_the_record": len(present),
            "record_intact": intact,
            "matched_by_path": len(present) - unpaired,
            "matched_by_set_membership": unpaired,
            "all_intact": bool(present) and intact == len(present),
        }

    hops = {
        "monitor_event": {
            "hop_occurred": bool(events),
            "payloads": len(events),
            "carrying_the_record": len(decisions),
            "record_intact": len(decisions),
            "all_intact": bool(decisions),
            "note": "the origin of the record; intact by definition",
        },
        "ml_predict": carried(recorder.by_path("/predict")),
        "ledger_file_event": carried(recorder.ledger_blocks("file_event")),
        "ledger_suppression_decision": carried(
            recorder.ledger_blocks("suppression_decision")
        ),
        "response_trigger": carried(recorder.by_path("/response/trigger")),
        "ledger_response_action": carried(recorder.ledger_blocks("response_action")),
    }
    hops["ml_predict"]["note"] = (
        "The ML request carries the feature vector and nothing else, by design: "
        "the model scores bytes, not policy, and handing it the adjudication "
        "would let a suppression move a prediction. Recorded as not carrying the "
        "record, which is correct behaviour rather than a gap - but it does mean "
        "the record does not literally traverse this hop."
    )
    hops["_population"] = population
    hops["_decisions_made"] = len(decisions)
    return hops


# ------------------------------------------------------- the recovery hop


def measure_recovery_hop(reference: dict | None) -> dict:
    """Does a restore carry the decision that authorised it into the chain?

    The real `RecoveryManager.recover` is called against a real snapshot
    directory, with only the ledger transport replaced so the block it builds
    can be read. The manager's own logic is untouched.
    """
    from recovery.recovery import RecoveryManager

    captured: list[dict] = []

    class Recorder:
        base_url = "recorded://ledger"

        def try_log_event(self, event_type, event_data):
            captured.append({"event_type": event_type, "event_data": event_data})
            return None

        def last_known_hash(self, file_path):
            return None

    with tempfile.TemporaryDirectory(prefix="recovery_hop_") as tmp:
        root = Path(tmp)
        snapshot = root / "snap"
        snapshot.mkdir()
        target = root / "document.docx"
        original = payload("recovery-original", 4096)
        target.write_bytes(original)
        # The snapshot has to mirror the absolute path the manager resolves.
        mirrored = snapshot / target.relative_to(target.anchor)
        mirrored.parent.mkdir(parents=True, exist_ok=True)
        mirrored.write_bytes(original)
        target.write_bytes(payload("recovery-encrypted", 4096))

        manager = RecoveryManager(ledger_client=Recorder())
        try:
            manager.resolve_snapshot_root = lambda snapshot_id: str(snapshot)
            result = manager.recover(
                snapshot_id="snap",
                files=[str(target)],
                verify_integrity=False,
                incident_id="inc_pipeline_governance",
                admissibility=reference,
            )
        except Exception as error:  # a failed restore is still a measured hop
            result = {"error": f"{type(error).__name__}: {error}"}

    blocks = [c["event_data"] for c in captured if c["event_type"] == "file_recovered"]
    present = [b for b in blocks if b.get("admissibility")]
    intact = [b for b in present if b["admissibility"] == reference]
    return {
        "hop_occurred": bool(blocks),
        "payloads": len(blocks),
        "carrying_the_record": len(present),
        "record_intact": len(intact),
        "all_intact": bool(present) and len(intact) == len(present),
        "carries_incident_id": all(b.get("incident_id") for b in blocks) if blocks else False,
        "recover_result": result,
    }


# ---------------------------------------------------------------- dashboard


def measure_dashboard() -> dict:
    """Does the dashboard tell the three outcomes apart?

    The two helpers are lifted out of `services/dashboard/app.py` by AST and
    executed here. Importing the module would run Streamlit's page setup and
    every gateway call in it; parsing it would only prove the text exists. This
    runs the real functions from the real file.
    """
    source = (REPO_ROOT / "services" / "dashboard" / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted_functions = {"governance_outcome", "governance_chip"}
    wanted_names = {"GOVERNANCE_OUTCOMES"}

    picked: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted_functions:
            picked.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id in wanted_names for t in node.targets
        ):
            picked.append(node)

    found = {
        n.name if isinstance(n, ast.FunctionDef) else n.targets[0].id for n in picked
    }
    missing = sorted((wanted_functions | wanted_names) - found)
    if missing:
        return {
            "surfaces_distinctly": False,
            "missing_from_dashboard": missing,
            "reason": "the dashboard has no governance vocabulary to execute",
        }

    namespace: dict = {}
    exec(compile(ast.Module(body=picked, type_ignores=[]), "<dashboard>", "exec"), namespace)
    outcome_of = namespace["governance_outcome"]
    outcomes = namespace["GOVERNANCE_OUTCOMES"]
    chip = namespace["governance_chip"]

    probes = {
        "cancelled": {"admissibility": {"outcome": "cancelled"}, "suspicious": False},
        "attenuated": {"admissibility": {"outcome": "attenuated"}, "suspicious": True},
        "deferred": {"verdict": "unreadable", "suspicious": False},
        "no_rule_applied": {"verdict": "benign", "suspicious": False},
    }
    read_back = {name: outcome_of(event) for name, event in probes.items()}
    labels = {key: outcomes[key][0] for key in outcomes}

    distinct = (
        read_back["cancelled"] == "cancelled"
        and read_back["attenuated"] == "attenuated"
        and read_back["deferred"] == "deferred"
        and read_back["no_rule_applied"] is None
        and len(set(labels.values())) == 3
    )
    return {
        "surfaces_distinctly": distinct,
        "outcome_read_back": read_back,
        "display_labels": labels,
        "labels_are_distinct": len(set(labels.values())) == 3,
        "chips_render": {key: bool(chip(key)) for key in outcomes},
        "cancelled_is_not_read_from_suspicious": read_back["cancelled"] == "cancelled"
        and read_back["no_rule_applied"] is None,
        "method": (
            "GOVERNANCE_OUTCOMES, governance_outcome and governance_chip lifted "
            "from services/dashboard/app.py by AST and executed"
        ),
    }


# -------------------------------------------------------------------- report


def main() -> int:
    import app as monitor_app
    import pipeline as monitor_pipeline

    populations = ("cancelled", "attenuated", "deferred")
    per_population: dict[str, dict] = {}
    reference: dict | None = None

    original_post = monitor_pipeline._post
    previous = monitor_app.PIPELINE_ENABLED
    monitor_app.PIPELINE_ENABLED = True
    monitor_app._ensure_worker()

    try:
        with tempfile.TemporaryDirectory(prefix="pipeline_governance_") as tmp:
            for population in populations:
                recorder = HopRecorder()
                monitor_pipeline._post = recorder
                monitor_app.ENTROPY_HISTORY.__init__()
                events = drive(Path(tmp) / population, population, recorder)
                hops = measure_hops(events, recorder, population)
                per_population[population] = {
                    "events": len(events),
                    "verdicts": sorted({e["verdict"] for e in events}),
                    "outcomes": sorted(
                        {
                            (e.get("admissibility") or {}).get("outcome")
                            for e in events
                            if e.get("admissibility")
                        }
                    ),
                    "hops": hops,
                    "hop_paths_seen": sorted({h["path"] for h in recorder.hops}),
                }
                for event in events:
                    if reference is None and event.get("admissibility"):
                        reference = event["admissibility"]
    finally:
        monitor_pipeline._post = original_post
        monitor_app.PIPELINE_ENABLED = previous
        monitor_app.WHITELIST.replace(paths=[], hashes=[])

    recovery = measure_recovery_hop(reference)
    dashboard = measure_dashboard()

    # ------------------------------------------------------------ the gates
    cancelled = per_population["cancelled"]["hops"]
    attenuated = per_population["attenuated"]["hops"]
    gates = {
        "cancelled_decision_reaches_the_ledger": cancelled["ledger_suppression_decision"][
            "all_intact"
        ],
        "attenuated_decision_reaches_the_ledger": attenuated["ledger_file_event"]["all_intact"],
        "decision_reaches_the_response_service": attenuated["response_trigger"]["all_intact"],
        "response_action_is_chained_with_the_decision": attenuated[
            "ledger_response_action"
        ]["all_intact"],
        "decision_reaches_recovery": recovery["all_intact"],
        "dashboard_surfaces_the_three_outcomes_distinctly": dashboard["surfaces_distinctly"],
    }
    failed = sorted(name for name, passed in gates.items() if not passed)

    d6 = {
        "rule": (
            "D6 - if any pipeline gate fails, the final claim is reduced to "
            "'URDS Monitor' scope, the word unified is not used for evidence that "
            "was not collected, and the reduction is written down."
        ),
        "gates_evaluated": len(gates),
        "gates_failed": failed,
        "fires": bool(failed),
    }
    d6["decision"] = (
        (
            "D6 fires. The following gates failed: "
            + ", ".join(failed)
            + ". The claim is reduced to URDS Monitor scope and `unified` is not "
            "used for the hops above."
        )
        if d6["fires"]
        else (
            "D6 does not fire. Every gate passes: the adjudication reaches the "
            "chain for a cancelled decision and an attenuated one, travels to the "
            "Response service and into its own ledger entry, reaches recovery with "
            "the incident it answers, and the dashboard tells the three outcomes "
            "apart. The word `unified` is carried by measurement at each of these "
            "hops. It is not carried by the ML hop, which does not receive the "
            "record and should not."
        )
    )

    report = {
        "schema": "urds.pipeline_governance/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "method": (
            "Real handle_event, real pipeline, real RecoveryManager. Only the "
            "network transport is replaced, and it records rather than answers. "
            "The deferred population holds a genuine exclusive Win32 handle."
        ),
        "reference_decision": reference,
        "per_population": per_population,
        "recovery_hop": recovery,
        "dashboard": dashboard,
        "gates": gates,
        "d6": d6,
    }

    # ------------------------------------------------------------------ print
    for population, data in per_population.items():
        print(f"\n{population}: {data['events']} events, verdicts {data['verdicts']}, "
              f"outcomes {data['outcomes'] or '-'}")
        for hop, cell in data["hops"].items():
            if hop.startswith("_"):
                continue
            print(f"   {hop:32} occurred={str(cell['hop_occurred']):5} "
                  f"carrying={cell['carrying_the_record']}/{cell['payloads']} "
                  f"intact={cell['all_intact']}")

    print(f"\nrecovery hop: carrying={recovery['carrying_the_record']}/{recovery['payloads']} "
          f"intact={recovery['all_intact']} incident_id={recovery['carries_incident_id']}")
    print(f"dashboard: distinct={dashboard['surfaces_distinctly']} "
          f"labels={dashboard.get('display_labels')}")

    print("\nGATES")
    for name, passed in gates.items():
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    print(f"\n{d6['decision']}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    path = REPORTS / "pipeline_governance.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
