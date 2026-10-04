"""How many mitigation decisions actually reach the ledger - SI.

Table 9.8 carries the row *"Mitigation decisions reaching the ledger — 100%"*.
`docs/MITIGATION_INVENTORY.md` M-16 says from source reading that the figure
cannot be 100%, because `app.py:491` gates the downstream fan-out on
`suppression is None` and the ledger is only reachable through that fan-out - so
a *cancelled* suppression is never chained.

This measures it instead of arguing it. Three populations are driven through the
real `handle_event` with the fan-out pointed at a stub that records every
`/ledger/log` body:

    cancelled    a whitelist hash rule against a signal it outranks
    attenuated   a whitelist path rule against a signal that outranks it
    ungoverned   the container exemption, which never reaches adjudicate at all

and the report says, per population, how many events produced an adjudication and
how many of those adjudications arrived at the ledger.

It also asserts a *value* on every ledger write, not just a field count: an
event may name a process only when attribution resolved to CERTAIN
(`unsupported_pid`, claim C-16; ported from fix/evidence-integrity's 58ce021,
docs/CORRECTIONS.md). The same rule can be run over a real ledger:

    .venv\\Scripts\\python.exe scripts/ledger_coverage.py
    .venv\\Scripts\\python.exe scripts/ledger_coverage.py --ledger-db <run>\\data\\ledger.db

Writes reports/ledger_coverage.json only when URDS_WRITE_REPORTS=1. The
`--ledger-db` scan writes nothing, opens the database read-only, and exits 1 if
any block names a process the rule does not allow.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"

sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

EVENTS_PER_POPULATION = 12


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def payload(tag: str, size: int = 120_000) -> bytes:
    return hashlib.shake_256(tag.encode()).digest(size)


def unsupported_pid(event_data: dict) -> str | None:
    """Why this ledger event names a process the evidence does not support.

    None when it is fine. The rule is the pipeline's own: an event may name a
    process only when attribution was CERTAIN. A `process_id` of None is not an
    offence - "no process was identified" is the honest answer and has to stay
    expressible, or the pressure to invent one comes straight back. A number
    with anything short of CERTAIN beside it, or with nothing beside it, is.

    `attribution_candidates` is not read: it lists every PID whose audited
    write fell in the window, which is the evidence, not a claim that any one
    of them did it. That is where a PROBABLE answer's PIDs go on this branch.
    """
    if "process_id" not in event_data:
        return None
    pid = event_data.get("process_id")
    if pid is None:
        return None
    confidence = event_data.get("attribution_confidence")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return f"process_id {pid!r} is not a positive integer"
    if confidence != "certain":
        return (f"process_id {pid} is named with attribution_confidence "
                f"{confidence!r}; only 'certain' supports naming one")
    return None


def scan_writes(writes: list[dict]) -> dict:
    """`unsupported_pid` over ledger writes shaped `{event_type, event_data}`."""
    offences = []
    named = 0
    for write in writes:
        data = write.get("event_data") or {}
        if data.get("process_id") is not None:
            named += 1
        why = unsupported_pid(data)
        if why is None:
            continue
        offences.append({
            "block_id": write.get("block_id"),
            "event_type": write.get("event_type"),
            "file_path": data.get("file_path"),
            "process_id": data.get("process_id"),
            "attribution_confidence": data.get("attribution_confidence"),
            "why": why,
        })
    return {
        "events_examined": len(writes),
        "events_naming_a_process": named,
        "unsupported": len(offences),
        "detail": offences,
    }


def scan_ledger_db(path: str) -> dict:
    """The same rule over every block of a real ledger, opened read-only."""
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute("SELECT id, event_type, event_data FROM blocks ORDER BY id").fetchall()
    finally:
        conn.close()
    writes = []
    for block_id, event_type, raw in rows:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            data = {}
        writes.append({"block_id": block_id, "event_type": event_type,
                       "event_data": data if isinstance(data, dict) else {}})
    return scan_writes(writes)


class LedgerStub:
    """Records every ledger write the pipeline attempts.

    Replaces `pipeline._post` rather than standing up a real service: the
    question is which calls are *made*, and a stub answers it without needing
    the Compose stack. ML and response calls are answered plausibly so the
    pipeline runs to completion and the ledger call is actually reached.
    """

    def __init__(self) -> None:
        self.ledger_writes: list[dict] = []
        self.calls: list[str] = []

    def __call__(self, client, base_url, path, payload_body):
        self.calls.append(path)
        if path == "/ledger/log":
            self.ledger_writes.append(payload_body)
            return {"block_id": len(self.ledger_writes), "current_hash": "stub"}
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.95, "threat_level": "critical"}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["admin_notified"]}
        return {}

    # Any chained block that carries an adjudication counts, whatever its type.
    # This filter originally accepted `file_event` only, which was correct while
    # that was the sole block type able to hold one - and became an undercount
    # the moment `suppression_decision` existed, reporting the M-16 repair as
    # having changed nothing. The measurement was wrong, not the repair.
    ADJUDICATION_BLOCK_TYPES = ("file_event", "suppression_decision", "response_action")

    def adjudications(self) -> list[dict]:
        return [
            w["event_data"]["admissibility"]
            for w in self.ledger_writes
            if w.get("event_type") in self.ADJUDICATION_BLOCK_TYPES
            and (w.get("event_data") or {}).get("admissibility")
        ]

    def decisions_chained(self) -> set[str]:
        """The *files* whose decision reached the chain, not the writes it took.

        Counting writes reported 150% once the response hop began carrying the
        record too: an attenuated alert chains its adjudication in `file_event`
        and again in `response_action`. Both are correct and it is still one
        decision. Coverage is a question about decisions, so this deduplicates
        by the path the decision was about.
        """
        return {
            w["event_data"].get("file_path")
            for w in self.ledger_writes
            if w.get("event_type") in self.ADJUDICATION_BLOCK_TYPES
            and (w.get("event_data") or {}).get("admissibility")
            and (w.get("event_data") or {}).get("file_path")
        }

    # NOVELTY_PROOF_PLAN.md §9 row 10, and TC-23, name five things every chained
    # mitigation decision must carry. Coverage says the decision arrived; this
    # says it arrived whole. Two of the five were absent until P6.6, and the row
    # was reported as partial for exactly that reason.
    REQUIRED_RECORD_FIELDS = {
        "mitigation_id": lambda b: (b.get("admissibility") or {}).get("rule"),
        "validation_state": lambda b: b.get("validation_state"),
        "capability_levels": lambda b: (
            (b.get("admissibility") or {}).get("forgery_cost")
            and (b.get("admissibility") or {}).get("avoidance_cost")
        ),
        "policy_version": lambda b: b.get("policy_version"),
        "reason": lambda b: (b.get("admissibility") or {}).get("reason"),
    }

    def record_completeness(self) -> dict:
        """Per required field, how many chained adjudications actually carry it.

        Counted over blocks, not over files: an attenuated decision is chained on
        both a `file_event` and a `response_action`, and a record that is
        complete on one and not the other is not a complete record.
        """
        blocks = [
            w["event_data"]
            for w in self.ledger_writes
            if w.get("event_type") in self.ADJUDICATION_BLOCK_TYPES
            and (w.get("event_data") or {}).get("admissibility")
        ]
        present = {
            name: sum(1 for b in blocks if probe(b))
            for name, probe in self.REQUIRED_RECORD_FIELDS.items()
        }
        return {
            "blocks": len(blocks),
            "present": present,
            "complete": sum(
                1
                for b in blocks
                if all(probe(b) for probe in self.REQUIRED_RECORD_FIELDS.values())
            ),
            "example": (
                {
                    name: probe(blocks[0])
                    for name, probe in self.REQUIRED_RECORD_FIELDS.items()
                }
                if blocks
                else None
            ),
        }

    def unsupported_pids(self) -> dict:
        """Every ledger write naming a process the evidence does not support.

        A *value* assertion. `record_completeness` above asks whether a field
        is present, and a block carrying an invented PID satisfies that
        perfectly - which is how an invented process_id sat in the chain while
        the row meant to police it stayed green (docs/CORRECTIONS.md).
        """
        return scan_writes(self.ledger_writes)

    def block_types(self) -> dict:
        counts: dict[str, int] = {}
        for write in self.ledger_writes:
            key = write.get("event_type") or "unknown"
            counts[key] = counts.get(key, 0) + 1
        return counts


def drive(workdir: Path, monkeypatched_stub: LedgerStub, population: str) -> dict:
    """Write one population and return what the Monitor and the ledger saw."""
    import app as monitor_app
    import suppression as suppression_module

    workdir.mkdir(parents=True, exist_ok=True)
    results = []

    for index in range(EVENTS_PER_POPULATION):
        if population == "cancelled":
            # A hash whitelist entry (HIGH to forge) against static_entropy
            # (NEGLIGIBLE to avoid). The suppression outranks the signal, so
            # adjudicate admits it and the alert is cancelled.
            blob = payload(f"cancelled:{index}")
            path = workdir / f"cancelled_{index}.docx"
            path.write_bytes(blob)
            monitor_app.WHITELIST.replace(paths=[], hashes=[hashlib.sha256(blob).hexdigest()])
        elif population == "attenuated":
            # A path whitelist entry (LOW to forge) against structural_mismatch
            # (MODERATE to avoid, as declared). The signal outranks the rule, so
            # the alert stands and the decision is attenuated.
            blob = b"PK\x03\x04" + payload(f"attenuated:{index}")
            path = workdir / f"attenuated_{index}.zip"
            path.write_bytes(blob)
            monitor_app.WHITELIST.replace(paths=[str(workdir / "*")], hashes=[])
        else:
            # The container exemption: a genuine gzip member carrying
            # ciphertext. Never reaches adjudicate, because the verdict is not
            # suspicious and app.py:424 only adjudicates suspicious verdicts.
            path = workdir / f"ungoverned_{index}.gz"
            path.write_bytes(gzip.compress(payload(f"ungoverned:{index}")))
            monitor_app.WHITELIST.replace(paths=[], hashes=[])

        event = monitor_app.handle_event(str(path), "created")
        results.append(
            {
                "verdict": event["verdict"],
                "suspicious": event["suspicious"],
                "signal": event["signal"],
                "adjudicated": event["admissibility"] is not None,
                "outcome": (event["admissibility"] or {}).get("outcome"),
            }
        )

    # The fan-out is queued to a worker thread; let it drain.
    monitor_app._work.join()
    time.sleep(0.2)

    adjudicated = [r for r in results if r["adjudicated"]]
    return {
        "events": len(results),
        "adjudicated": len(adjudicated),
        "outcomes": sorted({r["outcome"] for r in adjudicated if r["outcome"]}),
        "verdicts": sorted({r["verdict"] for r in results}),
        "signals": sorted({r["signal"] for r in results if r["signal"]}),
        "suspicious_after_suppression": sum(1 for r in results if r["suspicious"]),
    }


def scan_db_main(path: str) -> int:
    """`--ledger-db`: the C-16 rule over a real run's chain. Writes nothing."""
    result = scan_ledger_db(path)
    print(f"process attribution integrity - {path}")
    print(f"  {result['events_examined']} blocks examined, {result['events_naming_a_process']} name a "
          f"process, {result['unsupported']} unsupported")
    by_kind: dict[str, int] = {}
    for entry in result["detail"]:
        why = entry["why"].split(";")[0].replace(f"process_id {entry['process_id']!r}", "process_id N")
        key = f"{entry['event_type']}: {why}"
        by_kind[key] = by_kind.get(key, 0) + 1
    for key, count in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print(f"    {count:5d}  {key}")
    return 1 if result["unsupported"] else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ledger-db", help="scan this ledger SQLite file instead (read-only, writes nothing)")
    args = parser.parse_args()
    if args.ledger_db:
        return scan_db_main(args.ledger_db)

    import app as monitor_app
    import pipeline as monitor_pipeline
    import suppression as suppression_module

    populations = ("cancelled", "attenuated", "ungoverned")
    findings: dict[str, dict] = {}

    original_post = monitor_pipeline._post
    previous_pipeline = monitor_app.PIPELINE_ENABLED
    monitor_app.PIPELINE_ENABLED = True
    monitor_app._ensure_worker()

    try:
        with tempfile.TemporaryDirectory(prefix="ledger_coverage_") as tmp:
            for population in populations:
                stub = LedgerStub()
                monitor_pipeline._post = stub
                monitor_app.ENTROPY_HISTORY.__init__()  # no history: judge each file fresh
                monitored = drive(Path(tmp) / population, stub, population)
                findings[population] = {
                    **monitored,
                    "ledger_writes": len(stub.ledger_writes),
                    "ledger_event_types": sorted({w.get("event_type") for w in stub.ledger_writes}),
                    "adjudication_writes": len(stub.adjudications()),
                    "adjudications_reaching_ledger": len(stub.decisions_chained()),
                    "ledger_block_types": stub.block_types(),
                    "record_completeness": stub.record_completeness(),
                    "unsupported_pids": stub.unsupported_pids(),
                }
    finally:
        monitor_pipeline._post = original_post
        monitor_app.PIPELINE_ENABLED = previous_pipeline
        monitor_app.WHITELIST.replace(paths=[], hashes=[])

    total_adjudicated = sum(f["adjudicated"] for f in findings.values())
    total_reaching = sum(f["adjudications_reaching_ledger"] for f in findings.values())
    coverage = (total_reaching / total_adjudicated) if total_adjudicated else 0.0

    completeness = [f["record_completeness"] for f in findings.values()]
    chained_blocks = sum(c["blocks"] for c in completeness)
    complete_blocks = sum(c["complete"] for c in completeness)
    field_totals = {
        name: sum(c["present"].get(name, 0) for c in completeness)
        for name in LedgerStub.REQUIRED_RECORD_FIELDS
    }

    pid_scans = [f["unsupported_pids"] for f in findings.values()]
    pids_examined = sum(s["events_examined"] for s in pid_scans)
    pids_named = sum(s["events_naming_a_process"] for s in pid_scans)
    pids_unsupported = sum(s["unsupported"] for s in pid_scans)
    pid_detail = [entry for s in pid_scans for entry in s["detail"]]

    report = {
        "schema": "urds.ledger_coverage/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "table_9_8_row": "Mitigation decisions reaching the ledger",
        "target": "100%",
        "measured_coverage": round(coverage, 4),
        "meets_target": total_reaching == total_adjudicated and total_adjudicated > 0,
        "adjudications_made": total_adjudicated,
        "adjudications_reaching_ledger": total_reaching,
        "process_attribution_integrity": {
            "rule": "A ledger event may name a process only when attribution "
                    "resolved to CERTAIN. process_id None is the honest value "
                    "for an unattributed write and is not counted against "
                    "this; a PID asserted without CERTAIN evidence behind it "
                    "is. attribution_candidates, the PIDs whose audited writes "
                    "fell in the window, are evidence and are not read.",
            "why_this_row_exists": "The completeness row below counts whether "
                                   "a field is present. It cannot tell an "
                                   "attributed PID from an invented one, and "
                                   "for a period it did not: see "
                                   "docs/CORRECTIONS.md.",
            "what_this_figure_means": "No attribution source runs here, so every "
                                      "answer is UNKNOWN and no event names a "
                                      "process: the zero is vacuously met and "
                                      "measures restraint, not correct "
                                      "attribution. The live chain is checked "
                                      "with --ledger-db on a real run's ledger.",
            "events_examined": pids_examined,
            "events_naming_a_process": pids_named,
            "unsupported": pids_unsupported,
            "detail": pid_detail,
            "meets_target": pids_unsupported == 0,
        },
        "record_completeness": {
            "required_fields": sorted(LedgerStub.REQUIRED_RECORD_FIELDS),
            "source": "NOVELTY_PROOF_PLAN.md §9 row 10; regression TC-23",
            "chained_blocks": chained_blocks,
            "complete_blocks": complete_blocks,
            "fraction_complete": (
                round(complete_blocks / chained_blocks, 4) if chained_blocks else 0.0
            ),
            "present_by_field": field_totals,
            "meets_target": chained_blocks > 0 and complete_blocks == chained_blocks,
        },
        "by_population": findings,
        "mechanism": (
            "The detection fan-out is still gated on `suppression is None`, and it "
            "still must be: a cancelled alert must not fire a response, or the "
            "operator's own rule would be pointless. What changed in P6.4 is that "
            "the *decision* no longer travels only on that path. A cancelled "
            "suppression now queues a `governance` work item of its own, and "
            "pipeline.log_governance_decision chains it as a `suppression_decision` "
            "block carrying the adjudication, the verdict it silenced and both "
            "costs - with no prediction and no response. An attenuated one is "
            "chained as before, in event_data.admissibility on the `file_event` "
            "block, and now a second time on the `response_action` block. The "
            "container exemption still produces no adjudication at all: app.py only "
            "adjudicates a verdict that is already suspicious, and benign_compressed "
            "is not - so it remains outside the governance layer entirely and this "
            "measurement counts no decision for it, because none was made."
        ),
        "what_this_row_does_not_cover": (
            "100% of the decisions the governance layer *makes*. The ungoverned "
            "population makes none, so it contributes nothing to either side of "
            "the ratio. The container exemption cancels evidence on every one of "
            "those twelve events and the chain holds no record of it. That gap is "
            "the subject of the P6.1 repair, not of this row, and reading this "
            "100% as 'every evidence-cancelling path is audited' would be wrong."
        ),
    }

    print("Table 9.8 - mitigation decisions reaching the ledger")
    print(f"  target 100%   measured {coverage:.1%}   meets_target={report['meets_target']}")
    for name, f in findings.items():
        print(
            f"  {name:<11} events={f['events']:<3} adjudicated={f['adjudicated']:<3} "
            f"outcomes={f['outcomes'] or '-'} ledger_writes={f['ledger_writes']:<3} "
            f"adjudications_chained={f['adjudications_reaching_ledger']}"
        )

    print("\nrow 10 - is the chained record complete?")
    print(
        f"  {complete_blocks}/{chained_blocks} chained adjudication blocks carry all "
        f"{len(LedgerStub.REQUIRED_RECORD_FIELDS)} required fields"
    )
    for name, count in sorted(field_totals.items()):
        print(f"    {name:<18} {count}/{chained_blocks}")

    print()
    print("process attribution integrity - does the chain name a process it cannot support?")
    print(f"  {pids_examined} ledger events examined, {pids_named} name a process, "
          f"{pids_unsupported} unsupported")
    for entry in pid_detail:
        print(f"    {entry['event_type']}: {entry['why']}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "ledger_coverage.json").write_text(json.dumps(report, indent=2))
    print(f"\nwrote {REPORTS / 'ledger_coverage.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
