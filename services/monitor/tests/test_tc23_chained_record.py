"""TC-23 (SI): every mitigation decision reaches the chain, complete.

Table 9.7 row: *every mitigation decision, including attenuated and deferred
ones, is chained with mitigation identifier, validation state, capability levels,
policy version and reason.*

Five fields, and until P6.6 three of them were written. `validation_state` and
`policy_version` were not, which is `NOVELTY_PROOF_PLAN.md` §9 row 10 and why the
Phase 6 report carried it as partial.

The two missing ones are the two that let a decision be *re-derived* rather than
merely read. Without `validation_state` the record cannot distinguish "no
validator exists for this format" from "the validator ran and could not finish" -
the tri-state collapses both to null, and §9.3 finding 1 is precisely about that
distinction. Without `policy_version` the rule that produced the decision is an
environment variable recorded nowhere, so a chain verified a year later says what
was decided and not what it was decided under.

Three block types can hold an adjudication and all three are asserted:

    suppression_decision   a cancelled decision, chained on its own path
    file_event             an attenuated one, which still fans out
    response_action        the attenuated one again, at the response hop

Adding the fields to the first two left 24 of 36 blocks complete in
`scripts/ledger_coverage.py`; the response hop was the other twelve, and a record
complete on one block and truncated on another is not a complete record.

The row is SI's. The tests live in the Monitor because that is where the block
payloads are built and where `handle_event` can be driven end to end with the
transport stubbed.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import sys
import time
import zipfile
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402
import containers  # noqa: E402
import detection  # noqa: E402
import pipeline  # noqa: E402

REQUIRED_FIELDS = {
    "mitigation_id": lambda b: (b.get("admissibility") or {}).get("rule"),
    "validation_state": lambda b: b.get("validation_state"),
    "capability_levels": lambda b: (
        (b.get("admissibility") or {}).get("forgery_cost")
        and (b.get("admissibility") or {}).get("avoidance_cost")
    ),
    "policy_version": lambda b: b.get("policy_version"),
    "reason": lambda b: (b.get("admissibility") or {}).get("reason"),
}

ADJUDICATION_BLOCKS = ("file_event", "suppression_decision", "response_action")


def payload(tag: str, size: int = 120_000) -> bytes:
    return hashlib.shake_256(tag.encode()).digest(size)


def truncated_zip(tag: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("payload.bin", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 0
        archive.writestr(info, payload(tag))
    full = buffer.getvalue()
    return full[: len(full) - 200]


class Recorder:
    """Stands in for `pipeline._post` and keeps every body it was handed."""

    def __init__(self) -> None:
        self.writes: list[dict] = []

    def __call__(self, client, base_url, path, body):
        if path == "/ledger/log":
            self.writes.append(body)
            return {"block_id": len(self.writes), "current_hash": "a" * 64}
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.95, "threat_level": "critical"}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["admin_notified"]}
        return {}

    def adjudications(self) -> list[dict]:
        return [
            w["event_data"]
            for w in self.writes
            if w.get("event_type") in ADJUDICATION_BLOCKS
            and (w.get("event_data") or {}).get("admissibility")
        ]


@pytest.fixture
def drive(monkeypatch, tmp_path):
    """Run one file through the real `handle_event` with the fan-out recorded."""
    recorder = Recorder()
    monkeypatch.setattr(pipeline, "_post", recorder)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monitor_app._ensure_worker()
    monitor_app.ENTROPY_HISTORY.clear()

    def run(name: str, blob: bytes, *, paths=None, hashes=None, policy=None):
        if policy is not None:
            monkeypatch.setattr(detection, "DEFAULT_CONTAINER_POLICY", policy)
        monitor_app.WHITELIST.replace(paths=paths or [], hashes=hashes or [])
        target = tmp_path / name
        target.write_bytes(blob)
        event = monitor_app.handle_event(str(target), "created")
        monitor_app._work.join()
        time.sleep(0.15)
        return event, recorder

    yield run
    monitor_app.WHITELIST.replace(paths=[], hashes=[])
    monitor_app.ENTROPY_HISTORY.clear()


def assert_complete(block: dict, where: str) -> None:
    missing = [name for name, probe in REQUIRED_FIELDS.items() if not probe(block)]
    assert missing == [], f"{where} is missing {missing}: {json.dumps(block, default=str)[:400]}"


def test_tc23_a_cancelled_decision_is_chained_complete(drive):
    """A hash whitelist entry, which outranks static_entropy and cancels it.

    This is the one an auditor most needs and the one the chain never held before
    P6.4: the fan-out is gated on `suppression is None`, so a cancelled alert
    reaches the ledger only on the governance path.
    """
    blob = payload("tc23:cancelled")
    event, recorder = drive(
        "cancelled.docx", blob, hashes=[hashlib.sha256(blob).hexdigest()]
    )

    assert event["admissibility"]["outcome"] == "cancelled"
    assert event["suspicious"] is False, "the alert was cancelled, as intended"

    blocks = [w for w in recorder.writes if w["event_type"] == "suppression_decision"]
    assert len(blocks) == 1, [w["event_type"] for w in recorder.writes]
    data = blocks[0]["event_data"]

    assert_complete(data, "suppression_decision")
    assert data["admissibility"]["rule"] == "hash"
    assert data["validation_state"] == containers.UNVALIDATED
    assert data["policy_version"] == detection.DEFAULT_CONTAINER_POLICY
    # And the verdict it silenced, so the entry says what disappeared.
    assert data["verdict"] == "suspected_encryption"


def test_tc23_an_attenuated_decision_is_chained_complete_on_every_block(drive):
    """A path whitelist against structural_mismatch, which outranks it.

    The alert stands, so the event goes through the pipeline and the record is
    chained twice - on the `file_event` and again on the `response_action`. Both
    have to be complete.
    """
    blob = b"PK\x03\x04" + payload("tc23:attenuated")
    event, recorder = drive("attenuated.zip", blob, paths=["*"])

    assert event["admissibility"]["outcome"] == "attenuated"
    assert event["suspicious"] is True, "an outranked rule must not cancel"

    carried = recorder.adjudications()
    types = sorted(
        w["event_type"] for w in recorder.writes if (w.get("event_data") or {}).get("admissibility")
    )
    assert types == ["file_event", "response_action"], types
    assert len(carried) == 2

    for block in carried:
        assert_complete(block, "attenuated block")
        assert block["admissibility"]["rule"] == "path"
        assert block["validation_state"] == containers.FORGED
        assert block["policy_version"] == detection.DEFAULT_CONTAINER_POLICY


def test_tc23_a_deferred_decision_is_chained_complete(drive):
    """The third outcome the row names, and the one P6.7 created.

    A half-written ZIP under a policy that refuses INCOMPLETE as proof yields the
    `deferred` verdict. It is adjudicated like any other suspicious verdict, and
    `validation_state` is what makes the entry legible afterwards: it says
    `incomplete`, which is the fact that produced the deferral rather than a
    conclusion.

    **The path whitelist cancels it**, and that is the recorded outcome rather
    than an oversight. Deferring does not change the signal - deliberately, so
    the deferred state is a statement about evidence and not a new severity - and
    the signal is `static_entropy`, which the deployed table prices NEGLIGIBLE.
    Every suppression outranks it. This is exactly the cell policy F of
    `docs/ADMISSION_RECOMPUTE.md` attenuates instead: on the plan's §5.2 ladder
    `path` forgery and `static_entropy` avoidance tie at Level 0, and §5.3's
    strict rule breaks the tie against the suppression. Policy F is not deployed,
    so this cancels, and the record of the cancellation is what has to be
    complete.
    """
    event, recorder = drive(
        "deferred.zip",
        truncated_zip("tc23:deferred"),
        paths=["*"],
        policy=detection.CONTAINER_POLICY_RATIO,
    )

    assert event["verdict"] == detection.DEFERRED
    assert event["admissibility"] is not None, "a deferral must still be adjudicated"
    assert event["admissibility"]["outcome"] == "cancelled"
    assert event["validation_state"] == containers.INCOMPLETE

    blocks = [w for w in recorder.writes if w["event_type"] == "suppression_decision"]
    assert len(blocks) == 1, "the cancelled deferral never reached the chain"
    data = blocks[0]["event_data"]

    assert_complete(data, "deferred block")
    assert data["validation_state"] == containers.INCOMPLETE, (
        "the one field that says why this was deferred rather than concluded"
    )
    assert data["policy_version"] == detection.CONTAINER_POLICY_RATIO
    assert data["verdict"] == detection.DEFERRED, (
        "the chain has to hold the deferral itself, not a generic suppression"
    )


def test_tc23_a_deferral_the_rule_does_not_outrank_is_attenuated_and_chained(drive):
    """The other half: a deferral that survives its suppression.

    A truncated JPEG reads FORGED rather than INCOMPLETE, so to get a deferral
    the rule has to lose on cost instead. Training mode is priced LOW and
    `partial_entropy` MODERATE, but a deferral's signal is `static_entropy` -
    so the only way to attenuate one on the deployed table is a rule cheaper than
    NEGLIGIBLE, and there is none. Recorded as the finding it is: **under the
    deployed cost table every deferral is cancellable by any operator rule that
    matches it.** The record survives, which is what the row requires; the alert
    does not.
    """
    import admissibility

    assert admissibility.avoidance_cost("static_entropy") == admissibility.NEGLIGIBLE
    cheaper = [
        rule
        for rule, cost in admissibility.FORGERY_COST.items()
        if cost <= admissibility.NEGLIGIBLE
    ]
    assert cheaper == [], (
        "a suppression at or below NEGLIGIBLE now exists; a deferral could be "
        "attenuated and this finding needs re-stating"
    )


def test_tc23_validation_state_tells_the_three_null_cases_apart(drive):
    """The reason the field exists.

    `container_valid` is null for all three of these. The chain has to say which.
    """
    cases = {
        "no_validator.rar": (b"Rar!\x1a\x07" + payload("tc23:rar"), containers.UNVALIDATED),
        "forged.zip": (b"PK\x03\x04" + payload("tc23:zip"), containers.FORGED),
        "genuine.gz": (gzip.compress(payload("tc23:gz")), containers.VALID),
    }
    seen = {}
    for name, (blob, expected) in cases.items():
        event, _recorder = drive(name, blob, paths=["*"])
        seen[name] = event["validation_state"]
        assert event["validation_state"] == expected, name

    assert len(set(seen.values())) == 3, seen


def test_tc23_the_five_field_names_are_the_ones_the_plan_asks_for():
    """A rename would pass every assertion above and break every auditor.

    The five names are quoted from `NOVELTY_PROOF_PLAN.md` §9 row 10, and
    `scripts/ledger_coverage.py` measures completeness against the same set.
    """
    assert set(REQUIRED_FIELDS) == {
        "mitigation_id",
        "validation_state",
        "capability_levels",
        "policy_version",
        "reason",
    }

    report = Path(__file__).resolve().parents[3] / "reports" / "ledger_coverage.json"
    if not report.exists():
        pytest.skip("reports/ledger_coverage.json is absent")
    recorded = json.loads(report.read_text(encoding="utf-8"))["record_completeness"]
    assert set(recorded["required_fields"]) == set(REQUIRED_FIELDS)
    assert recorded["meets_target"] is True
    assert recorded["complete_blocks"] == recorded["chained_blocks"]
