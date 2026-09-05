"""TC-18 (AS): every mitigation × signal pair, against the frozen table.

Table 9.7 row: *every mitigation × signal pair produces the recorded admission
under the frozen table; flips are asserted.*

`docs/ADMISSION_RECOMPUTE.md` and `reports/admission_recompute.json` are generated
by `scripts/admission_recompute.py`, which restates `adjudicate`'s comparison
rather than calling it - it has to, because it evaluates policies that are not
deployed. That restatement is the seam: the matrix can be right about a rule the
module no longer applies, and nothing would say so.

This test closes the seam from both ends.

  * Every live cell is driven through the real `admissibility.adjudicate`, and
    the outcome must equal what the report records for the **deployed** policy.
    Policy B is deployed as of P6.8, not policy A.
  * The declared cost table the report computed against must still be the table
    in `admissibility.py`. A cost changed in the module without regenerating the
    report would otherwise leave every cell agreeing with a stale number.
  * The recorded flips are re-derived from the recorded matrix and must match the
    recorded list, so the flip table cannot drift from the cells it summarises.

The `container` row is not live. `detection.classify` decides the exemption in a
branch and `app.handle_event` only adjudicates a verdict that is already
suspicious, so a `benign_compressed` verdict never reaches `adjudicate` at all.
That is §9.3 finding 1, and the row is skipped here for the reason the report
gives rather than quietly dropped.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import admissibility  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
REPORT = REPO_ROOT / "reports" / "admission_recompute.json"

# The policy `adjudicate` actually implements: `>` against the declared costs.
DEPLOYED_POLICY = "B"

pytestmark = pytest.mark.skipif(
    not REPORT.exists(),
    reason="reports/admission_recompute.json is absent; run scripts/admission_recompute.py",
)


@pytest.fixture(scope="module")
def report() -> dict:
    return json.loads(REPORT.read_text(encoding="utf-8"))


def live_cells(report: dict) -> list[tuple[str, str, dict]]:
    return [
        (cell["suppression"], cell["signal"], cell)
        for key, cell in report["matrix"][DEPLOYED_POLICY].items()
        if cell["admitted"] is not None
    ]


def test_tc18_the_deployed_policy_is_the_one_the_report_labels_deployed(report):
    """`>` is what the module does, and B is what the report calls `>`+declared."""
    spec = report["policies"][DEPLOYED_POLICY]
    assert spec["rule"] == ">"
    assert spec["costs"] == "declared"
    assert "DEPLOYED" in spec["label"], spec["label"]

    # And the module really does implement `>`, not `>=`. A tie must attenuate.
    tie = admissibility.adjudicate(
        {"signal": "static_entropy"}, {"rule": "unpriced-rule", "value": "x"}
    )
    assert admissibility.forgery_cost("unpriced-rule") == admissibility.avoidance_cost(
        "static_entropy"
    ), "this case only tests the comparison if the two costs are equal"
    assert tie["admitted"] is False
    assert tie["outcome"] == "attenuated"


def test_tc18_the_report_was_computed_against_the_table_that_is_deployed(report):
    """Guards against a cost edited in the module without regenerating."""
    for name, spec in report["suppressions"].items():
        if spec["declared"] is None:
            continue
        assert admissibility.FORGERY_COST[name] == spec["declared"], name
    for name, spec in report["signals"].items():
        assert admissibility.AVOIDANCE_COST[name] == spec["declared"], name

    assert set(report["signals"]) == set(admissibility.AVOIDANCE_COST)
    live = {n for n, s in report["suppressions"].items() if s["live"]}
    assert live == set(admissibility.FORGERY_COST)


def test_tc18_every_live_cell_is_covered(report):
    """The matrix has to be complete, or "every pair" means nothing."""
    cells = live_cells(report)
    assert len(cells) == len(admissibility.FORGERY_COST) * len(
        admissibility.AVOIDANCE_COST
    ) == 15

    ungoverned = [
        key
        for key, cell in report["matrix"][DEPLOYED_POLICY].items()
        if cell["admitted"] is None
    ]
    assert len(ungoverned) == 5, "the container exemption's five cells"
    assert all(key.startswith("container|") for key in ungoverned)


@pytest.mark.parametrize(
    "case",
    [
        (rule, signal)
        for rule in sorted(admissibility.FORGERY_COST)
        for signal in sorted(admissibility.AVOIDANCE_COST)
    ],
    ids=lambda case: f"{case[0]}x{case[1]}",
)
def test_tc18_adjudicate_matches_the_recorded_cell(case, report):
    """The row. Real `adjudicate`, recorded outcome, one pair at a time."""
    rule, signal = case
    recorded = report["matrix"][DEPLOYED_POLICY][f"{rule}|{signal}"]

    decision = admissibility.adjudicate(
        {"signal": signal}, {"rule": rule, "value": "operator-supplied"}
    )

    assert decision["admitted"] is recorded["admitted"], recorded
    assert decision["outcome"] == recorded["outcome"], recorded
    assert decision["forgery_cost"] == recorded["forgery_cost"]
    assert decision["avoidance_cost"] == recorded["avoidance_cost"]
    # An outranked rule is attenuated, never discarded: the record survives.
    assert decision["rule"] == rule
    assert decision["reason"]


def test_tc18_the_recorded_flips_are_exactly_what_the_matrix_implies(report):
    """The flip table cannot drift from the cells it summarises."""
    baseline = report["matrix"]["A"]
    derived = []
    for policy, cells in report["matrix"].items():
        if policy == "A":
            continue
        for key, cell in cells.items():
            base = baseline[key]
            if base["admitted"] is None or cell["admitted"] is None:
                continue
            if base["admitted"] != cell["admitted"]:
                derived.append((policy, cell["suppression"], cell["signal"]))

    recorded = [(f["policy"], f["suppression"], f["signal"]) for f in report["flips"]]
    assert sorted(derived) == sorted(recorded)
    assert len(recorded) == report["flip_count"]


def test_tc18_the_strict_rule_alone_flips_nothing_on_the_declared_table(report):
    """Why adopting §5.3's rule was safe, asserted rather than remembered.

    Policy B is the rule change with the deployed costs. If it ever stops being
    cell-for-cell identical to policy A, the change stopped being a no-op and the
    write-up in `docs/ADMISSION_RECOMPUTE.md` needs rewriting.
    """
    assert [f for f in report["flips"] if f["policy"] == "B"] == []


def test_tc18_d1_fires_on_the_plan_ladder_and_not_on_the_code_ladder(report):
    """The finding, locked in. Policy F is the plan applied end to end.

    §9.7 D1 fires when path-whitelist and training-mode admissions flip from
    admitted to attenuated. Phase 5 answered "none do" on the four-point ladder.
    On the plan's five-level ladder four do. Both halves are asserted, because a
    change that quietly removed either would erase the result.
    """
    predicted = [
        f
        for f in report["flips"]
        if f["suppression"] in {"path", "training_mode"}
        and f["from"] == "cancelled"
        and f["to"] == "attenuated"
    ]
    assert {f["policy"] for f in predicted} == {"F"}
    assert {(f["suppression"], f["signal"]) for f in predicted} == {
        ("path", "ransom_extension"),
        ("path", "static_entropy"),
        ("training_mode", "ransom_extension"),
        ("training_mode", "static_entropy"),
    }

    # And under F nothing but the hash whitelist cancels anything at all.
    survivors = {
        cell["suppression"]
        for cell in report["matrix"]["F"].values()
        if cell["admitted"]
    }
    assert survivors == {"hash"}
