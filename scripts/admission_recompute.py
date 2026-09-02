"""Every suppression x signal pair, recomputed under four policies - AS.

Item P5.5, Chapter 9 §9.4.1 → docs/ADMISSION_RECOMPUTE.md and
reports/admission_recompute.json.

§9.4.1 asks for the matrix over {hash, path, training mode, container exemption}
x every signal, "under both the current >= rule and the calibrated > rule, with
every flip marked". Two things changed between the deployed policy and the
calibrated one, and folding them together would hide which is responsible for
which flip, so four policies are computed and every flip is attributed:

    A  >=  declared costs   the deployed behaviour, today
    B  >   declared costs   the rule change alone
    C  >=  measured costs   the P5.4 calibration alone
    D  >   measured costs   both

The document is generated from the computation, not written alongside it. A
hand-copied table drifts the first time a cost moves.

    .venv\\Scripts\\python.exe scripts/admission_recompute.py

Writes both artefacts only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"
DOCS = REPO_ROOT / "docs"

sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

import admissibility  # noqa: E402

NAMES = admissibility.COST_NAMES

# The four suppressions §9.4.1 names. Three are live rules that reach
# adjudicate(); the fourth is the container exemption, which today is a branch
# in detection.classify and never reaches the governance layer at all. It is
# modelled here as the rule it would be if it did, which is the whole point of
# putting it in this matrix.
SUPPRESSIONS = {
    "hash": {
        "declared": admissibility.FORGERY_COST["hash"],
        "measured": admissibility.HIGH,
        "live": True,
        "note": "SHA-256 preimage. P5.4 negative control did not match.",
    },
    "path": {
        "declared": admissibility.FORGERY_COST["path"],
        "measured": admissibility.LOW,
        "live": True,
        "note": "Write into an approved directory. Measured LOW, as declared.",
    },
    "training_mode": {
        "declared": admissibility.FORGERY_COST["training_mode"],
        "measured": admissibility.LOW,
        "live": True,
        "note": "Poison the learned ceiling during the window. Measured LOW, as declared.",
    },
    "container": {
        "declared": None,
        "measured": admissibility.NEGLIGIBLE,
        "live": False,
        "note": (
            "Not a rule today - detection.py:702 is a branch, not a suppression, and "
            "never reaches adjudicate(). Modelled here at the level P5.4 measured for "
            "gzip.compress(ciphertext) and a ZIP_STORED member."
        ),
    },
}

# Every signal classify() can set, with the cost the table declares and the cost
# P5.4 measured.
SIGNALS = {
    "ransom_extension": {
        "declared": admissibility.AVOIDANCE_COST["ransom_extension"],
        "measured": admissibility.NEGLIGIBLE,
    },
    "static_entropy": {
        "declared": admissibility.AVOIDANCE_COST["static_entropy"],
        "measured": admissibility.NEGLIGIBLE,
    },
    "structural_mismatch": {
        "declared": admissibility.AVOIDANCE_COST["structural_mismatch"],
        "measured": admissibility.NEGLIGIBLE,
    },
    "partial_entropy": {
        "declared": admissibility.AVOIDANCE_COST["partial_entropy"],
        "measured": admissibility.MODERATE,
    },
    "entropy_rise": {
        "declared": admissibility.AVOIDANCE_COST["entropy_rise"],
        "measured": admissibility.LOW,
    },
}

POLICIES = {
    "A": {"rule": ">=", "costs": "declared", "label": "deployed today"},
    "B": {"rule": ">", "costs": "declared", "label": "rule change alone"},
    "C": {"rule": ">=", "costs": "measured", "label": "calibration alone"},
    "D": {"rule": ">", "costs": "measured", "label": "rule change and calibration"},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def admits(forging: int | None, avoiding: int, rule: str) -> bool | None:
    """One admission decision. None when the cost table has no entry.

    The `>=` branch is `admissibility.adjudicate`'s own comparison
    (admissibility.py:147), restated here rather than called so the same
    function can evaluate the `>` rule without the module being changed - no
    repair is written in Phase 5.
    """
    if forging is None:
        return None
    return forging >= avoiding if rule == ">=" else forging > avoiding


def compute() -> dict:
    cells: dict[str, dict[str, dict]] = {}
    for policy, spec in POLICIES.items():
        basis, rule = spec["costs"], spec["rule"]
        cells[policy] = {}
        for suppression, s in SUPPRESSIONS.items():
            for signal, g in SIGNALS.items():
                forging = s[basis]
                avoiding = g[basis]
                cells[policy][f"{suppression}|{signal}"] = {
                    "suppression": suppression,
                    "signal": signal,
                    "forgery_cost": None if forging is None else NAMES[forging],
                    "avoidance_cost": NAMES[avoiding],
                    "admitted": admits(forging, avoiding, rule),
                    "outcome": (
                        None
                        if forging is None
                        else ("cancelled" if admits(forging, avoiding, rule) else "attenuated")
                    ),
                }

    flips = []
    for policy in ("B", "C", "D"):
        for key, cell in cells[policy].items():
            base = cells["A"][key]
            if base["admitted"] is None or cell["admitted"] is None:
                continue
            if base["admitted"] != cell["admitted"]:
                flips.append(
                    {
                        "policy": policy,
                        "suppression": cell["suppression"],
                        "signal": cell["signal"],
                        "from": base["outcome"],
                        "to": cell["outcome"],
                        "attributed_to": {
                            "B": "the > rule alone",
                            "C": "the P5.4 calibration alone",
                            "D": "the > rule and the calibration together",
                        }[policy],
                    }
                )

    return {"cells": cells, "flips": flips}


# ---------------------------------------------------------------- rendering


def table(cells: dict, policy: str) -> str:
    spec = POLICIES[policy]
    header = "| suppression \\ signal | " + " | ".join(SIGNALS) + " |"
    divider = "|---|" + "|".join("---" for _ in SIGNALS) + "|"
    lines = [
        f"**Policy {policy} — `{spec['rule']}` with {spec['costs']} costs "
        f"({spec['label']})**",
        "",
        header,
        divider,
    ]
    for suppression in SUPPRESSIONS:
        row = [f"| `{suppression}`"]
        for signal in SIGNALS:
            cell = cells[policy][f"{suppression}|{signal}"]
            if cell["admitted"] is None:
                row.append(" — ")
            else:
                row.append(
                    f" **{'cancelled' if cell['admitted'] else 'attenuated'}** "
                    if cell["admitted"]
                    else " attenuated "
                )
        lines.append("|".join(row) + "|")
    return "\n".join(lines)


PREAMBLE = """# Admission-recompute matrix — every suppression against every signal

**Item P5.5 (AS). Chapter 9 §9.4.1. Generated by `scripts/admission_recompute.py`
— do not edit by hand; the tables below are computed, and a hand-copied table
drifts the first time a cost moves.**

§9.4.1 asks for the matrix over {hash, path, training mode, container exemption}
× every signal, recomputed "under both the current `≥` rule and the calibrated
`>` rule, with every flip marked".

Two things changed between the deployed policy and the calibrated one:

1. the comparison — `admissibility.py:147` admits when `forging >= avoiding`, so
   an equal-cost tie goes to the suppression;
2. the costs — P5.4 measured three of them differently from the table.

Folding both into one recomputation would leave every flip ambiguous, so four
policies are computed and each flip is attributed to whichever change caused it.

| Policy | Comparison | Costs | What it isolates |
|---|---|---|---|
| **A** | `>=` | declared | the deployed behaviour, today |
| **B** | `>` | declared | the rule change alone |
| **C** | `>=` | measured | the P5.4 calibration alone |
| **D** | `>` | measured | both |

**No repair is written in Phase 5.** `admissibility.adjudicate` is untouched;
this script restates its comparison so the `>` rule can be evaluated without
changing the module. Which policy ships, if any, is a Phase 6 decision made
against the frozen table.

## The costs this is computed over

Declared costs are read from `services/monitor/admissibility.py`. Measured costs
come from `reports/capability_calibration.json` (P5.4), where each was derived
from the operational facts of an attack that was built and run.
"""

CLOSING = """
## What the container exemption row means

`container` is not a suppression today. `detection.py:702` is a branch inside
`classify`, and `adjudicate()` is only called when the verdict is already
suspicious (`app.py:424`) — which a `benign_compressed` verdict is not. The row
is the exemption modelled *as if* it were governed, at the level P5.4 measured
for `gzip.compress(ciphertext)` and a `ZIP_STORED` member.

That is the honest way to put it in this matrix, and it is also the finding: the
Monitor's most-used evidence-cancelling path has no row in the cost table at all,
so under every one of the four policies it cancels whatever it likes.

## Limits of this matrix

- It is a matrix over the cost table, not over files. A cell says what
  `adjudicate` would decide given that pair; it does not say how often the pair
  occurs. Phase 6's three-arm experiment measures the second thing.
- `partial_entropy` was not empirically attacked in P5.4 — its level is derived
  from source analysis and recorded as such. Its rows inherit that.
- The `container` rows are hypothetical by construction, as above.
- The measured costs come from derivations written in one session by one author.
  Per P5.4's own record, `independent_human_reviewer` is false throughout.
"""


def d1_verdict(flips: list[dict]) -> str:
    """D1 asks specifically about path-whitelist and training-mode admissions.

    It anticipates one direction - cancelled becoming attenuated, i.e. two
    deployed mitigations turning out not to be cost-justified. The measurement
    produced the other direction, and the honest report says so rather than
    answering "the predicted branch was not taken" and stopping there.
    """
    mine = [f for f in flips if f["suppression"] in {"path", "training_mode"}]
    weakened = [f for f in mine if f["from"] == "cancelled" and f["to"] == "attenuated"]
    strengthened = [f for f in mine if f["from"] == "attenuated" and f["to"] == "cancelled"]

    lines = ["## D1 — evaluated, and the result runs against the direction it predicted\n"]
    lines.append(
        "§9.7 D1 fires when *path-whitelist and training-mode admissions flip from "
        "admitted to attenuated under the calibrated rule*, and instructs that this be "
        "reported as a primary finding: two deployed mitigations were not "
        "cost-justified.\n"
    )
    lines.append(
        f"**No cell flips in that direction ({len(weakened)} found). "
        f"{len(strengthened)} flip the other way** — from attenuated to cancelled.\n"
    )

    if strengthened:
        lines.append("| policy | suppression | signal | from | to |")
        lines.append("|---|---|---|---|---|")
        for flip in strengthened:
            lines.append(
                f"| {flip['policy']} | `{flip['suppression']}` | `{flip['signal']}` | "
                f"{flip['from']} | {flip['to']} |"
            )
        lines.append("")

    lines.append(
        """### Why, and why it matters more than the predicted branch would have

Both rules were priced LOW and P5.4 measured both at LOW — the *forgery* side of
the table was right. What moved is the *avoidance* side: `structural_mismatch`
fell from moderate to negligible and `entropy_rise` from moderate to low, because
P5.4 built the attacks that evade them and neither cost the attacker anything
close to moderate.

Under the cost model's own comparison, lowering what a signal costs to avoid
makes that signal **easier to cancel** — a LOW suppression now outranks a
NEGLIGIBLE signal. So applying the P5.4 calibration to the deployed policy would
let an operator's path whitelist cancel a structural-mismatch alert, which policy
A correctly refuses.

**That is a defect in the cost model, exposed by the calibration.** The two
quantities have been conflated:

- *how cheaply an attacker who wants to avoid this signal can avoid it* — which
  is what P5.4 measured;
- *how much the signal is worth when it does fire* — which is what the
  comparison against a suppression actually needs.

They are not the same, and for `structural_mismatch` they point opposite ways. A
file that trips structural mismatch is one whose author did **not** spend the one
standard-library call that would have avoided it. The signal is cheap to evade
and, precisely because of that, strong evidence when it fires — an attacker who
could have avoided it would have.

### What is not being done about it

Per D1: the ladder is **not** retro-fitted, and the calibration is **not**
applied to make the inconvenience go away. Neither `admissibility.py` nor any
cost in it is changed in Phase 5.

The refinement this points at — separating avoidance cost from evidential weight,
so that a signal's evadability stops licensing its cancellation — is proposed as
**`cost-policy-v2`** in `docs/PHASE5_PREDECLARED_BOUNDS.md`, to be argued and
versioned in Phase 6 rather than applied silently here.

### The consequence for Phase 6

Policy C must not ship. Policy D is narrower but still admits
`path × structural_mismatch` and `training_mode × structural_mismatch`, because
the `>` rule only removes the equal-cost tie — it does not repair a genuine cost
inversion. Note that the `>` rule *does* undo the `entropy_rise` flips, which is
exactly what a tie-breaker should do and is the clearest argument in its favour
that this matrix produces.
"""
    )
    return "\n".join(lines)


def render(result: dict) -> str:
    cells, flips = result["cells"], result["flips"]

    cost_rows = ["| entry | kind | declared | measured | changed |", "|---|---|---|---|---|"]
    for name, spec in SUPPRESSIONS.items():
        declared = "—" if spec["declared"] is None else NAMES[spec["declared"]]
        measured = NAMES[spec["measured"]]
        cost_rows.append(
            f"| `{name}` | forgery | {declared} | {measured} | "
            f"{'**yes**' if declared != measured else 'no'} |"
        )
    for name, spec in SIGNALS.items():
        declared, measured = NAMES[spec["declared"]], NAMES[spec["measured"]]
        cost_rows.append(
            f"| `{name}` | avoidance | {declared} | {measured} | "
            f"{'**yes**' if declared != measured else 'no'} |"
        )

    parts = [PREAMBLE, "\n".join(cost_rows), ""]
    for policy in POLICIES:
        parts.append(table(cells, policy))
        parts.append("")

    parts.append(f"## Flips against policy A\n\n**{len(flips)} cells flip.**\n")
    if flips:
        parts.append("| policy | suppression | signal | from | to | caused by |")
        parts.append("|---|---|---|---|---|---|")
        for flip in flips:
            parts.append(
                f"| {flip['policy']} | `{flip['suppression']}` | `{flip['signal']}` | "
                f"{flip['from']} | {flip['to']} | {flip['attributed_to']} |"
            )
    else:
        parts.append("No cell changes its admission under any of the three alternatives.")
    parts.append("")
    parts.append(d1_verdict(flips))
    parts.append(CLOSING)
    return "\n".join(parts)


def main() -> int:
    result = compute()
    document = render(result)

    report = {
        "schema": "urds.admission_recompute/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "policies": POLICIES,
        "suppressions": {
            k: {**v, "declared_name": None if v["declared"] is None else NAMES[v["declared"]],
                "measured_name": NAMES[v["measured"]]}
            for k, v in SUPPRESSIONS.items()
        },
        "signals": {
            k: {**v, "declared_name": NAMES[v["declared"]], "measured_name": NAMES[v["measured"]]}
            for k, v in SIGNALS.items()
        },
        "matrix": result["cells"],
        "flips": result["flips"],
        "flip_count": len(result["flips"]),
    }

    print(f"cells per policy: {len(result['cells']['A'])}   flips against A: {len(result['flips'])}")
    for flip in result["flips"]:
        print(f"  {flip['policy']}  {flip['suppression']:<14} x {flip['signal']:<20} "
              f"{flip['from']} -> {flip['to']}   ({flip['attributed_to']})")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: artefacts not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "admission_recompute.json").write_text(json.dumps(report, indent=2))
    (DOCS / "ADMISSION_RECOMPUTE.md").write_text(document, encoding="utf-8")
    print(f"\nwrote {REPORTS / 'admission_recompute.json'}")
    print(f"wrote {DOCS / 'ADMISSION_RECOMPUTE.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
