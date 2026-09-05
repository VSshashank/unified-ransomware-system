"""Every suppression x signal pair, recomputed under six policies - AS.

Item P5.5, Chapter 9 §9.4.1 → docs/ADMISSION_RECOMPUTE.md and
reports/admission_recompute.json.

§9.4.1 asks for the matrix over {hash, path, training mode, container exemption}
x every signal, "under both the current >= rule and the calibrated > rule, with
every flip marked". Two things changed between the deployed policy and the
calibrated one, and folding them together would hide which is responsible for
which flip, so four policies are computed and every flip is attributed:

    A  >=  declared costs   the behaviour before P6.8
    B  >   declared costs   the rule change alone - and, since P6.8, deployed
    C  >=  measured costs   the P5.4 calibration alone
    D  >   measured costs   both
    E  >=  plan levels      the plan's ladder alone
    F  >   plan levels      the plan's ladder and the plan's rule - the policy
                            NOVELTY_PROOF_PLAN.md mandates end to end

E and F were added in Phase 6, after the P0 finding that the proof plan does not
exist was found to be wrong. §5.2 of that plan is a five-level ladder and §5.3
mandates the strict rule; §6 asks specifically what the strict rule does when
`path` and `training_mode` forgery tie with an avoidance cost. On the code's
four-point ladder they do not tie, and Phase 5 reported that D1's predicted
direction did not occur. On the plan's ladder they do tie, and it does.

The plan levels are read from reports/capability_calibration.json rather than
restated here, so a level cannot drift between the file that measured it and the
file that uses it. The script fails rather than falling back to a hard-coded
number.

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

# §5.2's rungs, by name, for the two policies computed on the plan's ladder.
PLAN_NAMES = {
    0: "direct attacker control",
    1: "public primitive",
    2: "format-aware capability",
    3: "new engineering or unavailable privilege",
    4: "secret/preimage",
}

CALIBRATION = REPORTS / "capability_calibration.json"


def calibrated_levels() -> tuple[dict[str, int], dict[str, int]]:
    """Both ladders, per cost-table key, read from what P5.4 actually recorded.

    §5.1 step 6 says to assign *the lowest* reproducible level, so where two
    strategies defeat the same entry the cheaper one is the level. Raises if the
    calibration has not been run: a matrix that quietly substituted a number
    nobody measured would be worse than one that does not build.

    Read rather than restated, on both scales, because the measured level for
    `partial_entropy` moved once the locked tooling search §5.1 asks for was
    actually run for it - and a hard-coded copy here would have kept computing
    the matrix against a number the calibration no longer holds.
    """
    if not CALIBRATION.exists():
        raise SystemExit(
            f"{CALIBRATION} is missing - run scripts/capability_calibration.py first"
        )
    report = json.loads(CALIBRATION.read_text(encoding="utf-8"))
    code: dict[str, int] = {}
    plan: dict[str, int] = {}
    for entry in report["levels"]:
        key = entry["cost_table_key"]
        code[key] = min(code.get(key, entry["measured_level"]), entry["measured_level"])
        level = entry["plan_level"]["level"]
        plan[key] = min(plan.get(key, level), level)
    return code, plan


MEASURED, PLAN = calibrated_levels()

# The four suppressions §9.4.1 names. Three are live rules that reach
# adjudicate(); the fourth is the container exemption, which today is a branch
# in detection.classify and never reaches the governance layer at all. It is
# modelled here as the rule it would be if it did, which is the whole point of
# putting it in this matrix.
SUPPRESSIONS = {
    "hash": {
        "declared": admissibility.FORGERY_COST["hash"],
        "measured": MEASURED["hash"],
        "plan": PLAN["hash"],
        "live": True,
        "note": "SHA-256 preimage. P5.4 negative control did not match.",
    },
    "path": {
        "declared": admissibility.FORGERY_COST["path"],
        "measured": MEASURED["path"],
        "plan": PLAN["path"],
        "live": True,
        "note": (
            "Write into an approved directory. Measured LOW on the code ladder, as "
            "declared - and Level 0 on the plan's, which puts choosing a path "
            "alongside choosing bytes. That single rung is what creates the tie §6 "
            "asks about."
        ),
    },
    "training_mode": {
        "declared": admissibility.FORGERY_COST["training_mode"],
        "measured": MEASURED["training_mode"],
        "plan": PLAN["training_mode"],
        "live": True,
        "note": (
            "Poison the learned ceiling during the window. Measured LOW on the code "
            "ladder, as declared, and Level 0 on the plan's."
        ),
    },
    "container": {
        "declared": None,
        "measured": MEASURED["static_entropy"],
        # §5.1 step 6: the lowest reproducible level. Under the deployed `legacy`
        # policy the exemption fires on a header, so the cheapest way to forge it
        # is the four-byte magic prefix P5.4 measured at Level 0 - not the
        # standard-library container, which is Level 1 and is what the repair
        # would make necessary. The cheaper one is the level.
        "plan": PLAN["static_entropy"],
        "live": False,
        "note": (
            "Not a rule today - detection.py:702 is a branch, not a suppression, and "
            "never reaches adjudicate(). Modelled on the code ladder at the level "
            "P5.4 measured for gzip.compress(ciphertext) and a ZIP_STORED member, "
            "and on the plan's ladder at the level of the cheapest construction the "
            "deployed policy accepts, which is a magic prefix at Level 0. Under the "
            "repair the cheapest becomes a standard-library container at Level 1."
        ),
    },
}

# Every signal classify() can set, with the cost the table declares and the cost
# P5.4 measured.
SIGNALS = {
    "ransom_extension": {
        "plan": PLAN["ransom_extension"],
        "declared": admissibility.AVOIDANCE_COST["ransom_extension"],
        "measured": MEASURED["ransom_extension"],
    },
    "static_entropy": {
        "plan": PLAN["static_entropy"],
        "declared": admissibility.AVOIDANCE_COST["static_entropy"],
        "measured": MEASURED["static_entropy"],
    },
    "structural_mismatch": {
        "plan": PLAN["structural_mismatch"],
        "declared": admissibility.AVOIDANCE_COST["structural_mismatch"],
        "measured": MEASURED["structural_mismatch"],
    },
    "partial_entropy": {
        "plan": PLAN["partial_entropy"],
        "declared": admissibility.AVOIDANCE_COST["partial_entropy"],
        "measured": MEASURED["partial_entropy"],
    },
    "entropy_rise": {
        "plan": PLAN["entropy_rise"],
        "declared": admissibility.AVOIDANCE_COST["entropy_rise"],
        "measured": MEASURED["entropy_rise"],
    },
}

POLICIES = {
    "A": {"rule": ">=", "costs": "declared", "label": "the behaviour before P6.8"},
    "B": {"rule": ">", "costs": "declared", "label": "rule change alone - DEPLOYED"},
    "C": {"rule": ">=", "costs": "measured", "label": "calibration alone"},
    "D": {"rule": ">", "costs": "measured", "label": "rule change and calibration"},
    "E": {"rule": ">=", "costs": "plan", "label": "the plan's ladder alone"},
    "F": {
        "rule": ">",
        "costs": "plan",
        "label": "the plan's ladder and the plan's rule",
    },
}

# Which scale each basis is written on. The two are not comparable rung for rung
# and the rendered tables say which one they are reading.
BASIS_NAMES = {"declared": NAMES, "measured": NAMES, "plan": PLAN_NAMES}


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
                names = BASIS_NAMES[basis]
                cells[policy][f"{suppression}|{signal}"] = {
                    "suppression": suppression,
                    "signal": signal,
                    "forgery_cost": None if forging is None else names[forging],
                    "avoidance_cost": names[avoiding],
                    "admitted": admits(forging, avoiding, rule),
                    "outcome": (
                        None
                        if forging is None
                        else ("cancelled" if admits(forging, avoiding, rule) else "attenuated")
                    ),
                }

    flips = []
    for policy in ("B", "C", "D", "E", "F"):
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
                            "E": "the plan's five-level ladder alone",
                            "F": "the plan's ladder and the plan's strict rule",
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

Three things can change between the deployed policy and the calibrated one:

1. the comparison — an equal-cost tie went to the suppression under `>=`;
2. the costs — P5.4 measured three of them differently from the table;
3. **the ladder itself** — `NOVELTY_PROOF_PLAN.md` §5.2 is a five-level scale,
   not the four-point one `admissibility.py` is written on.

Folding them into one recomputation would leave every flip ambiguous, so six
policies are computed and each flip is attributed to whichever change caused it.

| Policy | Comparison | Costs | What it isolates |
|---|---|---|---|
| **A** | `>=` | declared | the behaviour before P6.8 |
| **B** | `>` | declared | the rule change alone — **deployed since P6.8** |
| **C** | `>=` | measured | the P5.4 calibration alone |
| **D** | `>` | measured | both |
| **E** | `>=` | plan levels | the plan's ladder alone |
| **F** | `>` | plan levels | the plan's ladder and the plan's rule — **the policy the plan mandates** |

E and F did not exist in Phase 5. They were added once the P0 finding that
`NOVELTY_PROOF_PLAN.md` had never existed was found to be wrong: §9.1 makes that
document the governing method, §5.3 mandates the strict rule, and §6 asks
specifically what the strict rule does to a tie between `path` / `training_mode`
forgery and an avoidance cost. The answer depends entirely on which ladder the
question is asked on, and this matrix now asks it on both.

**Policy B is deployed.** `admissibility.adjudicate` admits on `>` as of P6.8,
per §5.3: *"equal capability does not demonstrate that the mitigation is harder
to forge"*. Against the declared table that is a no-op — every one of the fifteen
live cells decides the same way under both comparisons — which is exactly why it
was safe to adopt and why adopting it settles nothing on its own.

**No cost in `admissibility.py` was changed.** Policies C, D, E and F are
computed here and are not deployed; what that costs is set out below.

## The costs this is computed over

Declared costs are read from `services/monitor/admissibility.py`. Measured costs
and plan levels are both **read from** `reports/capability_calibration.json`
(P5.4) rather than restated here — the measured level for `partial_entropy` moved
once the locked tooling search was actually run for it, and a hard-coded copy
would have kept computing this matrix against a number the calibration no longer
holds. In that file each level was
derived twice, in opposite decision orders, from the operational facts of an
attack that was built and run. The two ladders are **not comparable rung for
rung**: the code's `low` ("a location the attacker can already write to") has no
counterpart in the plan, which puts choosing a path in Level 0 beside choosing
bytes, and the code's `high` conflates the plan's Level 3 and Level 4.
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
so under every one of the six policies it cancels whatever it likes.

On the plan's ladder the row is Level 0, following §5.1 step 6 — *assign the
lowest reproducible capability level*. Under the deployed `legacy` policy the
exemption fires on a header, so the cheapest forgery is the four-byte magic
prefix, not the standard-library container at Level 1. The Phase 6 repair is
precisely the change that would raise it from 0 to 1.

## Limits of this matrix

- It is a matrix over the cost table, not over files. A cell says what
  `adjudicate` would decide given that pair; it does not say how often the pair
  occurs. Phase 6's three-arm experiment measures the second thing.
- Every level is now empirical. `partial_entropy` was the one derived from source
  analysis, and it was re-measured: `base64.b64encode(ciphertext)` defeats it, and
  the row moved from moderate to negligible. 10 of 10 strategies were built and
  run.
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
    code_ladder = [f for f in weakened if f["policy"] in {"B", "C", "D"}]
    plan_ladder = [f for f in weakened if f["policy"] in {"E", "F"}]

    lines = ["## D1 — it depends entirely on which ladder the question is asked on\n"]
    lines.append(
        "§9.7 D1 fires when *path-whitelist and training-mode admissions flip from "
        "admitted to attenuated under the calibrated rule*, and instructs that this be "
        "reported as a primary finding: two deployed mitigations were not "
        "cost-justified.\n"
    )
    lines.append(
        f"**On the code's four-point ladder it does not fire — {len(code_ladder)} cells "
        f"flip in that direction. On the plan's five-level ladder it fires: "
        f"{len(plan_ladder)} do.** {len(strengthened)} cells flip the other way, from "
        f"attenuated to cancelled - "
        f"{sum(1 for f in strengthened if f['policy'] in {'C', 'D'})} from the P5.4 "
        f"calibration and {sum(1 for f in strengthened if f['policy'] in {'E', 'F'})} "
        "from the plan's ladder read without the plan's rule.\n"
    )

    if plan_ladder:
        lines.append(
            "### The flips D1 predicted, under policy F\n\n"
            "Policy F is the plan applied end to end — its §5.2 ladder and its §5.3 "
            "strict rule. It is the policy the governing method document mandates.\n"
        )
        lines.append("| policy | suppression | signal | from | to |")
        lines.append("|---|---|---|---|---|")
        for flip in plan_ladder:
            lines.append(
                f"| {flip['policy']} | `{flip['suppression']}` | `{flip['signal']}` | "
                f"{flip['from']} | {flip['to']} |"
            )
        lines.append("")
        lines.append(
            """**On the plan's ladder, `path` and `training_mode` forgery are both Level 0,
and so are `ransom_extension` and `static_entropy` avoidance.** Four ties, and
§5.3 breaks all four against the suppression. Under policy F the whitelist path
rule and training mode cancel nothing at all: the only suppression that still
cancels anything is the hash whitelist, at Level 4.

§6 of the plan set this out as a hypothesis — *"if path and training-mode forgery
are both Level 1 and static-entropy avoidance is also Level 1, the strict rule
changes those entries from admitted to attenuated"*. The tie is real and it is at
Level 0 rather than Level 1, and the consequence is the one the plan named: **two
deployed mitigations are not cost-justified under the governing method's own
scale.**

The reason the two ladders disagree is a single rung. `admissibility.py` prices
"a location the attacker can already write to" at `low`, one step above choosing
bytes. §5.2 puts *"write bytes, choose a path, rename a file, or prefix a
recognized magic value"* all in Level 0, and reserves Level 1 for the case where a
public primitive does the work. A path whitelist is forged by choosing a path.
On the code's scale that outranks a `negligible` signal; on the plan's it ties
with one.

**Neither ladder is deployed and neither is being retro-fitted.** What is
recorded is that the answer to D1 is not a property of the system — it is a
property of the scale the question is asked on, and Phase 5 answered it on the
scale that was to hand rather than on the one §9.1 makes governing.\n"""
        )

    if strengthened:
        lines.append(
            "### The flips that go the other way\n\n"
            "Every one of these makes a suppression *more* able to cancel evidence "
            "than the deployed table allows. None is adopted.\n"
        )
        lines.append("| policy | suppression | signal | from | to |")
        lines.append("|---|---|---|---|---|")
        for flip in strengthened:
            lines.append(
                f"| {flip['policy']} | `{flip['suppression']}` | `{flip['signal']}` | "
                f"{flip['from']} | {flip['to']} |"
            )
        lines.append("")

    lines.append(
        """### Why the code ladder moves the other way

Both rules were priced LOW and P5.4 measured both at LOW — the *forgery* side of
the table was right. What moved is the *avoidance* side. Three signals the table
prices at moderate were measured cheaper, because P5.4 built the attacks that
evade them and none cost the attacker anything close to moderate:

- `structural_mismatch` moderate → negligible — `gzip.compress(ciphertext)`
- `entropy_rise` moderate → low — write to a path nothing has measured
- `partial_entropy` moderate → negligible — `base64.b64encode(ciphertext)`

The third of those was recorded in Phase 5 as *not buildable* without
distribution-aware code, and that was wrong. §5.1's locked tooling search had not
been run for the row, and §5.3 names base64 as Level 1 in the same sentence it
names standard-library container generation. Base64 flattens uniform ciphertext
to exactly 6.00 bits/byte, which is under the block threshold, under the file
threshold, and under the differential floor — **one standard-library call defeats
all three entropy signals at once**, at a cost of 33% in file size. It is the
cheapest attack in the whole calibration and it was priced as the most expensive
avoidance in the table.

Under the cost model's own comparison, lowering what a signal costs to avoid
makes that signal **easier to cancel** — a LOW suppression now outranks a
NEGLIGIBLE signal. So applying the P5.4 calibration to the deployed policy would
let an operator's path whitelist cancel a structural-mismatch alert, which policy
A correctly refuses.

**That is a defect in the cost model, exposed by the calibration**, and it is
present on both ladders. The two quantities have been conflated:

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
applied to make the inconvenience go away. No cost in `admissibility.py` is
changed — not by Phase 5, and not by Phase 6.

The one thing Phase 6 did change is the *comparison*, to the `>` §5.3 mandates.
That was adopted because it is a no-op against the declared table (policy B is
cell-for-cell identical to policy A) and because the governing method document
requires it. Adopting the plan's **ladder** as well is policy F, and it is not
adopted: it would disable the path whitelist and training mode entirely, and it
would invalidate every arm of the Phase 6 experiment, all of which were measured
against the declared table. That is a decision with an operational cost, and it
belongs with `cost-policy-v2` rather than in a commit that also does five other
things.

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

    cost_rows = [
        "| entry | kind | declared | measured | changed | plan level (§5.2) |",
        "|---|---|---|---|---|---|",
    ]
    for name, spec in SUPPRESSIONS.items():
        declared = "—" if spec["declared"] is None else NAMES[spec["declared"]]
        measured = NAMES[spec["measured"]]
        cost_rows.append(
            f"| `{name}` | forgery | {declared} | {measured} | "
            f"{'**yes**' if declared != measured else 'no'} | "
            f"{spec['plan']} — {PLAN_NAMES[spec['plan']]} |"
        )
    for name, spec in SIGNALS.items():
        declared, measured = NAMES[spec["declared"]], NAMES[spec["measured"]]
        cost_rows.append(
            f"| `{name}` | avoidance | {declared} | {measured} | "
            f"{'**yes**' if declared != measured else 'no'} | "
            f"{spec['plan']} — {PLAN_NAMES[spec['plan']]} |"
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
