"""What each arm costs on genuine benign files, per stratum - NI.

Item P6.3, Chapter 9 §9.4.2 and the artefact register §9.8. Writes
reports/benign_tradeoff.json.

The analysis is not chosen here. It was fixed in `docs/PHASE5_PREDECLARED_BOUNDS.md`
at the Week 20 gate, before any repair existed, and this script executes that
specification and nothing else:

  * **Paired.** Every arm scores the *same* file. The verdicts come from
    `reports/three_arm_experiment.json`, where all arms were run over one
    reading of each file, so a difference between arms cannot be a difference
    between two reads of a disk.
  * **Unit:** one file, one verdict. A false positive is `suspicious: true` on a
    file from the frozen benign corpus.
  * **Per stratum, never pooled.** §9.4.2 requires it so that a clean validated
    stratum cannot average away a costly unvalidated one.
  * **Exact McNemar**, binomial and one-sided, on the discordant pairs.
    Concordant pairs carry no information about the difference and are excluded
    from the test while staying in the denominator of the reported rate.
  * **Clopper-Pearson**, one-sided, 95%. The **upper limit** is what the bounds
    are compared against - never the point estimate.
  * **No multiplicity adjustment** across strata, because each bound is a
    separate predeclared decision rather than a family of hypotheses about one
    effect. Recorded in the predeclaration, not decided here.

Two predeclared numbers are evaluated:

  Bound 1  the validated-format false-positive difference must be within
           **2.00 pp** at the upper limit. n = 155 after the Week 21 growth, so
           only b = 0 clears it - b = 1 bounds at 3.024 pp.
  Bound 2  the `unvalidated x incompressible` rate may not be so high that this
           stratum alone pushes the corpus-wide rate over Table 5.9's 5%. On the
           corpus as frozen that is **15.0 pp**. D5 applies.

**Arm C is the arm the bounds were written for.** Arm D was selected after Arm
C's benign cost was seen; its statistics are computed and reported, and no
predeclared criterion is claimed for it. Marking that distinction is the whole
reason the arm labels are carried through this script.

    .venv\\Scripts\\python.exe scripts/benign_tradeoff.py

Writes the report only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from math import comb
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"

try:
    from scipy.stats import beta
except ImportError:  # pragma: no cover - scipy is in the project venv
    print("scipy is required for the Clopper-Pearson limits")
    raise

BASELINE_ARM = "A"

# Predeclared. Both come from docs/PHASE5_PREDECLARED_BOUNDS.md and neither is
# computed from a result seen in this session.
BOUND_1_PP = 2.00
BOUND_2_PP = 15.0
CORPUS_WIDE_BUDGET = 0.05

VALIDATED_STRATA = ("validated_x_compressible", "validated_x_incompressible")
D5_STRATUM = "unvalidated_x_incompressible"

# The arm the predeclared bounds were written for. Everything else is reported
# and explicitly not judged against them.
PREDECLARED_ARM = "C"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def mcnemar_exact_one_sided(b: int, c: int) -> float | None:
    """P(B >= b) where B ~ Binomial(b + c, 0.5). None when nothing is discordant.

    One-sided, testing whether the arm has *more* false positives than the
    baseline. That is the direction the bounds care about: an arm that removes
    false positives is not a non-inferiority concern.
    """
    n = b + c
    if n == 0:
        return None
    return sum(comb(n, k) for k in range(b, n + 1)) / (2**n)


def clopper_pearson_upper(successes: int, n: int, confidence: float = 0.95) -> float:
    """One-sided upper limit, in percentage points."""
    if n == 0:
        return float("nan")
    if successes >= n:
        return 100.0
    return 100.0 * float(beta.ppf(confidence, successes + 1, n - successes))


def compare(rows: list[dict], arm: str) -> dict:
    """One arm against the baseline over one set of paired files."""
    n = len(rows)
    b = sum(
        1
        for r in rows
        if not r["arms"][BASELINE_ARM]["suspicious"] and r["arms"][arm]["suspicious"]
    )
    c = sum(
        1
        for r in rows
        if r["arms"][BASELINE_ARM]["suspicious"] and not r["arms"][arm]["suspicious"]
    )
    baseline_fp = sum(1 for r in rows if r["arms"][BASELINE_ARM]["suspicious"])
    arm_fp = sum(1 for r in rows if r["arms"][arm]["suspicious"])

    result = {
        "files": n,
        "baseline_false_positives": baseline_fp,
        "arm_false_positives": arm_fp,
        "baseline_rate": round(baseline_fp / n, 4) if n else None,
        "arm_rate": round(arm_fp / n, 4) if n else None,
        "discordant_b_arm_only": b,
        "discordant_c_baseline_only": c,
        "discordant_total": b + c,
        "point_difference_pp": round(100.0 * (b - c) / n, 4) if n else None,
        "mcnemar_exact_one_sided_p": mcnemar_exact_one_sided(b, c),
    }

    # The interval. With the baseline at zero false positives every discordant
    # pair is an arm-only one, c is zero, and the paired difference is exactly
    # b/n - so the Clopper-Pearson limit on b successes in n trials *is* the
    # limit on the difference. When c is not zero that identity breaks, and
    # saying so is better than reporting a bound that does not hold.
    if c == 0:
        result["upper_limit_pp"] = round(clopper_pearson_upper(b, n), 4)
        result["upper_limit_basis"] = (
            "Clopper-Pearson one-sided 95% on b of n. The baseline has no false "
            "positives in this cell, so c = 0 and the paired difference is b/n."
        )
    else:
        result["upper_limit_pp"] = None
        result["upper_limit_basis"] = (
            f"not computed: c = {c}, so the paired difference is not b/n and the "
            "Clopper-Pearson limit on b of n would not bound it. The predeclared "
            "analysis assumed the baseline at zero, which this cell violates."
        )
    return result


def main() -> int:
    source = REPORTS / "three_arm_experiment.json"
    if not source.exists():
        raise SystemExit(
            f"no {source} - run scripts/three_arm_experiment.py first"
        )
    experiment = json.loads(source.read_text())
    benign = experiment["benign"]
    arms = [a for a in experiment["arms"] if a != BASELINE_ARM]
    strata = sorted({r["stratum"] for r in benign})

    per_stratum = {}
    for stratum in strata:
        rows = [r for r in benign if r["stratum"] == stratum]
        per_stratum[stratum] = {arm: compare(rows, arm) for arm in arms}

    # Bound 1 is stated over "validated formats", which is both validated cells
    # together. Reported that way for the bound, and per cell as well because
    # §9.4.2 asks for per-stratum reporting and the two are different questions.
    validated_rows = [r for r in benign if r["stratum"] in VALIDATED_STRATA]
    validated = {arm: compare(validated_rows, arm) for arm in arms}

    corpus_wide = {arm: compare(benign, arm) for arm in arms}

    # ------------------------------------------------------------- Bound 1
    bound_1 = {
        "statement": (
            "False-positive difference on validated formats must be within 2.00 "
            "percentage points at the upper limit of a one-sided 95% interval."
        ),
        "source": "Table 9.8; docs/PHASE5_PREDECLARED_BOUNDS.md Bound 1",
        "tolerance_pp": BOUND_1_PP,
        "n_validated": len(validated_rows),
        "predeclared_arm": PREDECLARED_ARM,
        "by_arm": {},
    }
    for arm in arms:
        v = validated[arm]
        limit = v["upper_limit_pp"]
        bound_1["by_arm"][arm] = {
            "new_false_positives": v["discordant_b_arm_only"],
            "point_difference_pp": v["point_difference_pp"],
            "upper_limit_pp": limit,
            "meets_bound": (limit is not None and limit <= BOUND_1_PP),
            "judged_against_the_predeclared_bound": arm == PREDECLARED_ARM,
        }

    predeclared = bound_1["by_arm"][PREDECLARED_ARM]
    bound_1["verdict"] = (
        f"Arm {PREDECLARED_ARM} introduces {predeclared['new_false_positives']} new "
        f"false positives on {len(validated_rows)} validated-format files, an upper "
        f"limit of {predeclared['upper_limit_pp']} pp against a tolerance of "
        f"{BOUND_1_PP} pp. "
        + (
            "The bound is met."
            if predeclared["meets_bound"]
            else "The bound is NOT met."
        )
    )
    bound_1["note_on_other_arms"] = (
        "Every other arm's figure is reported for completeness and none is judged "
        "against this bound. Arm D in particular was selected after Arm C's benign "
        "cost was measured; presenting its result as meeting a predeclared bound "
        "would be choosing the arm after seeing the data."
    )

    # ------------------------------------------------------------- Bound 2 / D5
    d5_rows = [r for r in benign if r["stratum"] == D5_STRATUM]
    bound_2 = {
        "statement": (
            "The unvalidated x incompressible false-positive rate may not be so "
            "high that this stratum alone would push the corpus-wide rate above "
            "Table 5.9's 5%."
        ),
        "source": "Table 9.8 (no number given); docs/PHASE5_PREDECLARED_BOUNDS.md Bound 2",
        "tolerance_pp": BOUND_2_PP,
        "stratum_files": len(d5_rows),
        "stratum_share_of_corpus": round(len(d5_rows) / len(benign), 4),
        "corpus_wide_budget": CORPUS_WIDE_BUDGET,
        "by_arm": {},
    }
    for arm in arms:
        cell = per_stratum[D5_STRATUM][arm]
        rate_pp = 100.0 * cell["arm_false_positives"] / cell["files"]
        contribution = (
            cell["arm_false_positives"] / len(benign) if benign else None
        )
        bound_2["by_arm"][arm] = {
            "false_positives": cell["arm_false_positives"],
            "rate_pp": round(rate_pp, 4),
            "upper_limit_pp": cell["upper_limit_pp"],
            "within_tolerance": rate_pp <= BOUND_2_PP,
            "contribution_to_corpus_wide_rate": round(contribution, 4),
            "alone_exceeds_corpus_budget": contribution > CORPUS_WIDE_BUDGET,
        }

    d5_arm = bound_2["by_arm"][PREDECLARED_ARM]
    d5 = {
        "rule": (
            "D5 - if false positives in the unvalidated x incompressible stratum "
            "exceed the predeclared tolerance, do not ship the repair by default. "
            "Ship behind an operator switch and state that a real validator for "
            "that format is the correct long-term fix."
        ),
        "fires": not d5_arm["within_tolerance"],
        "measured_rate_pp": d5_arm["rate_pp"],
        "tolerance_pp": BOUND_2_PP,
    }
    d5["decision"] = (
        (
            f"D5 fires. Arm {PREDECLARED_ARM} raises {d5_arm['false_positives']} false "
            f"positives on {bound_2['stratum_files']} files in this stratum - "
            f"{d5_arm['rate_pp']} pp against a tolerance of {BOUND_2_PP} pp, which it "
            f"exceeds by a factor of {d5_arm['rate_pp'] / BOUND_2_PP:.1f}. The repair "
            "does NOT ship by default. It stays behind CONTAINER_EXEMPTION_POLICY, "
            "whose default is `legacy`, and the correct long-term fix is a real "
            "structural validator for bzip2, xz, GIF and RIFF - which Chapter 9 "
            "§9.13 places outside this project's scope."
        )
        if d5["fires"]
        else (
            f"D5 does not fire. Arm {PREDECLARED_ARM} raises {d5_arm['rate_pp']} pp in "
            f"this stratum, within the {BOUND_2_PP} pp tolerance."
        )
    )

    report = {
        "schema": "urds.benign_tradeoff/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "source_experiment": {
            "file": "reports/three_arm_experiment.json",
            "commit": experiment["commit"],
            "benign_corpus_tag": experiment["benign_corpus"]["tag"],
            "files": len(benign),
        },
        "analysis": {
            "design": "paired; every arm scores the same file from one reading",
            "baseline_arm": BASELINE_ARM,
            "unit": "one file, one verdict; a false positive is suspicious: true",
            "test": "exact McNemar, binomial, one-sided, on discordant pairs",
            "interval": "Clopper-Pearson, one-sided, 95%; the upper limit is what is judged",
            "multiplicity": "no adjustment across strata, per the predeclaration",
            "predeclared_in": "docs/PHASE5_PREDECLARED_BOUNDS.md",
        },
        "per_stratum": per_stratum,
        "validated_formats_combined": validated,
        "corpus_wide": corpus_wide,
        "bound_1": bound_1,
        "bound_2": bound_2,
        "d5": d5,
    }

    # ------------------------------------------------------------------ print
    width = 30
    for stratum in strata:
        print(f"\n{stratum}  (n={per_stratum[stratum][arms[0]]['files']})")
        print(f"  {'arm':4} {'FP':>5} {'b':>4} {'c':>4} {'diff pp':>9} "
              f"{'upper pp':>9} {'McNemar p':>11}")
        for arm in arms:
            cell = per_stratum[stratum][arm]
            p = cell["mcnemar_exact_one_sided_p"]
            limit = cell["upper_limit_pp"]
            print(
                f"  {arm:4} {cell['arm_false_positives']:>5} "
                f"{cell['discordant_b_arm_only']:>4} {cell['discordant_c_baseline_only']:>4} "
                f"{cell['point_difference_pp']:>9.3f} "
                f"{(f'{limit:.3f}' if limit is not None else 'n/a'):>9} "
                f"{(f'{p:.2e}' if p is not None else 'n/a'):>11}"
            )

    print(f"\n{'BOUND 1':{width}} validated formats, n={len(validated_rows)}, "
          f"tolerance {BOUND_1_PP} pp")
    for arm in arms:
        row = bound_1["by_arm"][arm]
        judged = "  <- the predeclared arm" if row["judged_against_the_predeclared_bound"] else ""
        limit = row["upper_limit_pp"]
        print(f"  arm {arm:3} b={row['new_false_positives']:>3}  upper "
              f"{(f'{limit:.3f}' if limit is not None else 'n/a'):>7} pp  "
              f"{'MEETS' if row['meets_bound'] else 'FAILS'}{judged}")
    print(f"\n{bound_1['verdict']}")

    print(f"\n{'BOUND 2 / D5':{width}} {D5_STRATUM}, n={len(d5_rows)}, "
          f"tolerance {BOUND_2_PP} pp")
    for arm in arms:
        row = bound_2["by_arm"][arm]
        print(f"  arm {arm:3} {row['false_positives']:>3}/{len(d5_rows)} = "
              f"{row['rate_pp']:>7.3f} pp  "
              f"{'within' if row['within_tolerance'] else 'EXCEEDS'}")
    print(f"\n{d5['decision']}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    path = REPORTS / "benign_tradeoff.json"
    path.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
