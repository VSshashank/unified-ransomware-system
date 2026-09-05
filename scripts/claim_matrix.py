"""The claim-to-artefact matrix, checked rather than tabulated (P8.2).

Table 9.9 fixes the wording of eight claims and names the artefact each one
requires. A markdown table saying "claim X is supported by report Y" is worth
very little: nothing stops Y from moving, and nothing checks that the figure
quoted in the claim is the figure Y actually holds.

So each claim here carries a machine-checkable assertion:

- `artefact` - the file Table 9.9 requires, which must exist;
- `check` - a path into that artefact and the value expected there, so a claim
  quoting "25.323 pp" fails if the report now says something else;
- `tests` - the regression that would fail first if the claim stopped holding.

Every claim also carries its `wording` - the exact phrase Table 9.9 permits -
and `wording_required: true` where that phrase is mandatory. Two rows record
claims that are **not** made: general detection improvement, and patentability.
They are in the matrix because a claim matrix that lists only what is claimed
cannot show that a forbidden claim was avoided on purpose.

Usage:

    python scripts/claim_matrix.py            # check every claim, print a table
    python scripts/claim_matrix.py --tests    # also run each claim's regressions
    URDS_WRITE_REPORTS=1 python scripts/claim_matrix.py

Exit status is 1 if any claim fails its check, so this runs in CI as the
regression on the thesis itself.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
OUT = REPORTS / "claim_matrix.json"

NOT_CLAIMED = "NOT CLAIMED"

# --------------------------------------------------------------------------
# The claims. `check` is (relative artefact path, path into the JSON, expected).
# A path element that is an int indexes a list. `None` for `check` means the
# claim is supported by a document rather than a figure, and only the artefact's
# existence is verified.
# --------------------------------------------------------------------------

CLAIMS: list[dict] = [
    # ---- Table 9.9 rows, in the order the table gives them ----
    {
        "id": "C-01",
        "table_9_9_row": "The team built the system",
        "wording": "The project team designed and implemented...",
        "wording_required": True,
        "claim": "The project team designed and implemented a six-service "
                 "ransomware detection and recovery system.",
        "requires": "PROJECT_IMPLEMENTATION_RECORD.md",
        "artefact": "PROJECT_IMPLEMENTATION_RECORD.md",
        "check": ("reports/implementation_record.json",
                  ["totals", "contributors"], 4),
        "tests": [],
        "note": "The record also states that 82 of 92 commits on HEAD are "
                "AI-assisted and that the contribution is lopsided. The claim "
                "is made with those facts published, not around them.",
    },
    {
        "id": "C-02",
        "table_9_9_row": "The exemption is ungoverned",
        "wording": "In the reviewed URDS Monitor...",
        "wording_required": True,
        "claim": "In the reviewed URDS Monitor, the container exemption cancels "
                 "a high-entropy alert without reaching the governance layer "
                 "that prices every other mitigation.",
        "requires": "Source audit and evidence report",
        "artefact": "docs/CAPABILITY_GOVERNED_EXCEPTIONS.md",
        "check": ("reports/ledger_coverage.json",
                  ["by_population", "ungoverned", "adjudicated"], 0),
        "tests": ["services/monitor/tests/test_tc18_admission_matrix.py"],
        "note": "0 adjudications from the ungoverned population. The exemption "
                "returns benign_compressed, and app.handle_event adjudicates "
                "only a verdict that is already suspicious.",
    },
    {
        "id": "C-03",
        "table_9_9_row": "11 of 16 formats are unvalidated",
        "wording": "The current registry contains...",
        "wording_required": True,
        "claim": "The current registry contains seventeen recognised container "
                 "formats and structural validators for six of them; eleven are "
                 "accepted on their header alone.",
        "requires": "Registry and evidence report",
        "artefact": "services/monitor/containers.py",
        "check": ("reports/capability_calibration.json",
                  ["summary", "levels_measured"], 10),
        "tests": ["services/monitor/tests/test_tc14_unvalidated_closure.py"],
        "note": "Table 9.9 states 11 of 16. The code recognises seventeen: "
                "sixteen names in detection._CONTAINER_SIGNATURES plus "
                "iso-bmff, which identify_container matches on a separate ftyp "
                "branch. The unvalidated count of eleven is the same either "
                "way; the difference is one validated format the plan's total "
                "omits, and the claim uses the code's number.",
    },
    {
        "id": "C-04",
        "table_9_9_row": "Structural validation is low-capability",
        "wording": "Under the declared capability model...",
        "wording_required": True,
        "claim": "Under the declared capability model, forging the container "
                 "exemption is negligible-cost: four bytes for an unvalidated "
                 "format, one standard-library call for a validated one.",
        "requires": "Calibration record",
        "artefact": "reports/capability_calibration.json",
        "check": ("reports/capability_calibration.json",
                  ["levels", 0, "measured_name"], "negligible"),
        "tests": ["services/monitor/tests/test_tc18_admission_matrix.py"],
        "note": "10 of 10 levels carry an empirical source trail; none is "
                "derived from source alone. Both ladders are recorded per "
                "strategy, because the level depends on which ladder is asked. "
                "The figure is 10 with models/behavioral_model.pkl present. On "
                "a clean checkout - models/ is gitignored - the "
                "ml_confidence_gate level is recorded unresolved under D2 and "
                "the count is 9. That is D2 working as designed; the other "
                "nine levels reproduce anywhere. See "
                "docs/REPRODUCIBILITY_APPENDIX.md section 6.",
    },
    {
        "id": "C-15",
        "table_9_9_row": "(beyond the table) calibration coverage",
        "wording": None,
        "wording_required": False,
        "claim": "Every capability level that could be measured carries an "
                 "empirical source trail: 10 of 10 with the trained model "
                 "present, 9 of 10 on a clean checkout where the tenth is "
                 "recorded unresolved under D2 rather than assumed.",
        "requires": "Calibration record",
        "artefact": "reports/capability_calibration.json",
        "check": ("reports/capability_calibration.json",
                  ["summary", "with_empirical_source_trail"], (10, 9)),
        "tests": [],
        "note": "The two acceptable values are not a weakened check. "
                "Cforge(ml_confidence_gate) scores a feature vector against "
                "models/behavioral_model.pkl, which is gitignored because it is "
                "a trained artefact derived from EMBER. With the model the "
                "level is measured; without it D2's unresolved branch is taken, "
                "which is the designed behaviour and is recorded as such. Any "
                "other value means a level stopped being measurable. See "
                "docs/REPRODUCIBILITY_APPENDIX.md section 6 and thesis 11.6.",
    },
    {
        "id": "C-05",
        "table_9_9_row": "The repair closes the bypass",
        "wording": "The repair closed the evaluated bypass...",
        "wording_required": True,
        "claim": "The repair closed the evaluated bypass: Arm C flags 21/21 of "
                 "family A1, 3/3 of A2, 2/2 of A3, 3/3 of A4 and 3/3 of A7.",
        "requires": "Arms A/B/C and regression",
        "artefact": "reports/three_arm_experiment.json",
        "check": ("reports/three_arm_experiment.json",
                  ["per_arm", "C", "attack", "by_family",
                   "A1_header_over_ciphertext", "flagged"], 21),
        "tests": ["services/monitor/tests/test_tc14_unvalidated_closure.py"],
        "note": "'evaluated' is doing work in this sentence. It closed the "
                "seven families built for it, on one frozen corpus. Family A7 "
                "shows Arm D defeated by a prepended JPEG marker chain, so the "
                "family list is not a proof of closure in general.",
    },
    {
        "id": "C-06",
        "table_9_9_row": "Benign cost is acceptable",
        "wording": "On the evaluated corpus...",
        "wording_required": True,
        "claim": "NOT MADE. On the evaluated corpus the benign cost is NOT "
                 "acceptable: the one-sided 95% upper limit on the "
                 "false-positive difference for validated formats is 25.323 "
                 "percentage points against a predeclared tolerance of 2.00.",
        "requires": "Stratified corpus and paired statistics",
        "artefact": "reports/benign_tradeoff.json",
        "check": ("reports/benign_tradeoff.json",
                  ["bound_1", "by_arm", "C", "upper_limit_pp"], 25.3235),
        "tests": ["services/monitor/tests/test_tc19_benign_bound.py"],
        "note": "The Table 9.9 row exists for a claim this work does not get "
                "to make. The bound was predeclared before the corpus was "
                "built, it failed, and the repair does not ship. Reported as "
                "the primary finding rather than retuned until it passed.",
    },
    {
        "id": "C-07",
        "table_9_9_row": "The pipeline preserves trust",
        "wording": "In the evaluated URDS pipeline...",
        "wording_required": True,
        "claim": "In the evaluated URDS pipeline, one adjudication travels "
                 "Monitor to ML to Ledger to Response to Recovery, and every "
                 "chained block carries all five required fields - 36 of 36.",
        "requires": "TC-23 ... TC-25",
        "artefact": "reports/ledger_coverage.json",
        "check": ("reports/ledger_coverage.json",
                  ["record_completeness", "complete_blocks"], 36),
        "tests": ["services/monitor/tests/test_tc23_chained_record.py",
                  "services/gateway/tests/test_tc25_full_traverse.py"],
        "note": "The ML hop deliberately does not receive the adjudication - "
                "the model scores bytes, not policy - and TC-25 asserts that "
                "absence so it stays a recorded decision rather than a gap.",
    },
    {
        "id": "C-08",
        "table_9_9_row": "Ransomware detection improved generally",
        "wording": NOT_CLAIMED,
        "wording_required": True,
        "claim": NOT_CLAIMED,
        "requires": "External detector comparison",
        "artefact": None,
        "check": None,
        "tests": [],
        "note": "No external-detector comparison was run; §9.13 places it out "
                "of scope. No sentence in the thesis, the paper or the defence "
                "material claims general improvement, and the repair that was "
                "measured does not ship.",
    },
    {
        "id": "C-09",
        "table_9_9_row": "Patentability or legal novelty",
        "wording": NOT_CLAIMED,
        "wording_required": True,
        "claim": NOT_CLAIMED,
        "requires": "Formal legal and prior-art review",
        "artefact": None,
        "check": None,
        "tests": [],
        "note": "Never inferred from this work. No prior-art or legal review "
                "was conducted, so the question is not one this project is in "
                "a position to answer either way.",
    },

    # ---- Headline results beyond Table 9.9's eight rows ----
    {
        "id": "C-10",
        "table_9_9_row": "(beyond the table) the methodological result",
        "wording": None,
        "wording_required": False,
        "claim": "Decision rule D1 fires on NOVELTY_PROOF_PLAN.md §5.2's "
                 "five-level ladder and does not fire on admissibility.py's "
                 "four-point one. Sixteen of twenty cells flip across the six "
                 "policies.",
        "requires": "Admission-recompute matrix on both ladders",
        "artefact": "docs/ADMISSION_RECOMPUTE.md",
        "check": ("reports/admission_recompute.json", ["flip_count"], 16),
        "tests": ["services/monitor/tests/test_tc18_admission_matrix.py"],
        "note": "Phase 5 answered D1 'no cells flip'. That is correct on the "
                "scale it used and wrong on the scale §9.1 makes governing. "
                "Policy F is the computation and is not deployed.",
    },
    {
        "id": "C-11",
        "table_9_9_row": "(beyond the table) the cheapest attack found",
        "wording": None,
        "wording_required": False,
        "claim": "base64.b64encode(ciphertext) lands at exactly 6.000 "
                 "bits/byte and is below all three of the Monitor's entropy "
                 "thresholds, so static_entropy, partial_entropy and "
                 "entropy_rise all fail to fire.",
        "requires": "Calibration record",
        "artefact": "reports/capability_calibration.json",
        "check": ("reports/capability_calibration.json",
                  ["levels", 4, "measured_name"], "negligible"),
        "tests": [],
        "note": "S-1 in the security audit. No detector is written for it: the "
                "obvious counter fires on PEM, .eml, JWT and data-URI content "
                "whose benign cost has not been measured, and this project's "
                "rule is that a mitigation is not proposed until it has been.",
    },
    {
        "id": "C-12",
        "table_9_9_row": "(beyond the table) what the ledger is evidence of",
        "wording": None,
        "wording_required": False,
        "claim": "The hash chain detects in-place tampering 20 times out of 20 "
                 "and structural rewriting 0 times out of 8. 'Tamper-evident' "
                 "means tamper-evident against an attacker who does not "
                 "recompute.",
        "requires": "Tamper sweep and its regression",
        "artefact": "reports/tamper_sweep.json",
        "check": ("reports/tamper_sweep.json", ["structural", "detected"], 0),
        "tests": ["services/ledger/tests/test_tamper_sweep.py"],
        "note": "The chain is unkeyed SHA-256 over public inputs, so an "
                "attacker who can write the database recomputes exactly what "
                "the verifier recomputes. The four undetected cases are "
                "asserted as undetected, so the boundary cannot move quietly.",
    },
    {
        "id": "C-13",
        "table_9_9_row": "(beyond the table) the latency claim",
        "wording": None,
        "wording_required": False,
        "claim": "Detection latency holds the 100 ms budget at p95 (94.650 ms) "
                 "and misses it at p99 (110.550 ms) under 16-way concurrency.",
        "requires": "Load test",
        "artefact": "reports/load_test.json",
        "check": ("reports/load_test.json",
                  ["concurrent_detection", "latency", "p99_ms"], 110.55),
        "tests": [],
        "note": "Say 'within 100 ms at p95 under 16-way concurrency', never "
                "'under 100 ms'. The figure is wall-clock on one host and the "
                "report records which; the reproducible part is the shape, not "
                "the digits.",
    },
    {
        "id": "C-14",
        "table_9_9_row": "(beyond the table) the recovery scope",
        "wording": None,
        "wording_required": False,
        "claim": "Local snapshot restore is verified 13/13 and five injected "
                 "failure modes are each reported distinctly, none as "
                 "verified. VSS-backed restore is NOT measured.",
        "requires": "Failure injection and VSS status",
        "artefact": "reports/vss_status.json",
        "check": ("reports/vss_status.json",
                  ["platform_status", "elevated"], False),
        "tests": ["services/response/recovery/tests"],
        "note": "Acceptance row 12, still partial. The blocker is measured "
                "rather than asserted: the host reports VSS supported, the "
                "shell is not elevated, and both operations refuse for that "
                "one reason.",
    },
]


# --------------------------------------------------------------------------

def dig(value, path: list):
    for key in path:
        if isinstance(key, int):
            if not isinstance(value, list) or key >= len(value):
                return KeyError(key)
            value = value[key]
        else:
            if not isinstance(value, dict) or key not in value:
                return KeyError(key)
            value = value[key]
    return value


def check_claim(claim: dict) -> dict:
    """Verify the artefact exists and the quoted figure is what it holds."""
    result = {"id": claim["id"], "status": "ok", "detail": ""}

    artefact = claim["artefact"]
    if artefact is not None:
        if not (ROOT / artefact).is_file():
            result["status"] = "FAIL"
            result["detail"] = f"artefact missing: {artefact}"
            return result

    if claim["check"] is None:
        result["detail"] = ("not claimed" if claim["claim"] == NOT_CLAIMED
                            else "artefact present; no figure to check")
        return result

    rel, path, expected = claim["check"]
    target = ROOT / rel
    if not target.is_file():
        result["status"] = "FAIL"
        result["detail"] = f"evidence file missing: {rel}"
        return result
    try:
        found = dig(json.loads(target.read_text(encoding="utf-8")), list(path))
    except json.JSONDecodeError as exc:
        result["status"] = "FAIL"
        result["detail"] = f"{rel} is not valid JSON: {exc}"
        return result

    if isinstance(found, KeyError):
        result["status"] = "FAIL"
        result["detail"] = f"{rel}: no such path {'.'.join(map(str, path))}"
        return result

    # A tuple of expected values means the claim itself states more than one
    # acceptable outcome, each for a documented reason - see C-15, where the
    # figure differs depending on whether a gitignored trained model is
    # present. Any value outside the tuple is still a failure.
    if isinstance(expected, tuple):
        same = found in expected
    elif isinstance(expected, float) and isinstance(found, (int, float)):
        same = abs(found - expected) < 1e-6
    else:
        same = found == expected

    if not same:
        result["status"] = "FAIL"
        result["detail"] = (f"{rel}:{'.'.join(map(str, path))} is {found!r}, "
                            f"claim quotes {expected!r}")
    else:
        result["detail"] = f"{'.'.join(map(str, path))} = {found!r}"
    return result


def run_tests(claim: dict) -> dict | None:
    """Run the regressions a claim names, from the owning service's directory."""
    if not claim["tests"]:
        return None
    outcomes = {}
    for target in claim["tests"]:
        parts = target.split("/")
        service = "/".join(parts[:2]) if parts[0] == "services" else "."
        rel = "/".join(parts[2:]) if parts[0] == "services" else target
        done = subprocess.run(
            [sys.executable, "-m", "pytest", rel, "-q", "--no-header"],
            cwd=ROOT / service, capture_output=True, text=True,
            encoding="utf-8", errors="replace")
        tail = [line for line in done.stdout.strip().splitlines() if line.strip()]
        outcomes[target] = {
            "returncode": done.returncode,
            "summary": tail[-1] if tail else "(no output)",
        }
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", action="store_true",
                        help="also run each claim's named regressions")
    args = parser.parse_args()

    rows = []
    failures = 0
    for claim in CLAIMS:
        result = check_claim(claim)
        if result["status"] != "ok":
            failures += 1
        row = dict(claim)
        row["verification"] = result
        if args.tests:
            row["test_run"] = run_tests(claim)
        rows.append(row)

    print(f"{'id':6s} {'status':7s} {'row':44s} detail")
    print("-" * 118)
    for row in rows:
        result = row["verification"]
        print(f"{row['id']:6s} {result['status']:7s} "
              f"{row['table_9_9_row'][:44]:44s} {result['detail'][:60]}")
        if args.tests and row.get("test_run"):
            for target, outcome in row["test_run"].items():
                mark = "pass" if outcome["returncode"] == 0 else "FAIL"
                print(f"{'':14s} {mark}  {target}  {outcome['summary'][:52]}")
    print("-" * 118)

    made = sum(1 for c in CLAIMS if c["claim"] != NOT_CLAIMED)
    print(f"{len(CLAIMS)} claims in the matrix: {made} made, "
          f"{len(CLAIMS) - made} recorded as not claimed")
    mandatory = sum(1 for c in CLAIMS if c["wording_required"])
    print(f"{mandatory} carry Table 9.9's mandatory wording")
    print(f"{failures} failed verification")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() in {"1", "true", "yes"}:
        REPORTS.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "urds.claim_matrix.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "claims": rows,
            "summary": {"total": len(CLAIMS), "made": made,
                        "not_claimed": len(CLAIMS) - made,
                        "mandatory_wording": mandatory,
                        "failed_verification": failures},
        }
        with open(OUT, "w", encoding="utf-8", newline="") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        print(f"\nwrote {OUT}")
    else:
        print("\nURDS_WRITE_REPORTS is not set: report not written")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
