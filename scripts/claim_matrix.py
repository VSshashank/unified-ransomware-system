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
                 "verified. VSS-backed restore IS measured: on an elevated "
                 "Windows host a real Volume Shadow Copy restored a file that "
                 "had been encrypted in place, and the SHA-256 round trip "
                 "returned the original bytes.",
        "requires": "Failure injection and the elevated VSS round trip",
        "artefact": "reports/vss_restore_verified.json",
        # Five assertions, not one. A lone `round_trip_verified: true` is a
        # self-reported boolean in a hand-produced file - the exact shape of
        # evidence this matrix exists to distrust. So the row also pins the
        # elevation that made the measurement possible, the hash the file
        # started and ended at, and `attack_changed_the_file`, without which a
        # restore that did nothing to an untouched file would report success
        # just as loudly.
        "check": [
            ("reports/vss_restore_verified.json",
             ["platform_status", "elevated"], True),
            ("reports/vss_restore_verified.json",
             ["attack_changed_the_file"], True),
            ("reports/vss_restore_verified.json", ["original_sha256"],
             "b22a3f28897defe4e860e3fdb3c3120e6bb79a26ab6bc54bdec07575375815a0"),
            ("reports/vss_restore_verified.json", ["restored_sha256"],
             "b22a3f28897defe4e860e3fdb3c3120e6bb79a26ab6bc54bdec07575375815a0"),
            ("reports/vss_restore_verified.json", ["round_trip_verified"], True),
        ],
        "tests": ["services/response/recovery/tests"],
        "note": "Acceptance row 12, no longer partial, and this row was "
                "changed deliberately rather than by a gate going red. Until "
                "2026-09-17 it asserted the opposite - that VSS-backed restore "
                "was NOT measured - by checking vss_status.json for "
                "platform_status.elevated == false. The branch that measured "
                "the restore wrote its evidence to a different file, so that "
                "check would have gone on passing, and the matrix would have "
                "stayed green while the claim it made had become untrue. "
                "reports/vss_status.json is kept: it is the honest record of "
                "the period when elevation was the blocker.",
    },
    {
        "id": "C-16",
        "table_9_9_row": "(beyond the table) no invented process in the chain",
        "wording": None,
        "wording_required": False,
        "claim": "No event in the tamper-evident chain names a process that "
                 "attribution did not resolve to CERTAIN. Across 48 ledger "
                 "writes driven through the real pipeline, 0 are unsupported.",
        "requires": "Ledger coverage scan",
        "artefact": "reports/ledger_coverage.json",
        "check": [
            ("reports/ledger_coverage.json",
             ["process_attribution_integrity", "unsupported"], 0),
            ("reports/ledger_coverage.json",
             ["process_attribution_integrity", "meets_target"], True),
            # Pins that the scan examined something. Without this a future
            # change that quietly stopped collecting events would report
            # `unsupported: 0` and pass, which is the failure mode this whole
            # row was added to end - a green check over an absence.
            ("reports/ledger_coverage.json",
             ["process_attribution_integrity", "events_examined"], 48),
        ],
        "tests": ["services/monitor/tests/test_ledger_pid_integrity.py"],
        "note": "C-07 above checks that 36 chained blocks carry all five "
                "required fields. That is a count of field *presence*, and it "
                "cannot distinguish an attributed PID from an invented one - "
                "which is not hypothetical: a fabricated process_id was "
                "written into the chain by scripts/si_demo.py and carried in "
                "the suite this matrix cites, and C-07 stayed green "
                "throughout, because the field was there. This row asserts a "
                "value instead. "
                "Read the figure precisely: on a host with no Security-log "
                "audit source every write resolves to UNKNOWN, so 0 of those "
                "48 events names a process at all and the zero is vacuously "
                "satisfied. It measures restraint, not correct attribution. "
                "The named regression feeds the scan PIDs that must be "
                "flagged, so the zero is known to be a measurement rather "
                "than an absence of one; correct attribution under a live "
                "audit source is C-14's sibling evidence, "
                "reports/attribution_live_run.json.",
    },
    {
        "id": "C-17",
        "table_9_9_row": "(beyond the table) the floor under any response time",
        "wording": None,
        "wording_required": False,
        "claim": "Windows Security-channel audit records are delivered on a "
                 "flush timer bounded near one second and independent of write "
                 "rate. Under an uncapped burst 0 of 120 records arrived inside "
                 "750 ms and 120 of 120 arrived inside 3000 ms. Time-to-suspend "
                 "cannot go below this, because the PID arrives with the record.",
        "requires": "Elevated Windows host with the File System audit "
                    "subcategory enabled and a SACL on the measured path",
        "artefact": "reports/attribution_delivery_lag.json",
        "check": [
            # The ceiling is the number that matters, and it is asserted as a
            # bound rather than as an equality: it is a timer, so the exact
            # figure moves by a few milliseconds between runs while the shape
            # does not.
            ("reports/attribution_delivery_lag.json",
             ["results", 3, "within_750ms"], 0),
            ("reports/attribution_delivery_lag.json",
             ["results", 3, "within_3000ms"], 120),
            ("reports/attribution_delivery_lag.json",
             ["results", 3, "never_attributed"], 0),
        ],
        "tests": [],
        "note": "This row exists because a constant in this repository was set "
                "below the floor of the mechanism it reads and nothing caught "
                "it. ATTRIBUTION_WINDOW_MS was 750 ms against a delivery "
                "ceiling of ~1010 ms, so under a burst the correlation window "
                "closed before any record it could have matched arrived - and "
                "the first Phase 3 acceptance measured the consequence as 40 "
                "of 40 documents destroyed with nothing suspended. The window "
                "is now 3000 ms. "
                "Read the burst row precisely: `within_750ms: 0` is the "
                "assertion, and it is an assertion that the *old* value could "
                "not work, not that the new one is sufficient for anything. "
                "What follows from it is a lower bound on FEBR - the "
                "attacker's write rate times the delivery lag - which no "
                "amount of work inside the agent can reduce. Closing that "
                "needs a mechanism that names the writer synchronously with "
                "the write; see docs/LIMITATIONS.md section 1.",
    },
    {
        "id": "C-18",
        "table_9_9_row": "(beyond the table) which attack shapes a response can reach at all",
        "wording": None,
        "wording_required": False,
        "claim": "Whether an encryptor can be suspended is decided by how long "
                 "its process lives, before any question about detection. "
                 "7-Zip archives and unlinks a 500-document corpus in about "
                 "230 ms, against an audit delivery lag of 600-1010 ms, so it "
                 "is gone before the record naming it arrives. A loop around "
                 "openssl has the same property per writer and the opposite "
                 "one per campaign: the driver that unlinks each original "
                 "outlives the lag, which is why that arm is suspended and "
                 "this one is not.",
        "requires": "7-Zip and OpenSSL on the host; no elevation and no agent",
        "artefact": "reports/encryptor_lifetime.json",
        "check": [
            # Categories, not timings. Each arm sits nowhere near a boundary,
            # so the category is the finding and the millisecond figure is the
            # sample - see `_reachability` in the measuring script.
            ("reports/encryptor_lifetime.json",
             ["seven_zip", "reachability"], "unreachable"),
            ("reports/encryptor_lifetime.json",
             ["openssl_loop", "writer_reachability"], "unreachable"),
            ("reports/encryptor_lifetime.json",
             ["openssl_loop", "campaign_reachability"], "reachable"),
            # The correction this artefact exists to make.
            ("reports/encryptor_lifetime.json",
             ["seven_zip", "sdel_unlinks_during_the_run"], True),
        ],
        "tests": [],
        "note": "This row exists because the previous Phase 3 artefact gave the "
                "wrong reason for arm A1's escape, and no gate covered the "
                "sentence that gave it. It said 7-Zip's -sdel unlinks only "
                "after the archive completes, and it attributed the miss to the "
                "container-separability result. Neither holds: the first unlink "
                "lands about 130 ms in, and in the acceptance the decoy "
                "tripwire fired, the agent attributed the deletions to 7z.exe "
                "with CERTAIN confidence, and the response was refused because "
                "the PID no longer existed. See docs/CORRECTIONS.md correction "
                "10. "
                "The second consequence is about the benign half: an arm that "
                "finishes faster than the delivery lag completes untouched "
                "whatever the detector decided, so it cannot be quoted as "
                "evidence of specificity. The benign arms now record "
                "outlived_the_delivery_lag and an arm that did not is reported "
                "as inconclusive.",
    },
    # ---- Phase 5: the adversary nobody here wrote ----
    {
        "id": "C-19",
        "table_9_9_row": "(beyond the table) attribution accuracy against third-party encryptors",
        "wording": None,
        "wording_required": False,
        "claim": "Across six arms of third-party encryptors run inside the "
                 "protected path - OpenSSL, GnuPG, 7-Zip and Red Canary's "
                 "published Atomic Red Team T1486-8, 1,227 files restored and "
                 "verified - the agent mis-attributed no file event to any "
                 "process: 255 of 1,209 events were resolved to a PID with "
                 "CERTAIN confidence, and every one of those 255 was a process "
                 "the launcher had recorded starting. It is zero because the "
                 "system declines to name a writer it cannot prove, not "
                 "because it identifies them all: 954 events were left "
                 "unresolved, and under burst the reason given is an empty "
                 "audit window rather than a disputed one.",
        "requires": "OpenSSL, GnuPG and 7-Zip on the host; the agent running; "
                    "elevation for the ledger",
        "artefact": "reports/phase5_attack_corpus.json",
        "check": [
            ("reports/phase5_attack_corpus.json",
             ["summary", "total_misattributions"], 0),
            ("reports/phase5_attack_corpus.json",
             ["summary", "arms_run"], 6),
            # Nothing was suspended, and the artefact says so rather than
            # leaving the §5 bound looking untested.
            ("reports/phase5_attack_corpus.json",
             ["summary",
              "a_third_party_encryptor_was_suspended_within_bounds"], False),
            # Graded against the runner's answer key, not the agent's record.
            ("reports/phase5_attack_corpus.json",
             ["arms", 4, "metrics", "attribution_correct"], 20),
            ("reports/phase5_attack_corpus.json",
             ["arms", 4, "metrics", "attribution_misattributed"], 0),
        ],
        "tests": ["agent/tests/test_phase5.py"],
        "note": "The number the build plan asks to be zero is zero, and the "
                "number beside it is the cost of keeping it there. A "
                "mis-attributed PID in a hash chain is the defect this branch "
                "exists to fix (docs/CORRECTIONS.md corrections 1 and 11), so "
                "the ladder refuses rather than guesses - and 79 per cent of "
                "the events across these arms arrive with no audited write to "
                "match them. Neither figure can be read without the other, and "
                "the spread between arms is the shape of it: the in-place arm "
                "resolved 216 of 296, the gpg loop 0 of 493. "
                "Two arms produced no events at all and both are real misses "
                "with measured causes - 7-Zip's output is a structurally "
                "valid encrypted container (LIMITATIONS 14), and the atomic's "
                "ciphertext is 123 bytes, which cannot reach a 7.5 bits/byte "
                "threshold at any quality of encryption (LIMITATIONS 22). "
                "The bound the plan sets on suspension is asserted here as "
                "**not met**, so that it cannot read as untested. "
                "The harness that produced all of this is itself gated by "
                "agent/tests/test_phase5.py, which exists because five earlier "
                "runs of it published numbers that were not true - see "
                "corrections 13 to 17.",
    },
    {
        "id": "C-20",
        "table_9_9_row": "(beyond the table) false-positive suspensions per hour of ordinary work",
        "wording": None,
        "wording_required": False,
        "claim": "An hour of ordinary third-party work inside the protected "
                 "path - 7-Zip archiving, tar/gzip, makecab, a git clone and "
                 "gc, a virtualenv build, bulk binary copying and base64 "
                 "encoding, 3,385 workload runs over 519 cycles - produced "
                 "**six** suspensions of processes the harness had started, a "
                 "rate of 5.98 per hour. The design target was zero and it is "
                 "not met. All six were git.exe and all six were resumed: no "
                 "benign process was terminated, and nothing outside the "
                 "harness's own processes was suspended at all. Alerts are a "
                 "different figure and a much larger one - 3,204 file events "
                 "were flagged as suspected encryption in the same hour, "
                 "almost all of them zlib-compressed git objects and makecab "
                 "output, which carry ciphertext-grade entropy behind a header "
                 "the registry does not recognise.",
        "requires": "The agent running; the benign tools installed; one clear "
                    "hour with nothing else writing to the protected path",
        "artefact": "reports/phase5_benign_soak.json",
        "check": [
            ("reports/phase5_benign_soak.json",
             ["metrics", "false_positive_suspensions"], 6),
            ("reports/phase5_benign_soak.json",
             ["metrics", "suspensions_of_other_software"], 0),
            ("reports/phase5_benign_soak.json",
             ["metrics", "flagged_file_events"], 3204),
            ("reports/phase5_benign_soak.json",
             ["metrics", "chain_valid"], True),
        ],
        "tests": ["agent/tests/test_phase5.py"],
        "note": "This row records a missed bound, so it is worth being "
                "precise about what it does and does not gate. Two of the "
                "four figures are wall-clock counts from one hour on one host "
                "and a re-run will not reproduce them; they are pinned "
                "because the matrix compares values, and a re-run is expected "
                "to re-stamp them. The two that are structural - nothing "
                "outside this run's own processes was suspended, and the "
                "chain verified - are the ones a reader should weigh. "
                "The finding is 'not zero', not 'exactly six'. "
                "It is also a lower bound on the rate: six members of the "
                "build plan's benign corpus are absent from this host - "
                "ffmpeg, VeraCrypt, Windows Update, a Visual Studio build, "
                "browser cache churn and OneDrive sync - each named in "
                "`not_installed` with the reason, and npm-install failed all "
                "519 attempts on this host so it measured nothing. "
                "The 3,204 alerts are the more interesting number and they "
                "corroborate the thesis's separability result (§7.8) from the "
                "benign side: git's loose objects are zlib streams with no "
                "recognised header, which is the same shape as ciphertext "
                "under every content-only predicate this system has.",
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

    # `check` is one (rel, path, expected) tuple, or a list of them when the
    # claim states more than one thing. Every assertion in the list must hold:
    # a claim that says three things and checks one of them is a claim with two
    # unchecked parts.
    checks = claim["check"]
    if isinstance(checks, tuple):
        checks = [checks]

    details = []
    for rel, path, expected in checks:
        ok, detail = check_one(rel, path, expected)
        details.append(detail)
        if not ok:
            result["status"] = "FAIL"
            result["detail"] = detail
            return result

    result["detail"] = "; ".join(details)
    return result


def check_one(rel: str, path: list, expected) -> tuple[bool, str]:
    """One assertion: the figure at `path` inside `rel` is `expected`."""
    target = ROOT / rel
    if not target.is_file():
        return False, f"evidence file missing: {rel}"
    try:
        found = dig(json.loads(target.read_text(encoding="utf-8")), list(path))
    except json.JSONDecodeError as exc:
        return False, f"{rel} is not valid JSON: {exc}"

    if isinstance(found, KeyError):
        return False, f"{rel}: no such path {'.'.join(map(str, path))}"

    # A tuple of expected values means the claim itself states more than one
    # acceptable outcome, each for a documented reason - see C-15, where the
    # figure differs depending on whether a gitignored trained model is
    # present. Any value outside the tuple is still a failure.
    if isinstance(expected, tuple):
        same = found in expected
    elif isinstance(expected, bool) or isinstance(found, bool):
        # bool is a subclass of int, so `True == 1` and `1 == True`. A claim
        # quoting a boolean must not be satisfied by a count that happens to
        # be 1, and a claim quoting 1 must not be satisfied by `true`.
        same = found is expected
    elif isinstance(expected, float) and isinstance(found, (int, float)):
        same = abs(found - expected) < 1e-6
    else:
        same = found == expected

    if not same:
        return False, (f"{rel}:{'.'.join(map(str, path))} is {found!r}, "
                       f"claim quotes {expected!r}")
    return True, f"{'.'.join(map(str, path))} = {found!r}"


# --------------------------------------------------------------------------
# Provenance and freshness.
#
# Everything above proves exactly one thing: *the artefact says X*. It cannot
# prove *X is true of the code at HEAD*. An artefact generated on a branch that
# was never merged, or carried forward from before the change it is supposed to
# measure, satisfies every check above and is worth nothing. That hole sat in
# this script - the project's own best tool - until 2026-09-17.
#
# So every JSON evidence file the matrix reads must carry `generated_at` and
# the `commit` it was produced at, and that commit must be an ancestor of HEAD.
#
# What this does NOT prove, said plainly because the gap is the whole point of
# the tool: it does not detect a hand-edited artefact. The stamp lives in the
# same file as the figure, so whoever can edit one can edit the other. That is
# `scripts/artefact_manifest.py --verify`, which digests every stable artefact
# and runs immediately before this script in the reproduction gate. Provenance
# answers "is this evidence from this line of development"; the manifest
# answers "is this evidence the bytes we froze". Neither answers the other.
#
# Nor does it prove the artefact is current with respect to its *inputs*: a
# report stamped at an ancestor commit is accepted even if the code that
# generates it changed afterwards. Doing better needs an artefact-to-source
# dependency map, which does not exist here. Each row instead reports how many
# commits behind HEAD its evidence is, so the gap is visible rather than silent.
# --------------------------------------------------------------------------

def git_run(*args: str, root: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root or ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")


def git_context(root: Path | None = None) -> dict:
    """Whether there is a repository here with enough history to judge."""
    head = git_run("rev-parse", "HEAD", root=root)
    if head.returncode != 0:
        return {"available": False,
                "reason": "not a git checkout, or git is not installed"}
    shallow = git_run("rev-parse", "--is-shallow-repository", root=root)
    return {
        "available": True,
        "head": head.stdout.strip(),
        "shallow": shallow.stdout.strip() == "true",
    }


def provenance_artefacts(root: Path | None = None) -> list[str]:
    """Every JSON evidence file that claims a provenance, cited or not.

    Two sources, because being cited by a claim and asserting where you came
    from are different things and either one should be enough to be checked.

    The first is the matrix's own reading list. The second is every
    `reports/*.json` carrying both a `generated_at` and a `commit`: a file that
    stamps itself is asserting it was produced at a known point in this
    history, and an assertion nothing verifies is the shape of defect this
    whole gate exists for. Until this was added, the two artefacts recording
    whether the host agent met its acceptance - `agent_phase2_acceptance.json`
    and `agent_phase3_acceptance.json` - were stamped and unchecked, which is
    exactly how docs/CORRECTIONS.md correction 9 happened: the Phase 3 artefact
    was rewritten and the thing pinning it was not.

    Reports with no stamp are left alone rather than failed. Several predate
    the convention and are not evidence for any claim; failing them here would
    turn one gate into a campaign, and a gate nobody can get green is a gate
    people learn to skip.
    """
    root = root or ROOT
    found: list[str] = []
    for claim in CLAIMS:
        candidates = []
        if claim["artefact"]:
            candidates.append(claim["artefact"])
        if claim["check"] is not None:
            checks = claim["check"]
            if isinstance(checks, tuple):
                checks = [checks]
            candidates.extend(rel for rel, _, _ in checks)
        for rel in candidates:
            # Only JSON evidence. A .md or .py artefact is tracked source, and
            # git already says which commit it is at; stamping a generated_at
            # into a source file would mean nothing.
            if rel.endswith(".json") and rel not in found:
                found.append(rel)

    for path in sorted((root / "reports").glob("*.json")):
        rel = path.relative_to(root).as_posix()
        if rel in found:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue          # check_provenance's job, and only if cited
        if isinstance(payload, dict) and "generated_at" in payload and "commit" in payload:
            found.append(rel)

    return sorted(found)


def check_provenance(rel: str, context: dict, root: Path | None = None) -> dict:
    """The artefact says where it came from, and that commit is behind HEAD."""
    root = root or ROOT
    result = {"artefact": rel, "status": "ok", "detail": ""}
    target = root / rel

    if not target.is_file():
        return {**result, "status": "FAIL", "detail": f"missing: {rel}"}
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {**result, "status": "FAIL", "detail": f"not valid JSON: {exc}"}
    if not isinstance(payload, dict):
        return {**result, "status": "FAIL",
                "detail": "top level is not an object, so it carries no stamp"}

    missing = [k for k in ("generated_at", "commit") if k not in payload]
    if missing:
        return {**result, "status": "FAIL",
                "detail": f"no {' and no '.join(missing)}; regenerate it with "
                          f"URDS_WRITE_REPORTS=1 so the generator stamps it"}

    stamp = payload["generated_at"]
    try:
        when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return {**result, "status": "FAIL",
                "detail": f"generated_at {stamp!r} is not an ISO 8601 instant"}
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    ahead = (when - datetime.now(timezone.utc)).total_seconds()
    if ahead > 86400:
        return {**result, "status": "FAIL",
                "detail": f"generated_at {stamp} is {ahead / 3600:.0f}h in the "
                          f"future; check the clock that wrote it"}

    commit = str(payload["commit"])
    if not context["available"]:
        return {**result, "status": "FAIL",
                "detail": f"cannot verify {commit[:9]}: {context['reason']}. "
                          f"Run this from a git checkout."}

    resolved = git_run("rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}",
                       root=root)
    if resolved.returncode != 0:
        hint = (" (shallow clone: run `git fetch --unshallow`)"
                if context["shallow"] else "")
        return {**result, "status": "FAIL",
                "detail": f"commit {commit[:9]} is not in this repository{hint}"}

    if git_run("merge-base", "--is-ancestor", commit, "HEAD",
               root=root).returncode != 0:
        return {**result, "status": "FAIL",
                "detail": f"commit {commit[:9]} is not an ancestor of HEAD: "
                          f"this evidence is from another line of development"}

    behind = git_run("rev-list", "--count", f"{commit}..HEAD",
                     root=root).stdout.strip()
    return {**result, "detail": f"{commit[:9]}, {behind} commits behind HEAD"}


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

    context = git_context()
    provenance = [check_provenance(rel, context)
                  for rel in provenance_artefacts()]
    stale = sum(1 for entry in provenance if entry["status"] != "ok")

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

    print()
    print(f"{'provenance':6s} {'status':7s} {'artefact':44s} detail")
    print("-" * 118)
    for entry in provenance:
        print(f"{'':6s} {entry['status']:7s} {entry['artefact'][:44]:44s} "
              f"{entry['detail'][:60]}")
    print("-" * 118)
    print(f"{len(provenance)} evidence artefacts carry a commit that is an "
          f"ancestor of HEAD: {len(provenance) - stale} yes, {stale} no")

    made = sum(1 for c in CLAIMS if c["claim"] != NOT_CLAIMED)
    print(f"{len(CLAIMS)} claims in the matrix: {made} made, "
          f"{len(CLAIMS) - made} recorded as not claimed")
    mandatory = sum(1 for c in CLAIMS if c["wording_required"])
    print(f"{mandatory} carry Table 9.9's mandatory wording")
    print(f"{failures} failed verification, {stale} failed provenance")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() in {"1", "true", "yes"}:
        REPORTS.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "urds.claim_matrix.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "claims": rows,
            "provenance": {"git": context, "artefacts": provenance},
            "summary": {"total": len(CLAIMS), "made": made,
                        "not_claimed": len(CLAIMS) - made,
                        "mandatory_wording": mandatory,
                        "failed_verification": failures,
                        "failed_provenance": stale},
        }
        with open(OUT, "w", encoding="utf-8", newline="") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        print(f"\nwrote {OUT}")
    else:
        print("\nURDS_WRITE_REPORTS is not set: report not written")

    return 1 if (failures or stale) else 0


if __name__ == "__main__":
    sys.exit(main())
