# Capability-governed exception admissibility in a ransomware monitor — paper draft

**Item P7.4 (NI + SH). Phase 7, Week 27.**

**Every headline sentence in this draft carries a bracketed pointer to the test,
report or stated assumption that supports it.** That is the P7.4 requirement, and
it is also the only way a reader can tell which sentences are results and which
are framing. A sentence with no pointer is framing; if one has a pointer that
does not resolve, the sentence is wrong and the pointer is how you find out.

Wording follows Table 9.9, which is mandatory. Where it constrains a phrase, the
constrained phrase is used verbatim rather than paraphrased into something
stronger.

---

## Abstract

The project team designed and implemented a six-service ransomware detection and
recovery system, and this work examines one mechanism inside it: the rule that
lets a recognised container header cancel a high-entropy alert. In the reviewed
URDS Monitor that rule is applied outside the system's own governance layer
[`docs/ADMISSION_RECOMPUTE.md`, the `container` row; `reports/ledger_coverage.json`,
`by_population.ungoverned` — 0 adjudications from 12 events].

Under the declared capability model, forging that exemption costs an attacker
four bytes for eleven of the seventeen container formats the current registry
contains, and one standard-library call for the rest
[`reports/capability_calibration.json`; `services/monitor/tests/test_tc14_unvalidated_closure.py`].
A repair was predeclared, implemented behind a policy switch, and evaluated in
five arms against a frozen corpus. The repair closed the evaluated bypass — 21/21,
3/3 and 2/2 on three attack families [`reports/three_arm_experiment.json`] — and
its benign cost exceeded the predeclared bound: on the evaluated corpus the
one-sided 95% upper limit on the false-positive difference is 25.323 percentage
points against a tolerance of 2.00 [`reports/benign_tradeoff.json`, `bound_1`].
**The repair therefore does not ship.**

The contribution is the method and its negative results, not a detector that
performs better. Ransomware detection improved generally is not claimed.

---

## 1. What was examined, and what was not

The project team designed and implemented the system; this work audits one
mechanism in it and does not re-derive the rest
[`docs/PHASE1-4_COMPLETION_SUMMARY.md` for what was built].

**In scope.** The container exemption in `detection.classify`, the capability
cost model in `admissibility.py`, and their propagation through ML, ledger,
response and recovery.

**Out of scope, by Chapter 9 §9.13.** Adaptive search over repair variants,
Pareto optimisation, a framework abstraction, new structural validators for the
eleven unvalidated formats, comparison against external detectors, blockchain
anchoring, mobile support, any claim beyond URDS, and any claim about
patentability [§9.13; patentability or legal novelty is never inferred from this
work].

XGBoost, FastAPI, watchdog, EMBER, CLEAR and RanSAP are inputs to this work, not
contributions of it.

---

## 2. The mechanism

`detection.classify` returns `benign_compressed` when a file's entropy is above
threshold and its first bytes match a recognised container signature. The purpose
is real: a ZIP, a JPEG and a PDF are all near-uniform by construction, and a
detector without the exemption flags every one of them
[`reports/three_arm_experiment.json`, Arm B: 185 of 275 benign files flagged].

`admissibility.adjudicate` is the system's governance layer. It prices what it
costs an attacker to *avoid* each detection signal and to *forge* each
suppression, and admits a suppression only when forging costs strictly more than
avoiding [`services/monitor/admissibility.py`;
`services/monitor/tests/test_tc18_admission_matrix.py`].

**The exemption does not reach that layer.** `app.handle_event` adjudicates only
a verdict that is already suspicious, and `benign_compressed` is not
[`services/monitor/app.py`; `reports/ledger_coverage.json`]. In the reviewed URDS
Monitor the most-used evidence-cancelling path in the system is the one path the
governance layer never sees.

---

## 3. Calibration

Ten strategies, each **built and run** against the deployed code, with the
operational facts of the attack recorded and the capability level derived from
those facts twice, in opposite decision orders
[`scripts/capability_calibration.py`; `reports/capability_calibration.json`]. All
ten reproduce; none is unresolved; **10 of 10 carry an empirical source trail**.

Under the declared capability model, three of the five detection signals are
cheaper to avoid than the cost table says:

| signal | declared | measured | the attack |
|---|---|---|---|
| `structural_mismatch` | moderate | **negligible** | `gzip.compress(ciphertext)` |
| `entropy_rise` | moderate | **low** | write to a path nothing has measured |
| `partial_entropy` | moderate | **negligible** | `base64.b64encode(ciphertext)` |

The third of those is the strongest single result in the calibration and it was
missed in the first pass [`docs/PHASE5_COMPLETION_REPORT.md` §3.1]. Base64 spends
eight output bits per six of input, so uniform ciphertext lands at exactly 6.000
bits/byte — below the whole-file threshold of 7.5, below the per-block threshold
of 7.9, and below the differential floor of 7.0. **One standard-library call
defeats all three entropy signals at once**, at a cost of 33% in file size
[`reports/capability_calibration.json`, `partial_entropy`; `docs/SECURITY_AUDIT.md` S-1].

The governing method document's own five-level ladder is a different scale from
the four-point one the deployed table is written on, and the levels are not
comparable rung for rung. Every strategy therefore carries a level on both
[`reports/capability_calibration.json`, `plan_level`].

---

## 4. Admission recomputation

Twenty mitigation × signal cells under six policies: the deployed comparison and
the strict one, against the declared costs, the measured costs, and the governing
document's ladder [`scripts/admission_recompute.py`;
`docs/ADMISSION_RECOMPUTE.md`]. **Sixteen cells flip**, each attributed to the
change that caused it.

Two results matter.

**The strict rule is free on the deployed table.** All fifteen live cells decide
identically under `>` and `>=`, which is why the rule the governing document
mandates was adopted without argument, and why adopting it settles nothing
[`docs/ADMISSION_RECOMPUTE.md`, policy B; `test_tc18_admission_matrix.py`].

**Decision rule D1 fires, on the governing ladder and not on the deployed one.**
Phase 5 reported that path-whitelist and training-mode admissions did not flip
from admitted to attenuated. That is true on the four-point scale and false on the
five-level one: there, `path` and `training_mode` forgery are both Level 0, so are
`ransom_extension` and `static_entropy` avoidance, and the strict rule breaks all
four ties against the suppression. Under that policy the path whitelist and
training mode cancel nothing at all [`docs/ADMISSION_RECOMPUTE.md`, policy F].

**The answer to D1 is a property of the scale the question is asked on, not of the
system.** That is a methodological result, and it is the one this work would
defend hardest.

---

## 5. The experiment

Five arms over 34 attack cases in seven families and a frozen 275-file benign
corpus, paired — every arm scores the same file from one reading, so no arm can
differ by a disk read [`scripts/three_arm_experiment.py`;
`reports/three_arm_experiment.json`; corpus tag `corpus-frozen-week21`].

| family | A (deployed) | B (null) | C1 | C (repair) | D (post-hoc) |
|---|---|---|---|---|---|
| A1 header over ciphertext (21) | 7 | 21 | 21 | **21** | 21 |
| A2 standard-library container (3) | 0 | 3 | 0 | **3** | 3 |
| A3 incomplete container (2) | 1 | 2 | 2 | **2** | 2 |
| A4 intermittent in a valid container (3) | 0 | 3 | 0 | **3** | 3 |
| A7 forged inner content (3) | 0 | 3 | 0 | **3** | 1 |
| benign false positives (275) | 0 | 185 | 90 | **120** | 90 |

The repair closed the evaluated bypass. On the evaluated corpus its benign cost is
120 false positives in 275 files.

**Three decision rules fire and one does not.**

- **D3 does not fire.** Arm B — the exemption deleted — produces a 67.3%
  false-positive rate against a 5% budget, so the governance layer is doing work
  that deleting the mitigation cannot do. This is the one branch favourable to the
  project and it is the null control that establishes it.
- **D4 fires**, and Arm C answers it: C1 leaves all three standard-library
  container witnesses benign, and the compression-yield clause closes them.
- **D5 fires hard.** On the unvalidated × incompressible stratum every arm
  including the null control raises false positives on **90 of 90** files —
  100.0 pp against a 15.0 pp tolerance [`reports/benign_tradeoff.json`, `d5`].
- **Bound 1 fails** at 25.323 pp against 2.00 [`reports/benign_tradeoff.json`,
  `bound_1`; `services/monitor/tests/test_tc19_benign_bound.py`].

**`CONTAINER_EXEMPTION_POLICY` therefore defaults to `legacy` and the repair does
not ship.** The correct long-term fix is a real structural validator for bzip2,
xz, GIF and RIFF, which §9.13 places outside this project's scope. Both halves are
reported.

Detection latency is unchanged by the repair: all five arms measure within
noise of each other at ~3.3 ms median, interleaved per repetition with rotation
[`reports/three_arm_experiment.json`, `latency_ms`].

---

## 6. Integration

In the evaluated URDS pipeline, one adjudication travels Monitor → ML → Ledger →
Response → Recovery, and every hop holds the *same* record rather than a lookalike
[`services/gateway/tests/test_tc25_full_traverse.py`, asserted as equality;
`reports/pipeline_governance.json`]. The ML hop deliberately does not receive it —
the model scores bytes, not policy — and that absence is asserted so it stays a
recorded decision.

Every chained mitigation decision carries all five required fields — mitigation
identifier, validation state, capability levels, policy version and reason —
across all three block types that can hold one: **36 of 36 blocks**
[`reports/ledger_coverage.json`, `record_completeness`;
`services/monitor/tests/test_tc23_chained_record.py`].

An incomplete validation now yields a named `deferred` state rather than a
conclusion the evidence does not support
[`services/monitor/tests/test_tc16_incomplete_deferred.py`].

---

## 7. What this system does not stop

Nine open findings, each built and run [`docs/SECURITY_AUDIT.md`].

The two worth a reader's attention:

**The ledger detects edits, not rewrites.** Twenty in-place tampers at three
positions are all detected — 20/20, which is the "100% of the time" the exit gate
requires. Eight structural tampers are detected zero times, and none of them can
be: the chain is unkeyed SHA-256 over public inputs, so an attacker who can write
the database recomputes exactly what the verifier will recompute
[`reports/tamper_sweep.json`; `services/ledger/tests/test_tamper_sweep.py`].
**"Tamper-evident" here means tamper-evident against an attacker who does not
recompute.** Closing it needs a signing key or an external anchor; §9.13 places
anchoring out of scope.

**The Monitor outruns its own audit trail.** Under sustained load it accepts
events 18.7× faster than it forwards them to the ledger, into an unbounded queue
[`reports/load_test.json`]. The backlog grows fastest during exactly the burst it
exists to record. Detection latency holds the 100 ms budget at p95 (94.650 ms) and
misses it at p99 (110.550 ms) under 16-way concurrency, where the single-file
benchmark reports 25.764 ms at p95 [`reports/as_benchmarks.json`].

---

## 8. Limitations

Stated, not buried.

1. **Monitor-scoped where recovery is concerned.** Local restore is verified
   13/13; VSS-backed restore is not measured, and the blocker is elevation rather
   than capability [`reports/vss_status.json`].
2. **One reviewer.** §9.15 asks for AS↔NI reproduction of every capability level.
   Every level here was derived twice, in opposite decision orders, from the same
   recorded facts — which is the reproduction protocol — but by one author in one
   session. Every record carries
   `reproduction.independent_human_reviewer: false` and none claims otherwise.
3. **A synthetic corpus.** 275 procedurally generated files, byte-identically
   reproducible from a recorded seed, stratified by validator coverage and
   compressibility. It is not a sample of anyone's real filesystem, and the
   false-positive figures are figures about it.
4. **In-process measurement.** The Compose stack, the network between containers
   and a real filesystem under real load are unmeasured.
5. **A methodological result, not a better detector.** Ransomware detection
   improved generally is not claimed, and nothing here generalises beyond URDS.
6. **The P0 error.** Phases 5 and 6 were carried out believing the governing
   method document did not exist. It does. What that cost is set out in
   `docs/METHOD_DOCUMENT_STATUS.md`, and the largest single item is that D1 was
   answered on the wrong ladder and reversed when asked again on the right one.

---

## 9. Contribution

1. A method for pricing a false-positive mitigation against the detection signal
   it cancels, with every price built and run rather than assigned.
2. The finding that the answer to a capability-governance question depends on the
   ladder it is asked on, demonstrated by the same question producing opposite
   answers on two scales over one set of recorded facts.
3. A repair that closes the evaluated bypass and is rejected on its measured
   benign cost — reported as a negative result rather than tuned until it passed.
4. An audit trail that carries the decision to every hop that acts on it, and a
   measured statement of what that trail is and is not evidence of.

---

## Appendix — every headline sentence and its evidence

| § | Sentence | Evidence | Kind |
|---|---|---|---|
| Abstract | the exemption is applied outside the governance layer | `reports/ledger_coverage.json` `by_population.ungoverned` | report |
| Abstract | four bytes for eleven formats | `test_tc14_unvalidated_closure.py` | test |
| Abstract | the repair closed the evaluated bypass | `reports/three_arm_experiment.json` | report |
| Abstract | 25.323 pp against 2.00 | `test_tc19_benign_bound.py` | test |
| 2 | Arm B flags 185 of 275 | `reports/three_arm_experiment.json` | report |
| 2 | the exemption never reaches `adjudicate` | `test_tc18_admission_matrix.py` (five ungoverned cells) | test |
| 3 | 10 of 10 empirical | `reports/capability_calibration.json` `summary` | report |
| 3 | base64 at 6.000 bits/byte defeats all three | `reports/capability_calibration.json` `partial_entropy` | report |
| 4 | 16 cells flip | `reports/admission_recompute.json` `flip_count` | report |
| 4 | the strict rule is free on the deployed table | `test_tc18_admission_matrix.py` | test |
| 4 | D1 fires on the plan's ladder | `test_tc18_admission_matrix.py` | test |
| 5 | family-by-family closure | `reports/three_arm_experiment.json` | report |
| 5 | D5 fires at 100.0 pp | `test_tc19_benign_bound.py` | test |
| 5 | latency unchanged across arms | `reports/three_arm_experiment.json` `latency_ms` | report |
| 6 | one record at every hop, by equality | `test_tc25_full_traverse.py` | test |
| 6 | 36 of 36 blocks complete | `test_tc23_chained_record.py` | test |
| 6 | INCOMPLETE yields `deferred` | `test_tc16_incomplete_deferred.py` | test |
| 7 | 20/20 in-place, 0/8 structural | `test_tamper_sweep.py` | test |
| 7 | 18.7:1 production to drain | `reports/load_test.json` | report |
| 7 | p95 94.650 ms, p99 110.550 ms | `reports/load_test.json` | report |
| 8.1 | VSS not measured, blocker is elevation | `reports/vss_status.json` | report |
| 8.2 | one reviewer | `reports/capability_calibration.json` `second_reviewer_statement` | stated assumption |
| 8.3 | the corpus is synthetic and seeded | `test_tc20_corpus_labels.py` | test |
| 8.4 | in-process measurement | `reports/load_test.json` `limits` | stated assumption |
| 8.5 | no general claim | Table 9.9 | stated assumption |
| 8.6 | the P0 error | `docs/METHOD_DOCUMENT_STATUS.md` | stated assumption |
