# Phase 8 completion report

**Branch** `feat/admissibility-governance-novelty-v2` · **Date** 5 September 2026

This is the final report `docs/PHASE5-8_MASTER_PROMPT.md` §5 requires. It has
seven sections, in the order the prompt lists them, and it is written to be read
by someone who does not trust it: every figure names the artefact it comes from
and the command that regenerates that artefact.

**Everything here was measured in this session or is quoted from an artefact
regenerated in this session.** The Week 32 gate — a clean `git clone`, a fresh
virtual environment per service, every artefact regenerated, every digest
compared, every claim re-checked and all five suites run — passed on 5 September
2026 at commit `07dfdac`: **27 stages, 0 failed**. `reports/reproduction_check.json`
is the machine-readable record.

---

## 1. P0 … P8.4, one line each

`~` marks partial. Every row names the artefact and the command that proves it.

### Phase 5 — calibration

| Item | Status | Artefact | Proving command |
|---|---|---|---|
| **P5.0** Baseline freeze | done | `reports/phase5_baseline.json` | `python scripts/phase5_baseline.py` |
| **P5.1** Mitigation-path inventory | done | `docs/MITIGATION_INVENTORY.md` | inspection; each entry names its source file and line |
| **P5.2** Extended evidence harness | done | `reports/recf_exemption_evidence.json` | `URDS_WRITE_REPORTS=1 python scripts/recf_exemption_evidence.py` |
| **P5.3** Stratified benign corpus, frozen | done | `reports/benign_corpus_manifest.json`, tag `corpus-frozen-week19` | `python scripts/build_benign_corpus.py --verify` |
| **P5.4** Capability search, locked and reproduced | done | `reports/capability_calibration.json`, tag `cost-table-frozen-week20` | `URDS_WRITE_REPORTS=1 python scripts/capability_calibration.py` |
| **P5.5** Admission-recompute matrix | done | `reports/admission_recompute.json`, `docs/ADMISSION_RECOMPUTE.md` | `URDS_WRITE_REPORTS=1 python scripts/admission_recompute.py` |
| **P5.6** Predeclare the Phase 6 bounds | done | `docs/PHASE5_PREDECLARED_BOUNDS.md` | committed before the repair branch opened |

### Phase 6 — repair and experiment

| Item | Status | Artefact | Proving command |
|---|---|---|---|
| **P6.1** Repair behind a configuration switch | done | `CONTAINER_EXEMPTION_POLICY`, five values | `services/monitor/tests/test_tc14_*.py` |
| **P6.2** Three-arm experiment | done | `reports/three_arm_experiment.json` | `URDS_WRITE_REPORTS=1 python scripts/three_arm_experiment.py` |
| **P6.3** Paired benign statistics | done | `reports/benign_tradeoff.json` | `URDS_WRITE_REPORTS=1 python scripts/benign_tradeoff.py` |
| **P6.4** Pipeline integration | done | `reports/pipeline_governance.json` | `URDS_WRITE_REPORTS=1 python scripts/pipeline_governance.py` |
| **P6.5** Failure injection | done | `reports/failure_injection.json` | `URDS_WRITE_REPORTS=1 python scripts/failure_injection.py` |
| **P6.6** Five fields in every adjudication block | done | `reports/ledger_coverage.json`, 36/36 | `URDS_WRITE_REPORTS=1 python scripts/ledger_coverage.py` |
| **P6.7** The named `deferred` state for INCOMPLETE | done | `services/monitor/tests/test_tc16_incomplete_deferred.py` | `pytest tests/test_tc16_incomplete_deferred.py` |
| **P6.8** Both ladders, and the strict rule adopted | done | `reports/capability_calibration.json` levels; policies E and F | `URDS_WRITE_REPORTS=1 python scripts/admission_recompute.py` |

### Phase 7 — hardening

| Item | Status | Artefact | Proving command |
|---|---|---|---|
| **P7.1** Regression suite TC-14 … TC-25 | done | `services/monitor/tests/test_tc*.py` | `pytest` per service |
| **P7.2** CI pipeline | **~ partial** | `.github/workflows/tests.yml` exists | **no CI run has ever been observed** — see §6 |
| **P7.3** Security audit, load testing, tamper verification | done | `docs/SECURITY_AUDIT.md`, `reports/load_test.json`, `reports/tamper_sweep.json` | `URDS_WRITE_REPORTS=1 python scripts/load_test.py`; `… scripts/tamper_sweep.py` |
| **P7.4** Paper draft, user manual, demonstration | **~ partial** | `docs/PAPER_DRAFT.md`, `docs/USER_MANUAL.md`, `docs/DEMONSTRATION_SCRIPT.md`, `reports/si_demo_evidence.txt` | the script and its evidence exist; **no video was recorded** — see §6 |

### Phase 8 — write-up

| Item | Status | Artefact | Proving command |
|---|---|---|---|
| **P8.1** Final thesis, 80–100 pages | done | `docs/THESIS.md` — 24,115 words, 2,812 lines, 46 tables, 12 chapters and 9 appendices | `python -c "print(len(open('docs/THESIS.md',encoding='utf-8').read().split()))"` |
| **P8.1** Authorship record | done | `PROJECT_IMPLEMENTATION_RECORD.md` | `python scripts/implementation_record.py` |
| **P8.1** Negative results chapter | done | `docs/THESIS.md` ch. 10, ten sections | — |
| **P8.1** Limitations chapter | done | `docs/THESIS.md` ch. 11, ten sections | — |
| **P8.1** Superseded figures retained with dates | done | `docs/THESIS.md` Appendix D, ten rows | — |
| **P8.2** Claim-to-artefact matrix | done | `docs/CLAIM_MATRIX.md`, `reports/claim_matrix.json` | `python scripts/claim_matrix.py` — 15 claims, 0 failed |
| **P8.3** Defence presentation | done | `docs/DEFENCE_PRESENTATION.md` — 20 slides, 12 anticipated questions | — |
| **P8.3** Packaged deployment | **~ partial** | `reports/release_package.json`, `dist/urds-ddedac8ac79e.zip`, 202 files, 1.1 MiB, audit 11/11 | `URDS_WRITE_REPORTS=1 python scripts/package_release.py` — **images not built, stack not started**, see §6 |
| **P8.4** Reproducibility appendix | done | `docs/REPRODUCIBILITY_APPENDIX.md`, `reports/artefact_manifest.json` | `python scripts/artefact_manifest.py --verify` |
| **Week 32 exit gate** | **done, by execution** | `reports/reproduction_check.json` | `python scripts/verify_reproduction.py` — 27 stages, 0 failed |

**Score: 26 done, 3 partial, 0 not done.** Every partial is a partial for a
reason outside what could be measured here, and §6 gives each one its evidence.

---

## 2. D1 … D6, every evaluation

| Rule | Question | Answer | Artefact |
|---|---|---|---|
| **D1** | Do the path-whitelist and training-mode admissions flip from admitted to attenuated under the calibrated rule? | **Depends on the ladder, and that is the finding.** 0 cells flip on `admissibility.py`'s four-point scale — the Phase 5 answer. **4 cells flip under policy F**, the plan's five-level ladder with the plan's strict `>` rule, which plan §9.1 makes governing | `reports/admission_recompute.json`, policies A–F |
| **D2** | Does any capability level fail to reproduce? | **No.** 10 of 10 reproduce across opposite derivation orders, 0 unresolved. **On a clean checkout it is 9 of 10**, with `C_forge(ml_confidence_gate)` recorded unresolved because it needs the gitignored model — which is D2 working as designed | `reports/capability_calibration.json`, `summary.reproduced` |
| **D3** | Is the null control's false-positive cost acceptable, making the mitigation not worth governing? | **Does not fire.** Arm B — the exemption deleted outright — flags 185 of 275, 67.3%, against a 5% budget. Deleting the exemption is not an option, so something has to decide when it applies | `reports/three_arm_experiment.json`, `d3` |
| **D4** | Does validator coverage alone leave a standard-library container witness benign? | **Fires.** Arm C1 flags **0 of 3** A2 witnesses. The compression-yield clause is what closes them, which is what makes C the repair rather than C1 | `reports/three_arm_experiment.json`, `d4` |
| **D5** | Do false positives in the unvalidated × incompressible stratum exceed tolerance? | **Fires hard.** **100.0 pp against a 15.0 pp tolerance** — 90 false positives on 90 files — identical across arms B, C1, C and D. Exceeds by a factor of 6.7 | `reports/benign_tradeoff.json`, `d5` |
| **D6** | Is a decision recorded without reaching the ledger? | **Was firing; now closed.** All six pipeline gates pass and **36 of 36 chained adjudication blocks carry all five required fields**, measured per field | `reports/ledger_coverage.json`, `reports/pipeline_governance.json`, `d6` |

**Four fire, one does not, one was closed. The single rule that does not fire is
the only one whose firing would have been favourable to the project** — D3, whose
branch would have said the mitigation is not worth governing.

D5's consequence is the headline negative result: **`CONTAINER_EXEMPTION_POLICY`
stays `legacy` and the repair does not ship.** It exists, it is tested, it closes
34 of 34 attack cases, and it is off.

---

## 3. Table 9.8, every benchmark with its measured value

Table 9.8 (plan §9.11) continues Table 5.9. Nine rows.

| # | Measure | Target | Measured | Met | Artefact |
|---|---|---|---|---|---|
| 1 | Simulator families detected and restored | 13 / 13, no regression | **13 / 13 detected, every one within 2 s, every restore round-trip true** | **yes** | `reports/simulator_families.json` |
| 2 | Detection-path latency after repair | median within the sub-100 ms budget; median and IQR over ≥10 repetitions | 20 repetitions × 7 files = 140 samples per arm, interleaved and rotating. Arm A median **3.093 ms**, IQR 0.388; Arm C median **3.085 ms**, IQR 0.175; Arm D median 3.083 ms, IQR 0.374. **The repair costs nothing measurable at the median** — Arm C is 0.008 ms *faster* than the baseline, which is well inside the IQR and means the two are indistinguishable | **yes** | `reports/three_arm_experiment.json`, `latency_ms` |
| 3 | False-positive difference, validated formats | ≤ 2 pp, one-sided 95% bound | **25.3235 pp** — 30 new false positives on 155 validated files. Exact McNemar on 30 discordant pairs, p ≈ 9 × 10⁻¹⁰ | **NO** | `reports/benign_tradeoff.json`, `bound_1` |
| 4 | False-positive difference, unvalidated × incompressible | measured and reported; no zero-cost assumption; D5 applies | **100.0 pp** on 90 of 90 files, against the 15.0 pp predeclared tolerance. **D5 applies and fires** | reported; **tolerance exceeded** | `reports/benign_tradeoff.json`, `bound_2` |
| 5 | Capability levels with a reproducible source trail | 100% | **10 of 10** in a checkout with the trained model; **9 of 10 on a clean checkout**, the tenth recorded unresolved under D2 | **yes**, with the clean-checkout caveat stated | `reports/capability_calibration.json`, `summary.with_empirical_source_trail` |
| 6 | Capability levels independently reproduced | 100%, or recorded unresolved under D2 | **10 of 10 reproduce**, each derived twice in opposite orders from the same recorded facts. **`independent_human_reviewer` is `false` on every record** — the plan §9.15 reproduction ring was not achieved | **~ partial**; see §6 | `reports/capability_calibration.json`, `levels[].reproduction` |
| 7 | Mitigation decisions reaching the ledger | 100% | **100.0%** — 24 of 24 adjudications reach the chain, 36 of 36 blocks complete on all five fields | **yes**, with the qualification carried in the report's own `what_this_row_does_not_cover`: it is 100% of the decisions the *governance layer* makes, and the container exemption makes none | `reports/ledger_coverage.json` |
| 8 | Trusted-restore verification on snapshot-backed cases | 100% | **not measured.** VSS is reported supported, the code reaches the `wmi:Win32_ShadowCopy` backend, and both `list_snapshots` and `create_snapshot` refuse because the process is not elevated | **NO — not measured** | `reports/vss_status.json` |
| 9 | Injected ledger-tamper cases failing verification | 100% | **In-place tamper: 20 of 20 detected, 100%.** **Structural tamper: 0 of 8 detected.** 28 cases total | **yes for the class the row means; no for the class it does not name** | `reports/tamper_sweep.json` |

**Six rows met, one met with a stated caveat, one partial, two not met.** Rows 3
and 4 are the D5/D3 finding; row 8 is a shell privilege; row 9's second half is
the unkeyed-chain finding of thesis §9.1.

Row 9 needs its wording stated exactly, because a summary of it is misleading:
**the chain detects an edit and does not detect a rewrite.** An attacker with
database write access who recomputes the chain after their change leaves nothing
for `verify` to find. That is a property of an unkeyed hash chain, not a defect,
and adding a key is out of scope under plan §9.13. The claim carried forward is
*tamper-evident against an attacker who does not recompute the chain* — never
*tamper-evident* unqualified.

---

## 4. Every capability level, with its source trail

Ten strategies, each built, written to a real file and scored by
`detection.classify` as deployed. `reports/capability_calibration.json` carries
the full record including the artefact SHA-256 of every attack's bytes.

| # | Strategy | Declared | Measured (code ladder) | Plan §5.2 | Source trail | Reproduced |
|---|---|---|---|---|---|---|
| 1 | `container_exemption` / `gzip.compress(ciphertext, mtime=0)` | moderate | **negligible** | 1 public primitive | attack built and run; artefact hashed | yes |
| 2 | `container_exemption` / `ZIP_STORED` member | moderate | **negligible** | 1 public primitive | attack built and run; artefact hashed | yes |
| 3 | `static_entropy` / magic bytes over ciphertext | negligible | negligible | 0 direct control | attack built and run | yes |
| 4 | `entropy_rise` / write to an unobserved path | moderate | **low** | 0 direct control | attack built and run, both sides recorded | yes |
| 5 | `partial_entropy` / `base64.b64encode` | moderate | **negligible** | 1 public primitive | attack built and run; entropy exactly 6.000 | yes |
| 6 | `ransom_extension` / do not rename | negligible | negligible | 0 direct control | zero attacker statements; measured with and without | yes |
| 7 | whitelist path rule / write into an approved directory | low | low | **0 direct control** | attack built and run; `write_location_only: true` | yes |
| 8 | whitelist hash rule / produce a file with an approved SHA-256 | high | **high** | **4 secret or preimage** | **negative control**: an attacker-controlled file against a populated hash whitelist, `attack_succeeded: false` | yes |
| 9 | `training_mode` / poison the learned ceiling | low | low | **0 direct control** | attack built and run; six observed writes, learned ceiling 8.0 | yes |
| 10 | `C_forge(ml_confidence_gate)` / hold confidence under 0.7 | high | **negligible** | 1 public primitive | six variations scored; **2 of 6 came in under the gate with the content still ciphertext**. **Needs the gitignored model** | yes locally; **unresolved on a clean checkout** |

**Five of ten disagree with the declared cost table, and every disagreement is in
the same direction: the attack is cheaper than declared.** Strategies 1, 2, 4, 5
and 10. The largest single gap is 10 — declared high, measured negligible.

**The three strategies whose declared value survived contact were already priced
at the bottom of the scale**, where an over-estimate has nowhere to go. The cost
table is not uniformly wrong; it is wrong wherever it estimated an attack instead
of running one.

**Independent reproduction: none.** Every level was derived twice, in opposite
decision orders, over the same recorded facts and without reference to the first
conclusion — which is the protocol — **but by one author in one session**. Every
record carries `reproduction.independent_human_reviewer: false`. §6 says what
that costs.

---

## 5. Every number this work proved wrong, with the correction

Two kinds: figures this repository asserted that turned out to be wrong, and
defects the reproduction gate found in this project's own tooling. Both are
listed; neither is summarised away.

### 5.1 Figures corrected

| Figure | Was | Now | Date | Why |
|---|---|---|---|---|
| D1's answer | 0 cells flip | **4 cells flip** on the plan's ladder | 2026-09-04 | asked on the code's four-point ladder; plan §9.1 makes the plan's five-level ladder governing |
| `partial_entropy` avoidance cost | moderate | **negligible** | 2026-09-05 | `base64.b64encode` reaches exactly 6.000 bits/byte, under all three entropy thresholds at once |
| Admission flip count | 12 | **16** | 2026-09-05 | policies E and F added; the `partial_entropy` recalibration moved four more |
| Capability levels with an empirical trail | 9 of 10 | **10 of 10** | 2026-09-05 | `partial_entropy` was the one level derived from source; it is now built |
| Acceptance table | 10 of 14 met | **12 met, 1 partial, 1 failed** | 2026-09-04 | rows 3 and 10 closed by P6.7 and P6.6 |
| Ledger record completeness | 24 of 36 blocks | **36 of 36** | 2026-09-04 | `response_action` was a third block type carrying an adjudication and was not being checked |
| Arm D's status | post-hoc | **variant predeclared, choice post-hoc** | 2026-09-04 | plan §7.1 lists inner-content validation among five candidate variants; the conservative label is kept anyway |
| "Tamper-evident" | unqualified | **against an attacker who does not recompute the chain** | 2026-09-05 | 0 of 8 structural cases detected |
| Detection latency | 25.764 ms p95 | **94.650 ms p95, 110.550 ms p99 under 16-way concurrency** | 2026-09-05 | the first was a single-file benchmark; the concurrent p95 is 3.7× slower |
| Test count, clean checkout | 639 passed | **659 passed** | 2026-09-05 | TC-26 added 20 cases |
| Recognised container formats | "11 of 16 unvalidated" | **11 of 17 unvalidated** | 2026-09-05 | `iso-bmff` is matched on a separate offset-4 branch, so counting names in the signature table gives 16 and the registry holds 17 |
| Freeze commit hashes | four tag-object hashes | **four commit hashes**, tag objects shown separately | 2026-09-05 | all four tags are annotated, so `git rev-parse <tag>` returns the tag object rather than the commit |

### 5.2 Defects the reproduction gate found in this project's own work

Ten, across five failed gate runs. **Every one meant an independent reader could
not have reproduced a figure the thesis quotes.**

| # | Defect | Consequence |
|---|---|---|
| 1 | `Pillow` undeclared | clean checkout fails the corpus rebuild; every benign figure is downstream |
| 2 | `capability_calibration.py` raised `KeyError: 'attack'` on the no-model record | **crashed on every clean checkout**, since `models/` is gitignored |
| 3 | "10 of 10 empirical" is 9 of 10 without the model | the claim as worded was not reproducible by anyone but its author |
| 4 | `fpdf2` and `scipy` undeclared | scipy worked only as a transitive dependency of scikit-learn |
| 5 | `admission_recompute.py` raised `KeyError: 'cost_table_key'` | same short record; the first fix had patched one consumer |
| 6 | Claim C-04's check tested the model-dependent coverage counter | the claim is about the container exemption's cost. Repointed at `levels[0].measured_name`; the coverage figure became C-15 |
| 7 | **`build_benign_corpus.py` defaulted to `--per-cell 8`** | **the appendix's own command built a 149-file corpus while every benign figure is about the 275-file one.** `bound_2.stratum_files` came out **48** where the thesis says 90; Bound 1 came out **27.1752 pp** where the thesis says 25.3235 pp. `--verify` passed anyway, because it read `per_cell` back from the manifest it had just overwritten |
| 8 | Three unpinned `gzip.compress` timestamps | three witness SHA-256s changed on every run; their recorded hashes could not be checked |
| 9 | Volatile-field removal was top-level only | `detection_seconds` and `collateral_events_flagged` were declared volatile and never excluded — a declaration that does not take effect reads as a decision that was made |
| 10 | TC-22 asserted a key that exists only with a model | failed on every clean checkout |

All ten are fixed and the sixth gate run passed. Defect 7 is the one worth
dwelling on: **a document that was accurate, a command that ran, and an exit
status of zero together produced the wrong number.** Nothing about reading the
appendix would have found it.

**An appendix that is written and not run is a description of a reproduction, not
a reproduction.** Thesis §10.8 records this as a result in its own right.

---

## 6. Everything left undone, with the reason and the evidence

Nine items. None is omitted because it is inconvenient.

**1. The repair does not ship.** `CONTAINER_EXEMPTION_POLICY` stays `legacy`.
D5 fires at **100.0 pp against a 15.0 pp tolerance** on the unvalidated ×
incompressible stratum, and Bound 1 fails at 25.3235 pp against 2.00 pp. The
repair exists, is tested and closes 34 of 34 attack cases; it is off.
*Evidence:* `reports/benign_tradeoff.json`, `d5`, `bound_1`.
*What would close it:* structural validators for `bzip2`, `xz`, GIF and RIFF —
which plan §9.13 puts out of scope.

**2. Policy F is not deployed.** The plan's own combination — its five-level
ladder and its strict `>` rule — is computed, reported and not adopted. Adopting
it would attenuate two suppressions that are on by default today.
*Evidence:* `reports/admission_recompute.json`, policy F; thesis §6.5.

**3. Eleven of seventeen recognised formats have no structural validator.**
Four bytes of signature buy an exemption for each. Arm A misses exactly the
fourteen A1 cases whose format has no validator.
*Evidence:* `reports/three_arm_experiment.json`, family A1.
*Reason not done:* plan §9.13, explicitly out of scope.

**4. `base64.b64encode` defeats all three entropy signals at once**, at 6.000
bits/byte and +33% size. **No detector is written for it.**
*Evidence:* `reports/capability_calibration.json`, strategy 5.
*Reason not done:* writing one is a new signal, not a repair to the one under
study.

**5. The plan §9.15 reproduction ring was not achieved.** The ring is AS↔NI and
SI↔SH, with the reproducing member recording their result before seeing the
original. Every capability record carries
`reproduction.independent_human_reviewer: false`.
*Evidence:* `reports/capability_calibration.json`; `PROJECT_IMPLEMENTATION_RECORD.md`.
*Reason not done:* it needs a second person, and no second person reviewed.
**This is the most substantial gap in the whole submission** — every level was
derived twice by one author in one session, which is a protocol and not
independence.

**6. No CI run has ever been observed.** `.github/workflows/tests.yml` exists.
The matrix has never executed on a runner, so no badge is claimed and the Week 28
gate's CI half stays open.
*Evidence:* `PROJECT_IMPLEMENTATION_RECORD.md`; no run URL exists to cite.
*What would close it:* opening a pull request against this branch.

**7. VSS-backed restoration is not measured.** Acceptance row 12 and Table 9.8
row 8. VSS reports supported; both operations refuse because the process is not
elevated.
*Evidence:* `reports/vss_status.json` — `elevated: false`, `blocker: "elevation"`,
`acceptance_check_run: false`.
*What would close it:* an Administrator shell. Every restore figure in this work
comes from the file-copy path.

**8. The deployment package is verified complete, not verified to run.** The
audit passes 11 of 11 checks and the archive is built and hashed. **The images
were not built and the stack was not started**, because that needs a Docker
daemon and no recorded run had one.
*Evidence:* `reports/release_package.json`, `what_this_does_not_show`.

**9. No demonstration video was recorded.** `docs/DEMONSTRATION_SCRIPT.md` and
`reports/si_demo_evidence.txt` exist; the recording does not.
*Reason not done:* recording it is not something that can be measured or
verified from this repository, and a claim that it exists would be unfalsifiable
from the artefacts. It is reported undone rather than asserted.

Three further limits that are not items of work:

- **The corpus is synthetic.** 275 procedurally generated files from a recorded
  seed. It is not a sample of anyone's real filesystem, and every false-positive
  figure is a figure about this corpus. Nine of seventeen formats are
  represented; the eight absent ones have no free encoder in this environment,
  and six of those eight also have no validator — so the stratum where D5 fires
  is represented by four formats rather than eleven. The direction of that bias
  is not known and no claim is made that it is small.
- **Measurement is in-process.** Every latency and every hop figure imports from
  `services/monitor` directly rather than going over HTTP. The deployed numbers
  are worse than these, not better.
- **The attack families were built by the author of the repair.** Thirty-four
  cases across seven families. A7 exists only because the inner-content appeal
  suggested its own attack, and nothing guarantees a further clause would not
  have its own A8. The wording is *the repair closed the evaluated bypass*, never
  that the bypass class is closed.

---

## 7. The freeze and gate commits

Plan §9.15 asks for the four freeze/gate commit hashes. All four tags are
annotated, so `git rev-parse <tag>` returns the **tag object** and
`git rev-list -n 1 <tag>` returns the **commit**. Both are given, because
quoting the first as the second was itself one of the corrections in §5.1.

| Tag | **Commit** | Tag object | Date | What it froze |
|---|---|---|---|---|
| `corpus-frozen-week19` | **`2c242d6`** | `2175d9c` | 2026-09-02 | the benign corpus manifest |
| `cost-table-frozen-week20` | **`0354d8f`** | `9a4269b` | 2026-09-02 | the declared capability cost table |
| `corpus-frozen-week21` | **`9a40bc6`** | `38f32ed` | 2026-09-03 | the corpus as re-frozen for the experiment |
| `repair-accepted-week24` | **`e69bb3a`** | `a230245` | 2026-09-03 | the Week 24 gate decision |

**Week 32 gate:** commit `07dfdac`, 5 September 2026 — 27 stages, 0 failed;
every deterministic artefact matched its recorded digest, every claim re-checked,
659 tests passed with 21 skipped and none failed.

---

## What this work claims, in the wording Table 9.9 requires

- The project team designed and implemented the capability-governed exception
  admissibility layer and its calibration.
- **In the reviewed URDS Monitor**, the container exemption returns before
  adjudication is reached, so the governance layer is never asked about it.
- **The current registry contains** seventeen recognised formats and six
  structural validators.
- **Under the declared capability model**, five of ten measured strategies cost
  less than the table declared, all in the same direction.
- **The repair closed the evaluated bypass** — 34 of 34 attack cases under Arm C.
- **On the evaluated corpus**, that repair costs 25.3235 pp against a 2.00 pp
  bound and 100.0 pp against a 15.0 pp tolerance, so it does not ship.
- **In the evaluated URDS pipeline**, the governance decision reaches the hops
  that act on it.

**Ransomware detection improved generally is not claimed.** Every figure here is
URDS against URDS under five policy values on one synthetic corpus, and plan
§9.13 puts external comparison out of scope. **Patentability is not inferred and
no priority claim is made.**

The result this work does claim is methodological: **measuring what a mitigation
costs an attacker, rather than declaring it, changed five of ten prices, reversed
one decision rule, and stopped a repair that closes every attack it was built
against from shipping.** Every one of those outcomes is unfavourable to the
system under study, and each is reported as a primary finding.
