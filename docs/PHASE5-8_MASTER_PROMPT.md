# Master prompt — finish Phases 5–8 (Weeks 17–32)

Copy everything below the line into a fresh Claude Code session opened at
`D:\Unified_Ransomware_Project`.

---

You are completing Phases 5–8 (Semester 2, Weeks 17–32) of the **Unified Ransomware
Detection & Recovery System** exactly as Chapter 9 of the plan specifies: every
deliverable built, every number measured, every predeclared decision rule honoured in the
order it was written.

## 0. Sources of truth

1. **The Semester 2 roadmap** — `C:\Users\nikhi\OneDrive\Desktop\plan.pdf` (Chapter 9,
   13 pages). This is the schedule, ownership and acceptance layer. `poppler` is not
   installed, so the Read tool cannot page it. Extract it first:

   ```bash
   .venv/Scripts/python.exe -c "from pypdf import PdfReader; r=PdfReader(r'C:\Users\nikhi\OneDrive\Desktop\plan.pdf'); open('docs/_plan_ch9.txt','w',encoding='utf-8').write('\n'.join((p.extract_text() or '') for p in r.pages))"
   ```

   Read all 13 pages before you change anything. Do not work from the summaries below
   alone — they are an index, not a substitute. Do not commit `docs/_plan_ch9.txt`.
2. **The reference document** — `C:\Users\nikhi\OneDrive\Desktop\College\Unified Ransomware Detection System.pdf`
   (v1.6, 68 pages). Chapters 1–8 are unchanged; Tables 5.7, 5.8 and 5.9 remain binding.
   Extract it the same way when you need it.
3. **The method document** — `NOVELTY_PROOF_PLAN.md`. §9.1 names it as the governing
   method: **where it and Chapter 9 disagree, the proof plan governs the method and
   Chapter 9 governs the calendar.** *This file does not exist in the repository as of
   2 Sep 2026.* Item **P0** below deals with that. Do not invent its contents to suit a
   result you already have.
4. **Phase 1–4 record** — `docs/PHASE1-4_COMPLETION_SUMMARY.md`,
   `docs/PHASE4_VERIFICATION_REPORT.md`, `docs/CAPABILITY_GOVERNED_EXCEPTIONS.md`,
   `docs/DETECTION_HARDENING.md`. Treat every claim in them as an assertion to
   re-verify, not as evidence.
5. **The code** — branch `feat/detection-hardening` at `fba11bf`. Six services under
   `services/`, Monitor logic in `services/monitor/{detection,containers,suppression,admissibility,pe_features,pipeline}.py`.

## 1. Definition of done

Phases 5–8 are complete when all of the following hold simultaneously:

- Every deliverable in §9.4.1–§9.4.4 exists at the path §9.8 assigns it. Work that does
  not land at one of those paths is not counted as done.
- All four exit gates (Weeks 20, 24, 28, 32) are satisfied, **in order**, each recorded in
  a commit.
- Every decision point D1–D6 in §9.7 has been evaluated against the measurement, and the
  branch actually taken is written down with its evidence — including where the
  inconvenient branch was the correct one.
- TC-14 … TC-25 exist as tests and pass; TC-01 … TC-13 have not regressed.
- Every acceptance benchmark in Table 9.8 is measured and met, or explicitly reported as
  unmet under the applicable decision rule.
- §9.12.1, §9.12.2 and §9.12.3 are met in full, with the Polygon-anchoring bullet traded
  for the documented original contribution exactly as §9.2 permits.
- Every sentence in the thesis, paper and defence uses the wording Table 9.9 mandates.
- Test suite green: no regression below the Phase 4 baseline of **11/11 Table 5.8 cases,
  10/10 Table 5.9 benchmarks, 13/13 simulator families detected and restored**. Re-measure
  that baseline yourself before you touch anything (item P5.0) — do not take these numbers
  on trust.

## 2. Ground rules — these are not negotiable

1. **Measure, never assert.** Every number in a doc, report, commit message or thesis
   sentence must come from a command you ran in this session. If you did not measure it,
   do not write it. If a previously committed number is wrong, correct it and say so.
2. **Calibrate before repairing.** §9.4.1 is explicit: *no repair is written in Phase 5.*
   A repair chosen before calibration is a repair the cost table was fitted to justify. Do
   not open a repair branch until the cost table is frozen in a commit.
3. **Predeclare, then measure.** The D5 false-positive tolerance and the non-inferiority
   bound must be chosen, justified and committed **before** Phase 6 begins. Choosing them
   after seeing the result is precisely what §9.7 exists to prevent.
4. **A negative result is a result.** D1, D3 and D4 all describe outcomes that make the
   team's own work look less necessary. Report them as primary findings. Never retro-fit
   the capability ladder to preserve a deployed mitigation; a genuine refinement is
   proposed, justified and versioned as `cost-policy-v2`, never applied silently.
5. **Second-reviewer rule.** No capability level is accepted on one member's word. The
   reproduction ring is AS↔NI and SI↔SH. The reproducing member records their result
   **before** seeing the original conclusion. Where you are acting for both members,
   reproduce from the recorded protocol alone — re-derive the level from the artefacts and
   commands, not from the first conclusion — and label the record as such rather than
   claiming an independent human reviewer.
6. **Do not regress what works.** Before and after every item:
   ```bash
   for svc in gateway ledger monitor ml-engine response; do (cd services/$svc && python -m pytest -q); done
   ```
   13/13 simulator families must keep detecting and restoring, and all Table 5.9 targets
   must stay met. If a change trades one criterion for another, stop and report the trade
   rather than choosing silently.
7. **Reports are gated.** `reports/` is only written when `URDS_WRITE_REPORTS=1`. Keep it
   that way. Refresh committed evidence deliberately, never as a test side effect.
8. **Windows first.** Use `.venv\Scripts\python.exe`. VSS work needs an elevated shell.
9. **Commit per item**, Listing 4.1 convention (`feat(monitor): …`, `fix(ml): …`,
   `test(api): …`, `docs(thesis): …`). The body states what was measured. Branch
   `feat/admissibility-governance-novelty-v2` off `feat/detection-hardening`; per-member
   work follows `feature/<INITIALS>-<topic>`. Freeze commits (cost table, corpus manifest)
   are **tagged**, and their hashes are quoted in the thesis.
10. **Never silently drop scope.** If an item is impossible, harmful to a graded criterion,
    or genuinely out of the Weeks 17–32 window, finish everything else and list it in the
    final report with the reason and the evidence.
11. **Never fabricate an artefact.** No mocked screenshots, no hand-written "log output",
    no invented corpus rows, no capability level asserted from reasoning alone. Every level
    needs a reproducible source trail: the exact command, its output, and the artefact hash.
12. **Stay inside scope.** §9.13 is binding: no adaptive RECF-DR search, no Pareto
    optimisation, no `recf_dr/` framework, no new structural validators for the eleven
    unvalidated formats, no external-detector comparison, no Polygon anchoring, no mobile
    support, no generalisation claim beyond URDS, no patentability claim. These must not
    consume Weeks 17–32.

## 3. Work items

Each item gives its §9 citation, what exists today, what "done" means, and how it is
proven. Verify the "today" column yourself — it was checked on 2 Sep 2026 and may have
moved.

### P0 — Establish the method document (do this first)

`NOVELTY_PROOF_PLAN.md` is cited by §9.1 as governing the method, by §9.4.2 for the
acceptance table, and by §9.7. It is not in the repository. Before any measurement:

- Search the repo, all branches, and `docs/` for it (`git log --all --diff-filter=A --name-only | grep -i novelty`).
- If it exists somewhere, restore it to the repository root and read it in full.
- If it genuinely does not exist, **stop and report that to the user before writing one.**
  The acceptance table it carries decides what Phase 6 must measure; authoring it yourself
  after seeing the Phase 5 results is the exact failure mode rule 2 forbids. If the user
  directs you to write it, write it *before* Phase 5 measurement begins, commit it, and say
  in the final report that the method document was authored in this session and by whom.

### Phase 5 (Weeks 17–20) — Governance calibration and evidence. **No repair in this phase.**

**P5.0. Baseline freeze.** (SH, §9.8 → `reports/phase5_baseline.json`)
Today: no such file. Done = a measured record of the starting state — commit hash, test
counts per service, the 10 Table 5.9 benchmarks by their stated measurement methods (CPU
averaged over a 1-hour monitoring period, RAM peak during stress test — a 5-second sample
satisfies neither), 13/13 simulator families, and artefact hashes. Every later "no
regression" claim is measured against this file.

**P5.1. Mitigation-path inventory.** (AS, → `docs/MITIGATION_INVENTORY.md`)
Today: `docs/CAPABILITY_GOVERNED_EXCEPTIONS.md` and `docs/DETECTION_HARDENING.md` cover
part of this, untracked. Done = every path across **all six services** that can cancel,
attenuate or defer evidence, with: call site (`file:line`), what it can cancel, whether it
reaches `admissibility.adjudicate()`, and whether its decision reaches the ledger. Derive
it by reading the code, not by summarising the existing docs.

**P5.2. Extended evidence harness.** (AS, → `scripts/recf_exemption_evidence.py`,
`reports/recf_exemption_evidence.json`)
Done = a harness covering (a) all 20 signature entries across the 16 formats, (b) the
standard-library valid-container witness (`gzip.compress(ciphertext)` and a `ZIP_STORED`
member), (c) the `INCOMPLETE` validator witness, and (d) fresh-versus-observed paths.
Report per-entry: validator present, `validate_container()` result, `classify()` outcome.
The §9.3 finding to reproduce first: 11 of 16 formats have no structural validator,
`validate_container()` returns `None`, and `detection.classify()` tests
`container_valid is not False` — so "I could not check" is treated as "I checked and it
passed". Confirm or refute the recorded run of 13 unvalidated entries returning
`benign_compressed` and none returning suspicious. If the current code differs, the code
wins and the finding is restated.

**P5.3. Stratified benign corpus, assembled and frozen.** (NI, →
`reports/benign_corpus_manifest.json`, tagged at Week 19)
Done = genuine benign files stratified by {validated, unvalidated} × {compressible,
incompressible}, with per-file hash, source and stratum in the manifest, and a recorded
seed that rebuilds it byte-identically. Risk row: if the target size cannot be reached,
**report exact counts and treat undersized formats descriptively** — five or six
deployment-relevant formats only. Do not claim 16-format coverage.

**P5.4. Capability search, locked and reproduced.** (AS + NI, →
`reports/capability_calibration.json`)
Done = for each strategy — container, entropy, whitelist, training-mode (AS) and
`Cforge(ml_confidence_gate)` (NI) — the measured capability level an attacker needs, with a
reproducible source trail: exact command, output, artefact hash. Includes NI's measurement
of the capability required to hold model confidence below 0.7 while still meeting the
attacker objective (§9.3 finding 3: `ml-engine/app.py` maps confidence at 0.9/0.7/0.4,
`response/app.py` acts only on `high`/`critical`, and below that line nothing records that
an action was withheld). Each level is then independently reproduced per rule 5. **D2
applies:** a level that cannot be reproduced is recorded as *unresolved* and the policy
takes the conservative (lower-forgery) reading. Expect `structural_mismatch` to fall from
MODERATE to Level 1 — `admissibility.py` prices it on the reasoning that the attacker "has
to ship an encoder", and a single standard-library call defeats that.

**P5.5. Admission-recompute matrix.** (AS, → `docs/ADMISSION_RECOMPUTE.md`)
Done = every {hash, path, training mode, container exemption} × every signal, recomputed
under both the current `≥` rule and the calibrated `>` rule, with every flip marked.
**D1 applies:** if path-whitelist and training-mode admissions flip from admitted to
attenuated, report it as a primary finding — two deployed mitigations were not
cost-justified.

**P5.6. Predeclare the Phase 6 bounds.** (§9.7 note on D5)
Done = the D5 false-positive tolerance and the §9.4.2 non-inferiority bound chosen,
justified in writing, and committed before Phase 6 opens.

**Exit gate — Week 20, COST TABLE FROZEN.** Every evidence-cancelling path classified,
every capability level with a reproduced source trail or an unresolved record, admission-flip
table complete. Freeze the cost table in a tagged commit **before any repair branch is
opened**, and quote the hash.

### Phase 6 (Weeks 21–24) — Repair, experiment and integration

**P6.1. Repair behind a configuration switch.** (AS, selected from the P5.5 table)
Done = the repair is off by default until D5 says otherwise, and its selection traces to a
row of the frozen table.

**P6.2. Three-arm experiment.** (AS, → `reports/three_arm_experiment.json`)
Arm A = current, Arm B = exemption removed entirely (null control), Arm C = calibrated
repair, over the same locked attack and benign cases. **D3 applies:** if Arm B's
false-positive cost is acceptable, report plainly that the governance layer is not required
for this mitigation. **D4 applies:** if Arm C still returns `benign_compressed` for the
standard-library valid container, the repair is insufficient — add provenance,
trusted-history or inner-content validation, or record it as an accepted residual
limitation with the attack documented. Arm C must **not** be certified on the
unvalidated-format witness alone.

**P6.3. Paired benign statistics.** (NI, → `reports/benign_tradeoff.json`)
Per-stratum paired statistics against the P5.3 corpus, evaluated against the predeclared
non-inferiority bound. **D5 applies:** if false positives in the unvalidated ×
incompressible stratum exceed the predeclared tolerance, do not ship the repair by default
— ship behind an operator switch and state that a real validator for that format is the
correct long-term fix.

**P6.4. Pipeline integration.** (SH + SI, → `reports/pipeline_governance.json`)
The policy decision record propagates ML → Ledger → Response → Recovery intact at every
hop, and the dashboard surfaces `cancelled`, `attenuated` and `deferred` distinctly.

**P6.5. Failure injection.** (SI, → `reports/failure_injection.json`)
Missing baseline, mismatched restore hash, corrupted snapshot, ledger tampering, response
isolation — each producing a distinct, recorded outcome; none reported as verified.

**Exit gate — Week 24, REPAIR ACCEPTED.** Every row of the `NOVELTY_PROOF_PLAN.md`
acceptance table measured and reported, pipeline gates pass, 13/13 families still detect and
restore. **D6 applies:** if any pipeline gate fails, the final claim is reduced to "URDS
Monitor" scope, the word *unified* is not used for evidence that was not collected, and the
reduction is written down.

### Phase 7 (Weeks 25–28) — Hardening, regression and documentation

**P7.1. Regression suite TC-14 … TC-25.** (All, →
`services/*/tests/test_tc1[4-9]*.py`, `test_tc2[0-5]*.py`)
One test per row of Table 9.7, each asserting the recorded outcome rather than observing it
incidentally:
- TC-14 (AS) each of the 11 unvalidated formats, given a fresh high-entropy attacker-valid
  payload, does **not** return a silent `benign_compressed` under Arm C.
- TC-15 (AS) a `gzip.compress` / `ZIP_STORED` container carrying content that fails its
  integrity objective is evaluated explicitly — closed, or recorded as an accepted residual
  limitation.
- TC-16 (AS) a validator returning `INCOMPLETE` yields `deferred` or `unverified`, never a
  silent benign cancellation.
- TC-17 (AS) a pasted header over ciphertext still returns `structural_mismatch`.
- TC-18 (AS) every mitigation × signal pair produces the recorded admission under the
  frozen table; flips are asserted.
- TC-19 (AS) genuine ZIP, GZIP, PNG, JPEG and PDF stay benign; the Arm C − Arm A
  false-positive difference stays within the predeclared bound.
- TC-20 (NI) no two training samples share a construction with opposite labels; the corpus
  rebuilds byte-identically from its recorded seed. (The corpus-label defect write-up is
  NI's §9.6.2 deliverable.)
- TC-21 (NI) per-kind accuracy reported for every class; no class hides beneath an aggregate.
- TC-22 (NI) a case suppressed by sub-threshold confidence still produces an adjudication
  record — the withheld action is visible, not silent.
- TC-23 (SI) every mitigation decision, including attenuated and deferred ones, is chained
  with mitigation identifier, validation state, capability levels, policy version and reason.
- TC-24 (SI) missing baseline, mismatched hash and corrupted snapshot produce three
  distinct outcomes; none is reported as verified.
- TC-25 (SH) one suspicious event traverses Monitor → ML → Ledger → Response → Recovery
  with the policy record intact at every hop.

**P7.2. CI pipeline.** (SH) The full suite runs on every pull request, from a clean
checkout. This is an Excellence-tier bullet and the mechanism that keeps P7.1 alive.

**P7.3. Security audit, load testing, tamper-resistance verification.** (SH + SI)
Measured, not asserted; injected ledger-tamper cases must fail verification 100% of the time.

**P7.4. Paper draft, user manual, demonstration video.** (NI + SH)
Every headline sentence maps to a test, a report or a stated assumption.

**Exit gate — Week 28.** Suite green in CI from a clean checkout; paper-to-evidence
mapping complete. Progress Report 2 (SH, Week 26) submitted.

### Phase 8 (Weeks 29–32) — Thesis, defence, delivery

**P8.1. Final thesis** — 80–100 pages, including the authorship record
(`PROJECT_IMPLEMENTATION_RECORD.md`), the method, **the negative results**, and an explicit
limitations chapter. Superseded figures are retained with dates, as already done in
`PHASE1-4_COMPLETION_SUMMARY.md`.

**P8.2. Claim-to-artefact matrix** — `docs/CLAIM_MATRIX.md`, every claim mapped to the
artefact Table 9.9 requires.

**P8.3. Defence presentation and packaged deployment.**

**P8.4. Reproducibility appendix** — exact commands, seeds and artefact hashes.

**Exit gate — Week 32, FINAL.** An independent reader can reproduce every headline figure
from the repository and the appendix alone. Verify this by actually re-running the appendix
commands from a clean checkout, not by inspection.

## 4. Claim discipline (Table 9.9 — mandatory wording)

| Claim | Allowed wording |
|---|---|
| The team built the system | "The project team designed and implemented…" |
| The exemption is ungoverned | "In the reviewed URDS Monitor…" |
| 11 of 16 formats unvalidated | "The current registry contains…" |
| Structural validation is low-capability | "Under the declared capability model…" |
| The repair closes the bypass | "The repair closed the evaluated bypass…" |
| Benign cost is acceptable | "On the evaluated corpus…" |
| The pipeline preserves trust | "In the evaluated URDS pipeline…" |
| Ransomware detection improved generally | **not claimed** |
| Patentability or legal novelty | **never inferred from this work** |

XGBoost, FastAPI, watchdog, EMBER, CLEAR and RanSAP are named as inputs wherever they
appear, never as contributions.

## 5. Final report

When you finish, produce a single report containing:

1. Each of P0 … P8.4: done / partially done / not done, with the artefact path and the
   command that proves it.
2. Every D1–D6 evaluation: what was measured, which branch was taken, and the evidence.
3. Every Table 9.8 benchmark with its measured value.
4. Every capability level: value, source trail, reproduced or unresolved.
5. Every number in this repository that this work proved wrong, with the correction.
6. Everything left undone, with the reason and the evidence — never silently omitted.
7. The four freeze/gate commit hashes.
