# Phase 6 completion report — Weeks 21–24, the repair, the experiment, and what it cost

**Branch `feat/admissibility-governance-novelty-v2`. Repair branch
`feature/AS-container-exemption-repair`, opened from `cost-table-frozen-week20`.**

Every number below came from a command run in this session. Where a previously
committed number was wrong, it is corrected here and the correction is named.

---

## 0. Before Phase 6 opened

Phase 5 was re-verified item by item against its artefacts rather than against
its own report. All eight deliverables exist at the paths §9.8 assigns them, the
Week 20 gate holds, `git diff feat/detection-hardening..cost-table-frozen-week20
-- services/` returns **0** lines, and both freeze tags resolve. The suite was
re-run independently of the baseline file: **465 passed, 2 skipped**, exit 0 on
all five services.

### The method document, again

`docs/METHOD_DOCUMENT_STATUS.md` records that `NOVELTY_PROOF_PLAN.md` has never
existed, and that resolving it means either finding it or authoring it *before
Phase 6 and without consulting the Phase 5 results*. The Phase 5 results were in
hand. **It was therefore not authored**, because an acceptance table written
after the numbers are known is fitted to them, which is the defect §9.4.1 forbids
for the repair and the cost table alike.

**The operative acceptance layer for the Week 24 gate is Table 9.8 together with
`docs/PHASE5_PREDECLARED_BOUNDS.md`.** That document was committed at the Week 20
freeze, before any Phase 6 measurement existed, so it functions as the
predeclared acceptance table the missing document would have supplied. Per
Table 9.9, no sentence anywhere in this work cites `NOVELTY_PROOF_PLAN.md` as a
source.

---

## 1. Deliverables

| Item | Artefact | Result |
|---|---|---|
| P6.0 | `reports/benign_corpus_manifest.json`, tag `corpus-frozen-week21` | 275 files, 155 validated — the predeclared remedy for Bound 1 |
| P6.1 | `services/monitor/{detection,containers,app}.py` | `CONTAINER_EXEMPTION_POLICY`, four settings, **off by default** |
| P6.2 | `reports/three_arm_experiment.json` | 31 attack cases in 7 families × 275 benign files × 5 arms |
| P6.3 | `reports/benign_tradeoff.json` | Per-stratum paired statistics; **D5 fires** |
| P6.4 | `reports/pipeline_governance.json` | 6 gates, all pass; **D6 does not fire** |
| P6.5 | `reports/failure_injection.json` | 5 injections, 5 distinct outcomes, none verified |

---

## 2. The repair, and where it came from

§9.4.1 forbids choosing a repair before the cost table freezes. The repair branch
was opened *from the freeze tag*, which is checkable in one command:

```bash
git merge-base --is-ancestor cost-table-frozen-week20 feature/AS-container-exemption-repair
```

**Which row it traces to.** P5.4 measured the forgery cost of the container
exemption at NEGLIGIBLE — `gzip.compress(ciphertext)` and a `ZIP_STORED` member
are one standard-library call each, not the MODERATE the table assumed. P5.1 row
M-06 records that `detection.py` tested `container_valid is not False`, so `None`
— no validator, INCOMPLETE, or unreadable — earned the same exemption as a
structure that was checked and passed.

`CONTAINER_EXEMPTION_POLICY` has four settings and the arms are settings of it,
not versions of the code:

| Setting | Arm | What it changes |
|---|---|---|
| `legacy` | **A** | nothing — what shipped through Phase 5. **The default.** |
| `strict-unvalidated` | C1 | the exemption requires a validator to have run and passed |
| `strict-unvalidated+ratio` | **C** | strict, plus: a general-purpose compressor that compressed nothing has explained nothing |
| `off` | B | no exemption at all — the null control |

An unrecognised value raises at import rather than being coerced, so a typo in a
deployment cannot become a policy change nobody chose.

---

## 3. The three-arm experiment

31 attack cases from seed `20260903`, each hashed into the report. 275 benign
files from `corpus-frozen-week21`, each hash-checked against the frozen manifest
before scoring — the harness refuses to run against a corpus that is not the
corpus that was frozen. All arms score one reading of each file, so an arm
difference cannot be a difference between two reads of a disk.

### Attack

| Family | A | B | C1 | C | D |
|---|---|---|---|---|---|
| A1 header over ciphertext | 7/21 | 21/21 | 21/21 | **21/21** | 21/21 |
| A2 standard-library container | 0/3 | 3/3 | 0/3 | **3/3** | 3/3 |
| A3 incomplete container | 1/2 | 2/2 | 2/2 | **2/2** | 2/2 |
| A4 intermittent in valid container | 0/3 | 3/3 | 0/3 | **3/3** | 3/3 |
| A5 control, naked ciphertext | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| A6 control, forged header | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| A7 forged inner content | 0/3 | 3/3 | 0/3 | **3/3** | 1/3 |

### Benign

| Stratum | A | B | C1 | C | D |
|---|---|---|---|---|---|
| unvalidated × compressible (30) | 0 | 0 | 0 | 0 | 0 |
| unvalidated × incompressible (90) | 0 | **90** | **90** | **90** | **90** |
| validated × compressible (60) | 0 | 0 | 0 | 0 | 0 |
| validated × incompressible (95) | 0 | **95** | 0 | **30** | 0 |
| **all 275** | **0** | **185** | **90** | **120** | **90** |

---

## 4. The decision rules

### D3 — does not fire, and the result is in the project's favour

D3 fires if Arm B's false-positive cost is *acceptable*, which would mean the
exemption is not worth governing and the governance layer is not required.

**Arm B flags 185 of 275 benign files — 67.3% against Table 5.9's 5% budget.**
It flags every file in `validated × incompressible`: a real PNG of a plot is a
valid PNG whose deflate could not compress noise. Deleting the exemption is not
an option, so something has to decide when it applies. That is the case *for* a
governance layer, and it is the one branch of Phase 6 that came out in the
project's favour.

### D4 — fires, and Arm C answers it

D4 fires if Arm C still returns `benign_compressed` for the standard-library
valid container. **Arm C flags all three; C1 flags none of them.**

The guard matters more than the verdict. §9.7 says Arm C must not be certified on
the unvalidated-format witness alone, so A1 and A2 are counted separately in the
report and A2 passes on its own evidence. Had they been pooled, C1 would have
read as 21/24 — 87.5% — while missing the entire family that D4 is about.

The clause that does it is the compression-yield check, read from sizes the
archive already declares about itself. It validates nothing, so §9.13's bar on
new structural validators for the eleven unvalidated formats is untouched.

### D5 — fires, hard

The predeclared tolerance for `unvalidated × incompressible` is **15.0 pp**.
Arm C measures **100.0 pp** — 90 of 90 — which exceeds it by a factor of 6.7.

> **Per D5 the repair does not ship by default.** It stays behind
> `CONTAINER_EXEMPTION_POLICY`, whose default is `legacy`, and **a real
> structural validator for bzip2, xz, GIF and RIFF is the correct long-term
> fix** — which §9.13 places outside this project's scope.

This stratum's cost is *identical* across B, C1, C and D. It is entirely the
strict clause: those formats have no validator, so "no structural validator ran
on it" is the only thing the detector can say about any of them, and no amount of
ratio or inner-content evidence changes it.

One number is worth stating on its own: `bzip2_text` — a bzip2 archive of prose —
flags at entropy **7.87**. bzip2 compresses text well enough that its output is
indistinguishable from ciphertext by entropy. The false positives here are not
edge cases.

### D6 — does not fire

All six pipeline gates pass (§6 below). The claim is not reduced to "URDS
Monitor" scope.

### D1 and D2 — unchanged from Phase 5

D1's `cost-policy-v2` remains **proposed, not applied**. `admissibility.py` is
byte-for-byte identical to `cost-table-frozen-week20`. D2 recorded no unresolved
level and that has not changed.

---

## 5. Bound 1 — the predeclared bound, and Arm C fails it

The corpus was grown first, per Bound 1's own predeclared remedy 1, **before any
Arm B or Arm C measurement** — the commit order is the evidence. `--per-cell`
8 → 15, 149 files → 275, validated 85 → **155**.

The growth is purely additive, and that was measured rather than assumed: all
**149 of 149** Week 19 files retain their exact SHA-256, stratum and Arm A
verdict; 0 changed; 126 added; 270 of 270 generated files rebuild byte-identically
from the seed.

| Arm | new FPs on 155 validated files | one-sided 95% upper limit | vs 2.00 pp |
|---|---|---|---|
| B | 95 | 67.842 pp | fails |
| C1 | 0 | 1.914 pp | meets |
| **C** | **30** | **25.323 pp** | **FAILS** ← the predeclared arm |
| D | 0 | 1.914 pp | meets |

**Arm C fails Bound 1 by an order of magnitude.** The 30 are all
`zip_deflated_photo` and `gzip_photo` — real archives of already-compressed
JPEGs, which the ratio clause correctly identifies as having compressed nothing
and therefore wrongly treats as unexplained entropy.

**C1 and D clear the bound and neither is claimed to meet it.** C1 is not the
repair — D4 already ruled it insufficient. Arm D was selected *after* Arm C's
benign cost was measured. Reporting either as meeting a predeclared bound would
be choosing the arm after seeing the data, which is exactly what §9.7 exists to
prevent. The figures are in the report; the claim is not made.

Bound 2 was re-evaluated from its own composition-independent rule and is
**unchanged at 15.0 pp** (48/149 = 32.215% → 15.521%; 90/275 = 32.727% →
15.278%; both round down to 15.0). Both figures are recorded, as the rule
requires.

---

## 6. Pipeline integration — six gates, all passing

| Gate | Status |
|---|---|
| Cancelled decision reaches the ledger | **PASS** |
| Attenuated decision reaches the ledger | **PASS** |
| Decision reaches the Response service | **PASS** |
| Response action is chained with the decision | **PASS** |
| Decision reaches recovery | **PASS** |
| Dashboard surfaces the three outcomes distinctly | **PASS** |

**Table 9.8 row 7 moves from 50.0% to 100.0%** — the one row that failed outright
at the Week 20 gate.

The fan-out is still gated on `suppression is None`, and still must be: a
cancelled alert must not fire a response, or the operator's own rule would be
pointless. What changed is that the *decision* no longer travels only on that
path. A cancelled suppression queues its own `governance` work item and is
chained as a `suppression_decision` block carrying the adjudication, the verdict
it silenced and both costs — with no prediction and no response.

The dashboard had **no** governance vocabulary at all before this. It now reads
the outcome from the adjudication record and never infers it from `suspicious` —
which is the mistake the old code could not avoid, because a cancelled alert and
a benign file both report `suspicious: false`.

### What row 7's 100% does *not* mean

It is 100% of the decisions the governance layer **makes**. In the coverage
measurement's `ungoverned` population, twelve events had their evidence cancelled
by the container exemption and the chain holds no record of any of them — and
coverage is still 100%, because no decision was made to chain. M-05 and M-06
stand exactly as written in the Phase 5 inventory. Reading this figure as "every
evidence-cancelling path is audited" would be wrong, and the report carries that
qualification in its own field so the number cannot travel without it.

---

## 7. Failure injection

Five injections, five distinct recorded outcomes, none reported as verified.

| Injection | Recorded outcome |
|---|---|
| missing baseline | restored, **not verified**, `partial` — "No prior hash for this path in the ledger" |
| mismatched restore hash | restored, **not verified**, `partial` — "does not match ledger block 41" |
| corrupted snapshot | **not restored**, `failed`, plus a `recovery_failed` block |
| ledger tampering | **detected** — "hash chain broken at block 4 … the walk stopped there, having checked 4 of 6" |
| response isolation | `simulated`, **`enforced: false`**, with the rules that would have applied |

The distinctness check compares a signature built from what an operator would
actually read — restored, verified, status, enforced, detected, reason — not from
the injection's name. Two injections with the same signature are two failures
nobody can tell apart, which is the same as not recording them.

The tamper is written through SQL rather than the API, because that is what a
tamper-detection claim has to hold up against someone who has stopped using the
API, and it is read back on a fresh connection so the verdict cannot come from a
cached row the writer still holds.

---

## 8. Arm D — a post-hoc refinement, and the attack that prices it

Arm C's 30 validated-format false positives raised a real question: is that cost
irreducible? D4 names inner-content validation as an admissible response, so
`strict-unvalidated+ratio+inner` was built to test it. It takes a bounded inflate
of the first member and asks the *existing* validators for a head-level opinion
on what came out.

**The trade is exact.** Arm D removes all 30 validated-format false positives and
keeps A1–A4 at 100%. It pays with A7: **1 of 3**, against Arm C's 3 of 3.

A7 is the attack written to price the refinement, and it is not hypothetical.
Arm D catches the naive version — four JPEG magic bytes in front of ciphertext,
whose marker chain does not parse, so the inner check calls it FORGED. It misses
both versions that ship a genuine JPEG through its SOS marker with ciphertext
where the scan data goes. Every marker in those is real, and nothing in a 64 KB
leading sample distinguishes ciphertext from scan data. **The appeal raises the
attacker's price from one standard-library call to prepending a real marker
chain, and that is all it does.**

Arm D still cannot ship: 90/275 = 32.7% corpus-wide, all of it the unvalidated
stratum.

---

## 9. What this phase proved wrong

1. **A repair can close an attack and still be unshippable.** Arm C closes every
   attack family — including the standard-library container that Phase 5
   measured at NEGLIGIBLE cost — and fails both predeclared bounds. The
   governance layer's problem was never that it could not be repaired; it is that
   the repair costs more than the project's own false-positive budget allows.
2. **The strict clause's cost is not a tuning problem.** It is identical across
   four arms. Eleven formats have no validator and §9.13 forbids writing one, so
   "I could not check" is all the detector can say — and once it stops treating
   that as "I checked and it passed", every genuine file in those formats flags.
3. **Two quantities that look like one.** The ratio clause cannot separate a
   backup of compressed data from an encryption of plaintext, because on the
   evidence it reads they are the same thing. Inner-content validation separates
   them one level in, and an attacker who prepends a real marker chain collapses
   them again.

---

## 10. Errors found and corrected in this session

Recorded because rule 1 requires it, and because three of the four were mine.

| What | How it was found | Correction |
|---|---|---|
| The latency measurement ran each arm to completion in turn and reported Arm C — which does the most work — as the **fastest**, 3.530 ms against Arm A's 4.204 ms | the ranking was backwards from the work done | arms interleaved within each repetition, order rotating. All five now sit within 0.2 ms of each other |
| `ledger_coverage.py` counted only `file_event` blocks, reporting the M-16 repair as having changed nothing | coverage stayed at exactly 50.0% after a repair that visibly wrote blocks | filter widened, then **150%** appeared because an attenuated decision is now chained twice; coverage is counted per decision, deduplicated by path |
| `pipeline_governance.py` compared every hop against a single reference record and reported the cancelled population as 6 of 6 carrying and **0 intact** | a hash-whitelist rule carries the hash it matched, so six files produce six different records | pairing is per event by file path; hops carrying no path are matched against the set |
| The tamper injection's wording said "block 4 of 4 checked", reading as a complete chain | the ledger had 6 blocks | now says the walk stopped at block 4 having checked 4 of 6 |

### A pre-existing flake, not caused by this work

Two timing benchmarks fail intermittently under full-suite load:
`test_benchmarks.py::test_detection_latency_under_100ms` and
`test_tc11_concurrent.py::test_tc11_detection_stays_within_budget_under_load`.
Across seven full monitor runs each failed once; each passes 6 of 6 in isolation.
**Verified as pre-existing** by stashing the Phase 6 changes and reproducing the
flake on the code at `5e6d635`. Both assert a wall-clock threshold, so an
unrelated test holding the CPU fails them. This makes any "no regression" claim
non-deterministic, and the same defect class was already fixed once in
`scripts/phase5_baseline.py` by counting a window in samples instead of seconds.
Recorded, not worked around.

---

## 11. Table 9.8 at the Week 24 gate

| # | Measure | Target | Measured | Met |
|---|---|---|---|---|
| 1 | Simulator families detected and restored | 13/13, no regression | **13/13** under the default policy **and** under Arm C, all within 2 s, all restore round-trips true | **yes** |
| 2 | Detection-path latency after repair | median sub-100 ms; median and IQR over ≥10 reps | Arm C **median 4.192 ms, IQR 6.486 ms**, p95 13.661 ms over 140 samples | **yes** |
| 3 | False-positive difference, validated formats | ≤2 pp, one-sided 95% | Arm C **25.323 pp** (30 of 155) | **NO** |
| 4 | False-positive difference, unvalidated × incompressible | measured and reported; D5 applies | Arm C **100.0 pp** (90 of 90) vs a 15.0 pp tolerance | **reported; D5 fires** |
| 5 | Capability levels with a reproducible source trail | 100% | **9 of 10 empirical**, 1 derived from source and labelled | **9/10** |
| 6 | Capability levels independently reproduced | 100%, or unresolved under D2 | **10/10 protocol-reproduced, 0/10 independently human-reproduced** | **no** |
| 7 | Mitigation decisions reaching the ledger | 100% | **100.0%** — was 50.0% at Week 20 | **yes** |
| 8 | Trusted-restore verification on snapshot-backed cases | 100% | **13/13 local restore round-trips**; VSS-backed restore still not measured — needs an elevated shell | **partial** |
| 9 | Injected ledger-tamper cases failing verification | 100% | **1/1** injected tamper detected at the right block, plus 32/32 tamper and chain-verification tests | **yes** |

Rows 3 and 6 are the two that fail. Row 3 fails on the measurement and is the
central finding of this phase. Row 6 is unchanged from Week 20: the protocol was
reproduced, the independence was not, and every record still carries
`independent_human_reviewer: false`.

---

## 12. The Week 24 gate, condition by condition

| §9.4.2 requires | Status |
|---|---|
| Every row of the acceptance table measured and reported | **9 of 9 measured**, against Table 9.8 + `PHASE5_PREDECLARED_BOUNDS.md`, the substitution recorded in §0 |
| Pipeline gates pass | **6 of 6** — `reports/pipeline_governance.json` |
| 13/13 families still detect and restore | **13/13**, under the default policy and under Arm C |
| D6 — reduce the claim if any gate failed | **does not fire**; no reduction written |
| Repair does not ship before D5 is evaluated | **D5 evaluated and fires**; the default is still `legacy` |
| Repair branch opened after the freeze | `git merge-base --is-ancestor cost-table-frozen-week20 feature/AS-container-exemption-repair` → **true** |

---

## 13. Left undone

| Item | Reason |
|---|---|
| **The repair shipping on by default** | D5 fires at 100 pp against a 15.0 pp tolerance. This is the correct outcome, not an omission |
| **A structural validator for bzip2, xz, GIF, RIFF** | §9.13 places it outside scope. It is named as the correct long-term fix and is the single change that would make the repair shippable |
| **Bound 1 for Arm C** | Fails at 25.323 pp. Not remediable without either a validator for the unvalidated formats or accepting Arm D's A7 exposure |
| **Independent human reproduction** (§9.15, Table 9.8 row 6) | One author, one session. Unchanged from Phase 5 |
| **VSS-backed recovery measurement** | Needs an elevated shell, which this session does not have |
| **Compose-stack measurement** | No Docker stack was brought up; all measurement is in-process, with the real handlers called directly |
| **The two flaky timing benchmarks** | Pre-existing, out of scope for Phase 6, recorded in §10 |
| **`NOVELTY_PROOF_PLAN.md`** | Deliberately not authored — see §0 |
| **Phases 7 and 8** | Out of scope for this session |

---

## 14. Freeze and gate commits

| What | Tag |
|---|---|
| Corpus manifest, Week 19 | `corpus-frozen-week19` |
| Cost table, Week 20 | `cost-table-frozen-week20` |
| Corpus manifest grown, Week 21 | `corpus-frozen-week21` |
| Repair accepted, Week 24 | `repair-accepted-week24` |

Resolve any of them with `git rev-list -n 1 <tag>`. A report cannot carry the
hash of the commit that carries it.
