# Phase 5 completion report — Weeks 17–20, the cost table frozen

**Branch** `feat/admissibility-governance-novelty-v2`, off `feat/detection-hardening` at `fba11bf`.
**Scope of this session:** Phase 5 only, through the Week 20 exit gate. **No repair
is written** — §9.4.1 forbids it, and none was.

Phases 6, 7 and 8 are not attempted here and nothing below should be read as
claiming otherwise.

---

## 1. Deliverables

| Item | Owner | Status | Artefact | Proving command |
|---|---|---|---|---|
| **P0** method document | — | **Not done, by direction** | `docs/METHOD_DOCUMENT_STATUS.md` | `git log --all --diff-filter=A --name-only \| grep -i novelty` |
| **P5.0** baseline freeze | SH | **Done** | `reports/phase5_baseline.json` | `URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/phase5_baseline.py` |
| **P5.1** mitigation inventory | AS | **Done** | `docs/MITIGATION_INVENTORY.md` | source read; every `file:line` resolved with `grep -n` |
| **P5.2** evidence harness | AS | **Done** | `scripts/recf_exemption_evidence.py`, `reports/recf_exemption_evidence.json` | `URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/recf_exemption_evidence.py` |
| **P5.3** benign corpus | NI | **Done, undersized** | `reports/benign_corpus_manifest.json`, tag `corpus-frozen-week19` | `.venv/Scripts/python.exe scripts/build_benign_corpus.py --verify` |
| **P5.4** capability search | AS + NI | **Done, reproduction qualified** | `reports/capability_calibration.json` | `URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/capability_calibration.py` |
| **P5.5** admission recompute | AS | **Done** | `docs/ADMISSION_RECOMPUTE.md`, `reports/admission_recompute.json` | `URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/admission_recompute.py` |
| **P5.6** predeclared bounds | AS + NI | **Done** | `docs/PHASE5_PREDECLARED_BOUNDS.md` | committed before any Arm B/C measurement exists |

### P0 — the governing method document does not exist

`NOVELTY_PROOF_PLAN.md` is cited by §9.1 as governing the method and by §9.4.2 for
the Week 24 acceptance table. It is not in the working tree, not on any of the 9
local or 11 remote branches, and `git log --all --diff-filter=A --name-only` — which
lists every path ever *added* anywhere in history — has no match. It was never
committed.

The user was asked before any measurement ran and directed that Phase 5 proceed
without it. **Chapter 9's Table 9.8 is therefore the operative acceptance layer and
§9.7 D1–D6 the operative decision layer.** The cost is recorded in
`docs/METHOD_DOCUMENT_STATUS.md`: the Week 24 gate is under-defined, and capability
acceptance has only the system's own four-point scale to calibrate against. This
session stops at Week 20, so the first is deferred rather than incurred.

`docs/CAPABILITY_GOVERNED_EXCEPTIONS.md` was considered as a substitute and
rejected — it states that its cost scale "is a modelling choice, not a
measurement", which is the thing Phase 5 exists to convert.

---

## 2. Decision points

D3, D4, D5 and D6 are Phase 6 decisions (Weeks 22–24) and are **not evaluated
here** — there is no Arm B, no Arm C and no pipeline gate run. D1 and D2 are Week
20 decisions and both were evaluated.

### D1 — evaluated. The result runs opposite to the direction it predicted.

D1 fires when *path-whitelist and training-mode admissions flip from admitted to
attenuated under the calibrated rule*, and instructs that this be reported as a
primary finding: two deployed mitigations not cost-justified.

**Zero cells flip that way. Four flip the other way** — from attenuated to
**cancelled** — under policy C (`≥` with measured costs):

| policy | suppression | signal | from | to |
|---|---|---|---|---|
| C | `path` | `structural_mismatch` | attenuated | cancelled |
| C | `path` | `entropy_rise` | attenuated | cancelled |
| C | `training_mode` | `structural_mismatch` | attenuated | cancelled |
| C | `training_mode` | `entropy_rise` | attenuated | cancelled |

The forgery side of the table was right — both rules measured LOW as declared.
What moved is the avoidance side, and under this comparison **a signal that is
cheaper to avoid is easier to cancel**. Applying the P5.4 calibration to the
deployed policy would let an operator's path whitelist cancel a structural-mismatch
alert, which policy A correctly refuses.

That is a defect in the cost model, exposed by the calibration. One number does two
jobs — *what an attacker who wants to evade the signal spends* and *what the signal
is worth when it fires* — and for `structural_mismatch` they point opposite ways. A
file that trips it is one whose author did not spend the single standard-library
call that would have avoided it.

**Per D1, nothing was retro-fitted.** `services/monitor/admissibility.py` is byte-for-byte
unchanged. The refinement is *proposed* as `cost-policy-v2` in
`docs/PHASE5_PREDECLARED_BOUNDS.md`, to be argued in Phase 6.

**Consequence for Phase 6:** policy C must not ship. Policy D still admits both
`structural_mismatch` cells — the `>` rule removes an equal-cost tie, not a cost
inversion. It does undo both `entropy_rise` flips, which is the clearest argument
this matrix produces in its favour.

### D2 — evaluated. No level went unresolved, but the reproduction is qualified.

All 10 measured levels were derived twice, in opposite decision orders, over the
same recorded operational facts and without either derivation seeing the other's
conclusion. **10 of 10 agreed; 0 unresolved.** D2's conservative-reading branch was
therefore not exercised.

**This is not the AS↔NI reproduction §9.15 asks for.** Both derivations were
written in one session by one author. Every record in
`reports/capability_calibration.json` carries
`reproduction.independent_human_reviewer: false`, and no claim of independent human
confirmation is made anywhere in this work. Under Table 9.8's row *"Capability
levels independently reproduced — 100%, or recorded unresolved under D2"*, the
honest reading is that the **protocol** was reproduced and the **independence** was
not.

---

## 3. Capability levels

From `reports/capability_calibration.json`. Nine of the ten carry an empirical
source trail — the exact command, the artefact hash where one exists, and the
attack that was built and run. The tenth is derived from source and says so.

| Strategy | Kind | Declared | Measured | Attack | Agreed |
|---|---|---|---|---|---|
| container exemption / `gzip.compress` | avoidance | moderate | **negligible** | succeeded | yes |
| container exemption / `ZIP_STORED` | avoidance | moderate | **negligible** | succeeded | yes |
| `static_entropy` / magic over ciphertext | avoidance | negligible | negligible | succeeded | yes |
| `entropy_rise` / unobserved path | avoidance | moderate | **low** | succeeded | yes |
| `partial_entropy` / flatten every block | avoidance | moderate | moderate | *not built* | yes |
| `ransom_extension` / do not rename | avoidance | negligible | negligible | succeeded | yes |
| whitelist `path` / approved directory | forgery | low | low | succeeded | yes |
| whitelist `hash` / SHA-256 preimage | forgery | high | high | **failed** | yes |
| `training_mode` / poison the ceiling | forgery | low | low | succeeded | yes |
| `Cforge(ml_confidence_gate)` | avoidance | *(absent from table)* | **negligible** | succeeded | yes |

**Source trail: 9 of 10 empirical, 1 derived** (`summary.with_empirical_source_trail`).
`partial_entropy` was not built — the attack is a constraint on the encryptor's
output distribution rather than a wrapper around it, and the record says so rather
than claiming a trail it does not have. `whitelist hash` counts as empirical
despite having no artefact: a preimage produces none, and its negative control is
a real measurement — an attacker-controlled file offered against a populated hash
whitelist, which did not match.

**The declared level `high` for `Cforge(ml_confidence_gate)` is not a table entry.**
It is `UNKNOWN_AVOIDANCE`, the fail-closed default for a signal with no cost. The
ML gate is ungoverned, not priced high.

---

## 4. What this work proved wrong

Corrections to numbers and claims already recorded in this repository or in
Chapter 9, per ground rule 1.

| Claim | Where it was recorded | Correction |
|---|---|---|
| `structural_mismatch` costs MODERATE — the attacker "has to ship an encoder" | `admissibility.py:80` and its comment | `gzip.compress(ciphertext)` is one statement, ships nothing, installs nothing, needs no knowledge of the gzip layout. **Measured negligible.** Left in place — no repair in Phase 5. |
| The exemption bypass is "Level 1 on the project's own capability ladder" | Chapter 9 §9.3, finding 2 | Both derivations return **Level 0**. The LOW rung is defined as *"a location the attacker can already write to"* and this attack chooses no location. Either reading refutes MODERATE. |
| The ML confidence gate silently withholds response | Chapter 9 §9.3, finding 3 | **Restated, not confirmed.** `pipeline.effective_threat_level` floors a Monitor-suspicious event at `high`, and `pipeline.run` is only reached for suspicious events, so the 0.7 gate cannot withhold on the only live caller. |
| `entropy_rise` costs MODERATE to avoid | `admissibility.py:88` | Avoided by writing to a path the Monitor has not measured — a choice of location, **low**. `app.py:349` hands the attacker that for free on any delete-then-create. |
| CPU and RAM measured per Table 5.9's methods | `test_benchmarks.py:290`, `:336`; `reports/as_benchmarks.json` | Both sample a **5.0-second** loop. Table 5.9 asks for "Average during 1-hour monitoring period" and "Peak memory consumption during stress test". |
| Suite is 371 passed, 2 skipped | `docs/FLOW.md`, `docs/APPROACH.md` | **465 passed, 2 skipped**, measured twice this session. |
| `detection.py` 478 lines, `app.py` 570, `pipeline.py` 192 | `docs/FLOW.md` | **726, 769, 233.** FLOW.md had no section at all for `containers.py`, `suppression.py` or `admissibility.py`. |
| Polygon anchoring is deferred to Weeks 17–24 | `docs/APPROACH.md` §9 | §9.2 **drops** it from the core plan and trades its Excellence bullet for the documented original contribution. |
| — | this report's own first draft | The inventory summary said 28 paths over a breakdown summing to 32; the document carries **34** rows. Corrected in `f5fff38`. |
| — | this session's own first baseline run | The CPU window reported 5587 seconds carrying 1164 one-per-second samples — **~19 minutes of the 60 requested**. Corrected in `20d426a`; the window is now counted in samples. |

### Two defects found that no existing measurement could have seen

Both surfaced from the long window and are recorded in
`measurements.queue_backpressure`:

- **`app._work` is `queue.Queue()` with no `maxsize`** (`app.py:129`), drained by
  one worker making three HTTP calls per event. When the downstream is unreachable
  the producer outruns the consumer without bound. RSS over the flawed window grew
  monotonically 116 MB → 233 MB and had not levelled off when it ended. The
  condition that triggers it — an unreachable ledger — is the one that arises
  during an incident.
- **`app._SEEN_FILES` is an untrimmed `set[str]`** (`app.py:92`), gaining one entry
  per unique path ever seen.

Both stay under the 500 MB target here. **Neither is fixed** — §9.4.1 forbids
writing repairs in Phase 5.

### One reasoned claim the measurement overturned

Drafting P5.4 I reasoned that a valid container plus intermittent encryption evades
the `partial_entropy` branch because that branch is guarded by `not high_entropy`.
Building the file disproved the mechanism. A real `ZIP_STORED` archive of 40
alternating 4 KB blocks — half ciphertext, half prose — measures **6.84 bits/byte**
with `high_entropy_block_fraction` 0.5. It is skipped because the guard is
`container_valid is not True` and the container is genuinely valid. `classify()`
returns plain **`benign`**, reason *"entropy 6.84 below threshold 7.5"*.

Half the file is unrecoverable, nothing fires, nothing is fanned out, nothing is
scored. The corrected mechanism is in the artefact; the reasoned one is not.

---

## 4a. Table 9.8 acceptance benchmarks

Five of the nine rows are Phase 6 measurements and cannot be answered at the Week
20 gate. They are marked as such rather than left blank or guessed.

| # | Measure | Target | Measured at Week 20 | Met |
|---|---|---|---|---|
| 1 | Simulator families detected and restored | 13/13, no regression | **13/13**, all within 2 s, all restore round-trips true | **yes** |
| 2 | Detection-path latency *after repair* | median within sub-100 ms; median and IQR over ≥10 reps | *no repair exists in Phase 5.* Baseline over 40 reps: **median 11.29 ms, IQR 20.47 ms**, p95 23.99 ms | **n/a** |
| 3 | False-positive difference, validated formats | ≤2 pp, one-sided 95% | *needs Arm C.* **And the corpus cannot support the bound**: 85 validated files bound a perfect result at 3.46 pp; 149 needed | **not evaluable** |
| 4 | False-positive difference, unvalidated × incompressible | measured and reported; D5 applies | *needs Arm C.* Arm A baseline on the frozen corpus is **0 / 48** | **pending** |
| 5 | Capability levels with a reproducible source trail | 100% | **9 of 10 empirical**, 1 derived from source and labelled as derived | **9/10** |
| 6 | Capability levels independently reproduced | 100%, or unresolved under D2 | **10/10 protocol-reproduced, 0/10 independently human-reproduced.** 0 unresolved | **no** — see D2 |
| 7 | Mitigation decisions reaching the ledger | 100% | **50.0%** — `reports/ledger_coverage.json` | **NO** |
| 8 | Trusted-restore verification on snapshot-backed cases | 100% | **13/13 local restore round-trips.** VSS-backed restore not measured — needs an elevated shell | **partial** |
| 9 | Injected ledger-tamper cases failing verification | 100% | **32/32** tamper and chain-verification tests pass, including a live external-connection tamper | **yes** |

Row 7 is the one that fails outright, and it fails by construction rather than by
accident — see D1's neighbour finding, M-16. Row 6 fails only in the sense that
matters: the protocol was reproduced, the independence was not.

## 4b. Table 5.9, measured by the methods it states

From `reports/phase5_baseline.json`. All ten rows met.

| Measure | Target | Measured | Method as actually run |
|---|---|---|---|
| Detection latency | <100 ms | **23.99 ms** p95 (median 11.29, IQR 20.47, n=40) | timestamp diff, entry to verdict |
| Response time | <2 s | **0.052 s** worst of 10 | real child process through `actions.terminate_process` |
| False positive rate | <5 % | **0 %** (0/40) | benign corpus through `classify` |
| ML inference | <100 ms | **1.10 ms** | `services/ml-engine` benchmark suite, run by this harness |
| API response p95 | <200 ms | **2.53 ms** | `services/gateway` benchmark suite, run by this harness |
| CPU during monitoring | <15 % | **1.278 %** of 14 cores | **3600 effective samples over a 3732.8 s wall span** |
| RAM peak | <500 MB | **69.79 MB** (baseline 63.07, +6.73) | 300 s stress, 3499 × 512 KB events |
| File recovery | 100 % | **true** | 13/13 simulator restore round-trips |
| Ledger verification | <50 ms | **4.76 ms** worst of 20 | 500-block chain, fresh connection per verify |
| Dashboard latency | <1 s | **31.0 ms** worst of 10 | write → readable on `GET /monitor/events` |

**The CPU row is the one that took work to earn.** Table 5.9 says *"Average during
1-hour monitoring period"*, and this is the first measurement in the repository
that is one: 3600 samples at one per second, over a 3732.8 s wall span, of which
132.8 s was suspend or descheduling — a 3.6 % overhead, recorded in
`suspended_or_descheduled_seconds` rather than hidden inside the average. The load
was 71,683 files at a realistic 10 % high-entropy / 90 % document mix, not the
all-`os.urandom` burst the first attempt used.

The committed 5-second figure it supersedes (1.02 %, `reports/as_benchmarks.json`)
is **not wrong** — it is a correct 5-second measurement. It simply is not the
measurement Table 5.9 specifies, and 1.278 % over the full hour is close enough to
it that no conclusion changes.

### What the hour showed that five seconds cannot

`rss_first_mb` 67.88 → `rss_last_mb` **58.41**, peak 81.7 MB. With the fan-out
disabled, RSS does **not** grow over an hour — it ends lower than it started. That
is what identifies the 116 MB → 233 MB growth seen in the superseded run as the
undrained fan-out backlog rather than a leak in the monitoring path.

`measurements.queue_backpressure` then pins that down directly:

| | |
|---|---|
| events driven | 4000 |
| queue depth afterwards | **3999** — the worker drained one |
| `_work.maxsize` | **0 (unbounded)** |
| `_SEEN_FILES` after one hour of monitoring | **71,797 paths**, growing to 75,797 |

`app._work` is `queue.Queue()` with no bound (`app.py:129`), drained by a single
worker making three HTTP calls per event. When the downstream is unreachable the
producer outruns the consumer without limit, and each queued item retains an event
dict, a feature dict and a verdict. `app._SEEN_FILES` (`app.py:92`) is a `set[str]`
that gains an entry per unique path and is never trimmed — one hour of monitoring
left 71,797 path strings resident.

Both stay under the 500 MB target here. **Neither is fixed** — §9.4.1 forbids
writing repairs in Phase 5, and neither is in the Phase 5 scope. They are recorded
for Phase 6/7.

## 5. Left undone

| Item | Reason | Evidence |
|---|---|---|
| **P0** `NOVELTY_PROOF_PLAN.md` | User directed that Phase 5 proceed without it rather than have it authored in this session | `docs/METHOD_DOCUMENT_STATUS.md` |
| **Independent human reproduction** of capability levels (§9.15, Table 9.8) | One author, one session. The protocol was reproduced; the independence was not | `reproduction.independent_human_reviewer: false` on every record |
| **P5.3 coverage** — 9 of 16 registry formats | No encoder available here for `rar`, `7z`, `lz4`, `zstd`, `mp3`, `ogg`, `flac`, `iso-bmff`. Hand-assembling one would be the forgery this corpus exists to be the opposite of | `summary.formats_in_registry_with_no_encoder_here` |
| **P5.3 sample size** — 85 validated files | Insufficient for Table 9.8's ≤2 pp bound at one-sided 95%: even a perfect result bounds at 3.46 pp. 149 needed | `docs/PHASE5_PREDECLARED_BOUNDS.md` §Bound 1 |
| **`partial_entropy` empirical attack** | The attack is a constraint on the encryptor's output distribution, not a wrapper; level derived from source and recorded as derived | `capability_calibration.json`, `measurement.attack_built: false` |
| **VSS-backed recovery measurement** | Needs an elevated shell, which this session does not have. `file_recovery_success` comes from the simulator sweep's local restore round-trips | 2 skipped tests in `services/response` |
| **Compose-stack pipeline measurement** | No Docker stack was brought up; all measurement is in-process. `pipeline.run` warnings in the run log show the fan-out failing DNS | `baseline_run.log` |
| **Phases 6, 7, 8** | Out of scope for this session by direction | — |

---

## 6. Freeze and gate commits

| What | Commit | Tag |
|---|---|---|
| Corpus manifest frozen (Week 19, §9.15) | `2c242d6` | `corpus-frozen-week19` |
| Cost table frozen (Week 20, §9.4.1 exit gate) | `947ed8c` — artefacts | `cost-table-frozen-week20` |

Both are annotated tags. Quote them in the thesis, per §9.15.

`947ed8c` is the commit at which every Phase 5 artefact reached its final measured
state — the baseline, the evidence report, the corpus manifest, the calibration,
the admission matrix, the ledger-coverage measurement and the predeclared bounds.
The tag itself sits one commit later, on the commit that finalises *this document*,
so that checking the tag out gives a reader the complete and self-consistent gate
state. A report cannot contain the hash of the commit that contains it; resolve the
tag instead:

```bash
git rev-list -n 1 cost-table-frozen-week20
```

### The Week 20 gate, condition by condition

| §9.4.1 requires | Status |
|---|---|
| Every evidence-cancelling path classified | **34 call sites**, 29 of them evidence-cancelling, across all six services — `docs/MITIGATION_INVENTORY.md` |
| Every capability level with a reproducible source trail **or** an unresolved record | **9 of 10 empirical, 1 derived and labelled as derived.** 0 unresolved |
| Confirmed by a second reviewer | **Protocol reproduced, independence not.** See D2 — this is a shortfall, not a pass |
| Admission-flip table complete | **20 cells × 4 policies, 6 flips attributed** — `docs/ADMISSION_RECOMPUTE.md` |
| Cost table frozen **before any repair branch is opened** | **No repair branch was opened.** `services/` has zero diff lines across the whole phase |

The last row is the one §9.4.1 cares most about, and it is checkable in one
command:

```bash
git diff feat/detection-hardening..HEAD -- services/ | wc -l
```

returns **0**. `services/monitor/admissibility.py` — the cost table itself — is
byte-for-byte identical to the branch point. Nothing in Phase 5 touched the code;
the five harnesses in `scripts/` measure it and the seven documents record it.

---

## 7. Regression

Measured three times — at the start of the session, inside the baseline harness,
and again at the gate. All three green and identical:

| Service | Passed | Skipped |
|---|---|---|
| monitor | 222 | 0 |
| response | 86 | 2 |
| gateway | 78 | 0 |
| ledger | 42 | 0 |
| ml-engine | 37 | 0 |
| **Total** | **465** | **2** |

13/13 simulator families detected, all within 2 s, all restore round-trips true
(`reports/simulator_families.json`, re-measured this session).

The two skips assert a POSIX SIGTERM guarantee with no Windows equivalent; a
Windows-specific test covers the same ground.
