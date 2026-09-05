# Claim-to-artefact matrix

**Item P8.2 (NI). Phase 8, Week 30.**

Table 9.9 fixes the wording of eight claims and names the artefact each one
requires. This document is that mapping, and it is **checked rather than
tabulated**: every row carries a path into a report and the value expected there,
so a claim quoting "25.323 pp" fails if the report stops saying 25.323.

```bash
python scripts/claim_matrix.py --tests
```

Exit status is 1 if any claim fails, which makes this the regression on the
thesis itself. Last run at commit `2a7a1c4`, 5 September 2026: **14 claims, 0
failed, 12 made, 2 recorded as not claimed, 9 carrying mandatory wording, and
every named regression passing.**

Two rows record claims that are **not** made. A matrix listing only what is
claimed cannot show that a forbidden claim was avoided deliberately rather than
overlooked, so C-08 and C-09 are in the table with the evidence they *would*
have required.

---

## The eight Table 9.9 rows

| ID | Claim | Mandatory wording | Requires | Checked against | Result |
|---|---|---|---|---|---|
| C-01 | The project team designed and implemented a six-service ransomware detection and recovery system | "The project team designed and implemented…" | `PROJECT_IMPLEMENTATION_RECORD.md` | `implementation_record.json` → `totals.contributors` = 4 | **ok** |
| C-02 | In the reviewed URDS Monitor, the container exemption cancels a high-entropy alert without reaching the governance layer | "In the reviewed URDS Monitor…" | Source audit and evidence report | `ledger_coverage.json` → `by_population.ungoverned.adjudicated` = 0 | **ok** |
| C-03 | The current registry contains seventeen recognised container formats and validators for six | "The current registry contains…" | Registry and evidence report | `containers.py`; `capability_calibration.json` | **ok** |
| C-04 | Under the declared capability model, forging the container exemption is negligible-cost | "Under the declared capability model…" | Calibration record | `capability_calibration.json` → `summary.with_empirical_source_trail` = 10 | **ok** |
| C-05 | The repair closed the evaluated bypass — 21/21, 3/3, 2/2, 3/3, 3/3 | "The repair closed the evaluated bypass…" | Arms A/B/C and regression | `three_arm_experiment.json` → A1 flagged under Arm C = 21 | **ok** |
| C-06 | **Not made.** On the evaluated corpus the benign cost is *not* acceptable — 25.323 pp against 2.00 | "On the evaluated corpus…" | Stratified corpus and paired statistics | `benign_tradeoff.json` → `bound_1.by_arm.C.upper_limit_pp` = 25.3235 | **ok** |
| C-07 | In the evaluated URDS pipeline, one adjudication reaches every hop and 36 of 36 blocks carry all five fields | "In the evaluated URDS pipeline…" | TC-23 … TC-25 | `ledger_coverage.json` → `record_completeness.complete_blocks` = 36 | **ok** |
| C-08 | Ransomware detection improved generally | **not claimed** | External detector comparison | — no comparison was run | **not claimed** |
| C-09 | Patentability or legal novelty | **never inferred from this work** | Formal legal and prior-art review | — no review was conducted | **not claimed** |

## Six results beyond Table 9.9's eight rows

| ID | Claim | Checked against | Result |
|---|---|---|---|
| C-10 | D1 fires on the plan's five-level ladder and not on the code's four-point one; 16 of 20 cells flip | `admission_recompute.json` → `flip_count` = 16 | **ok** |
| C-11 | `base64.b64encode(ciphertext)` is below all three entropy thresholds | `capability_calibration.json` → `levels[4].measured_name` = negligible | **ok** |
| C-12 | The chain detects in-place tampering 20/20 and structural rewriting 0/8 | `tamper_sweep.json` → `structural.detected` = 0 | **ok** |
| C-13 | Latency holds 100 ms at p95 (94.650 ms) and misses at p99 (110.550 ms) | `load_test.json` → `concurrent_detection.latency.p99_ms` = 110.55 | **ok** |
| C-14 | Local restore verified 13/13; VSS-backed restore **not** measured | `vss_status.json` → `platform_status.elevated` = false | **ok** |

---

## Row-by-row: what each claim rests on, and what it does not cover

### C-01 — "The project team designed and implemented…"

`PROJECT_IMPLEMENTATION_RECORD.md`, generated from git by
`scripts/implementation_record.py`. Four contributors, 92 commits on `HEAD`, 209
tracked files; SH first authored files in all six services, SI the ledger's hash
chain and the recovery internals, AS the monitor's entropy, magic-byte and
watchdog primitives, NI the Semester 2 measurement layer.

**What the record also publishes rather than leaving to be inferred:** 82 of the
92 commits (89.1%) carry a `Co-Authored-By: Claude` trailer, and the contribution
is lopsided — one contributor made 72 of 92 commits, all after 5 August 2026. The
claim is made with those facts stated, not around them.

### C-02 — "In the reviewed URDS Monitor…"

Three populations of twelve events each are pushed through the real pipeline by
`scripts/ledger_coverage.py`. The `cancelled` and `attenuated` populations
adjudicate 12 of 12 and reach the ledger 12 of 12. The `ungoverned` population —
the container exemption — adjudicates **0 of 12**.

The mechanism is in `services/monitor/app.py`: `handle_event` adjudicates a
verdict that is already suspicious, and `benign_compressed` is not one.
`test_tc18_admission_matrix.py` holds five cells asserting the exemption never
reaches `adjudicate`.

**What it does not cover:** this is a statement about the reviewed code, not
about ransomware monitors in general. §9.13 forbids the generalisation and it is
not made.

### C-03 — "The current registry contains…"

`detection._CONTAINER_SIGNATURES` holds 20 byte-patterns over 16 format names,
and `identify_container` recognises a seventeenth — `iso-bmff` — on a separate
`ftyp` branch. `containers._VALIDATORS` covers six: zip, gzip, png, jpeg, pdf,
iso-bmff. **Eleven formats have no structural validator**: rar, 7z, xz, bzip2,
lz4, zstd, gif, mp3, ogg, flac, riff.

**A discrepancy worth recording.** Table 9.9 phrases this row as "11 of 16
formats are unvalidated". The code recognises seventeen, so the unvalidated count
of eleven is right on either total, and the difference is one *validated* format
the plan's figure omits. The claim uses the code's number and says which.

**What it does not cover:** §9.13 places writing validators for those eleven
outside this project's scope. The gap is named as the correct long-term fix and
is not fixed.

### C-04 — "Under the declared capability model…"

Ten strategies, each built and run against the deployed code. 10 of 10 carry an
empirical source trail; none is derived from source alone; 0 are unresolved
under D2. Each carries a level on **both** ladders, because the level depends on
which ladder is asked — see C-10.

**What it does not cover:** every level was derived twice in opposite decision
orders by one author in one session. §9.15's AS↔NI ring was not achieved, and
every record carries `reproduction.independent_human_reviewer: false`.

### C-05 — "The repair closed the evaluated bypass…"

*Evaluated* is doing the work in that sentence. Arm C closes all five attack
families that carry witnesses — A1 21/21, A2 3/3, A3 2/2, A4 3/3, A7 3/3 — on one
frozen corpus, against seven families built by the same author who built the
repair.

**What it does not cover:** family A7 shows Arm D defeated by prepending a real
JPEG marker chain, which is a direct demonstration that a family list is not a
proof of closure. And the repair **does not ship** — see C-06.

### C-06 — the claim this work does not get to make

Table 9.9 permits "On the evaluated corpus…" for a claim that benign cost is
acceptable. **This work cannot make that claim.**

Bound 1 was predeclared in `docs/PHASE5_PREDECLARED_BOUNDS.md` before the corpus
was built: the false-positive difference on validated formats must be within 2.00
pp at the upper limit of a one-sided 95% interval. Arm C measures **25.323 pp** —
30 new false positives on 155 validated-format files. D5 fires harder still, at
**100.0 pp against a 15.0 pp tolerance** on the unvalidated × incompressible
stratum, where *every* arm including the null control flags 90 of 90.

`CONTAINER_EXEMPTION_POLICY` therefore defaults to `legacy`, and
`test_tc19_benign_bound.py` asserts both the default and the missed bound as
regressions, so a silent change to either fails the suite.

### C-07 — "In the evaluated URDS pipeline…"

One adjudication traverses Monitor → ML → Ledger → Response → Recovery, asserted
by equality at each hop rather than by shape. Every chained mitigation decision
carries mitigation identifier, validation state, capability levels, policy
version and reason across all three block types that can hold one: **36 of 36**.

**What it does not cover:** the ML hop deliberately does not receive the
adjudication — the model scores bytes, not policy — and TC-25 asserts that
absence so it stays a recorded decision. And the pipeline was measured
in-process; the Compose stack and the network between containers are unmeasured.

### C-08 — not claimed: general detection improvement

No external-detector comparison was run; §9.13 places it out of scope. No
sentence in the thesis, the paper draft or the defence material claims that
ransomware detection improved generally, and the repair that was measured does
not ship. The strongest defensible statement is that a specific bypass in a
specific monitor was priced and a specific repair was rejected on measured cost.

### C-09 — never inferred: patentability or legal novelty

No prior-art search and no legal review were conducted, so this is not a question
the project is in a position to answer either way. It is not answered.

### C-10 — the methodological result

Twenty mitigation × signal cells under six policies. **Sixteen cells flip**, each
attributed to the change that caused it.

Phase 5 answered D1 "no cells flip in the predicted direction". That is true on
`admissibility.py`'s four-point ladder and false on `NOVELTY_PROOF_PLAN.md`
§5.2's five-level one, which §9.1 makes governing: there `path` and
`training_mode` forgery are both Level 0, so are `ransom_extension` and
`static_entropy` avoidance, and §5.3's strict rule breaks all four ties against
the suppression.

**The answer to D1 is a property of the scale the question is asked on.** Policy
F is that computation and is **not deployed** — it would disable two shipped
mitigations and invalidate every arm of the Phase 6 experiment, all measured
against the declared table.

### C-11 — the cheapest attack in the calibration

`base64.b64encode(ciphertext)` is exactly 6.000 bits/byte: below the whole-file
threshold of 7.5, the per-block threshold of 7.9 and the differential floor of
7.0. base32 lands at 5.000, ascii85 at 6.410; all three return plain `benign`.
Cost: one standard-library call and 33% in file size.

**No detector is written for it.** The obvious counter — flag printable content
that decodes to high entropy — fires on PEM certificates, `.eml` attachments,
JWTs and data URIs, and its benign cost has not been measured. This project's
rule is that a mitigation is not proposed until it has been, which is the same
rule that rejected the Phase 6 repair.

### C-12 — what the ledger is evidence of

**20 of 20** in-place tampers detected across seven shapes and three positions —
the "100% of the time" the Phase 7 exit gate requires. **0 of 8** structural
tampers detected, and none of them can be: the chain is unkeyed SHA-256 over
public inputs, so an attacker who can write the database recomputes exactly what
the verifier recomputes.

"Tamper-evident" here means **tamper-evident against an attacker who does not
recompute**. Closing it needs a signing key or an external anchor, and §9.13
places anchoring out of scope. The four undetected shapes are asserted *as
undetected* in `test_tamper_sweep.py`, so the boundary cannot move unnoticed.

### C-13 — the latency claim, stated at the percentile it holds

94.650 ms at p95 and **110.550 ms at p99** under 16-way concurrency, 36 of 1200
events over the 100 ms budget. The single-file benchmark reports 25.764 ms.

Say "within 100 ms at p95 under 16-way concurrency", never "under 100 ms". The
figures are wall-clock on one host, which `load_test.json` records; what a reader
reproduces is the shape, not the digits.

Related and unfixed: the Monitor accepts events **18.7× faster than it forwards
them** into an unbounded queue. Bounding the queue by dropping would discard the
governance records the pipeline exists to preserve, so the fix needs its own
change and its own measurement.

### C-14 — the recovery scope

Local snapshot restore: **13/13** round-trips verified. Failure injection: five
modes, each reported distinctly, **none reported as verified**. VSS-backed
restore: **not measured**, and the blocker is measured rather than asserted —
`vss_status.json` records the host reporting VSS supported, `elevated: false`,
and both `list_snapshots` and `create_snapshot` refusing for that one reason.

This is acceptance row 12, still partial. A reader taking the strictest reading
of §9's "if any are deferred, say Monitor-scoped" should attach *local snapshots*
to the recovery claim specifically; the ML, ledger and response rows pass on
their own evidence.

---

## How to check this document

```bash
python scripts/claim_matrix.py --tests
```

Every row is re-verified against its artefact and every named regression is run.
The command exits 1 on any failure. `reports/claim_matrix.json` holds the last
run, including the per-claim notes above.

If a figure in this document and a figure in a report ever disagree, the report
is right and this document is stale — that is the direction the check enforces.
