# Phase 7 — hardening, regression and documentation

**Weeks 25–28. Every figure here comes from a command that was run, and the
command is given.**

Phase 7 asks for four things: a regression suite covering Table 9.7, a CI
pipeline that keeps it alive, security and load and tamper measurement, and
documentation whose every headline sentence maps to evidence. Three are done. The
fourth is done except for a video, which was not recorded and is not
substituted for.

---

## 0. The exit gate, answered first

> **Week 28.** Suite green in CI from a clean checkout; paper-to-evidence mapping
> complete.

| gate item | status | evidence |
|---|---|---|
| Suite green | **yes** | 657 passed, 2 skipped across five services |
| From a clean checkout | **yes, verified** | fresh clone at this commit: **639 passed, 20 skipped, 0 failed** |
| In CI | **workflow committed and verified locally; no CI run has occurred** | `.github/workflows/tests.yml` |
| Paper-to-evidence mapping | **yes** | `docs/PAPER_DRAFT.md`, appendix — 26 headline sentences, each mapped |

**The one item not fully closed is "in CI".** The workflow exists, its YAML
parses, and every command it runs was executed locally against the tree it will
check out. But no GitHub Actions run has happened, because that needs a pull
request and this session cannot open one and watch it. **A green badge has not
been observed and is not claimed.** The next person to open a PR will get the
first real run, and if it fails the failure is in the workflow rather than in the
suite — the suite is verified from a clean checkout below.

### The clean-checkout verification

```bash
git clone --local --no-hardlinks -b <branch> . /tmp/clean
for s in gateway ledger monitor ml-engine response; do (cd /tmp/clean/services/$s && python -m pytest -q); done
```

| service | working tree | clean clone |
|---|---|---|
| gateway | 86 passed | 86 passed |
| ledger | 67 passed | 67 passed |
| monitor | 361 passed | 361 passed |
| ml-engine | 48 passed | **30 passed, 18 skipped** |
| response | 95 passed, 2 skipped | 95 passed, 2 skipped |
| **total** | **657 passed, 2 skipped** | **639 passed, 20 skipped, 0 failed** |

The eighteen extra skips are all one thing: `models/` is gitignored, so a clean
checkout has no `behavioural_model.pkl`, and eighteen ml-engine tests are
`skipif`-gated on it with that reason printed. A pickle is not a source artefact.
The alternative — training a model inside the job — would test a different model
from the one that ships, which is worse than a labelled skip.

**Table 9.7's rows do not skip.** TC-20 rebuilds the training corpus from its
recorded seed and TC-21 reads a tracked report, so both run in a clean checkout:
11 passed there.

---

## 1. P7.1 — the regression suite, TC-14 … TC-25

One test per row, each asserting the recorded outcome rather than observing it
incidentally. **165 cases across twelve rows**, in four services.

| row | owner | file | cases |
|---|---|---|---|
| TC-14 unvalidated-format closure | AS | `services/monitor/tests/test_tc14_unvalidated_closure.py` | 24 |
| TC-15 integrity objective | AS | `services/monitor/tests/test_tc15_integrity_objective.py` | 13 |
| TC-16 incomplete → deferred | AS | `services/monitor/tests/test_tc16_incomplete_deferred.py` | 13 |
| TC-17 pasted header | AS | `services/monitor/tests/test_tc17_pasted_header.py` | 32 |
| TC-18 admission matrix | AS | `services/monitor/tests/test_tc18_admission_matrix.py` | 21 |
| TC-19 benign bound | AS | `services/monitor/tests/test_tc19_benign_bound.py` | 18 |
| TC-20 corpus labels and seed | NI | `services/ml-engine/tests/test_tc20_corpus_labels.py` | 5 |
| TC-21 per-kind accuracy | NI | `services/ml-engine/tests/test_tc21_per_kind_accuracy.py` | 6 |
| TC-22 confidence-gate record | NI | `services/monitor/tests/test_tc22_confidence_gate_record.py` | 10 |
| TC-23 chained record | SI | `services/monitor/tests/test_tc23_chained_record.py` | 6 |
| TC-24 recovery outcomes | SI | `services/response/tests/test_tc24_recovery_outcomes.py` | 9 |
| TC-25 full traverse | SH | `services/gateway/tests/test_tc25_full_traverse.py` | 8 |

TC-01 … TC-13 have not regressed: the suite went from 467 to 657 by addition
only, with no test removed and one renamed. The 190 new cases are these 165 plus
the 25 tamper-sweep regressions P7.3 added.

### The identifier collision, resolved

`docs/FLOW.md` flagged that `test_tc13_suppression_e2e.py` labelled its
training-mode cases **TC-14**, which Chapter 9 Table 9.7 assigns to the
unvalidated-format witness. Two different cases cannot share an identifier a table
maps to evidence. The local cases are now **TC-13b** and nothing they assert
changed.

### Three tests that hold negative results

Written to fail loudly if the result ever improves without the experiment being
re-run, which is what a regression test for a negative finding is for.

- **TC-19** asserts Bound 1 at **25.323 pp against 2.00 pp** and D5 at **100.0 pp
  against 15.0 pp**, from the artefacts that measured them. If it ever fails, the
  repair became non-inferior and D5's ruling plus the Phase 6 report need
  revisiting.
- **TC-14** asserts that the deployed default still clears all eleven unvalidated
  formats, and that `CONTAINER_EXEMPTION_POLICY` is still `legacy`. A silent
  default change fails it.
- **`test_tamper_sweep.py`** asserts the four *undetected* structural tampers as
  undetected, each with the message a maintainer needs if it starts passing. A
  boundary nobody tests is a boundary nobody notices moving.

### What TC-23 found while being written

A `deferred` verdict keeps the `static_entropy` signal — deliberately, so that
deferring is a statement about evidence rather than a new severity. `static_entropy`
is priced NEGLIGIBLE, and every suppression in the deployed table outranks it.
**So every deferral is cancellable by any operator rule that matches it.** The
record of the cancellation is complete, which is what §9 row 10 requires; the
alert is not. It is exactly the cell policy F of `docs/ADMISSION_RECOMPUTE.md`
attenuates instead, and it is now asserted in both places.

---

## 2. P7.2 — the CI pipeline

`.github/workflows/tests.yml`. Six jobs: one per service, plus a named
`TC-14 … TC-25` job so the acceptance rows appear as their own line in the checks
list rather than buried in a log.

**One job per service is forced, not chosen.** A single pytest process over
`services/` does not work and cannot be made to without changing how the
containers load. Each service uses flat module names matching its container
layout — every one has its own `app.py`, and gateway and response both have a
`main.py` — so one process imports whichever reached `sys.path` first and every
later service tests the wrong module.

Measured: **19 failed and 113 collection errors** in one pass, against 632 passed
across five per-service runs. Test-file basename collisions (`test_api.py` in
three services) are the smaller, more visible instance of the same problem, and
were what made `pytest services` fail at collection before any of this was looked
at.

**Two real defects found by writing it.**

1. `psutil` is imported by the Monitor's benchmarks and is not in
   `services/monitor/requirements.txt`. It is genuinely test-only — nothing the
   container runs imports it — so the workflow installs it as one and names it,
   rather than adding a runtime dependency to fix a test.
2. A zero-byte file named `=` had been committed to the repository root by a
   shell mishap in commit `aa0af69`. Removed.

`URDS_WRITE_REPORTS` is empty in the workflow. CI measures nothing, and a green
run that regenerated an artefact would silently replace something a frozen tag is
meant to pin.

---

## 3. P7.3 — security audit, load testing, tamper resistance

### Tamper resistance — the requirement is met, and its boundary is now measured

```bash
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/tamper_sweep.py
```

28 cases: every tamper shape at every position, each against its own freshly built
40-block chain, tampered **through SQL** rather than the API, verified from a
fresh ledger instance so no cached connection can answer from a pre-edit snapshot.

| class | cases | detected |
|---|---|---|
| in-place | 20 | **20 — 100.0%** |
| structural | 8 | **0** |

The exit gate says injected tamper cases must fail verification 100% of the time.
On in-place edits they do. The second row is the result worth having: the chain is
unkeyed SHA-256 over public inputs, so an attacker who can write the database
recomputes exactly what the verifier will recompute. Appending, truncating, or
rewriting a block and re-chaining forward all produce a chain that verifies clean.

**"Tamper-evident" here means tamper-evident against an attacker who does not
recompute.** Closing it needs a signing key or an external anchor; §9.13 places
anchoring out of scope.

The first run reported 19/21 and **both misses were mine, not the ledger's**: one
case overwrote `previous_hash` on block 1 with `"0" * 64`, which is `GENESIS_HASH`
and therefore a no-op; the other classified "delete the newest block" as an
in-place edit when it is a truncation. Both are fixed, and the regression test now
asserts that the genesis value and the tamper value differ so the first cannot
silently recur.

### Load testing

```bash
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/load_test.py
```

**Detection latency under 16-way concurrency**, 1200 events over four shapes:

| | one file, idle (`as_benchmarks.json`) | 16 threads |
|---|---|---|
| median | — | 61.279 ms |
| mean | 10.493 ms | 62.998 ms |
| p95 | 25.764 ms | **94.650 ms** |
| p99 | — | **110.550 ms** |
| max | 27.167 ms | 131.560 ms |
| over the 100 ms budget | 0 of 40 | **36 of 1200 — 3.0%** |

Table 5.9's 100 ms holds at the median and at p95 and **misses at p99**. The
existing benchmark measures one file at a time on an idle machine, which is not
the condition a ransomware detector is judged in: a mass encryption run *is* a
burst of concurrent filesystem events. The defensible statement is "100 ms at p95
under 16-way concurrency".

**The fan-out queue.** `app._work` has `maxsize` 0. With downstream hops at 20 ms:
1723 events produced in 8 seconds, **peak depth 1631**, the worker cleared 92 —
the Monitor accepts events **18.7× faster than it forwards them**, and nothing
bounds the backlog. Clearing 1631 at the measured hop latency takes 97.9 seconds.
Every queued item is a ledger write that has not happened, so the audit trail falls
behind during exactly the burst it exists to record.

**`_SEEN_FILES`.** 214.3 bytes per distinct path over 20,000 realistic Windows
paths. One million paths ≈ 214 MB against a 500 MB target; the structure alone
exceeds it around 2.3 million. A slow leak with a small constant — recorded
because "unbounded" and "unbounded, at 214 bytes each" are different statements.

**Nothing is fixed.** Bounding the queue means choosing what to do on overflow,
and the obvious choice — drop — silently discards the governance records
`log_governance_decision` was added to preserve. The defensible shape is a bounded
queue whose overflow is itself recorded, and that is a design decision with an
operator cost belonging in its own change with its own measurement.

### The security audit

`docs/SECURITY_AUDIT.md`. Eleven findings, each with the command that produced it:
nine open, two closed. The headline is **S-1**, and it came out of finishing
Phase 5's last derived capability level:

```python
base64.b64encode(ciphertext)   #  6.000 bits/byte
```

Below the whole-file threshold of 7.5, below the per-block threshold of 7.9, and
below the differential floor of 7.0. **One standard-library call defeats all three
entropy signals at once**, at 33% in file size. It is the cheapest attack in the
whole calibration and the cost table priced it as the most expensive avoidance in
the system.

No detector is written for it. The obvious counter — flag high-printable content
that decodes to high entropy — fires on PEM certificates, `.eml` attachments,
JWTs, data URIs and embedded images, and this project's method is that a
mitigation is not proposed until its benign cost is measured. It is recorded open.

---

## 4. P7.4 — documentation

| deliverable | status | artefact |
|---|---|---|
| Paper draft | **done** | `docs/PAPER_DRAFT.md` |
| Paper-to-evidence mapping | **done** | its appendix — 26 sentences, each to a test, report or stated assumption |
| User manual | **done** | `docs/USER_MANUAL.md` |
| Demonstration video | **not recorded** | `docs/DEMONSTRATION_SCRIPT.md` is the runbook |

**No video exists and nothing stands in for one.** The Docker daemon was not
running on the measurement host, so the Compose stack the demonstration drives
could not be brought up, and VSS needs an elevated shell this session did not
have, so step 7 could not be performed at all. A screenshot or a hand-written
transcript presented as a recording would be a fabricated artefact.
`docs/DEMONSTRATION_SCRIPT.md` gives the eight-step sequence with the command, the
expected output and the evidence path for each, so a person with a daemon and an
Administrator prompt can record it without deciding anything.

---

## 5. What Phase 7 changed about earlier claims

| was | is | why |
|---|---|---|
| "detection latency under 100 ms" | 100 ms at p95 under 16-way concurrency; p99 is 110.550 ms | measured under concurrency for the first time |
| "tamper-evident ledger" | tamper-evident against an attacker who does not recompute | 8 structural tampers, 0 detected |
| "injected tamper cases detected" (n=1) | 20 of 20 in-place, across 3 positions | one case does not support a 100% claim |
| `partial_entropy` avoidance costs `moderate` | `negligible` — one standard-library call | §5.1's tooling search was finally run for that row |
| 9 of 10 capability levels empirical | **10 of 10** | the tenth was built |
| Table 9.7's TC-14 is training mode | TC-14 is the unvalidated-format witness; the local cases are TC-13b | Chapter 9 owns the identifier |

---

## 6. What is left undone, and why

1. **No CI run has been observed.** The workflow is committed and every command in
   it verified locally. A green badge is not claimed. Opening a pull request is
   what closes this.
2. **VSS-backed restore is unverified.** The blocker is measured rather than
   asserted: `reports/vss_status.json` records the host reporting VSS supported,
   `elevated: false`, and both `list_snapshots` and `create_snapshot` refusing.
   Needs an Administrator shell.
3. **The demonstration video.** See P7.4.
4. **The Compose stack is unmeasured.** Every load and pipeline figure here is
   in-process on one machine. The Docker daemon was not running.
5. **Independent human reproduction.** §9.15 asks for AS↔NI reproduction of every
   capability level. Every level is derived twice in opposite decision orders from
   the same recorded facts — the reproduction protocol — but by one author in one
   session. Every record carries `independent_human_reviewer: false`.
6. **Eighteen ml-engine tests skip in a clean checkout.** `models/` is gitignored.
   Labelled, with the reason, and Table 9.7's rows are unaffected.
7. **Nine open security findings.** Each has a fix and none is written, for the
   reason stated against each: an unmeasured mitigation is a guess with a
   changelog entry. `docs/SECURITY_AUDIT.md`.
8. **The frozen benign corpus is not in the repository.** `corpus/` is untracked;
   `reports/benign_corpus_manifest.json` is tracked, and
   `scripts/build_benign_corpus.py` rebuilds all 275 files byte-identically from
   the recorded seed. That is the reproducibility route, and verifying it end to
   end from a clean checkout is P8.4's job, not this phase's.
