# Security audit — what an attacker gets, measured

**Item P7.3 (SH + SI). Phase 7, Week 27. Every number here comes from a command
that was run; the command is given with the number.**

This is not a checklist against a standard. It is the list of things this system
does not stop, each one built and executed against the running code, with what it
costs an attacker and what closing it would cost the project. Where a finding is
closed, the artefact that closes it is named. Where it is open, it says so, and
where it is out of scope it says which clause puts it there.

Nothing in this document is a fix. Three of the findings below have obvious-looking
fixes, and the reason none is written here is the same reason the container repair
does not ship: a mitigation whose benign cost has not been measured is not a
mitigation, it is a guess with a changelog entry.

## Summary

| # | Finding | Attacker cost | Status |
|---|---|---|---|
| S-1 | `base64.b64encode` defeats all three entropy signals at once | one standard-library call, +33% file size | **open** |
| S-2 | Eleven of seventeen registry formats have no structural validator | four bytes | **open**, §9.13 |
| S-3 | The hash chain does not detect a re-chained, truncated or appended ledger | database write access | **open by design**, §9.13 |
| S-4 | The container exemption is outside the governance layer entirely | four bytes | **open**, and the subject of Phase 6 |
| S-5 | Detection latency exceeds its budget at p99 under concurrency | none — a busy machine does it | **open**, measured |
| S-6 | The fan-out queue is unbounded and the Monitor outruns it 18.7:1 | write files quickly | **open**, measured |
| S-7 | `_SEEN_FILES` grows without bound | one distinct path at a time | **open**, measured, small constant |
| S-8 | Two deployed suppressions are not cost-justified on the plan's ladder | already available to the attacker | **open**, measured |
| S-9 | Snapshot-backed restoration is unverified | — | **not measured**, needs elevation |
| S-10 | A pasted container header defeated the detector entirely | four bytes | **closed** |
| S-11 | A cancelled suppression never reached the ledger | — | **closed** |

---

## S-1 — one standard-library call defeats every entropy signal

**Command:** `.venv\Scripts\python.exe scripts/capability_calibration.py`
**Artefact:** `reports/capability_calibration.json`, strategy
`partial_entropy / never reach ciphertext entropy in any block`

```python
base64.b64encode(ciphertext)
```

Base64 spends eight output bits per six bits of input, so uniform ciphertext
lands at exactly **6.000 bits/byte**. Every entropy gate in `detection.py` sits
above that:

| signal | threshold | measured | fires? |
|---|---|---|---|
| `static_entropy` | 7.5 whole-file | 6.000 | no |
| `partial_entropy` | 7.9 per 4KB block | max block 5.99, high-block fraction 0.00 | no |
| `entropy_rise` | rise ≥ 2.0 **and** result ≥ 7.0 | rise 1.98 from prose, result 6.000 | no, for either reason |

`base32` lands at 5.000 and `ascii85` at 6.410; all three return plain `benign`.
The same payload unencoded returns `suspected_encryption` on `static_entropy`,
and on a watched path `entropy_rise` at a delta of 3.98.

**What it costs the attacker:** one statement, no dependencies, no knowledge of
any format, and 33% in file size for base64 or 60% for base32. On the plan's §5.2
ladder it is Level 1, *public primitive* — which §5.3 names explicitly, in the
same sentence as standard-library container generation.

**What it cost the project:** `partial_entropy` avoidance was priced `moderate`
in `admissibility.py` and was the only capability level in Phase 5 derived from
source rather than built. The reasoning was that flattening the distribution
required the attacker to encrypt less or post-process with distribution-aware
code. An expanding alphabet does it with one call. §5.1's locked tooling search
had not been run for that row, and this is what running it found.

**Why no fix is written here.** The obvious counter — flag high-printable content
that decodes to high entropy — fires on PEM certificates, `.eml` attachments,
JWTs, data URIs, base64-embedded images in JSON and source, and Windows
certificate stores. Its benign cost has not been measured, and this project's
whole method is that a mitigation is not proposed until it has been. The finding
is recorded open.

---

## S-2 — eleven formats have no structural validator

**Command:** `services/monitor` → `pytest tests/test_tc14_unvalidated_closure.py`
**Artefact:** `reports/three_arm_experiment.json`, family A1

`containers._VALIDATORS` decides six formats: zip, gzip, png, jpeg, pdf,
iso-bmff. `detection._CONTAINER_SIGNATURES` recognises seventeen. For the other
eleven — **rar, 7z, xz, bzip2, lz4, zstd, gif, mp3, ogg, flac, riff** —
`validate_container` returns `None`, and under the deployed `legacy` policy that
`None` is read as an explanation for high entropy.

Measured: a magic prefix followed by ciphertext is `benign_compressed` under Arm A
for **all eleven**, and flagged for all eleven under Arm C.

**What it costs the attacker:** four bytes. Level 0 on the plan's ladder — the
same rung as choosing a filename.

**Why it is not fixed.** Arm C closes it and Arm C does not ship: D5 fired at
**100.0 pp** false positives on the unvalidated × incompressible stratum against a
15.0 pp tolerance, and Bound 1 failed at 25.323 pp against 2.00 pp. The correct
long-term fix is a real structural validator for bzip2, xz, GIF and RIFF, and
Chapter 9 §9.13 places writing one outside this project's scope. Both halves are
recorded rather than one.

---

## S-3 — the hash chain detects edits, not rewrites

**Command:** `.venv\Scripts\python.exe scripts/tamper_sweep.py`
**Artefact:** `reports/tamper_sweep.json`
**Regression:** `services/ledger/tests/test_tamper_sweep.py`

28 cases: every tamper shape at every position, each against its own freshly
built 40-block chain, tampered through SQL rather than the API, verified from a
fresh ledger instance.

| class | cases | detected |
|---|---|---|
| in-place — a column rewritten, an interior row deleted, two payloads swapped | 20 | **20 (100.0%)** |
| structural — a block appended, the newest deleted, the tail truncated, a suffix re-chained | 8 | **0** |

The first row is the P7.3 requirement and it is met. The second is the finding.
The chain hashes `timestamp + event_type + event_data + previous_hash` with
unkeyed SHA-256. Every input is public and there is no secret in the scheme, so an
attacker who can write the database file recomputes exactly what the verifier will
recompute. Rewriting a block and re-chaining forward produces a chain that
verifies clean, with the original evidence gone.

**"Tamper-evident" here means tamper-evident against an attacker who does not
recompute.** That is a much smaller claim than the phrase suggests and it should
be written that way everywhere it appears.

**What would close it:** a signing key the attacker does not hold, or an external
anchor recording what the tip was before they arrived. §9.13 places anchoring out
of scope, so the limit stands and is reported.

---

## S-4 — the container exemption is not governed at all

**Artefact:** `docs/ADMISSION_RECOMPUTE.md`, the `container` row

`admissibility.adjudicate` is the governance layer, and `app.handle_event` only
calls it for a verdict that is already suspicious. A `benign_compressed` verdict
is not suspicious. So the Monitor's most-used evidence-cancelling path never
reaches the layer that exists to price evidence-cancelling paths, has no row in
the cost table, and under every one of the six computed policies cancels whatever
it likes.

`scripts/ledger_coverage.py` measures the consequence directly: the ungoverned
population produces **0 adjudications from 12 events**, so it contributes nothing
to either side of the 100% coverage figure. Reading that 100% as "every
evidence-cancelling path is audited" would be wrong, and the artefact says so in
its own `what_this_row_does_not_cover` field.

---

## S-5 — the latency budget holds at p95 and not at p99

**Command:** `.venv\Scripts\python.exe scripts/load_test.py`
**Artefact:** `reports/load_test.json`

1200 events, four shapes, 16 threads, fan-out disabled so this measures the
detection path the budget is written against.

| | single event, idle | 16 threads |
|---|---|---|
| median | — | **61.279 ms** |
| mean | 10.493 ms | 62.998 ms |
| p95 | 25.764 ms | **94.650 ms** |
| p99 | — | **110.550 ms** |
| max | 27.167 ms | **131.560 ms** |
| over the 100 ms budget | 0 of 40 | **36 of 1200 (3.0%)** |

Throughput 251.8 events/s, no errors.

Table 5.9's 100 ms is met at the median and at p95 and **missed at p99**. The
existing benchmark in `reports/as_benchmarks.json` measures one file at a time on
an idle machine, which is not the condition a detector is judged in — a mass
encryption run is precisely a burst of concurrent filesystem events. The honest
statement of the benchmark is "100 ms at p95 under 16-way concurrency", not
"100 ms".

---

## S-6 — the Monitor accepts events 18.7× faster than it can forward them

**Command:** `.venv\Scripts\python.exe scripts/load_test.py`
**Artefact:** `reports/load_test.json`, `fan_out_queue`

`app._work` is a `queue.Queue` with `maxsize` 0 — unbounded. Producers are
watchdog threads; the consumer is one worker making three HTTP calls per event.
With the downstream hops answering in 20 ms:

- **1723 events produced in 8 seconds**, 215 per second
- **peak queue depth 1631** — the worker cleared 92 of the 1723, a ratio of 18.7:1
- clearing that backlog at the measured hop latency would take **97.9 seconds**
- nothing bounds it, and each entry holds a full event dict

The backlog grows fastest exactly when it matters least to be behind: a mass
encryption run is the burst. Every queued item is a ledger write that has not
happened, so the audit record falls arbitrarily far behind the attack it is
supposed to be recording, and memory grows with it.

**What a fix has to decide, and why one is not written here.** Bounding the queue
means choosing what to do on overflow, and the obvious choice — drop — silently
discards governance records, which is the exact failure `log_governance_decision`
was added to fix. A defensible shape is a bounded queue whose overflow is itself
recorded: a counter on `/monitor/stats` and one ledger entry per overflow window
saying how many decisions were lost. That is a design decision with an operator
cost, and it belongs in its own change with its own measurement.

---

## S-7 — `_SEEN_FILES` never shrinks

**Command:** `.venv\Scripts\python.exe scripts/load_test.py`
**Artefact:** `reports/load_test.json`, `seen_files_set`

`app._SEEN_FILES` answers "is this the first time this path has been seen", which
gates one ledger baseline write per path per monitor run. It is a plain `set` and
nothing removes from it, so its size is the number of distinct paths the process
has ever seen.

Measured over 20,000 realistic Windows paths: **214.3 bytes per distinct path**,
container plus strings.

So one million distinct paths is about **214 MB**, against Table 5.9's 500 MB RAM
target, and the target is exceeded by this structure alone somewhere around **2.3
million paths**. On a build server or a large source tree that is reachable.

This is the mildest finding here: a slow leak with a small constant, not an
imminent failure. It is recorded because "unbounded" and "unbounded and it costs
214 bytes each" are different statements, and only the second lets someone decide
whether to care.

---

## S-8 — two deployed suppressions are not cost-justified on the governing ladder

**Command:** `.venv\Scripts\python.exe scripts/admission_recompute.py`
**Artefact:** `docs/ADMISSION_RECOMPUTE.md`, policy F

On `NOVELTY_PROOF_PLAN.md` §5.2's five-level ladder, `path` and `training_mode`
forgery are both **Level 0** — §5.2 puts choosing a path beside choosing bytes —
and so are `ransom_extension` and `static_entropy` avoidance. Four ties, and
§5.3's strict rule breaks all four against the suppression.

Under policy F — the plan applied end to end — the whitelist path rule and
training mode cancel **nothing at all**; only the hash whitelist, at Level 4,
still cancels anything.

This is §9.7's decision rule D1 firing in the direction it predicted. Phase 5
reported that it did not fire, and that report was correct about the four-point
ladder it was measured on and wrong about the ladder §9.1 makes governing. The
answer to D1 is a property of the scale, not of the system.

Policy F is not deployed. Adopting it would disable two shipped mitigations
outright and invalidate every arm of the Phase 6 experiment, all of which were
measured against the declared table.

A consequence worth stating on its own: because a `deferred` verdict keeps the
`static_entropy` signal, and `static_entropy` is priced NEGLIGIBLE, **every
deferral is cancellable by any operator rule that matches it** under the deployed
table. The record of the cancellation is complete — that is what
`NOVELTY_PROOF_PLAN.md` §9 row 10 requires and `scripts/ledger_coverage.py`
measures at 36/36 — but the alert is not.

---

## S-9 — snapshot-backed restoration is not verified

**Command:** `.venv\Scripts\python.exe scripts/verify_vss.py --status-only`
**Artefact:** `reports/vss_status.json`

Local restore is measured: 13/13 round-trips, and five injected failures each
producing a distinct outcome with none reported as verified
(`reports/failure_injection.json`). VSS-backed restore is not.

The blocker is measured rather than asserted: the host reports `supported: true`,
backend `wmi:Win32_ShadowCopy`, `elevated: false`, and both `list_snapshots` and
`create_snapshot` refuse with an explicit elevation error. So the gap is a shell
privilege, not an unexercised capability — "not measured" alone does not
distinguish those.

---

## S-10 and S-11 — closed, and how

**S-10, the pasted header.** Before `containers.py` existed, four bytes of
container magic bought the entropy exemption outright; `scripts/ransomware_simulator.py`'s
`spoofer` family went undetected 8 times out of 8. Structural validation makes a
header with nothing behind it FORGED, and FORGED is evidence rather than an
explanation. Regression: `services/monitor/tests/test_tc17_pasted_header.py`,
five formats × five policies, asserting the **signal** and not just the verdict —
`structural_mismatch` costs MODERATE to avoid where `static_entropy` costs
NEGLIGIBLE, so reaching the right verdict on the wrong signal would let a path
whitelist cancel it.

**S-11, the invisible cancellation.** A suppression that cancelled an alert
stopped the event at the fan-out gate, so the one decision an auditor most needs
to see was the only one the chain never held. Coverage measured at 50.0%. A
cancelled decision now chains as its own `suppression_decision` block, with no
prediction and no response, carrying all five fields §9 row 10 requires.
Coverage 100.0%, record completeness 36/36 blocks.

---

## What this audit does not cover

- **The Compose stack.** Every measurement here is in-process on one machine.
  The network between containers, the gateway's rate limiting under load, and the
  real filesystem under real load are all unmeasured, and the figures above are
  Monitor-scoped.
- **Authentication and authorisation.** `services/gateway/tests/test_authz.py`
  covers TC-10; nothing here re-audits it.
- **The models as attack surface.** `reports/capability_calibration.json` measures
  what it costs to hold the behavioural model under its confidence gate, and
  finds the Monitor's floor makes the gate unreachable on the only live caller.
  Model extraction, poisoning through the deployed path, and adversarial input
  crafted against the feature vector are not examined.
- **Anything requiring elevation.** See S-9.
