# Corrections

**Dated 4 October 2026,** on `fix/windows-integration-defects`. Defects in this
branch's evidence: what each one was, what it produced, and what replaced it.

These were found and fixed first on the sibling branch `fix/evidence-integrity`
(commit `58ce021`, 17 September 2026), whose own `docs/CORRECTIONS.md` is the
original account. This branch never received that commit, so every one of them
was still here. They were ported by hand (`FIXES.md`, defect 14), because the
two branches respond to an attack differently: there an agent acts on a
`certain` answer at once; here the Monitor answers twice, and only the second
answer, one delivery horizon later, can be `certain`.

Most of these were not failures. They were passes. A demonstration that kills
the process it started does not go red, and a ledger field holding an invented
number satisfies a check that the field is present. Each published a result
that was not earned while every gate stayed green, so a reader cannot find
them by running the suites. That is the reason to write them down.

---

## 1. The demonstration supplied its own victim

**Where:** `scripts/attack_chain_demo.py`, the TC-07 block. Introduced on
6 August 2026 (`26d6de3`).

To exercise TC-07, *the offending process is terminated*, the end-to-end demo
wrote a high-entropy file, waited for the Monitor to detect it, and then ran:

```python
victim_process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
```

It asked the Response service to terminate that process, and recorded
`tc07_process_terminated: True` and a `kill_time_under_2s` figure from it. The
process it killed did not write the file. It was never detected, never
attributed, and connected to the attack only by having been started two lines
earlier by the script that scored the result.

**Replaced by:**
- The suspicious writes are made by a separate writer process, never by the
  demo. That gives attribution a process to name that the demo can check the
  answer against. It also stops a Monitor with a live attribution source from
  naming the demo itself as the attacker.
- TC-07 is read off the system, after the attack file's attribution question
  has closed (`judge_tc07`):
  - it passes only if the Monitor's answer was `certain`, named the writer,
    and the Monitor's own escalation terminated it;
  - an answer of `certain` naming any other process fails, and so does a
    termination that was refused;
  - anything short of `certain` is a skip, with the confidence and the reason
    printed.
- The demo terminates nothing, at any point. The writer exits by itself 10 s
  after its write if nothing stops it.

**Consequence, stated plainly:** where the Monitor has no Security-log audit
source (unelevated, no SACL on the watch path, or the Compose stack's
containers), TC-07 skips, and under correction 2 a skip makes the run exit 1.
That is the honest result. The green run before it was bought with a
`time.sleep(60)`.

## 2. A run that skipped a check still exited 0

**Where:**
- `scripts/attack_chain_demo.py`: `return 0 if not failures else 1`
- `scripts/si_demo.py`: `... and tc05 is not False`

Skipped checks are `None` and failed ones `False`. Both exit codes counted only
`False`, so a run that could not exercise a capability still reported success
to anything that reads a status rather than a transcript. For the attack demo,
half of this was already known: `docs/PHASE1-4_COMPLETION_SUMMARY.md` D-3
records that its printed summary had headlined "18/18" over 16 PASS and 2 SKIP,
and the summary was corrected then. The exit code was not, and it is the half
a machine reads. `si_demo.py` exited 0 when TC-05 was skipped because no
`--db` was given.

**Replaced by:** `exit_code()` in both scripts: 0 only when every check ran
and passed. A run with no checks at all is not a pass either.

## 3. Invented process identifiers in the tamper-evident chain

**Where:**
- `scripts/si_demo.py` wrote `"process_id": 6666` into a `file_encrypted`
  ledger event (introduced 6 August 2026, `841380c`).
- `services/response/recovery/tests/test_integration.py` wrote the same number
  in its TC-05 test (`f44372b`). It also wrote `"process_id": 4321` in its
  TC-04 test, which the sibling branch's correction did not cover. Both tests
  are in the directory claim C-14 cites.

Neither number was a measurement, a default, or a placeholder that was ever
resolved. In `si_demo.py` it mattered more than its size suggests, because
that demo's subject is the hash chain, and the chain's only value is that what
it holds can be trusted. An invented PID inside a tamper-evident record is
worse than an absent one: an auditor can see the absence, but not the
invention.

**Replaced by:** `process_id: None`, with `attribution_confidence: "unknown"`
(and, in the demo, a reason), in all three places. The forged rows that the
tamper checks write over these blocks no longer name a process either
(`si_demo.py` wrote `4`, the test `1`). Any edit is what those checks detect.

A synthetic shadow-copy GUID, `{66666666-7777-8888-9999-000000000000}`, in
`services/response/recovery/tests/test_vss_manager.py` was **not** a PID. It is
re-lettered to `{77777777-8888-9999-aaaa-bbbbbbbbbbbb}` so that
`git grep -n 6666 -- scripts services` is a literal gate with no remembered
exception. That change is cosmetic and is recorded only so it is not mistaken
for a substantive one later.

## 4. A completeness row that counted fields, not values

**Where:** `scripts/ledger_coverage.py` and claim C-07.

C-07 asserts that 36 chained adjudication blocks carry all five required
fields. It counts *presence*. A block carrying the invented PID from
correction 3 satisfies it perfectly, and C-07 was green the whole time that
number sat in the chain. Deleting the number does not fix this: the next
invented value would be just as invisible.

**Replaced by:** a scan that asserts a value, not a field count
(`unsupported_pid`): *a ledger event may name a process only when attribution
resolved to `CERTAIN`.* It is reported as `process_attribution_integrity` and
bound to a new claim, **C-16**. `ledger_coverage.py --ledger-db <file>` runs the
same rule over a real run's ledger.

**Read C-16's figure precisely.** The scan drives the real pipeline with no
audit source, so every answer is `UNKNOWN` and none of the 48 events names a
process. "0 unsupported" is therefore vacuously met: it measures restraint, not
correct attribution. A scan that never looked would report the same zero. So
`services/monitor/tests/test_ledger_pid_integrity.py` feeds it PIDs that must be
flagged, and C-16 also pins `events_examined == 48`.

**What porting it found on this branch.** The rule was written for a branch
whose agent never put a PID it was unsure of in the chain. This branch did, by
design. Run over the 2026-10-04 elevated run's ledger (1,556 blocks), it found
703 blocks naming a process, **649 of them unsupported**:

| Blocks | What they held |
|---|---|
| 299 | a Response `trigger` block with `process_id: 0`, the number used for "nobody was attributed" |
| 260 | an `attribution_escalation` block naming a PROBABLE answer's PID (two writers, or a writer that had exited) |
| 54 | a Response `terminate` block naming its target, with nothing saying what authorised the kill |
| 18 + 18 | a `file_event` block and its `trigger` block naming the first answer's PROBABLE PID |

The rule was not loosened to fit the chain. The chain was changed to fit the
rule (`pipeline.chained_pid`; `FIXES.md`, defect 14):
- `process_id` on a block now means "this process did it". It is set only on a
  CERTAIN answer, or as the target of a kill that was asked for.
- A PROBABLE answer's PIDs are recorded as `attribution_candidates`. That is
  every PID whose audited write fell in the window: the evidence, which the
  rule does not read.
- A trigger with nobody attributed records `None`, not `0`.
- A terminate block records the confidence and source that authorised it. A
  kill requested without them is an operator's, through the gateway, which
  does not forward them. Such a block is still recorded, and the scan reports
  it as naming a process without attribution, which is what it is.
- The Response service still receives a PROBABLE PID with an isolate-and-log
  trigger (`test_tc26_attribution.py`), and `/monitor/events` still names the
  PID a PROBABLE answer picked. What changed is only what the chain asserts.

## The tracked evidence the old code produced

- `reports/attack_chain_evidence.txt` and `reports/attack_chain_results.json`
  are from a run on 16 August 2026, by the code in correction 1. In that run
  the Response service refused to kill the self-spawned process (409: the
  container could not see the host PID), so no fabricated kill reached the
  file. TC-07 was recorded as SKIP and the run exited 0 (correction 2). Both
  files are **withdrawn**: each carries a notice saying so, and they are
  replaced by a run of the corrected demo against the live stack (see
  `FIXES.md`, defect 14, and the VM report of this re-test). The figures in
  them that other documents cite are marked **re-verification pending** there.
- `reports/si_demo_evidence.txt` (16 August 2026) does not contain the invented
  PID. Its transcript shows the recovery and the tamper check, and neither
  figure depends on the PID. The run that produced it did write 6666 into that
  run's ledger, which is not in the repository. It is kept, and is regenerated
  by the corrected demo.

## What these corrections do not touch

- `services/response/tests/test_actions.py` and `test_api.py` start a child
  process and kill it. That is a correct unit test: `terminate_process()`
  cannot be tested without a process to terminate, and the unit under test is
  the kill primitive itself. TC-07 timings quoted from those tests (91 ms,
  125.6 ms, 150 ms) measure the primitive. They are not, and were never
  presented as, detection to termination of an attacking process.
- PIDs in API request bodies in the gateway and Response tests (`4512`,
  `1234`) and in the ledger's storage tests are inputs to the code under test,
  not records of what a process did. They are left as they are.

## What is still not proven

- TC-07 end to end needs a Monitor with a live audit source and a Response
  service that can see host PIDs: native, elevated, with the audit SACL on the
  watch path. In the Compose arrangement the Response container has its own
  PID namespace, and the demo's TC-07 skips there.
- Attribution is Windows-only.

## Verifying

```bash
git grep -n 6666 -- scripts services
```

This returns nothing. From `services/monitor`:

```bash
python -m pytest tests/test_demo_integrity.py
```
