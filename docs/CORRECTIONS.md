# Corrections

**Dated 17 September 2026.** Ten defects in this repository's evidence: what
each one was, what it produced, and what replaced it.

This document exists because six of the first eight were not failures. They
were passes. A demonstration that spawns the process it then reports killing does
not go red; a claim whose evidence moves to a different file does not go red; a
row that counts whether a field is present does not go red when the field
contains an invented number; a setup script that prints `[ FAIL ]` and then
exits `0` does not go red for anything that reads an exit code. Each published
a result that was not earned, and each did so while every gate in the project
stayed green. A reader cannot find these by running the suite, which is the
only reason to write them down.

Corrections 7 and 8 were found later than the rest, during the work that put
the agent on a host. Both are earlier corrections recurring in a new file,
which is the argument for this document existing rather than for the defects
having been one-off slips.

Corrections 9 and 10 are two shapes this document did not previously have, and
both come from the commit that fixed Phase 3's response time. One is a gate that
was **red** while the commit message reported it green — the inverse of every
defect above it, and the only one a reader could have caught by running the
suite. The other is a published *explanation*: the artefact said why an attack
escaped, no gate covered that sentence, and it was wrong in a way that would
have sent the next reader to the wrong half of the system. Neither is a green
gate hiding a false claim, which is what the first eight have in common.

**This must reach the supervisor and co-authors before submission.** Three of
the corrections change figures or claims that appear in the write-up.

---

## 1. The demonstration supplied its own victim — F1

**Where:** `scripts/attack_chain_demo.py`, the TC-07 block.
**Introduced:** 6 August 2026, `26d6de3`. **Removed:** 17 September 2026.

The end-to-end demonstration wrote a high-entropy file into the watched path,
waited for the Monitor to detect it, and then — to exercise TC-07, *the
offending process is terminated* — ran:

```python
victim_process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
```

and asked the Response service to terminate that, recording
`tc07_process_terminated = True` and a `kill_time_under_2s` figure from it.

The process it terminated was not the process that wrote the file. It was not
detected, not attributed, and not connected to the attack by anything except
having been created two lines earlier by the script that was scoring the
result. The demo was the attacker, the victim and the judge at once, and the
row it produced described nothing about the system under test.

**Replaced by:** TC-07 now reads `process_id` and `attribution_confidence` off
the detection event and terminates only the process attribution resolved, and
only where that resolution was `CERTAIN`. Anything else records the confidence
and the reason and kills nothing. Nothing is spawned to stand in for a process
that was not identified.

**Consequence, stated plainly:** wherever the Response service runs in a
container with its own PID namespace — the default Compose arrangement — a
correct host PID still cannot be killed, so TC-07 now *skips*; and under
correction 2 a skip makes the run exit non-zero. A red run is the honest result
of a demonstration that cannot reach a host PID. The previous green one was
purchased with a `time.sleep(60)`.

## 2. A run that skipped a capability still exited 0 — F2

**Where:** `scripts/attack_chain_demo.py`, `return 0 if not failures else 1`.
**Introduced:** 6 August 2026, `26d6de3`. **Fixed:** 17 September 2026.

Skipped checks are recorded as `None`, failures as `False`. The exit code
counted only `False`, so a run that could not exercise a capability at all
still reported success to everything that reads a status rather than a
transcript.

Half of this was already known and fixed. `docs/PHASE1-4_COMPLETION_SUMMARY.md`
D-3 records that the printed summary had headlined "18/18 checks passed" over a
list showing 16 PASS and 2 SKIP, and that the summary line was corrected. The
exit code was not, and it is the half a machine reads.

**Replaced by:** `return 0 if not (failures or skipped) else 1`. An unproven
capability is not a passing one.

## 3. A fabricated process identifier, in the tamper-evident chain — F3

**Where:** `scripts/si_demo.py` (introduced 6 August 2026, `841380c`) and
`services/response/recovery/tests/test_integration.py` (introduced 6 August
2026, `f44372b`). **Removed:** 17 September 2026.

Both wrote `"process_id": 6666` into a `file_encrypted` ledger event. The value
was invented. No process with that identifier was involved in either the demo
or the test; the number is not a measurement, not a default, and not a
placeholder that was ever resolved.

It mattered more in `si_demo.py` than its size suggests, because that demo's
entire subject is the hash chain, and the chain's only value is that what it
holds can be trusted. A fabricated PID inside a tamper-evident record is worse
than an absent one: the absence is legible to an auditor and the fabrication is
not. It mattered in the test because that suite is cited by the claim matrix,
and evidence a claim rests on does not get to contain invented facts — however
incidental they are to the assertion, and the value was never asserted by the
test that carried it.

**Replaced by:** `process_id: None` with `attribution_confidence: "unknown"`
and a reason, in both places. "No process was identified" is the honest value,
and the pipeline already has a shape for saying it.

A third `6666` in `services/response/recovery/tests/test_vss_manager.py` was
**not** a fabricated PID. It was a synthetic shadow-copy GUID,
`{66666666-7777-8888-9999-000000000000}`, inside a sample of `vssadmin`
output. It has been re-lettered to `{77777777-8888-9999-aaaa-bbbbbbbbbbbb}` so
that `grep -rn "6666" scripts/ services/` is a literal gate with no remembered
exception. That change is cosmetic and is recorded here only so the
re-lettering is not later mistaken for a substantive one.

## 4. A claim that would have stayed green after becoming false — F6

**Where:** `scripts/claim_matrix.py` and `reports/claim_matrix.json`, row C-14.
**Corrected:** 17 September 2026.

C-14 asserted *"VSS-backed restore is NOT measured"*, and verified itself by
checking that `reports/vss_status.json` reported
`platform_status.elevated == false`. That was true and honest when written: the
blocker was a shell privilege, and the row said so.

The branch that then measured the restore on an elevated host wrote its
evidence to a **different file**, `reports/vss_restore_verified.json`. So once
that work merged, C-14's check would have gone on passing unchanged — the old
file still says `elevated: false` — while the claim it makes had become untrue.
Nothing would have gone red. The row had to be changed deliberately, by someone
who noticed. That is the failure mode worth naming: a claim matrix protects you
against a figure that moves, and not at all against a claim whose subject moves
out from under it.

**Replaced by:** C-14 reads the file that holds the measurement, and asserts
five things rather than one — the elevation that made the run possible, that
the attack actually changed the file, the SHA-256 the file started at, the
SHA-256 it was restored to, and the round-trip verdict. A lone
`round_trip_verified: true` is a self-reported boolean in a hand-produced file,
and `attack_changed_the_file` is there because a restore that did nothing to an
untouched file would report success just as loudly.
`reports/vss_status.json` is kept: it is the honest record of the period when
elevation was the blocker.

## 5. The matrix proved "the file says X", never "X is true of this code" — F7

**Where:** `scripts/claim_matrix.py`. **Added:** 17 September 2026.

The matrix read each artefact and compared the figure inside it to the figure
the claim quoted. It never asked where the artefact came from. A report
generated on a branch that was never merged, or carried forward from before the
change it is supposed to describe, satisfied every check in the file.

**Replaced by:** every JSON evidence artefact must now carry `generated_at` and
the `commit` it was produced at, and that commit must be an ancestor of `HEAD`.
Nine artefacts are checked. CI now checks out with `fetch-depth: 0`, because at
the default depth of 1 the older commits are absent, the ancestry question
cannot be decided, and the check would have silently skipped.

**What this does not do,** stated here because overclaiming it would repeat the
original error one level up: it does not detect a hand-edited artefact. The
stamp sits in the same file as the figure, so whoever can edit one can edit the
other. That is `scripts/artefact_manifest.py --verify`, which digests every
stable artefact and runs immediately before the matrix in the reproduction
gate. Provenance answers "is this evidence from this line of development"; the
manifest answers "is this evidence the bytes we froze". Neither answers the
other, and neither is a signature.

`reports/vss_restore_verified.json` carries a stamp **recovered from git
history** rather than written by the run that produced it — the elevated
round-trip predates the guard. The file says so in a `_provenance` field, so
that a recovered stamp is never mistaken for a self-reported one.

## 6. A completeness row that counted fields, not values — F8

**Where:** `scripts/ledger_coverage.py`, and claim C-07.
**Added:** 17 September 2026.

C-07 asserts that 36 chained adjudication blocks carry all five required
fields. It counts *presence*. A block carrying the fabricated PID from
correction 3 satisfies it perfectly — and did: C-07 was green for the entire
period that number sat in the chain, because the field was there.

Deleting the number does not fix this. The next invented value would be just as
invisible.

**Replaced by:** a new scan, `LedgerStub.unsupported_pids()`, asserting a value
relationship rather than a field count — *a ledger event may name a process
only when attribution resolved to `CERTAIN`* — reported as
`process_attribution_integrity` and bound to new claim **C-16**.

**Read C-16's figure precisely.** On a host with no Windows Security-log audit
source, attribution resolves to `UNKNOWN` for every write, so 0 of the 48
ledger events examined names a process **at all**, and "0 unsupported" is
*vacuously* satisfied. It measures restraint, not correct attribution. A scan
that never looked would report the same zero, so
`services/monitor/tests/test_ledger_pid_integrity.py` feeds it PIDs that must
be flagged, and C-16 additionally pins `events_examined == 48`, so that a
future change which quietly stopped collecting events cannot pass by examining
nothing.

## 7. The audit setup printed FAIL and exited 0 — F11

**Where:** `scripts/setup_attribution_audit.ps1`, the end-to-end probe.
**Found:** 17 September 2026. **Fixed:** 17 September 2026.

The script verifies its own work by writing a file into the watch path and
looking for the 4663 record that should follow. When that probe found nothing
it printed `[ FAIL ] End-to-end probe` and then exited `0`.

This is correction 2 again, in a different file and against a more consequential
check. Everything downstream of this script — the agent's ability to name a
process, and therefore to suspend anything at all — depends on auditing working,
and the one check that confirms it reported success to every caller that reads
an exit code rather than a transcript. An installer that runs this and branches
on `$LASTEXITCODE` would configure a machine that silently names nobody.

**Replaced by:** the script tracks whether any check failed and exits non-zero
if one did. A setup that cannot prove auditing works does not report that it
does.

## 8. A deletion named the detector as the process that did it — F13

**Where:** `services/monitor/app.py`, the `deleted` branch of `handle_event`.
**Introduced:** with the branch. **Fixed:** 17 September 2026.

Every filesystem deletion the Monitor observed produced an event carrying:

```python
"process_id": os.getpid(),
```

That is the *detector's own* process, and the event carried no
`attribution_confidence` field at all, so nothing downstream could tell that
the number was a placeholder rather than an answer. It is correction 3's defect
in a different shape: not a fabricated PID this time but a real one belonging
to a process that did not do the thing, in the field whose entire purpose is
naming who did.

It reached `/monitor/events` rather than the hash chain, which is the only
reason it is not a second F3.

**Replaced by:** `process_id: None`, `attribution_confidence: unknown`, and a
reason saying that deletions are attributed by the caller when the path is one
it protects. The agent now does exactly that, and DELETE was added to the
audited access rights so the question has an answer — see §4 of
[LIMITATIONS.md](LIMITATIONS.md).

## 9. A commit reported a green suite while leaving it red — F14

**Where:** `agent/tests/test_phase3.py`,
`test_the_phase3_acceptance_evidence_still_records_a_failure`.
**Introduced:** 17 September 2026, `f47d719`. **Fixed:** 17 September 2026.

The test pins the acceptance artefact so a failing phase cannot quietly become
a passing one:

```python
assert report["result"] == "FAILED"
for arm in report["attack_arms"]:
    assert arm["suspended"] is False
    assert arm["febr_files_encrypted_before_response"] == 40
```

Its own docstring says what to do when those numbers change: *"If someone later
fixes the throughput defect, this test changes in the same commit as the
measurement that justifies it."* Commit `f47d719` rewrote the artefact — new
schema, new corpus, FEBR 499 and 37 in place of 40, one arm suspended — and did
not touch the test. The test went red at that commit. The commit message
reported **`852 passed, 2 skipped`**.

The figure was not invented. It was measured before the artefact was rewritten
and not re-measured afterwards, and the suite cannot be run in one process here
— each service directory puts its own `main.py` on `sys.path`, so CI runs six
groups separately — which makes a stale total easy to carry forward.

What makes it a correction rather than an oversight is the direction. The claim
in the message was that every gate was green, and the single gate that was red
was the one guarding the claim the commit exists to make. It is also the first
of these a reader **can** find by running the suite: every earlier correction is
a green gate concealing a false claim, and this is a red gate concealed behind a
claim of green. That is worse in one specific way — it teaches the next reader
that the suite's printed total is a formality rather than a result.

**Replaced by:** the test asserts the current measurement, including the arm
that is now suspended, and asserts a FEBR *range* rather than a single value —
the response's floor is a periodic timer whose phase relative to the attack is
arbitrary, so a test pinned to one draw would go red on the next honest run. A
scratch runner that mirrors CI's six groups is checked in as
`scripts/run_all_tests.sh`, so the total in a commit message can be produced
rather than remembered.

That runner was itself wrong twice on its first run, which is the whole
argument for running a thing rather than trusting it. It summed the
per-group counts with `bc`, which is not installed in the Git Bash this
project is developed in, so every count parsed as zero: five groups of green
pytest output above a `TOTAL  0 passed, 0 failed` — and, because the failure
count parsed as zero too, an exit status of 0 that no red group could ever
change. A guard against a false green that was itself a false green. It also
looked for `services/recovery` and `services/ml_service`, neither of which
exists, and so never ran `services/ml-engine`, which CI does — 48 tests
outside the total. Both are fixed, the arithmetic is the shell's own, a
summary line that says `passed` but parses to nothing is now treated as red
rather than as empty, and the group list is the workflow's matrix. The number
in this branch's commit message — 869 passed, 0 failed, 2 skipped — is the
first one this project has published that was produced by the command a
reader can run.

## 10. The published reason an attack escaped was not the reason — F15

**Where:** `reports/agent_phase3_acceptance.json`, `attack_arms[0]`.
**Introduced:** 17 September 2026, `f47d719`. **Corrected:** 17 September 2026.

Arm A1 — `7z a -p -mhe=on -mx=0 -sdel` over the whole directory — was not
suspended, and the artefact explained why in two parts. Both were wrong.

> "(2) 7-Zip's `-sdel` unlinks the originals only *after* the archive completes,
> so all 520 deletions land in the process's final moments"

It does not. `scripts/measure_encryptor_lifetime.py` samples the file count
continuously and finds the first unlink about **130 ms** in, a third to a half of the way
through the run, with the corpus emptied progressively from there. The original
claim came from the acceptance harness, which sampled the file count **only
when the set of live PIDs changed** — and arm A1 is a single process, so after
the first sample there was never another until the run ended. One sample at the
start and one at the end look exactly like "nothing happened until the end".
This is the seventh time in this project that an apparent property of the system
turned out to be a property of the thing measuring it.

> "(1) Its output is a password-protected .7z at 8.0 bits/byte, and the detector
> adjudicates it `benign_compressed` … That is the Section 1.3 separability
> result"

True about the archive, and irrelevant to the outcome. The decoy field does not
consult the entropy verdict. In the re-run the tripwire fired 118 ms into the
attack, the agent attributed the deletions to `7z.exe` with `CERTAIN`
confidence, named it in the log, and the response was refused with `the response
guard refused pid 29172: PID 29172 does not exist`. A perfect verdict on the
archive's contents would have changed nothing, because there was no longer a
process to suspend.

The actual reason is one number. **7-Zip archives and unlinks five hundred
100 KB documents in 230-383 ms across three measurements on this host**, at
124-200 MB/s. The audit record that names it
takes 600–1010 ms to arrive. The process is gone three to four times over
before it can be named, and §4 of [LIMITATIONS.md](LIMITATIONS.md) — *a process
that finishes inside a second cannot be suspended* — covers it exactly.

Citing the separability result here was not a lie, but it was the wrong
explanation attached to the right outcome, and it pointed future work at the
detector when the binding constraint is the audit channel's delivery lag. A
reader deciding what to build next would have been sent to the wrong half of
the system.

**Replaced by:** `scripts/measure_encryptor_lifetime.py` and
`reports/encryptor_lifetime.json`, which measure process lifetime for both
attack shapes directly and outside any protected path, plus claim C-18 over
that artefact. The acceptance artefact now gives lifetime as the cause and
names the separability result only where it actually bites.

The same measurement invalidated half of the *benign* result. B1, B2 and B3
completed in 0.13 s, 0.43 s and 0.12 s — all shorter than the delivery lag — so
"completed untouched" was true of them whatever the detector decided, and could
not have been otherwise. They are now run over the full corpus with real
compression and full history, each arm records `outlived_the_delivery_lag`, and
an arm that did not is reported as inconclusive rather than counted as a clean
sheet.

---

## What these corrections do not touch

- **`services/response/tests/test_actions.py` spawns a child process and kills
  it.** That is a correct unit test: `terminate_process()` cannot be tested
  without a process to terminate, and the unit under test is the termination
  primitive itself. It is not the F1 pattern, where an *end-to-end*
  demonstration killed something the detector had never named. The published
  TC-07 timings (125.6 ms, 150 ms) come from this test and measure the kill
  primitive. They are not, and were never presented as, detection-to-
  termination of an attacking process.
- The detection primitives, the container registry, the hash chain, the
  gateway, the recovery manager and their suites are unaffected.
- No published figure is withdrawn by corrections 1–3. The demonstration's
  transcript backs no row in the claim matrix, and
  `reports/attack_chain_results.json` is cited by no claim. Correction 4
  changes a claim's direction — C-14 now says the restore *is* measured — which
  is a strengthening, not a retraction.

## What is still not proven

- **F10 remains open.** The Response service runs in a container with its own
  PID namespace, so a correct host PID cannot be killed through the Compose
  path. Every operational termination claim is blocked on it, and it is the
  reason TC-07 now skips rather than passes.
- Attribution is Windows-only, and needs an elevated host with the File System
  audit subcategory enabled and a Security log large enough not to wrap. A
  wrapped log presents as `UNKNOWN` rather than as an error.
- The chain is tamper-**evident**, not tamper-**resistant**, and it is unkeyed:
  it detects an edit and not a wholesale rewrite that recomputes the hashes.
  That is claim C-12's 0 of 8, and it is the correct permanent answer for an
  unkeyed chain rather than a gap waiting to be closed.

## Verifying each correction

```bash
grep -rn "6666" scripts/ services/
python scripts/claim_matrix.py
python scripts/ledger_coverage.py
```

The first returns nothing (correction 3). The second reports 16 claims, 0
failed verification and 0 failed provenance (corrections 4, 5, 6). The third
reports 48 events examined and 0 unsupported (correction 6).

From `services/monitor`:

```bash
python -m pytest tests/test_ledger_pid_integrity.py tests/test_claim_matrix.py
```

To watch correction 5 fail on purpose, stamp any evidence artefact's `commit`
field with a commit that is not an ancestor of `HEAD`. `claim_matrix.py` exits
1 and names the artefact and the reason.
