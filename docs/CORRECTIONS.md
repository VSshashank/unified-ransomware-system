# Corrections

**Dated 17 September 2026, extended 20 September 2026.** Nineteen defects in this
repository's evidence: what each one was, what it produced, and what replaced
it.

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

Corrections 11 to 14 come from Phase 5, and none was found by reading. All
four were found by running third-party encryptors at the agent and then asking
the hash chain what it knew. The first is a *correct* answer about the wrong
process — the first defect here that no rule forbids and no gate could have
caught. The second is the chain staying silent through an attack the agent
detected, attributed and responded to, which would have made Phase 5's own
headline metric uncomputable had it not been found.

The last two are not in the system at all. They are in the harness built to
measure it: one reported a response that never happened, the other reported no
response where the chain held one. Both published a number, and neither was
visible to any gate — the run they came from exited non-zero for other
reasons, and a harness defect does not announce itself as a harness defect.
Corrections 15 to 17 are three more from the harness, and 16 is the one worth
reading if you only read one: the measuring script's own chain verification was
holding a lock the agent's appends queued behind, so the harness starved the
thing it was measuring and then published the starvation as a detection
failure.

Fourteen of the defects in this repository have now been found in the thing
doing the measuring rather than in the thing measured, and the working rule that came
out of it is the one to take away from this document: **check the harness
before believing the verdict, especially a verdict you like.**

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

## 11. A confident answer about the wrong process — F16

**Where:** `services/monitor/attribution.py`, `WriteLog.lookup`.
**Introduced:** with the window. **Found:** 17 September 2026, while building
`install.ps1`'s self-test. **Fixed:** 18 September 2026, in Phase 5.

Every entry in the write log is stamped when its audit record was *delivered*,
and delivery trails the write by 600–1010 ms on this host. `lookup` compared
those entries against a window and against each other, and never against the
event it was being asked about. So when process A wrote a file and process B
overwrote it with ciphertext a second later, the only audited writer on that
path during the gap before B's record arrived was A — one distinct PID, from a
kernel-grade source, therefore `CERTAIN`, on A.

Block 16095 of this host's agent ledger is a measured instance:

```
file_event | verdict suspected_encryption | pid 27792 | conf certain
  reason: exactly one process wrote this path in the last 3000ms,
          from windows-security-4663
```

27792 was the self-test process; the encryptor it had just launched was the
actual writer. The agent suspended 27792.

This is the family correction 3 belongs to, arrived at from the opposite
direction. F3 put an invented PID in the chain. This put a *real* PID in the
chain, correctly derived from real evidence, belonging to a process that had
not done the thing — and then acted on it. Nothing was guessed and no rule was
broken, which is what makes it worth writing down: the answer was correct about
the evidence and wrong about the world, and no gate in the project could have
distinguished the two.

It was left unfixed for a day on purpose. The fix changes how many events park,
which changes TTS, which is a measured claim, so it belonged in the phase that
re-measures TTS rather than in a quiet edit to the attribution path.

**Replaced by:** `lookup` now takes `event_at` — when the filesystem event
being judged was observed — and refuses to answer at all when the newest
matching record predates it, returning `unknown` with that as the reason. The
event parks and `agent/pending.py` re-asks, carrying the *original* queued
moment on every re-ask so the record it is waiting for is not itself rejected
when it lands. Where nothing predates the event, which is every ordinary
detection, the answer is unchanged. Pinned by four tests in
`services/monitor/tests/test_tc26_attribution.py`, one of which asserts the old
behaviour on the same evidence so the fix cannot be mistaken for a no-op.

## 12. The chain did not record what the agent decided — F17

**Where:** `agent/agent.py`, `_act`, and `services/monitor/app.py`'s fan-out.
**Introduced:** with the agent. **Found and fixed:** 18 September 2026, by
Phase 5's attack corpus.

`app.handle_event` fans out to the ledger only for events it found suspicious,
and returns before the fan-out entirely for a deletion. That is right for the
Monitor — a file being removed is not an entropy verdict. It was wrong for the
agent, which *responds* to those events.

Measured, on this host, with 7-Zip pointed at the protected root:

```
7z a -p… -mhe=on -sdel  →  55 files archived, all 20 decoys deleted
agent.log  canary deleted: !_urds_canary_00.docx by pid 5844 (7z.exe)
           attribution arrived 2772 ms after the write
           benign -> refused (the response guard refused pid 5844:
                              PID 5844 does not exist)
ledger     file_event blocks naming any decoy: 0
           response_escalation blocks: 0
```

The agent saw all twenty deletions, named 7-Zip correctly, and recorded its
decision — in a plain text log file that anything running as the user can
rewrite. The hash chain, which is the part of this system whose whole claim is
that it cannot be quietly rewritten, showed that nothing had happened.

Phase 5's own headline metric is attribution accuracy, published from the
chain. It could not have been computed at all: the first run of the attack
corpus reported this arm as `detected=False`, because from the chain's point of
view it was.

**Replaced by:** `Agent._chain_unsuspicious_decision`, which writes a
`file_event` block for any event the agent responded to that the pipeline will
not carry, carrying the path, the process finally named, the confidence, the
decoy detail and the action taken. Deduplicated on (path, PID, action):
deletions arrive from the watchdog dozens of times — that run logged
forty-two lines for a single decoy — and a chain that grows by forty-two blocks
per touched file can be flooded into uselessness by an attacker rewriting one
decoy in a loop. A second, *different* decision about the same path still gets
its own block. Pinned by four tests in `agent/tests/test_agent.py`.

---

## 13. A suspension that never happened, reported as a headline metric — F18

**Where:** `scripts/adversary_corpus.py`, `SuspendWatch`. **Introduced:** with
the Phase 5 harness. **Found and fixed:** 18 September 2026, by reading a
result that was too good.

`SuspendWatch` polls the PIDs the runner recorded and reports the first one it
finds in `STATUS_STOPPED`. The `openssl-loop` arm starts two hundred processes
that live about 65 ms each, and Windows reuses their PIDs immediately. The
watcher found one of those numbers stopped and timed the response from it:

```
reports/phase5_attack_corpus.json, run of 18 September 2026 11:57
  openssl-loop  tts_s                 12.307
                observed_stopped_pid  6372
                suspended_pids        []        <- the agent's own chain
```

A time-to-suspend of 12.3 seconds, from a process the agent had never touched.
The ledger held no escalation at all for that arm; pid 6372 belonged to
unrelated software that happened to be suspended when the watcher looked. The
harness was reporting, as its headline metric, a response that did not occur.

This is the eleventh defect in this project found in the thing doing the
measuring rather than in the thing measured, and the second caused by a PID
that was not what it looked like.

**Replaced by:** the watcher now checks a candidate's `create_time()` against
the moment the runner recorded launching it, rejects anything more than five
seconds apart, and publishes the rejections rather than dropping them. On the
re-run the arm reported `tts_s: null` and `suspended_pids: []`, which agree;
`openssl-inplace` rejected pid 5160, recorded as launched at 1789716640.06 and
actually created at 1789716650.11 — ten seconds later, and a second phantom
had the guard not been there. Pinned by
`test_an_observed_suspension_must_be_the_process_that_was_launched`.

---

## 14. A suspension the chain recorded, reported as no suspension — F19

**Where:** `scripts/adversary_corpus.py`, the FEBR and TTS block.
**Introduced:** with the Phase 5 harness. **Found:** 20 September 2026, in the
re-run that fixed correction 13.

Correction 13's fix made the watcher strict, and strictness has a cost that was
not accounted for. The watcher reports only a freeze it saw itself — which is
right, because a check that reads the ledger cannot corroborate the ledger —
and where it saw none, the harness treated the arm as one where the response
never fired:

```
reports/phase5_attack_corpus.json, re-run of 18 September 2026 13:14
  gpg-loop  suspended_pids               [16476]   <- in the launcher's key
            observed_stopped_pid         null
            tts_s                        null
            febr_files_before_suspend    200       <- the whole corpus
```

The agent suspended the 104th of two hundred gpg processes and the chain
recorded it. The harness reported FEBR as all two hundred files, because its
fallback for "no suspension moment" is "every file was lost" — a fallback that
is right when nothing fired and wrong here, where something did. Both published
numbers were worse than the truth, which is the direction that does not get
caught by reading.

**Replaced by:** where the watcher saw nothing and the chain holds a
`response_escalation` naming a PID **the launcher's answer key already
contains**, the *moment* is taken from the block and FEBR is recounted against
it. The identity is never taken from the chain: the agent cannot nominate a PID
into its own answer key. The source is published as `suspend_moment_source`,
and because a block is stamped when it is written rather than when the suspend
call returned, a moment taken this way is late — so the TTS it yields is an
upper bound and the FEBR is at least as large as the true one. Pinned by
`test_a_suspension_the_chain_holds_is_not_reported_as_no_suspension` and
`test_the_bound_is_read_against_whichever_moment_exists`.

---

## 15. The cleanup reported removing what it had left behind — F20

**Where:** `scripts/benign_soak.py`, the working-directory teardown.
**Introduced:** with the benign soak. **Found and fixed:** 20 September 2026,
by listing the protected path after a run that said it was clean.

```
benign_soak.py, end of the 60-minute run
  removed D:\Unified_Ransomware_Project\watched_files\benign_soak_af3f3e5b

ls watched_files
  benign_soak_af3f3e5b\clone_cd78e6        139 MB, still there
```

`shutil.rmtree(workdir, ignore_errors=True)` ignores the errors, and the line
after it announces a removal that did not happen. Git marks every object under
`.git/objects` read-only, and Windows refuses to unlink a read-only file, so
the one workload that clones a repository is the one whose output survives its
own cleanup.

The consequence was not tidiness. The next thing scheduled in that directory
was the attack corpus, whose `sevenzip-root` arm archives **the whole protected
root** and counts what it finds as damage. It would have pulled 139 MB of
somebody else's repository into an encrypted archive, counted several thousand
of its files as encrypted, and reported all of it as the arm's result. The
leftover was found and removed by hand four minutes before that arm's run
began.

**Replaced by:** `_force_rmtree`, which clears the read-only bit and retries,
returns whether the tree actually went, and makes the caller print
`COULD NOT REMOVE ... it is still inside the protected path and the next run
will see it` when it did not. An ignored error and a confident message are
worse together than either alone.

---

## 16. The harness read the chain before the agent had finished writing it — F21

**Where:** `scripts/adversary_corpus.py`. **Introduced:** with the Phase 5
harness. **Found and fixed:** 20 September 2026, by not believing a result.

A six-arm run published five arms as `detected=False` with zero events on the
corpus. The agent had detected all of them:

```
reports/phase5_attack_corpus.json, run of 20 September 2026 15:40
  openssl-loop      file_event blocks on corpus   0     detected=False
  openssl-inplace   file_event blocks on corpus   0     detected=False
  gpg-loop          file_event blocks on corpus   0     detected=False

the ledger, queried afterwards over the same window
  openssl-loop      file_event  398   all suspected_encryption
  openssl-inplace   file_event  351
  gpg-loop          file_event  459
```

Those 1,208 blocks were written **after** the harness had read the chain for
each arm and moved on to the next. Nothing was missing; the question was asked
too early, and the silence was then published as a property of the system.

Two things caused the agent to be that far behind, and only one of them is the
agent's.

**The harness was starving it.** Each arm called `selftest.verify_chain`, which
`fetchall`s every block in the ledger and recomputes every hash. The ledger had
reached 285,632 blocks in a 180 MB file - it is deliberately not in WAL mode,
so a full-table SHARED lock is a wall the agent's own appends queue behind, six
times per run.

**And an hour of benign work leaves a real backlog.** The soak immediately
before this run added 184,841 blocks. §12 of `docs/LIMITATIONS.md` already said
a saturated agent drops writes and says so; this is the quieter version, where
it drops nothing and is simply minutes late.

**Replaced by** three things. Each arm now verifies only its own window of the
chain, anchored on the last block before it started, so a rewrite inside the
window is still caught and the whole-chain walk happens once per run instead of
once per arm. After each arm the harness writes a sentinel file into the
protected path and waits for its block: the agent processes its queue in order,
so the sentinel's arrival means everything before it has been dealt with. And
an arm whose sentinel never arrives is **out of bounds**, never quietly
reported - a chain read before its writer finished is not evidence about the
writer. Pinned by
`test_the_chain_is_not_read_before_the_agent_has_finished_writing`.

---

## 17. Another workload's backlog, graded against this one's answer key — F22

**Where:** `scripts/adversary_corpus.py`, the corpus filter for root-scope
arms. **Introduced:** with the Phase 5 harness. **Found and fixed:**
20 September 2026, in the same run as correction 16.

The same run reported **five mis-attributions** — the one number the build plan
requires to be zero. All five:

```
block 282443  makecab.exe  ...\benign_soak_af3f3e5b\bundle_444c85.cab
block 282445  git.exe      ...\benign_soak_af3f3e5b\clone_cd78e6\.git\objects\pack\tmp_pack_qs86P0
              reason: exactly one process wrote this path in the last 3000ms,
                      from windows-security-4663
```

`makecab.exe` did write that cabinet and `git.exe` did write that pack file.
The agent was right about both. They were the **benign soak's** files, written
an hour earlier and still in the queue, and they were graded against an answer
key belonging to a completely different run.

The arm is `sevenzip-root`, whose scope is the protected root itself, so the
corpus filter - a prefix match on the target - matched everything in the root
including another workload's leftovers. A harness that manufactures a
mis-attribution is worse than one that misses a real one: the number it
corrupts is the one the whole branch exists to defend.

**Replaced by:** a root-scope arm is graded against the file set it actually
had - the snapshot taken before it started, plus the corpus directory and the
archive it is allowed to create - rather than against everything that happens
to live under the root. Pinned by
`test_a_root_scoped_arm_is_graded_on_the_files_it_actually_had`.

---

## 18. `install.ps1` installed nothing and exited zero on a clean machine — F23

**Where:** `install.ps1`, the Python bootstrap. **Introduced:** with the
installer. **Found:** 20 September 2026, by running it on a clean Windows 11
guest — which is what Phase 4's acceptance is for, and which had never been
done until now.

```
winget install -e --id Python.Python.3.12 --silent --accept-*-agreements

Failed when searching source: msstore
An unexpected error occurred while executing the command:
0x8a15005e : The server certificate did not match any of the expected values.

The following packages were found among the working sources.
Please specify one of them using the --source option to proceed.
```

On a clean Windows 11 Enterprise Evaluation image the `msstore` source fails
to validate its server certificate. winget then finds the package in more than
one source, refuses to choose, prints an instruction to a nobody that is
reading it — the output goes to `Out-Null` — and **exits zero having installed
nothing.**

The installer then re-probes for Python, does not find it, and falls through to
its manual-install message. So it fails honestly in the end, which is why this
is a defect about *the machine the installer has never run on* rather than a
silent pass. But the step the acceptance exists to prove — "takes a clean VM to
a green self-test in one run" — cannot complete, and no amount of running the
installer on a developer machine that already has Python would ever show it.

This is the fourth time in this project that a step was believed to work
because it had only ever been exercised somewhere it could not fail.

**Replaced by:** `--source winget` on the install, with the reason written
where the next person will read it, and the same flag added to the manual-install
hint the failure path prints.

---

## 19. The installer's failure message named a remedy that did nothing — F24

**Where:** `install.ps1`, the RAM preflight. **Introduced:** with the
installer. **Found:** 20 September 2026, on the same clean Windows 11 guest as
correction 18, by following the instruction it printed.

```
[ FAIL ] 8 GB RAM or more  -  6 GB
         This machine reports 6 GB. The agent itself is small; the ml-engine
         and the model are not. Close other work, or use -NoDashboard, which
         leaves only the agent running.
Preflight failed. Nothing has been changed.
```

So the run was repeated with `-NoDashboard`, exactly as instructed:

```
[ FAIL ] 8 GB RAM or more  -  6 GB
         ... or use -NoDashboard, which leaves only the agent running.
Preflight failed. Nothing has been changed.
```

The bar was a constant. `-NoDashboard` changes what gets installed — it is
honoured in two other places in the same script — and the preflight never
looked at it, so an operator who does what the error says gets the error again,
word for word, and has no next move.

Nothing was claimed falsely and nothing was installed: the refusal is correct
behaviour and `Nothing has been changed` is true. What is wrong is that the
script's own advice is dead. That is a worse failure mode than a blunt refusal,
because it costs the reader a second run to discover the first one was
pointless.

**Replaced by:** the floor depends on what is being installed — 4 GB with
`-NoDashboard`, 8 GB without — and the check's label says which bar it is
applying, so the transcript shows the reader which run they are looking at. The
message now ends with what the flag actually does to the bar.

This is the second defect in two runs found only by installing on a machine
that did not already satisfy the installer.

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

The first returns nothing (correction 3). The second reports 20 claims and,
once Phase 5's two artefacts are committed, 0 failed verification and 0 failed
provenance (corrections 4, 5, 6). The third reports 48 events examined and 0
unsupported (correction 6).

Corrections 13 and 14 are in the harness, so they are verified by the tests
that pin it rather than by an artefact:

```bash
python -m pytest agent/tests/test_phase5.py -q
```

`test_an_observed_suspension_must_be_the_process_that_was_launched` fails if
the creation-time check is removed;
`test_a_suspension_the_chain_holds_is_not_reported_as_no_suspension` fails if
the moment is allowed to carry an identity the launcher never recorded.

From `services/monitor`:

```bash
python -m pytest tests/test_ledger_pid_integrity.py tests/test_claim_matrix.py
```

To watch correction 5 fail on purpose, stamp any evidence artefact's `commit`
field with a commit that is not an ancestor of `HEAD`. `claim_matrix.py` exits
1 and names the artefact and the reason.
