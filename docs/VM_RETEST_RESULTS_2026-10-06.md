# URDS - VM re-test results: `fix/vm-2026-10-05-findings`

**Date:** 2026-10-06 (VM wall clock, slewed; every interval below is a monotonic or
`perf_counter` measurement). **Tested tip:** `9798937` (the same code as the commit that
adds this file; this commit changes docs only). **Compared with:** `dc089ff`, VM test of
2026-10-05.
**How it was run:** the elevated half by the operator, as `C:\URDS-fix1005-run\addendum_elevated.ps1`
(native mode, six services from the `C:\URDS-fix1005` worktree, elevated, real Security-log
4663 audit source, real Volume Shadow Copy), then `r17_only.ps1`. The unelevated half by the
session that built the branch. The scripts and the evidence folders
(`evidence_20261006_175521`, `evidence_r17_20261006_202837`) are on the VM under
`C:\URDS-fix1005-run`, outside this repository; the numbers below are copied from them.

No bound claim was moved, the kill gate `Attribution.kill_authorised` and the safety
invariants were not touched, and C-16 holds (scan below).

---

## 1. Verdict by check

| Check | Result | Evidence |
|---|---|---|
| **R22** (was R16): a fresh writer behind a 20-write burst, x8 | **PASS** | B killed 8 of 8; write -> PID gone 1.641 / 1.693 / 1.689 / 1.692 / 1.711 / 1.712 / 1.739 / 1.836 s (all within 2.05 s); each B has an `incident_id`; ledger order correct. On `dc089ff` the same scenario waited behind A's escalations. |
| **R23** (was R14(b)): `attack_chain_demo.py`, four runs back to back with no wait | **PASS** | venv x2 and base interpreter x2, each 19/19. The writer PID the demo printed equals the PID the Monitor attributed `certain` and killed every time (1300, 12128, 2892, 7304). Gone 1.616-1.636 s after the write. |
| R23, unelevated | **PASS** | 16/19 checks, 3 skipped (TC-07 PID, terminated, kill time), exit 1, nobody killed: attribution `unknown` ("could not subscribe to the Security channel ... Access is denied"). Run from an unelevated shell against an unelevated stack. The script's own `runas /trustlevel` step did not start the demo, so this was done by hand. |
| **R24** (was F3): 13 families, kill, then `--restore` | **PASS** for restore | `--restore returns every decoy byte for byte`: 13 of 13 families 10/10, including grinder (9/10 on 2026-10-05). |
| R24, kill of each family | **unchanged, not a regression** | See section 2. |
| **R25** (was F6): incidents per suspicious file | **PASS, target not met** | See section 3. |
| **R26** (new): Response-side suspend / resume / leases | **PASS** | 25 of 25 (section 4). |
| **R27** (was G): dashboard deprecation warnings | **PASS** | See section 5. |
| R20 (monitor start/stop/start, then a fresh writer) | PASS | 5 of 5 cycles, handle delta total 1, every writer `certain` and killed in 1.585-1.600 s. |
| R21 (`/features` on a copied PE deleted in flight) | PASS | 5 of 5, 0 permission errors. |
| R13 (gateway latency with the dashboard open) | PASS | `/health` median 13.8 ms open, 13.2 ms closed; `/monitor/events` 10.9 / 10.6 ms. |
| R17 (audit setup on ten new folders) | **PASS** | See section 6. |
| e2e_check | 37 passed, 1 failed, 1 skipped | The one failure is the ledger-count check in section 7. 0 events named a wrong PID (70 named). |
| full_e2e | 104 passed, 12 failed | 11 are the kill check in section 2, 1 is the ledger-count check in section 7. 0 events named a wrong PID (251 named, 34 `certain`). |
| C-16 scan (`scripts/ledger_coverage.py`, saved ledger) | PASS | 1732 blocks examined, 112 name a process, 0 unsupported. |
| Ledger chain | PASS | valid, 1771 blocks after the demos, verify 9.5-11.1 ms. |

Machine state after: Security log size, File System audit subcategory, firewall, Defender and
the watch-folder audit rule as before; one Volume Shadow Copy left by the VSS check
(`{671436E9-76F9-4448-A683-CF37A5431404}`), as announced.

## 2. R24: which families are killed

| | 2026-10-05 (`dc089ff`) | 2026-10-06 (this branch) |
|---|---|---|
| "terminated, FEBR < 5" failing | copycat, headerspoof, locker, notedrop, partial, renamer, silent, spoofer, staged (FEBR 8), strider | the same ten, plus **poisoner** (FEBR 5) |
| "terminated, FEBR < 5" passing | grinder, poisoner, slowburn | grinder (4), slowburn (2) |
| `--restore` 10/10 | 12 of 13 (grinder 9/10) | **13 of 13** |

The families that are not terminated were attributed only `probable`, so the kill gate
refuses them. That is the gate working as specified and it was not changed; the horizon was
not changed either. Poisoner moved from a pass to FEBR 5, one file over the bound. One run
cannot say whether that is pace variation; it should be repeated before anything is read
into it.

## 3. R25 (was F6): incidents and blocks per suspicious file

From the saved ledger (a read-only counter script on the VM, `tools\r25_counts.py`). "Families" is the 130
files under the `full` folder (the 13 simulator families); "all" is all 339 suspicious files
of the run.

| | 2026-10-05 | families | all |
|---|---|---|---|
| file_event blocks per file | 1.91 | 1.154 | 1.077 |
| incidents per file, mean | n/a | 1.154 | 1.077 |
| incidents per file, median / max | 2 / 4 | 1 / 2 | 1 / 2 |
| ledger blocks per file | 6.06 | 5.446 | 4.735 |
| escalations refused or unreachable | 99 | 0 | 0 |

Escalation results this run: `not_escalated` 302, `terminated` 49, `terminated_earlier` 14.
307 of 365 escalation blocks list `coalesced_event_ids`.

**The F6 target of fewer than 3 blocks per file is not met** (4.7 to 5.4). The offline
replay of this branch had predicted 4.57.

## 4. R26: suspend / resume under leases (Response only)

`tools\r26_response_suspend.py` starts its own Response service on port 18604 with a stub
ledger, so no URDS service is touched. 25 of 25 passed: the stack's `/response/suspend`
answers 400 on an empty body (not 404) and `/response/leases` answers 200; a sleeper is
frozen with no heartbeat and flat CPU; a second suspend is a no-op with the same lease;
resume is once and idempotent; a 3 s lease expires and the process resumes by itself
(3.16 s); a wrong `started_at` is refused `PID_REUSED`; a process under `C:\Windows\System32`
is refused `SYSTEM_PROCESS`; the Response service and its ancestors are refused; terminate
with a `lease_id` kills and closes the lease; `NaN` / `Infinity` lease seconds are 400; an
unparsable `URDS_MONITOR_PID` refuses every suspend (`MONITOR_PID_INVALID`); the ledger
blocks carry `lease_id`, `incident_id`, `gate_verified: false` and
`attribution_supplied_by: "caller"`, and a caller-supplied gate is recorded as a claim and
never verified; stopping Response mid-lease four ways (TerminateProcess on the interpreter,
killing the venv launcher, `taskkill /T /F`, graceful) always resumed the process (0.016 to
0.203 s).

**What this does not show.** Nothing calls `/response/suspend`: the Monitor side (F2b, the
suspend-first response itself) was not built, so F2 and F2c are not measured. The C-16 scan
was not extended to the `process_suspended` / `process_resumed` blocks, whose `gate` is
caller-claimed.

## 5. R27: dashboard log

The elevated script reported "0 lines" but that was vacuous: its headless Edge never
rendered the page (DOM 0 bytes, dashboard log 92 bytes), so the R13 DOM markers are all
false in that run and should be ignored. It was checked again by hand: an unelevated stack
from the same worktree, the dashboard opened in the built-in browser, live data shown
("Threat Detected", pipeline stages, entropy trend). After about a minute open the dashboard
log has 5 lines, 0 `use_container_width` lines and 0 Arrow errors (about 69,510 lines in 35
minutes on 2026-10-05).

## 6. R17: audit setup on ten new folders

The first attempt (in the elevated script) was invalid and is not counted: a PowerShell
variable named `$r17` collided with `$R17` (names are case-insensitive), the ten-folder loop
ran on garbage paths, and it left an audit rule on a stray folder inside the worktree. The
rule was reverted with the project's own `-Revert`, the folder removed, and the script
fixed. The re-run (`r17_only.ps1`, ten new folders): setup exit 0 x10, `-Verify` exit 0 x10,
0 false failures, `-Revert` x10, no audit rule left on any folder, Security log size, audit
subcategory, Defender and shadow copies as before.

## 7. A decision for the owner: coalesced events and the ledger

The live check "every suspicious event reached the ledger" now fails: 38 of 70 in
e2e_check, 362 of 666 in full_e2e. The 666 suspicious events were traced against the saved
ledger: **362 have their own `file_event` block, 304 appear only as ids in
`coalesced_event_ids` of an escalation block, 0 appear in neither.** This follows from F6's
coalescing (defect 25). No event is lost, but a coalesced event no longer has a block of its
own. The harness check was not edited. Either the check should count `coalesced_event_ids`,
or coalesced events should keep a block of their own; that is a choice about what the ledger
promises, so it is not made here.

## 8. Not delivered, and not tested

- **F2b, Monitor side (suspend-first response):** not built by decision. F2 and F2c remain
  unmeasured.
- **Kills for many distinct PIDs are still sent one at a time** (`MONITOR_KILL_WORKERS`
  defaults to 1). R22's single-burst scenario passes without it; a flood of 20 different
  writers was not run. Enabling it needs the one serial-order test adjusted, which needs a
  decision.
- **F6's under-3-blocks-per-file target is not met** (section 3).
- R6b, D5 and A8 remain open.
- The branch had not been pushed before this commit.

## 9. After this run: what was changed in response, and what is proven

Written before the second VM run. What that run showed is in section 10, which corrects the
paragraph on the fastest families below.

- **Freeze-first, Monitor side (F2b), built** (defect 26): a new gate
  `suspend_authorised` (weaker than the kill gate only because a freeze can be undone),
  `services/monitor/suspend_policy.py`, and a lease that is released on `/monitor/stop`.
  The kill gate, the horizon and `COMPETITION_MS` are unchanged, and a terminate is sent
  only when `kill_authorised` is true. An independent review (no kill on weaker evidence,
  nothing left frozen past its lease) found two defects, both fixed with tests first: a
  kill could wait up to ~1 s for an in-flight freeze request, and a ledger field could carry
  a PID in a non-certain block (the ledger copy of the lease is now an allow-list and the
  C-16 scan checks it). Known limits are in the `FIXES.md` entry.
  **It cannot help the fastest simulator families.** In the 2026-10-06 ledger the 11
  unkilled families had already finished and exited before the 1.5 s horizon, and the first
  audit record arrives 0.4 to 1 s after the first write. Freeze-first only helps an
  attacker still running when that record arrives. The F2c measurement
  (`tools\r28_f2c.py`, `tools\r28_freeze_first.py` on the VM) will say how much.
- **Kill pool of 16 workers is now the default** (defect 22 follow-up). Kills for
  distinct PIDs no longer queue one behind another (20 different writers: the last kill
  0.30 s after the horizon, was 5.72 s). One existing test that assumed serial order was
  changed, with the owner's approval, to allow parallel kills. `MONITOR_KILL_WORKERS=1`
  restores the old behaviour. Not run live with 20 real writers.
- **Ledger:** coalesced events stay recorded by id (decision in section 7); the live
  checks now accept an id in `coalesced_event_ids` and fail if an event is in neither. The
  F6 target of under 3 blocks per file is restated as not met, not hit by logging less.
- **README:** killing a process needs Administrator rights and the Windows audit setup.
- **Tests on the merged branch** (run by the lead, one service at a time): gateway 108,
  ledger 99, response 206 + 2 skipped, dashboard 7, monitor 823 in the default
  environment. The monitor suite has two timing tests that fail intermittently on this VM
  (`test_detection_latency_under_100ms` and
  `test_detected_event_carries_every_feature_the_model_scores`): they failed in 3 of 5
  repeated runs of the merged tip and 1 of 5 of the commit before it, and pass when
  repeated. An interleaved comparison shows the same typical p95 (61-65 ms against a
  100 ms target) on both, with an occasional slow outlier on each. With freeze-first off
  (`MONITOR_SUSPEND_FIRST=0`) the suite gave 754 passed, 68 skipped (tests that need it
  on) and the same single latency flake.

## 10. Second VM run (evidence_20261006_225420) and the burst A/B (evidence_ab_20261006_233048)

**Freeze-first works live.** All 13 simulator families were frozen and then killed at about
1.6 s (first 2026-10-06 run: 4 of 13; 2026-10-05: 4 of 13). Files encrypted before the stop:
poisoner 0; locker, notedrop, partial, silent, slowburn 1; grinder, staged 2; renamer 3 (it
was 10 for nine of these). Not under 5: copycat 8, strider 8, spoofer 8, headerspoof 9. So the
earlier prediction in section 9 (the 11 unkilled families had already exited, nothing to
freeze) was wrong: they were still running when the first audit record of their burst
arrived. How early the stop lands depends on when the first audit batch arrives, which is
timing luck (records for a burst arrive 42 ms to 1.5 s late, median about 650 ms), so the 9-of-13
figure is one run's draw, not a guarantee.
Also live: R26 25/25; R20 5/5 cycles; R21; R13 and R27 clean; four demo runs 19/19; R28 S1
(sole slow attacker frozen at 1.0 s, killed at 1.6 s, 6 files written instead of about 8); S3
(Monitor stop mid-freeze: not frozen 0.06 s later); S4 (slow benign writer never frozen);
three live resumes (a benign writer, then an encryptor 0.5 s later: frozen, resumed, nobody
killed); 0 wrong PIDs; C-16 scan 281 blocks name a process, 0 unsupported.

**R28 S2 was a wrong expectation, not a defect.** It expected a second writer that starts
after the first writer's event to make the first one resumed. The competition window looks
back from the event, so the first writer is still alone in it and is killed at the horizon;
the second writer was frozen and killed only after the first one's writes had aged out of its
own 3 s window (it was then the sole writer). The kill rule did what it is documented to do.
The script's S2 checks were corrected.

**Other failures in that run, with causes.**
- Poisoner "not detected": it was killed before it encrypted any file, so the harness had
  nothing encrypted to count. The harness now accepts a terminated process with flagged
  writes and no encrypted file.
- Spoofer `--restore` 1/10: the kill landed in the middle of the simulator writing its
  manifest, leaving a 0-byte `.simulator_manifest.json`. The simulator writes it in place.
  Not changed (simulator); an atomic write would remove it.
- "One suspicious event not in the ledger" (387/388): present in the ledger saved afterwards
  (388/388); the live check ran while the ledger was still catching up.
- Ledger verify latency median 104 ms against 50 ms, defect 3 (+1.31 s against 1 s), and R22
  below: all during stretches when the VM's disk was slow (see next).

**R22 (burst of 20 writes, then a fresh writer) is disk-latency bound, and fails the same
way with both of this round's changes off.** The VM's file-flush latency varied between
3.4 and 23 ms per file within minutes (probes in `evidence_ab_...`). Five runs of the same
scenario, four repetitions each, write to PID gone for the fresh writer:

| configuration | burst time (s) | write to gone (s) | within 2.05 s |
|---|---|---|---|
| default (freeze-first on, 16 workers) | 0.14-0.32 | 1.96, 2.21, 2.33, 2.47 | 1 of 4 |
| freeze-first off | 0.08-0.11 | 1.71-1.78 | 4 of 4 |
| 1 worker | 0.25-0.27 | 2.24-2.43 | 0 of 4 |
| both off (the code before this round) | 0.24-0.28 | not killed (unknown), 2.16, 2.20, 2.21 | 0 of 4 |
| default again | 0.15-0.32 | 1.63, 2.20, 2.29, 2.53 | 1 of 4 |

The freeze-first-off run happened to land in a fast stretch (burst 0.09 s), so it is not a
clean comparison. What can be said: when the disk was slow, the configuration with both
changes off failed as much as the others, including one fresh writer never attributed. The
2026-10-06 first run passed 8 of 8 when the burst took 0.07 s. In slow stretches the
Monitor's ledger writes (about 80 blocks for a 20-file burst, each flushed) fall 4 to 8 s
behind; the kill itself is dispatched on time after the horizon, but the fresh writer's
event is processed late, so the horizon starts late. A consequence also seen in every
configuration: the Response service's `terminate` block can reach the ledger before the
Monitor's `file_event` block for the same incident (the order check fails). The kill is
prompt, the audit trail is late and out of order. Not fixed: it needs faster or batched
ledger writes. The honest statement of R22 is: passes at about 4 ms per file flush, misses
the 2.05 s target by 0.1-0.5 s at 10-16 ms.

*(Correction, section 13: the paragraph above that calls R22 disk-latency bound and says the fresh writer's event is processed late so the horizon starts late was an inference. A later run shows the kill does not depend on the ledger at all; see section 13.)*

## 11. After the A/B: what was built for the slow-disk burst, and what is not yet proven

Written before any VM run of this. Two changes (FIXES.md 28) and one tool fix (FIXES.md 29).

- **Ledger group commit** (`LEDGER_MAX_BATCH`, default 64): appends that overlap share a commit.
  Each caller still returns only when its block is durable; the chain, ids and order are
  unchanged. On the VM disk in a slow stretch, 80 appends: one writer unchanged; three writers
  3.4 -> 2.0 s; eight 2.8 -> 0.75 s.
- **Monitor tail** (`MONITOR_DEFER_TAIL_BLOCKS`, default on): the Monitor's last block per
  incident goes to a second thread so the pipeline worker moves on to the next event. Order
  inside one incident is unchanged (file_event, the response block, then the escalation);
  different incidents interleave. On a local stack with a fast disk and a 20-file burst the
  ledger caught up 2.0 s after the last write against 2.3 s without (20 repetitions each,
  interleaved) - about 12 percent. That is all that is measured. The local stack has no audit
  channel, so no escalation blocks were involved.
- **Simulator `--restore`** now survives a manifest the kill tore (the spoofer failure).

What this does not show: that R22 now passes on a slow disk. The gain is a fraction of the
serial path (about three commits per event become about two, overlapped, and concurrent writers
share commits), so it may close the 0.1-0.5 s misses or may not. The elevated check is
`r22_ab2.ps1`: default, tail off, both off, default again, with a disk probe before and after
each. Until it has run, R22 stays "passes only on a fast disk".

## 12. The elevated A/B of the slow-disk changes (evidence_ab2_20261007_061816) and a loaded-disk test

**Elevated, fast disk (about 3 ms per flush).** Four configurations, four reps each: default
(tail and group commit on), tail off, both off (the write path as it was), default again.
- B was killed within 2.05 s in 15 of 16 reps (1.64-1.84 s); the sixteenth, in `default_again`
  rep 1, was never attributed ("no record") and not killed. The earlier A/B had one such rep too,
  with both changes off, so it is not new: the audit record for the fresh writer did not arrive
  inside the delivery horizon. Not investigated further (it needs the Security log, which needs
  elevation).
- Ledger order held in 15 of 16 reps. The exception is `default` rep 2, during the one stretch
  where the disk was slower (flush 6-8 ms before that config; every other config about 3 ms):
  B's `file_event` landed 2.9 s after Response's `terminate` block. In every normal rep B's
  `file_event` lands 0.4-1.4 s before the terminate block, in all four configurations. There is no
  tail-off or both-off run from that slow stretch to compare it with, so this neither shows the
  change failing nor working.
- This run could not tell the configurations apart, because the disk was fast throughout.

**Local, with the disk loaded on purpose** (a background writer on the same volume: two streams of
4 MB fsync'd files, flush about 11 ms - the 10-16 ms range where R22 failed). Whole stack on this
machine, no audit channel, 20-file burst, time from the last write until the ledger stops growing;
median of four reps, two interleaved rounds:

| configuration | round 1 | round 2 |
|---|---|---|
| default (tail and group commit) | 9.5 s | 9.2 s |
| tail off (group commit only) | 12.2 s | 12.2 s |
| both off (as before) | 11.2 s | 11.7 s |

So under a slow disk the default is about 20-25 percent faster than the previous write path. The
gain needs both parts: group commit alone changes nothing for one serial writer. It is a
reduction, not a cure: 120 blocks still take about 9 s at an 11 ms flush. Changing the journal mode
(TRUNCATE, PERSIST) was measured under the same load and did nothing.

**What is still true.** On a disk that is slow enough, a fresh writer's event is processed late
and its detection block can follow its terminate block. The kill itself is dispatched on time after
the horizon. Whether the 20-25 percent is enough to bring the 2.2-2.5 s kills under 2.05 s is not
shown: no elevated run has yet been made on a slow disk with these changes. To make one: start
`disk_noise.py` (two streams of 4 MB fsync'd writes) on the same volume, then run `r22_ab2.ps1`.

## 13. The elevated A/B with the disk loaded on purpose (evidence_ab2_20261007_071226): what it corrects

`r22_ab2_loaded.ps1` runs `r22_ab2.ps1` while a background writer keeps the disk at a 10-40 ms
flush (probe medians 10-43 ms in the audited folder). Four configurations, four reps each;
freeze-first and the kill pool on in all.

**The kill does not depend on the ledger.** 16 of 16 fresh writers were killed within 2.05 s, 1.556
to 1.676 s, in every configuration - including both-off, the old write path. In the same runs the
ledger fell up to 20 s behind. So the 2026-10-06 slow-stretch misses (kills at 2.2-2.5 s, section 10)
were not caused by the disk or the ledger write path, and section 10's explanation (disk-latency
bound; the fresh writer's event processed late) is withdrawn as unsupported. What did cause them
is not known. Seen in that window and not now: B's detection latency 50-190 ms (5-22 ms in later
runs), so the machine was generally slower then; but that does not account for 0.7-1 s. It did not
reproduce in the two later runs: 15 of 16 on a fast disk (the sixteenth was an unattributed writer, below)
and 16 of 16 loaded (this section), the old write path included. The 4663 delivery lag for B was 70-1500 ms in the loaded run, all within the
1,500 ms horizon, so the horizon logic held.

**What the loaded run does show: the ledger backlog.** B's `file_event` block landed after Response's
`terminate` block in every rep of every configuration (the order check fails 16 of 16), because B's
detection waits behind the burst's. By how much, per rep (seconds after the terminate block):

| configuration | rep 1 | rep 2 | rep 3 | rep 4 |
|---|---|---|---|---|
| default (tail and group commit) | 2.9 | 2.8 | 4.0 | 2.7 |
| default again | 4.4 | 4.4 | 6.0 | 7.1 |
| tail off | 6.2 | 9.3 | 12.6 | 14.2 |
| both off (old write path) | 5.6 | 10.6 | 16.9 | 20.6 |

The old path loses ground with each burst (the ledger cannot keep up with a burst every 30 s on this
disk); the default stays at 3-7 s. That is the benefit of the two changes: a bounded ledger backlog
on a loaded disk, not a faster kill. It is not enough for the order check, which needs B's detection
block before the terminate block, so the audit trail is still late and out of order under load.

**Unattributed writer.** None in this run (16 of 16 attributed). Seen once in each of the two earlier
A/B runs (`both_off` rep 1 in the first, before these changes; `default_again` rep 1 in the fast run).
Cause unknown.

R22, as it stands: kill within 2.05 s in 31 of 32 reps across the fast and loaded runs of the new
code (the 32nd was the unattributed writer), and 8 of 8 in the first run; 11 of 20 in the one slow
window of section 10, unexplained. The
ledger-order check does not pass on a loaded disk.
