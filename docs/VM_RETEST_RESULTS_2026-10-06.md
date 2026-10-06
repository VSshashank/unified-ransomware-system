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

Nothing below has been run on the VM. It is built, reviewed and unit-tested only.

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
