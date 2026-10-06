# URDS - Windows VM re-test addendum: `fix/vm-2026-10-05-findings`

> **How to use this file.** Paste it **after**
> `docs/VM_TEST_PROMPT_fix-vm-2026-10-04-findings.md` (same rules, same setup,
> same report format, §9 of that prompt), in the same fresh Claude Code session
> on the Windows VM, started from an **Administrator** terminal if you can. Where
> this addendum and that prompt disagree, **this addendum wins**.
> The rows marked "overrides" below replace rows of that prompt's §7.
>
> This is still a **test** prompt: no product code is edited.

**Target:** the tip of branch `fix/vm-2026-10-05-findings`. Take the SHA from
`git rev-parse HEAD` in the checkout under test and write it, with the date, in the
report's title and "Environment" section, in place of `dc089ff`. It is **not
pushed**: the operator makes the checkout available (for example
`C:\URDS-fix1005`, a worktree of the `C:\URDS-main` repository).
**Previous VM test of this lineage:** `dc089ff`, 2026-10-05
(`reports/VM_TEST_REPORT_2026-10-05_dc089ff.md`, verdict **FAIL** on R16 and
R14(b)). Report every comparison against its numbers.

---

## A. What this branch changes, and what it does not

| Item | State on this branch |
|---|---|
| R16 - a kill waited behind another writer's escalations | Fixed in code (defect 22 and its review follow-ups: a killed or reused PID costs no round trip, ledger writing is off the kill path). **Not proven live.** One limit stays: kills for many *distinct* PIDs are still sent one at a time (`MONITOR_KILL_WORKERS` defaults to 1; 16 workers meets the bound in the unit test but breaks one test that assumes serial order, so it is off). R22's single-burst scenario does not depend on it; a 20-different-PID flood does, so report that case if you run it. |
| R14(b) - the demo's PID and event matching | Fixed in code (defect 23). **Not proven live.** |
| F3 - `--restore` after a mid-rewrite kill | Fixed in code (defect 24). |
| F6 - one incident per write, not per notification | Fixed where a question is open, i.e. elevated (defect 25). |
| Dashboard `use_container_width` log noise | Fixed (defect 27). |
| **F2b - suspend-first response** | **Half delivered.** The Response service can suspend, resume and lease (defect 26). **The Monitor side was not built**: nothing calls the new routes, so **no writer is ever suspended automatically**. |
| F2, F2c | F2 is unchanged and `KNOWN-OPEN`. F2c cannot be measured: there is no suspend to time. |

State **Docker cannot suspend a host PID**: in Compose, Response has its own PID
namespace and refuses every suspend there (`409 PID_NAMESPACE_ISOLATED`). The
stack must run natively for any suspend test.

`FIXES.md` entries 22-27 are the specification for what follows.

### Overrides of the base prompt

- Its §7 **F2b row** says a suspend route that exists "means this is not the
  described branch: stop". **Ignore that.** On this branch `/response/suspend`
  exists on purpose; row R26 below replaces it.
- Its §4 "seven new test files" list is extended by the new files in §B.
- Its §7 **R14 (b)**, **R16** and the F3 / F6 status rows are replaced by R22-R25.
- Everything else in its §7 (R13, R15, R17-R21) is re-run unchanged: row R9-R21.

---

## B. Phase 1 additions - suites and the new test files

Expected counts on this branch (measured on the author's VM, unelevated; run them
**elevated** and report the difference, as the base prompt asks):

| Suite | Expected |
|---|---|
| gateway | 108 passed |
| ledger | 99 passed |
| monitor | 660 passed |
| response | 206 passed, 2 skipped (the 2 skips are permanent on Windows: `SIGTERM cannot be ignored`; measured the same elevated and unelevated) |
| dashboard | 7 passed |
| ml-engine | as in the base prompt (nothing here touches it) |
| `claim_matrix.py --tests` | 0 failed; C-16: 48 events examined, 0 unsupported |

New test files that **must run, not skip**, and must pass three times in a row:
`services/monitor/tests/test_escalation_behind_other_writers.py`,
`test_pid_reuse_before_kill.py`, `test_escalation_kill_latency_under_load.py`,
`test_demo_process_bookkeeping.py`, `test_simulator_interrupt_restore.py`,
`test_one_incident_per_file.py`; `services/response/tests/test_ledger_client_reused.py`
and `services/response/tests/suspend/`; `services/gateway/tests/test_response_suspend_proxy.py`;
`services/dashboard/tests/test_no_deprecation_warnings.py`.
`test_demo_process_bookkeeping.py` includes a test through the real venv launcher:
it must not skip on the VM.

Offline: `scripts/defect25_replay.py <monitor_dir> <out.json>` replays run 2's
event shape; report its table beside FIXES.md defect 25's.

---

## C. Phase 2/3 additions - the new checks

| ID | Check | Method | Pass |
|---|---|---|---|
| **R22** (overrides R16) | A kill must not wait behind another writer's escalations | Elevated, native stack, as base R16: 20 rapid high-entropy writes by process A, then **immediately** one write by a fresh process B that stays alive 10 s. B write -> B's PID gone, monotonic clock. **8 runs.** Then `e2e_check.py` D1 straight after the D3 burst. Count `termination_refused_or_unreachable` and `terminated_earlier` results in the run's ledger | **all 8 <= 2.05 s** (was 1 of 8, 2.0-8.7 s); D1 first kill about 1.6 s, not 4.03 s; `termination_refused_or_unreachable` on `certain` answers falls sharply from 99; `terminated_earlier` appears instead (also count `pid_reused_before_kill` and `termination_unconfirmed_earlier`: both should be rare or zero in this scenario). Report every one of the 8 times. Also report one successful `/response/terminate` round trip (the one cost still serial) |
| **R23** (overrides R14 b) | The demo names the writer's real PID and matches only its own events | Elevated with the audit SACL on the watch folder. `python scripts\attack_chain_demo.py --watch-host <dir> --watch-container <dir>` from `.venv\Scripts\python.exe` and from the **base** interpreter, **two runs each, back to back with no wait**; then once unelevated | TC-07 passes naming the writer's own PID; the transcript shows one PID for the writer (the "writer pid" line and the "writer" line agree); a stale `annual_report.docx.locked` event from an earlier run's folder is not counted; exit 0. Unelevated: TC-07 skips and the exit is 1. **Watch for** (author's note): the demo now also matches the writer's payload hash; if step 4 says "monitor never reported the file" while the ledger shows the file, record both and report it as a fault with the evidence. No `/response/terminate` call or kill from the demo |
| **R24** (overrides F3) | `--restore` returns every file | Run `grinder` and `staged` against the live Monitor with the response engine on so each is **killed mid-run**, then `python scripts\ransomware_simulator.py --target-dir <dir> --restore`. Then `simulator_sweep.py` elevated | **10/10 byte-identical** against `pre_attack_manifest.json` for each of the two; no `.enc`/`.locked`/`.zip` or hex-named file left; the `urds-sim-*` folder gone from `%TEMP%\urds-simulator-originals`; sweep **13/13 detected** with the same `files_encrypted` per family as the 2026-10-05 recording (the simulator's pace and families are unchanged: a different count is a fault). Also restore after killing at least two more families |
| **R25** (overrides F6) | One incident per suspicious file | Elevated full run (run 2's shape). `ledger_coverage.py --ledger-db <run>\data\ledger.db` and count from the ledger: incidents and `file_event` blocks per suspicious file, ledger blocks per suspicious file, `coalesced_event_ids` on escalations. Inspect one `created, modified` file on `/monitor/events`. Two-writer cases | **mean incidents per suspicious file about 1.1** (median 1, was median 2, max 4); `file_event` blocks per file about 1.1 (was 1.91); ledger blocks per file well under the old 6.06 (the author's replay: 4.6; the original target of "< 3" is **not** met: report your number honestly); 0 unsupported PIDs; **130/130 flagged**; every two-writer case still never `certain`, nobody killed on it; a `modified` notification joined to an incident is on `/monitor/events` with `coalesced_into` |
| **R26** (overrides F2b) | The Response side of suspend-first response works, **driven by hand** | Elevated, native Response, through the **gateway with an admin token** (or Response directly on :8004). With a real `python.exe` sleeper: (1) `POST /response/suspend` (lease 30 s, attribution fields set, `image` and `started_at` of the sleeper) returns 200, the process's CPU is flat in `Get-Process`; (2) a second suspend returns `already_held: true`; (3) `POST /response/resume`, then again (second `resumed: false`); (4) a 3 s lease **expires** and the process resumes on its own; (5) wrong `started_at` -> `409 PID_REUSED`, process keeps running; (6) refuse the Monitor's own PID, `services\response`'s ancestors and a process under `C:\Windows\System32` (409 each); (7) suspend, then `POST /response/terminate` with the `lease_id`: process gone, lease closed; (8) **stop Response mid-lease** four ways (graceful stop, `Stop-Process -Force` on the serving interpreter, killing the venv launcher, `taskkill /T /F` on it): the sleeper resumes each time; (9) ledger: `process_suspended` / `process_resumed` blocks with the PID, `lease_id` and `incident_id` (joined to the terminate block), and the attribution fields marked `attribution_supplied_by: "caller"`; **`gate` is `null` with `gate_reason: "no gate supplied (operator request)"` unless you pass one, and `gate_verified` is always `false`**: Response does not evaluate any gate, so a suspend block is a record of what the caller claimed, not evidence it was authorised; `ledger_coverage.py` still 0 unsupported, and say so in the report: the C-16 scan was **not** extended to suspend/resume blocks (that was the unbuilt Monitor half); (10) bad input: `lease_seconds` of `NaN` / `Infinity` -> 400; `URDS_MONITOR_PID` written as `1234 5678`, `1234,5678` and `abc` (the last must refuse every suspend with `MONITOR_PID_INVALID`) | every case; **no process left frozen after teardown**: list `Get-Process` entries with all threads in `Wait:Suspended` (or `ps`-equivalent) in the report, empty expected. Report "**Monitor side not built; no automatic suspension**" in the same row, and report that nothing in the Monitor called `/response/suspend` in the run (grep the Monitor log and ledger: zero `process_suspended` blocks from the pipeline) |
| **R27** | Dashboard log noise | Dashboard open for 20 refreshes | `$Run\logs\dashboard.log` has no `use_container_width` deprecation line (was about 69,510 lines in 35 min) and every panel still renders; no `ArrowTypeError` (R19) |
| **F2** | Kill timing, unchanged | Base §6.2, medians and the FEBR table, beside the 2026-10-05 numbers (kill requested median 1.57 s after the read; FEBR < 5 for 3 of 13 families) | `KNOWN-OPEN`: report without pass or fail. Do **not** claim any change from F6/R16 unless the numbers show it |
| **F2c** | Files encrypted before suspension / time from the 4663's delivery to the suspend | **Cannot be measured on this branch**: no automatic suspend exists | Report "not measurable: Monitor side of F2b not built". Do not substitute another measurement. TC-01 (< 5 files encrypted) is stated as failing for the fast families if it still fails |
| **R9-R21** | The full previous regression set (R13, R15, R17-R21, VSS, TC rows) and the suites | Base prompt §7 unchanged | no regression; any FAIL here means a fix did not hold |

### What to hand back

The report in the base prompt's §9 format, with these rows added to its
regression table and a verdict line under its §9.2 rules. R22-R26 are the verdict
rows; R22 and R23 FAILED last time. The report's "Not tested" must say the
following if true: the Monitor-side F2b, F2c, and (if unelevated) anything that
needed elevation.

Do **not** start an ETW source, change the horizon (1,500 ms), the simulator's
pace or its families, or edit any bound claim. If a claim figure moves, stop and
report.
