# Fixes from the Windows integration test

Eight defects found by the Windows 11 VM integration test of commit `7dcee2a`,
fixed on `fix/windows-integration-defects`, one commit per defect, and five more
found re-testing this branch on the same VM (9 to 13). Each entry says what
changed, where, what tests it, and what can only be confirmed on the Windows
test VM. Measured figures in the README and `reports/` are unchanged;
claims they no longer describe are marked **re-verification pending**.

| # | Defect | Commit(s) |
|---|---|---|
| 1 | Audit-event correlation timed out before the 4663 arrived | `946e5e2`, follow-up `8847aa9` |
| 2 | A renamed file was correlated under its new name only | `1aa7f1b` (test adjustment `d17b6a9`) |
| 3 | Correlation blocked the watchdog thread | `f8904a1` |
| 4 | Recovery verification depended on path spelling | `84d91bb` |
| 5 | `setup_attribution_audit.ps1` did not restore prior machine state | `b2aa8c3` |
| 6 | `verify_vss.py --status-only` created a snapshot when elevated | `bd6006f` |
| 7 | streamlit 1.41.1 vs the Pillow 12.3.0 pin | `fd24a9d` |
| 8 | Attribution wording before start; training rewrote a tracked report | `8cef7bf` |
| 9 | The Monitor's reads stopped other processes renaming or deleting a file | `805084f` |
| 10 | Training mode timed its window and dwell on a slewed wall clock | `db8f38a` (test waits `529d872`) |
| 11 | A probable answer named a writer that came after the event | `ec21a43` |
| 12 | "Unreadable" was reported for a file being written, with nothing locked | `d6313f1` |
| 13 | The dashboard never rendered, and while open it saturated the gateway | `820d7a4` |

## The safety invariant

A kill is requested only when `Attribution.kill_authorised` is true
(`services/monitor/attribution.py:291`): confidence `certain`, from a
kernel-grade source, with a PID, and **not pending**. Defect 1 added the last
condition and a PID identity check at escalation, so improving how often
correlation succeeds cannot make it succeed wrongly. Each case the brief names
has a test that asserts the answer stays below `certain` and no terminate
request is made:

| Case | Test (`services/monitor/tests/…`) |
|---|---|
| two writers in the window | `test_attribution_delivery_lag.py::test_a_two_writers_are_final_probable_at_once`, `test_b_two_writers_in_different_flushes_are_never_certain`, `test_a_a_late_competitor_still_lowers_confidence`, `test_a_a_previous_writer_inside_the_competition_window_blocks_certain` |
| two writers across a rename | `test_rename_attribution.py::test_b_writes_by_two_processes_then_a_rename_are_not_certain`, `test_b_a_rename_over_a_file_another_process_wrote_is_not_certain` |
| a stale record | `test_a_a_stale_record_from_the_previous_write_is_not_evidence`, `test_a_a_record_delivered_after_the_horizon_is_not_an_answer` |
| a PID that has exited | `test_c_a_writer_that_exited_is_not_acted_on_and_says_why`, `test_d_an_exited_or_reused_pid_is_recorded_and_never_reaches_the_response_service` |
| a reused PID | `test_c_a_reused_pid_with_a_different_image_is_not_acted_on`, `test_c_a_reused_pid_started_after_the_write_is_not_acted_on_even_with_the_same_image` |
| identity unprovable | `test_c_an_unprovable_identity_is_not_acted_on` |
| an evicted competitor | `test_a_an_evicted_competitor_blocks_certain` |
| nothing short of the gate reaches terminate | `test_d_nothing_short_of_kill_authorised_reaches_terminate` |

The pre-existing TC-26 tests (`test_tc26_attribution.py`) pass unchanged: the
unanchored lookup they exercise is kept byte for byte (`WriteLog._lookup_legacy`).

## Ported from `fix/evidence-integrity`

- **Park and re-ask** (`agent/`'s pending questions): the first answer drives
  the non-destructive response; the question stays open and is re-asked as
  records arrive. `PendingAttribution`, `attribution.py:1467`.
- **The 3000 ms window**, as the *competition* window: how far back another
  writer makes the answer ambiguous. It only ever lowers confidence. The
  match window stays 750 ms (`attribution.py:150-196`).
- **A 16384-entry write log** (was 4096) with an eviction watermark: an
  eviction inside the competition window blocks `certain`.
- **Deletions carry no PID** instead of the Monitor's own (`app.py`, deleted branch).
- **`agent/dispatch.py`'s path-sharded lanes**, changed where the Monitor
  differs (defect 3).
- **The audit script's polling probe and failure counting**, plus the lesson
  behind its `-SaclOnly`: reverting one root turned auditing off for all the
  others (defect 5).

## 1. Correlation timed out before the audit record arrived

**Measured:** 4663 delivered 390–1032 ms after the write (median 1000 ms, 35
writes) against a 250 ms wait, so 0 of 35 fresh writes correlated, and the ones
that did took the *previous* write's record.

**What changed** (`services/monitor/attribution.py`):
- Records are stamped with the event's own `System/TimeCreated/@SystemTime`
  (`parse_system_time`, `:838`; UTC only). Records without one are dropped and
  counted (`SecurityLogSource.accept`, `:1044`). The lookup is anchored to the
  file event's observation time on the same clock (`_lookup_anchored`, `:635`):
  it matches writes in `[observed_at − 750 ms, read_at + 50 ms]`, and any other
  writer in `[observed_at − 3000 ms, read_at + 50 ms]` competes.
- The **delivery horizon**: nothing is `certain` until 1500 ms (+50 ms
  tolerance) after the file was read. The horizon runs on the monotonic
  performance counter, not the adjustable 15.6 ms wall clock. A match must have
  been *delivered* before the horizon closed, and a competitor delivered later
  still counts.
- A **two-step response**: the first answer (almost always pending) triggers
  isolate at once; `PendingAttribution` keeps the question open; at the horizon,
  exactly one kernel-grade writer whose PID is still the same process (psutil
  image and start time, `probe_process` `:1080`, `verify` `:1345`) escalates to
  `certain`. That calls `/response/terminate` on the **same incident** and
  writes a **new** `attribution_escalation` ledger block joined by `incident_id`
  (`pipeline.escalate`, `services/monitor/pipeline.py:257`). Every other outcome
  (no record, ambiguous, exited, reused, unverifiable) is written too, with no
  kill.
- Configurable, with defaults justified in the module docstring:
  `ATTRIBUTION_WINDOW_MS` 750, `_COMPETITION_MS` 3000, `_GRACE_MS` 0 (was 250),
  `_HORIZON_MS` 1500, `_CLOCK_TOLERANCE_MS` 50, `_MAX_ENTRIES` 16384. psutil is
  now a Monitor requirement.
- Follow-up (`8847aa9`): the escalation thread was started, and built its
  HTTP client, only when the first question closed. That put the client build
  on the kill's critical path; traced at 187 ms, and an untraced run missed 2 s
  at +2134 ms. It now starts with the watch (`_ensure_worker`/`_ensure_escalator`,
  `app.py:940-983`). Three traced runs afterwards: kill at +1585, +1597 and
  +1700 ms, each within 0.3 ms of the question closing.

**Tests:** `services/monitor/tests/test_attribution_delivery_lag.py` (50):
- real-time delivery at 0, 300 and 1000 ms escalates to `certain` inside 2 s,
  and at 1600 ms does not
- two writers are never `certain`
- stale records, late competitors, eviction
- exited, reused and unverifiable PIDs: no action, reason recorded
- the escalation block
- end to end through `handle_event`
- the escalation client test

**Docs:** `docs/PROCESS_ATTRIBUTION.md` §3–4 rewritten. §6a (the 16 September
live run) is marked **re-verification pending**, with its figures unchanged.

**Check on Windows:** a single write by a fresh process → `certain`, correct
PID, terminate within 2 s of detection. The 1500 ms horizon rests on the VM's
35-write measurement; a host whose flush is slower would need
`ATTRIBUTION_HORIZON_MS` raised.

## 2. Renamed files were correlated under the new name only

**Measured:** rewrite then rename to `*.locked`: 20/20 detected, 0/20 correlated.

**What changed:** `MonitorHandler.on_moved` passes both names
(`app.py:1004`). The event keeps the new name as `file_path` and adds
`renamed_from`, on `/monitor/events`, the `file_event` block and the
`attribution_escalation` block. The first look and the open question ask about
both names (`_correlate`, `app.py:735`, `also=`), so a writer of *either* name
competes. Writes by two processes, or a rename over a file another process just
wrote, are not `certain`.

**Tests:** `services/monitor/tests/test_rename_attribution.py` (10):
- write by A then rename → `certain` A
- asking about the new name alone reproduces 0/20
- A and B then rename → `probable`
- both names in the event and on the chain
- the locker shape escalating in real time

`d17b6a9` changes one test of this defect's own, in its own commit. The handler
test compared the whole call, so defect 3's new keyword argument would have
failed it; it now asserts the two names.

**Check on Windows:** write then rename by one process → `certain`, correct PID.

## 3. Correlation blocked the watchdog thread

**Measured:** 20 changes in ~0.1 s, detections stamped ~250 ms apart, the last
≥ 4.77 s after its write, while `detection_latency_ms` read 2–17 ms. One wait
reported 766 ms against a 250 ms grace.

**What changed:**
- `services/monitor/dispatch.py` (new): `CorrelationLanes`, four lanes sharded
  by crc32 of the normcased path, so one file's events are handed to the
  pipeline in order. Ported from `agent/dispatch.py`, with two changes: a full
  lane runs the job inline and counts it (`ran_inline`) instead of dropping a
  detection, and only correlation moves. Classification stays on the observer
  thread, so `/monitor/events` keeps watchdog's order.
- `handle_event(…, lanes=)` (`app.py:416`); `MonitorHandler` passes the running
  lanes, and a direct call still correlates before returning. The grace
  deadline is *observation + grace*, so time spent queued is not paid twice.
- New event fields: `observed_at`, `queue_wait_ms`, `response_dispatched_at`
  (set when the pipeline asks for a response, `pipeline.py:417`) and
  `attribution_wait_overrun_ms` (`attribution.py:288`). `detection_latency_ms`
  is unchanged; its docstring says it excludes every queue and the attribution
  wait. `/monitor/status` reports the lanes under `correlation` (`app.py:1160`).
- **The 766 ms overrun** (`dispatch.py:44`): explained as far as the evidence
  goes, not proven. It is 49 ticks of `GetTickCount64`, i.e. about 516 ms in
  which the observer thread was not scheduled. That overlaps the inferred 4663
  flush for ~40 decoy writes and the first post-reboot pipeline run. The fix
  removes the consequence and makes a recurrence measurable: the wait is off
  the observer thread, anchored to the observation, woken by the write log,
  measured on `perf_counter`, and reported as `attribution_wait_overrun_ms`.

**Tests:** `services/monitor/tests/test_correlation_lanes.py` (17):
- 20 suspicious events against a live source that never answers, through
  `MonitorHandler`: no `resolve` runs on the calling thread, and all are
  correlated within one grace of the last hand-over, on four lanes and on one
  (not 20 × grace)
- per-path order; a full lane runs inline and drops nothing
- the new fields; the overrun measurement

The timing bounds are stated against the events' own `detection_latency_ms`,
because classification stays on the calling thread by design.

**Check on Windows:** 20 rapid changes → last event ≤ 1 s after the last write;
`queue_wait_ms` present. The 766 ms cause can only be confirmed by a
recurrence, which will now show in `attribution_wait_overrun_ms`.

## 4. Recovery verification depended on path spelling

**Measured:** stored `C:/URDS-main/watched_files\tc01\file.docx`; recovering
`C:\URDS-main\watched_files\tc01\file.docx` restored the right bytes and
returned `partial`, "No prior hash for this path in the ledger".

**What changed:**
- At the source: `normalise_path` (`app.py:241`) is `os.path.normpath` of the
  absolute path, applied to the watch path in `start_monitoring` (`:1035`) and
  to every path and `renamed_from` in `handle_event` (`:455`).
  - **Case policy on Windows:** case is kept as given and never folded when
    stored. The path is evidence, and a directory can be case-sensitive
    (`fsutil setCaseSensitiveInfo`).
  - Comparison is case-insensitive, and happens in the reader.
- In the ledger: `services/ledger/path_keys.py` and `HashChainLedger.get_blocks`
  (`hash_chain.py:160`). Lookups compare a key derived from each row's stored
  `file_path`:
  - Windows-shaped paths (a drive letter or UNC prefix, decided by the path's
    shape because the ledger runs on Linux) by `ntpath.normpath` + `lower()`,
    with `\\?\` dropped.
  - POSIX paths by `posixpath.normpath`, case-sensitive.
  - The SQL prefilter is now the file's name, with non-ASCII runs as wildcards
    because canonical JSON escapes them.
  - Paging and `total` count matches. They used to count prefilter hits, which
    also let LIKE's case-insensitivity count `/watch/Report.doc` in a lookup for
    `/watch/report.doc`.
- **Why a computed key, not a `path_key` column:** filling it for existing rows
  would be an UPDATE of every row in a store with no update path by design.
  And a column outside the hash is one an attacker with the database file could
  re-point, aiming recovery's reference hash at another file's block, without
  `verify_chain` noticing. Deriving the match from `event_data` means every
  block a lookup returns names the path in hashed bytes. **No row is written and
  no stored byte changes.** The cost is a Python comparison of the rows that
  share the file's name.

**Tests:**
- `services/ledger/tests/test_path_spellings.py` (32):
  - mixed, backslash, forward-slash, different-case, `.`/`..`, doubled and
    `\\?\` spellings against rows in the old mixed form and in the normalised
    form; non-ASCII case; UNC
  - never another file (other folder, longer name, other drive, `straße` vs
    `strasse`); LIKE wildcards; POSIX case-sensitivity; paging
  - rows and chain byte-identical after lookups
  - 19 fail against the parent
- `services/monitor/tests/test_path_normalisation.py` (10), including a live
  watch posted with forward slashes.
- `services/response/recovery/tests/test_integration.py` (+6):
  - recovery verifies against a baseline stored in the old form under every
    spelling
  - the full Monitor → ledger → recovery loop given the VM's spelling verifies
    with both the typed and the recorded one

**Docs:** `docs/FLOW.md` (`get_blocks`).

**Check on Windows:** recover with `C:\...` and with the recorded spelling →
`integrity_verified: true` for both.

## 5. `setup_attribution_audit.ps1` did not restore prior machine state

**Measured:** setup shrank a 1 GiB Security log to 128 MB; `-Revert` disabled a
subcategory another component had enabled.

**What changed** (`scripts/setup_attribution_audit.ps1`):
- **Recorded first.** Before changing anything, setup reads and records the log
  size, the File System subcategory's Success/Failure and the path's existing
  audit rights, in `%ProgramData%\URDS\attribution_audit_state.json`
  (`-StatePath`; `Invoke-Setup`, `:449`).
  - If any of these, or an existing state file, cannot be read, it changes
    nothing.
  - A later setup, for another path or a re-run, keeps the first machine record.
- **Only raised.** The log size is only ever raised.
- **Only the missing rights.** The SACL gets only the rights not already
  audited, with Everyone matched by SID rather than by its localised name.
- **`-Revert` restores the record** (`Invoke-Revert`, `:583`):
  - It removes only the rights setup added (`Remove-WriteAudit`, `:332`).
  - It turns Success off only if setup turned it on, and never touches Failure.
  - It restores the log only to the recorded size, and only if the log is still
    at the size setup set.
  - Both machine-wide settings are restored only when the last recorded path is
    reverted.
  - With no state file, it changes nothing and prints the manual steps.
- **`-Verify`** prints the recorded prior state (`Invoke-Verify`, `:395`). The
  `[  ok  ]`/`[ FAIL ]` marks are kept.
- **Ported:** failures are counted and give a non-zero exit, and the probe
  polls to 4 s (`Invoke-AuditProbe`, `:247`).
- **Test seams:** every machine access goes through a wrapper, native commands
  through `Invoke-Native`, and the main body is skipped when the script is
  dot-sourced (`:680`).

**Tests:** `scripts/tests/setup_attribution_audit.Tests.ps1`, **Pester 3.4**
(inbox on Windows 10/11): 26 passing on the development host.
- Everything that touches the machine is mocked against an in-memory fake, with
  guards that throw if `auditpol`, `wevtutil`, `Get-WinEvent`, `Get-Acl` or
  `Set-Acl` is reached.
- SACL behaviour, including `RemoveAuditRule` keeping a rule's other rights, is
  checked on in-memory `DirectorySecurity` objects.
- Covered: the 1 GiB case, the order of record-then-change, per-bit restore,
  another component changing the log after setup, two paths, no state file, and
  `-Verify` output.
- Run with `powershell -ExecutionPolicy Bypass -Command "Invoke-Pester scripts/tests"`.
- **Not covered:** real `auditpol`/`Get-WinEvent` output and a real SACL write
  need an elevated host. `auditpol`'s text is parsed in English; on a localised
  build setup reads nothing it can restore and so changes nothing. Pester is
  not run in CI (Linux).

**Check on Windows:** 1 GiB log, then setup, then `-Revert` → log still 1 GiB;
audit setting as before. Also: a second watch path, and `-Verify` after setup.

## 6. `verify_vss.py --status-only` created a snapshot when elevated

**What changed:** `status_only()` skips `create_snapshot` when
`platform_status()["elevated"]` is true and records
`{"attempted": false, "reason": "not attempted: --status-only creates nothing"}`
(`scripts/verify_vss.py:81-99`). Unelevated, the attempt and its refusal record
are unchanged. `reports/vss_status.json` was recorded unelevated and is
untouched.

**Tests:** `services/response/recovery/tests/test_verify_vss_status_only.py` (3):
a mocked elevated manager's `create_snapshot` is never called, and the written
report carries the reason; unelevated, the refusal is still recorded.

**Check on Windows:** `--status-only`, elevated → shadow-copy count unchanged
(`vssadmin list shadows` before and after).

## 7. Dependency conflict

**What changed:** `services/dashboard/requirements.txt` pins
`streamlit==1.51.0`; the Pillow 12.3.0 pin stays.

**Evidence:** PyPI's published `requires_dist` for all 40 releases from 1.41.1
to 1.64.0.
- 1.41.1–1.50.0 declare `pillow<12,>=7.1.0`; **1.51.0 is the first** with
  `pillow<13,>=7.1.0`.
- Its other bounds fit every pin in the repository: numpy 2.5.1 (<3), pandas
  2.2.3 (<3), watchdog 6.0.0 (<7), requests 2.32.3 (<3).
- It fits python:3.11 (it needs >=3.10). streamlit-autorefresh 1.0.1 needs
  streamlit>=0.75, and plotly 5.24.1 does not constrain it.

**Tests:** none. No package was installed in this session. The dashboard passes
`use_container_width`, which 1.51.0 still accepts with a deprecation warning.
The README's Dashboard row is marked **re-verification pending**.

**Check on Windows:** a fresh venv with every requirements file → no resolver
conflict; the dashboard is healthy.

## 8. Minor

- **Wording.** `/monitor/attribution` before `POST /monitor/start` now says
  "not started yet: correlation starts with monitoring (POST /monitor/start)"
  (`attribution.NOT_STARTED`, `attribution.py:954`). A source that failed to
  start still reports its own reason.
  - Test: `services/monitor/tests/test_attribution_status_wording.py` (3).
- **Training output.** `src/train_behavioral_model.py` always writes `models/`,
  which the ML container mounts and reads first. It writes the tracked
  `reports/behavioral_model_metrics.json` only under `URDS_WRITE_REPORTS=1`
  (`write_metrics`, `:406`).
  - Why not only `models/`: TC-21 and the engine's fallback read the committed
    `reports/` copy, and `models/` is gitignored, so the tracked evidence must
    stay refreshable, deliberately.
  - Test: `services/ml-engine/tests/test_training_outputs.py` (5).

**Check on Windows:** `GET /monitor/attribution` before start shows the new
wording; a retrain leaves `git status` clean.

## 9. The Monitor's reads stopped anyone renaming or deleting the file

Found re-testing this branch, 2026-10-04, while preparing the defect 2 re-check.

**Measured:** a process writing a file in the watched tree and renaming it
straight away failed 6 of 6 times with `PermissionError [WinError 32]` while the
Monitor watched, and succeeded 6 of 6 times with the watch stopped. Python's
`open` asks for `FILE_SHARE_READ | FILE_SHARE_WRITE` and not
`FILE_SHARE_DELETE`, so while the Monitor held a just-written file open to
sample and hash it, no other process could rename or delete it. That is what
Office's save-to-temp-then-rename, editors' atomic saves and installers do,
within milliseconds of the write the Monitor is reacting to.

**What changed:** on Windows, `open_for_read` (`services/monitor/detection.py`)
opens through `CreateFileW` with all three share modes and wraps the handle with
`msvcrt.open_osfhandle`.
- A rename or delete that lands mid-read leaves the read going on against the
  same file.
- Failures raise what `open` raised (`WinError` maps 32/33/5 to
  `PermissionError`, 2/3 to `FileNotFoundError`), so the sharing-violation
  retry and the directory refusal are unchanged.
- The shared opener is bound to the module's name `open`: that is the seam
  `test_detection.py`'s lock tests patch, and they pass unedited. POSIX keeps
  the builtin; it has no share modes.
- Residual: `pefile.PE(path)` in `pe_features.py` still opens with the builtin.
  It runs only for on-demand `/features` analysis, not on file events.

**Tests:** `services/monitor/tests/test_read_shares_delete.py` (6). Rename and
delete while open fail on the old code; write-while-open, missing file,
directory, and an exclusive lock retried then refused pass on both.

**Verified live on the VM:** 20 of 20 write-then-rename by a separate process
succeeded with the fixed Monitor watching, and all 20 renames were still
detected as suspicious. Detection latency benchmark p95 37.8 ms, unchanged.

## 10. Training mode timed its window and dwell on a slewed wall clock

Found re-testing this branch, 2026-10-04.

**Measured:** `test_suppression.py::test_a_file_that_has_dwelled_does_raise_a_ceiling`
failed in two consecutive Monitor runs in a fresh venv (state `idle`, not
`active`, after an 80 ms sleep against a 50 ms dwell), then passed 15 of 15 in
each venv. The VM's wall clock is being slewed:

| Clock | Rate against a pypi.org HTTP `Date`, 41 s |
|---|---|
| `time.time()` | 0.801x |
| `time.perf_counter()` | 1.002x |
| `time.monotonic()` | 1.002x |

Over an earlier 60 s, `time.time()` gained 26.5 s on `perf_counter` (1.44x).
Windows Time is not synchronising (source "Local CMOS Clock"); VirtualBox's
guest time sync (`VBoxService`) steers the clock by changing its rate. No
backward step was seen. Changing the VM's time sync is a machine setting and is
out of scope.

**What changed:** `TrainingMode` (`services/monitor/suppression.py`) times both
of its durations, the window's expiry and each path's dwell, on
`time.monotonic()`. Neither is reported as a time of day (`status` gives
`seconds_remaining`).
- At 0.62x or slower, the old code turned the 80 ms sleep into less than the
  50 ms dwell, which is the failure above.
- At 1.44x, a 60 s window closed after about 42 s, and the dwell that keeps a
  poison write from raising a ceiling shrank by the same factor.
- The Monitor's `observed_at`/`read_at` stay on the wall clock on purpose: they
  are compared with 4663 `TimeCreated`, which is wall time. The delivery
  horizon was already on `perf_counter`.

**Tests:** `services/monitor/tests/test_training_mode_clock.py` (3) freezes the
wall clock the module sees. All three fail on the old code.

**Test-only follow-up, `529d872`:** five loops measured how long they had waited
with `time.time()`: the live-watcher wait helpers in `test_api.py` (on `main`),
`test_path_normalisation.py` and `test_attribution_delivery_lag.py` (this
branch), the 5 s windows of the CPU and memory benchmarks, and one elapsed-time
guard. They now use `time.monotonic()` (the guard, the `perf_counter` reading it
already took). No assertion changed. Wall-clock values handed to the code under
test stay on the wall clock.
- Why: on this VM a 5 s wait on `time.time()` lasts about 3.5 to 6.25 s of real
  time, and a forward step ends it at once.
- `test_tc01_file_creation_on_the_watched_path_is_detected` failed once in
  about 210 runs of its scenario on 2026-10-04, with the whole file finishing
  in 2.7 s: too fast for the 5 s wait to have run out in real time.
  **Correction:** that failure was not the clock. The final full pass caught
  the same fast failure with a traceback, and it is defect 12. The clock change
  still stands on its own: a wait budget has to be measured on an interval
  clock.

## 11. A probable answer named a writer that came after the event

Found by the elevated re-check on the VM, 2026-10-04 (run `20261004_115048`).

**Measured:** the check encrypted `report_2.txt`, then asked the Response
service to restore it as soon as the detection appeared. The restore opened the
file for writing at 06:21:01.712. That was 27 ms after the Monitor observed the
encryption (01.685), and inside the 50 ms clock tolerance after the read, so it
was rightly counted as a possible competitor. The answer was `probable`, with
four candidates (2504, 9508, 4604, 6388), and nothing was killed. But a
multi-writer answer reported "the most recent" writer. So the event and the
ledger named PID 6388, the Response service, as the probable encryptor. The
encryptor (4604), whose write preceded the observation, appeared only in the
candidate list.

**What changed:** the multi-writer branch of `_lookup_anchored`
(`services/monitor/attribution.py`) now names the most recent writer whose write
preceded the observation. Only if no candidate preceded it does it name the most
recent overall.
- The comparison allows one tick of slack: `OBSERVATION_TICK_S`, which is
  `time.get_clock_info("time").resolution`, 15.625 ms on the test host. A
  precise `TimeCreated` can sit up to one tick after the coarser `observed_at`.
- The answer's evidence (`written_at`, `delivered_at`) is the named writer's
  record.
- Candidates, confidence and `kill_authorised` are unchanged. A `probable`
  answer is never acted on, so no response changes; only the PID on the record
  does.

**Tests:** `services/monitor/tests/test_probable_reports_preceding_writer.py`
(4), including the VM run's three writes. On the old code it names 6388.

**Verified live:** the next elevated run named no wrong PID (0 of 79).

## 12. "Unreadable" was reported for a file being written, with nothing locked

Found in the final full pass, 2026-10-04.

**Measured:** `test_tc01_file_creation_on_the_watched_path_is_detected` failed.
The event that saw the whole 32,768-byte file carried entropy `None`, which is
the verdict "unreadable". Nothing was locked.
- `handle_event` (and `extract_features`) read the leading bytes, then the
  size. Watchdog's `created` fired, and the leading bytes were read from the
  still-empty file. Then the write landed, and the size came back full.
- `looks_unreadable(b"", 32768)` then read that as "bytes exist and we got
  none".
- The same race the other way round is why the diagnostic logged `created`
  events with `file_size: 0` and entropy 7.99.

It is also the one fast `test_tc01` failure seen earlier that day, at
`102c147`. Entry 10 had called that one consistent with the slewed clock; this
is the actual mechanism.

This is not a harmless label. An unreadable reading is never suspicious and
nothing re-reads it, so if no later notification arrives, the content is never
scored.

**What changed:** `_size_then_magic` (`services/monitor/app.py`), used by
`handle_event` and `extract_features`:
- The size is taken first, so a file that grows between the looks is read as
  what it now holds.
- An empty read of a file that had bytes is checked against the size again
  before it counts as a lock. A file truncated in between (an overwrite's first
  step) is empty, not locked.
- A real lock still reads as unreadable.

**Tests:** `services/monitor/tests/test_unreadable_is_a_lock_not_a_race.py` (3).
The grow-between-the-looks case fails on the old code; the truncate and
real-lock cases pass on both. `test_api.py` passed 15 of 15 afterwards.

**Not changed:** a file that grows between the size and the sample still
records a stale `file_size` beside the content it scored. The two baselines
under "Minor findings" are that case. Recovery verifies the hash, which covers
the full content.

## 13. The dashboard never rendered, and while open it saturated the gateway

Found by the full VM test of `5952218`, 2026-10-04 (F1 in
`reports/VM_TEST_REPORT_2026-10-04.md`).

**Measured:** `http://127.0.0.1:8501` showed its title and caption and nothing
else. While it was open, every gateway caller waited: `/health` 5.5-10.3 s
(0.81-0.88 s closed), one proxied GET 2.4-2.7 s (0.2 s closed). Two causes.
The page needed both to fail: with either one fixed it rendered on this VM
(live check below). Both are fixed.
- `call_downstream` built an `httpx.AsyncClient` per call. Building one loads
  certifi's CA bundle into a new SSL context, 267-376 ms here (8 samples),
  synchronously on the event loop, so every request queued behind it.
  `/health` paid it four times, one service after another.
- The dashboard reran the whole page every second (`st_autorefresh`). A
  full-page rerun cancels the run in progress at its next element
  (`on_scriptrunner_yield` in Streamlit 1.51), so a run longer than the
  interval never drew past the title. The six gateway calls each run made kept
  the gateway saturated, which kept every run longer than the interval.

The Monitor already builds its escalation thread's client ahead of time for
the same reason (`_ensure_escalator`); the gateway did not. Detection, attribution,
response and recovery never used the gateway, so they were not affected.

**What changed:**
- Gateway (`routers/proxy.py`, `main.py`): one client, built at startup in
  `lifespan`, reused by every downstream call and closed at shutdown. Idle
  connections expire at 4 s, before uvicorn's default 5 s keep-alive closes
  them from the service's end. `/health` asks the four services at once
  (`asyncio.gather`); the response is unchanged.
- Dashboard (`app.py`): the live panels are one
  `st.fragment(run_every="1s")`. A fragment's timed rerun does not preempt the
  run in progress, and a pending one is not queued twice, so a slow run is
  late rather than lost. Still a 1 s refresh, as the README states. The body
  moved into the function, so `git diff -w` shows the change. The helpers stay
  at module level: `scripts/pipeline_governance.py` lifts two of them by AST.
  `streamlit-autorefresh` is no longer imported and leaves
  `requirements.txt`; removing a pin cannot create a resolver conflict.

**Tests:**
- `services/gateway/tests/test_downstream_client.py` (5). `call_downstream`
  stays real; every client the gateway builds is counted and given an
  in-process transport. On the base commit, 4 fail: startup builds no client,
  the same 13 requests build 22, and `/health` has 1 service in flight instead
  of 4. The one-service-down case passes on both.
- `services/dashboard/tests/test_render.py` (3). Runs the real script with
  Streamlit's `AppTest` against a stubbed gateway. It checks that every panel
  is drawn, that a refresh makes the same six calls as before, and that a
  gateway that is down is reported. These pass on the base commit too:
  `AppTest` has no browser and no timer, so they guard the render path, not
  the refresh timing. The timing was checked live (below).
- The dashboard is not in the CI matrix, and `scripts/verify_reproduction.py`
  gives that as its reason for not installing it. Adding a job is the
  maintainer's call.

**Live check on the VM** (run `f1_20261004_192031`). The fixed stack ran on
8000-8004. The base commit's gateway ran on 8010 against the same services,
with four dashboards, one per old/new combination. Latency was timed with
`perf_counter`, one dashboard open at a time:

| Gateway latency, median (range) | Base gateway | Fixed gateway |
|---|---|---|
| `/health`, no dashboard open | 819 ms (791-863) | 18 ms (14-31) |
| `/monitor/events`, no dashboard open | 205 ms (197-221) | 10 ms (8-13) |
| `/health`, the matching dashboard open | 6,939 ms (6,215-7,787) | 19 ms (15-47) |
| `/monitor/events`, the matching dashboard open | 2,317 ms (1,672-2,536) | 10 ms (7-26) |

| Dashboard on gateway | Rendered | Refreshes |
|---|---|---|
| base on base (as tested) | title only, after 30 s | none drawn |
| fixed on fixed | every panel, banner "Threat Detected" | 19 in 20 s |
| fixed on base | every panel | 9 in 20 s, as fast as the base gateway answers; its `/health` fell to 1,388 ms median, because runs no longer pile up |
| base on fixed | every panel | about 1 a second |

A refresh was counted as one `POST /predict` in the gateway's access log; each
refresh ends with one. The browser pane was hidden for all four
(`visibilityState: hidden`), so the conditions were the same for each.

The other paths that now share the client were checked on the fixed stack:
- `/analyze` worked for a document and for random bytes.
- A forged token got a 401, and its `auth_failure` block reached the ledger.
- `/health` was healthy after idle gaps of 4.5, 5.0, 5.2, 5.5, 6.0 and 8.0 s.

That is 9 of 9 checks passed. The gateway logged 1,275 requests and no error.

**Not changed:**
- Each refresh still makes its six gateway calls one after another. The two
  measured, `/health` and `/monitor/events`, now take 18 and 10 ms.
- Now that the page renders, the dashboard logs a caught pyarrow
  `ArrowTypeError` for its two-column "Field / Value" tables, which mix text
  and numbers. Streamlit converts the column to text and the table shows. The
  base dashboard logs the same once it can reach those tables (base on fixed,
  above). It is log noise.

## Suites

Baseline at `7dcee2a` and after this branch, same venv (Python 3.12.10,
Windows 11, 4 vCPU), `URDS_WRITE_REPORTS` unset:

| Suite | Baseline (`7dcee2a`) | This branch | New tests |
|---|---|---|---|
| gateway | 86 passed | 91 passed | +5 (13) |
| ledger | 67 passed | 99 passed | +32 (defect 4) |
| monitor | 410 passed | 516 passed | +50 (1), +10 (2), +17 (3), +10 (4), +3 (8), +6 (9), +3 (10), +4 (11), +3 (12) |
| ml-engine | 45 passed, 3 skipped | 50 passed, 3 skipped | +5 (8) |
| response | 112 passed, 2 skipped | 121 passed, 2 skipped | +6 (4), +3 (6) |
| claim matrix (`--tests`) | 0 failed | 0 failed | — |
| Pester (`scripts/tests`) | — | 26 passed | +26 (5) |
| dashboard (`services/dashboard`, new) | — | 3 passed | +3 (13) |

The Monitor figure is from a re-run. In the full pass, it had two failures:
`test_detection_latency_under_100ms` (p95 143.1 ms) and
`test_tc11_detection_stays_within_budget_under_load` (p95 111.5 ms). Both are
baseline benchmarks that the untouched base commit was failing on the same
host at the same time.

Once the load eased, three alternating runs of those two benchmarks gave the
same p95 on both checkouts:

| Benchmark | Base | Branch |
|---|---|---|
| detection latency | 36.9–38.5 ms | 37.4–37.6 ms |
| TC-11 | 43.7–57.5 ms | 35.4–59.3 ms |

A second Monitor re-run had one real-watcher test fail (`test_tc01…`: the
create-then-write race its own comment describes). `test_api.py` then passed
8 of 8 alternating runs across the two checkouts; over the day, the base
commit failed it 1 time in 7 and the branch 0 in 7.

On the day of the final runs the development host was loaded heavily enough
that the **untouched base commit's own** latency benchmarks failed. Measured on
`7dcee2a`:
- `test_detection_latency_under_100ms`: p95 199.5 and 132.6 ms
- `test_tc11_detection_stays_within_budget_under_load`: p95 109.4 ms
- a real-watcher test in `test_api.py` failed 1 run in 3

Timing-bound tests on this branch were therefore compared against the base
commit on the same host at the same time, not against yesterday's numbers.

## Re-test on the Windows VM, 2026-10-04

Same VM (Windows 11 build 26200, VirtualBox, 4 vCPU, 6 GB), quiet: no other
test runs in parallel. The agent's shell was not elevated, so the operator ran
the elevated half (below).

### Suites, first pass

At `102c147` in `C:\URDS-main\.venv`, every suite passed on the first full
pass; no re-run was needed: gateway 86, ledger 99, monitor 500, ml-engine 50
(3 skipped), response 121 (2 skipped), claim matrix 0 failed, Pester 26.

Repeat runs in a fresh venv then found defect 10 and the one `test_tc01`
failure described there; that failure is defect 12. The suites table above is
the state after 9 to 13.

### Caveat: load flakiness

- `test_tc01`'s scenario, 40 runs quiet: the full-size event arrived after a
  median 23 ms, max 26 ms.
- 40 runs with four CPU burners on the 4 vCPUs: median 0.96 s, max 2.0 s. Single
  `handle_event` calls took 950-1900 ms, against 3-17 ms quiet: the watchdog
  thread was not scheduled.
- Across those 120 runs and 60 more of the test alone, no event was ever lost,
  and none would have failed the 5 s wait. The earlier failure needed more than
  5 s; the host then had other suites running in parallel.
- Two other causes, found later the same day:
  - The waits were timed on the slewed wall clock (defect 10).
  - A write landing between two looks at the file produced a false
    "unreadable" (defect 12). That was the fast `test_tc01` failure.
- **Finding, not changed:** with the test process at above-normal priority under
  the same load, arrival fell to median 0.63 s, max 0.99 s, and the 1 s
  `handle_event` stalls disappeared. An encryptor saturates the CPU too, so the
  Monitor's own priority under load is worth a decision. It is a product
  change outside these defects and is left to the maintainer.

### Caveat: defect 7, fresh venv

A new venv from the base Python 3.12.10, `pip` 26.2.1, then each service's
requirements and `scripts/requirements.txt`, one file at a time as the VM
runbook does: every install exit 0, no resolver warning, `pip check`: "No broken
requirements found". streamlit 1.51.0 with Pillow 12.3.0. The dashboard served
`/_stcore/health` "ok" and its page from that venv.

### Live check, unelevated

All six services run natively from the fresh venv, with a fresh ledger and
`RECOVERY_SNAPSHOT_ROOT` as the snapshot source (no VSS). 24 passed, 0 failed,
4 skipped (they need the audit source):

| Check | Result |
|---|---|
| health, all six services and the gateway aggregate | pass |
| 8: `/monitor/attribution` before start | "not started yet: correlation starts with monitoring (POST /monitor/start)" |
| 8: retrain, then `git status` | clean; only `models/` written |
| 4: watch path posted with `/` | stored as `C:\URDS-recheck\unelevated\watch` |
| 4: recover, four files, four spellings (as recorded, `/`, lower case, the pre-fix mixed form) | `integrity_verified: true` for all four; restored bytes match the baseline |
| 3: 20 rapid writes by one process | last full-size event 0.23 s after the last write; `queue_wait_ms` on 40 of 40 suspicious events, max 1.7 ms |
| ledger | every suspicious event has a block; chain verifies |
| gateway | 401 unauthenticated; 403 admin token without the bootstrap secret; routes and `/analyze` with it |

### The elevated half

The operator ran one script from an Administrator PowerShell:
`recheck_elevated.ps1`, with the live checks in `e2e_check.py`. Audit
settings were changed by the operator, not by the agent.

**Machine state, defect 5's own check:**
- The Security log is 1 GiB and the File System subcategory is `Success`.
  URDSAgent's installer left both that way.
- Setup recorded both, left both unchanged, and added an audit rule to
  `C:\URDS-recheck\watch` and `watch2`.
- Reverting `watch2` alone left `watch` and the machine-wide settings alone.
- The final `-Revert` removed only the rules setup had added.
- Before and after compared equal on every recorded item: log size,
  subcategory, rules on both folders, the state file, and shadow copies (none).

Final run, `20261004_120149`, at `ec21a43`: **42 passed, 0 failed.** Defect 12
(`d6313f1`) came after it, so it is covered by the suites and the unelevated
live check at `d6313f1` (25 passed, 0 failed, 4 needing the audit source
skipped), not by an elevated run.

| Re-check | Result |
|---|---|
| 5: 1 GiB log, setup, `-Verify`, second root, `-Revert` | log 1 GiB before and after; subcategory `Success` before and after; no rule left on either folder; reverting the second root left the first untouched |
| 6: `--status-only`, elevated | shadow copies 0 -> 0; "not attempted: --status-only creates nothing" |
| audit probe | a write under the watch path reached the Monitor as a 4663 (`writes_recorded` 0 -> 5) |
| 1: single write by a fresh process | 5 of 5 `certain`, correct PID, writer terminated |
| 2: write then rename by one process | 5 of 5: the rename event `certain`, correct PID, writer terminated |
| invariant: a benign writer, then an encryptor 0.5 s later | 3 of 3 never `certain`, nobody killed; the encryptor named |
| invariant: a second writer after the first one's detection | 2 of 2: the second writer never `certain`, never killed |
| all: every correlated event | 0 of 79 events name the wrong PID |
| 3, 4, 8, ledger, gateway, dashboard | pass, as unelevated |

**Response time, defect 1:** 9 of 10 terminate requests went out 1.0-1.4 s
after detection, inside the 2 s budget. The tenth, the first single write,
went out after 5.2 s, and did so in two runs. It was detected while the
pipeline was still working through the 40 detections of the preceding 20-write
burst: one worker does ML, ledger and response for each in turn, about 200 ms
apiece, 06:21:03.1 to 11.1 in the earlier run. Its question opens only once its
own non-destructive response has gone out. The base commit sent kills through
the same serial queue. **Finding, not changed:** a second process that starts
during a burst waits behind the backlog. Whether escalation should bypass the
queue is a design decision for the maintainer.

**What the first two elevated runs got wrong,** which was the check, not the
product:
- The first run's `e2e_check.py` deleted and recreated the audited watch folder
  before testing. The new folder inherited no audit rule, so Windows wrote no
  4663 for any test write and everything was `unknown`.
- A separate diagnostic (`diag_4663_timing.py`) measured 12 writes across four
  patterns. A 4663's `TimeCreated` is the handle's open, 1-2 ms before the
  write, and it reaches the Monitor 0.6-0.8 s later. That is what defect 1's
  matching assumes.
- The check now empties the folder instead and probes the audit first.
- The second run's two-writer check had the second writer write *after* the
  first writer's detection. That does not breach the invariant; it now has its
  own case.

**Minor findings, not changed:**
- Two `file_baseline` blocks record `file_size: 0` while their `file_hash` is
  the full 16,368-byte file's. The size is read just before the writer's bytes
  land and the hash just after. Recovery verifies the hash, which is right; the
  size field is stale.
- The Monitor subscribes to the Security channel twice per start (`build_source`
  starts the source, then `Attributor.start` starts it again). The second
  handle replaces the first. This is harmless and pre-existing.
