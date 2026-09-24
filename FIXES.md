# Fixes from the Windows integration test

Eight defects found by the Windows 11 VM integration test of commit `7dcee2a`,
fixed on `fix/windows-integration-defects`, one commit per defect. Each entry
says what changed, where, what tests it, and what can only be confirmed on the
Windows test VM. Measured figures in the README and `reports/` are unchanged;
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

## Suites

Baseline at `7dcee2a` and after this branch, same venv (Python 3.12.10,
Windows 11, 4 vCPU), `URDS_WRITE_REPORTS` unset:

| Suite | Baseline (`7dcee2a`) | This branch | New tests |
|---|---|---|---|
| gateway | 86 passed | 86 passed | — |
| ledger | 67 passed | 99 passed | +32 (defect 4) |
| monitor | 410 passed | 500 passed | +50 (1), +10 (2), +17 (3), +10 (4), +3 (8) |
| ml-engine | 45 passed, 3 skipped | 50 passed, 3 skipped | +5 (8) |
| response | 112 passed, 2 skipped | 121 passed, 2 skipped | +6 (4), +3 (6) |
| claim matrix (`--tests`) | 0 failed | 0 failed | — |
| Pester (`scripts/tests`) | — | 26 passed | +26 (5) |

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
