## 25. One incident per watchdog notification, not per file (F6)

Found by the full VM test of 2026-10-05 (F6 in
`VM_TEST_REPORT_2026-10-05_dc089ff.md`). Open since the 2026-10-04 run.

**Measured:** in the elevated run 2 ledger
(`C:\URDS-latest-run\20261005_203206\run2\data\ledger.db`), read read-only:
- 530 `file_event` blocks for 275 suspicious files. Per file: 40 files had 1
  block, 222 had 2, 6 had 3, 7 had 4. (The report's own analysis counted
  522 for 273 files, median 2, max 4, 6.06 blocks per file.)
- The commonest sequences per file were `created, modified` (161 files) and
  `modified, modified` (51).
- Gap from one notification to the next `modified` on the same path, from the
  escalation blocks' `observed_at`: median 11.3 ms, p90 21.8 ms. 233 of 243
  were within 50 ms and 239 within 100 ms. The rest were 240 ms (an invariant
  check, a second writer) and about 60 s (a later run on the same folder).
- In 15 files with more than one notification, the content hash changed
  between notifications.
- Every notification had its own question, `file_event`, two
  `response_action` blocks (the Monitor's and the Response service's) and
  `attribution_escalation`. A `certain` one also had its own terminate
  request: 99 were refused because the PID was already dead.

**Cause:** `_correlate` opened a new incident for every suspicious
notification: `incident_id_for(event_id)`, a new question, a new detection on
`_work`. Nothing asked whether an incident for that file was already open.
Windows reports one write as 1-3 notifications, so one write became 2-4
incidents. R16 (defect 22) is the escalation queue that those extra
incidents fill.

**What changed** (`services/monitor/app.py`, plus one field in `pipeline.py`):
- **The join rule.** A suspicious notification joins the open incident for
  its file (`_join_open_incident`, called at the top of `_correlate`) when all
  of these hold:
  - it is `modified`, not a rename;
  - its content hash equals the hash the incident's first notification read,
    so it reports the same write again;
  - an incident for the same path (normcase'd, as attribution compares paths)
    has its question **open**;
  - that incident was opened after the last `created`, `deleted` or `renamed`
    notification for the path. `handle_event` gives each such notification a
    sequence number on the watchdog thread, so the order is the
    notification order;
  - the incident's first read was at most `MONITOR_COALESCE_MS` ago. The
    default is 100 ms, which covers 239 of the 243 measured follow-ups.

  Otherwise the notification opens its own incident, exactly as before.
- **A joined notification** is still recorded on `/monitor/events`, in order.
  It carries the incident's `incident_id` and `coalesced_into`. It opens no
  question and queues no detection, so it gets no `file_event`, no
  `response_action`, no trigger and no escalation of its own. The first event
  lists the joined IDs in `coalesced_event_ids`. When the question closes,
  every joined event gets the closing answer, so none is left reading
  "pending".
- **The question grows to cover the joined write.** Joining moves the
  question's read time and horizon to the joined notification's read
  (`horizon_from`, `read_at`, `settle_at`, `settle_mono`). The match window
  keeps its start. So:
  - the competition window is the union of both notifications' windows;
  - the question closes one full horizon after the *later* read;
  - a record for the joined write, including a second writer's, that arrives
    late but inside its horizon is still counted;
  - CERTAIN still means exactly one writer across the whole span.

  The cost: a kill can come up to `MONITOR_COALESCE_MS` later. In the measured
  shape that is about 11 ms.
- **Write order against the sweep.** The horizon is written before the read
  time. `Attributor.recheck` reads the read time before the horizon, so a
  sweep running at the same moment can see a longer horizon with the old
  window, but never the wider window with the old horizon.
  - A question cannot close at its horizon while it can still be joined: 100
    ms is far less than the 1.55 s span.
  - A question that closes early as `ambiguous` at the same instant still
    ends with no kill, whatever the joined write adds.
- **When a question closes**, the pending thread's callback is now
  `_question_closed`. It marks the incident closed, so nothing more joins it,
  hands the answer to the joined events, and then calls `_on_question_closed`
  unchanged. Open incidents are indexed by path, for joining, and by
  question, for closing. Both indexes are bounded by `ATTRIBUTION_MAX_ANCHORS`,
  and so is the per-path sequence table (4x).
- **`pipeline.record_escalation`** adds one field: `coalesced_event_ids`, the
  notifications the incident covered. This is why `horizon_closed_at` can be
  up to `MONITOR_COALESCE_MS` later than `observed_at` plus the horizon.
- **Terminate requests.** With one question per incident there is one
  escalation, and so at most one terminate request per incident. A later
  incident naming a PID that is already handled is package A's mechanism
  (defect 22). It is not built here.
- **E2's hook.** `first, _ = attributor.verify(first)` and the lines around it
  are unchanged. The join returns before `attributor.resolve`, so a joined
  notification will not reach E2's `on_first_answer` hook either. That
  matches "at most one suspend per PID per incident".
  `escalation_action`'s signature is unchanged.

**The two `response_action` blocks per incident: both kept.** They record
different things:
- **The Response service's block** (`/response/trigger`, `action: "trigger"`)
  is the actor's record. It holds what was asked (`action_required`), whom it
  targeted (`process_id`, only when a kill was asked for, per C-16), on what
  evidence (`attribution_confidence`, `attribution_reason`,
  `attribution_candidates`, `process_image`), and what it did
  (`actions_taken`).
- **The Monitor's block** (`pipeline.run`) is the detector's record of that
  outcome, joined to the file. It is the only response-hop block with
  `file_path` and `file_hash`, and it holds the full governance record
  (`validation_state`, `policy_version`, `admissibility`).
- Removing the Monitor's block would remove what `ledger_coverage.py`
  (`ADJUDICATION_BLOCK_TYPES`, record completeness), TC-23
  (`test_tc23_chained_record.py` asserts `["file_event", "response_action"]`)
  and `pipeline_governance.py` (`ledger_response_action` hop) count. Removing
  the Response service's block would remove the actor's own C-16-checked
  record. Either removal would move a bound claim or edit a test.
- Coalescing removes the duplicate *pairs*: in the replay, `response_action`
  blocks went from 1,112 to 652.

**Tests:** `services/monitor/tests/test_one_incident_per_file.py` (13). The
horizon clock is injected (`Clock`), so no test waits for a horizon. The
longest sleep is 0.3 s.
- Fix tests (fail on base):
  - `test_created_then_two_modified_are_one_incident`: one question, one
    `file_event`, one trigger, one terminate and one escalation for
    `created, modified, modified`. All three events are on `/monitor/events`
    with the same incident, and the escalation lists the two joined IDs.
  - `test_the_joined_notifications_carry_the_closing_answer`.
  - `test_an_older_incident_still_answers_its_joined_notifications`: a newer
    incident on the same path (other bytes) does not orphan the older one's
    joined events.
  - `test_the_lanes_join_in_order_too`: the watchdog path, with correlation
    on the lanes.
  - `test_a_joined_notifications_write_is_waited_for_over_its_own_horizon`:
    nothing closes between the first read's horizon and the joined read's.
  - `test_a_second_writer_is_seen_and_lowers_confidence[identical_bytes]`:
    another PID writes identical bytes after the first read. The incident
    names both, is not CERTAIN, and nobody is killed.
- Guard tests (pass on base and now, for what must not change):
  - `test_a_second_writer_is_seen_and_lowers_confidence[other_bytes]`;
  - `test_different_bytes_are_never_folded`;
  - `test_a_created_notification_never_joins`;
  - `test_a_new_file_after_a_deletion_is_never_folded`;
  - `test_a_rename_is_handled_as_before`;
  - `test_a_notification_past_the_coalescing_window_opens_its_own_incident`;
  - `test_a_notification_after_the_question_closed_opens_its_own_incident`.
- **On base `dc089ff`: 6 failed, 7 passed.** Run on a clean `git archive
  dc089ff` export with this test file copied in:

  ```
  FAILED test_created_then_two_modified_are_one_incident
      AssertionError: 3 attribution questions opened for one write
  FAILED test_the_joined_notifications_carry_the_closing_answer
      KeyError: 'coalesced_event_ids'
  FAILED test_an_older_incident_still_answers_its_joined_notifications
      KeyError: 'coalesced_into'
  FAILED test_the_lanes_join_in_order_too
      assert 3 == 1   (opened())
  FAILED test_a_joined_notifications_write_is_waited_for_over_its_own_horizon
      AssertionError: {'closed': {'verified': 1}, ...}   (the first question closed alone)
  FAILED test_a_second_writer_is_seen_and_lowers_confidence[identical_bytes]
      KeyError: 'coalesced_into'
  ```
- **This commit:** 13 passed, three runs in a row (3.3 s, 3.6 s, 3.8 s).
- **Monitor suite:** 570 passed on base, 583 passed now (570 + 13). No
  existing test edited.
- **Bound claims.** `ledger_coverage.py`, `pipeline_governance.py`,
  `claim_matrix.py` and `tamper_sweep.py` were run (with `URDS_WRITE_REPORTS`
  unset) on the base export and on this commit. Their output is identical
  apart from timestamps: 100.0% coverage, 36/36 complete, 0 unsupported PIDs,
  all governance gates PASS, 0 claims failing verification. None of these
  scripts can coalesce: each sends one notification per distinct path with no
  attribution source, so no question opens.
- **An existing test that shaped the rule.** The first version joined on path
  alone, and `test_correlation_lanes.py::test_c_a_files_events_reach_the_pipeline_queue_in_order`
  failed: four rewrites of one file, each must reach `_work`. That is why
  different bytes are never folded. The test passes unchanged.

**Replay** (`docs/fixes_drafts/defect-25_replay.py`):
- What it replays: the run 2 ledger's per-file notification sequences (types,
  gaps, content changes, the PIDs each answer listed), through the real
  `handle_event`, correlation lanes and `_correlate`.
- Stubs: a fake kernel-grade source (1,500 ms horizon, records 300 ms late),
  ML, the ledger, and a Response stub that writes its own `response_action`
  blocks and refuses a PID it already killed.
- Fidelity: the base replay reproduces the run's distribution exactly (40 /
  222 / 6 / 7).

| | base `dc089ff` | this commit (2 runs) |
|---|---|---|
| suspicious notifications on `/monitor/events` | 530 | 530, 530 |
| joined to an open incident | 0 | 227, 228 |
| incidents per suspicious file, mean (median, max) | 1.93 (2, 4) | 1.10 (1, 2), 1.10 (1, 2) |
| files with 1 / 2 / 3 / 4 incidents | 40 / 222 / 6 / 7 | 247 / 28 / 0 / 0, 248 / 27 / 0 / 0 |
| `file_event` blocks | 530 | 303, 302 |
| ledger blocks per suspicious file | 7.90 | 4.58, 4.57 |
| terminate requests (refused) | 52 (4) | 48 (0), 48 (0) |

Notes on the table:
- "Ledger blocks per suspicious file" counts every block that names the file
  or one of its incidents, including the stub Response service's blocks. It
  is not the report's 6.06 metric, which was computed differently on the real
  chain. Compare the two columns, not either one with 6.06.
- The files still at 2 incidents are those whose run had `created, created`,
  `renamed, renamed`, changed bytes, or a gap over 100 ms. All are kept apart
  on purpose.

**Live, unelevated (secondary):** the real watchdog on a temp dir, 20 new
48 KB files:
- base: 37 suspicious notifications, 17 files with 2 incidents;
- this commit: 39 notifications, 19 files with 2 incidents, 0 joined.

Unchanged, as designed: with no attribution source no question opens, so
there is nothing to join. **Coalescing only acts where a question is open,
that is elevated with the 4663 source.** The unelevated chain still has about
2 incidents per new file.

**Check on Windows:** the elevated full run (run 2's shape). Then
`ledger_coverage.py --ledger-db <run>\data\ledger.db`:
- 0 unsupported;
- `file_event` blocks per suspicious file about 1.1, not 1.91;
- incidents per file median 1;
- `attribution_escalation` blocks with a non-empty `coalesced_event_ids` on
  most files;
- `termination_refused_or_unreachable` falls together with defect 22;
- detection 130/130 (`simulator_sweep.py`).

Then check one `created, modified` file on `/monitor/events`: two events, the
second with `coalesced_into` and the closing answer.

**Not changed:**
- the kill gate (`kill_authorised`), `HORIZON_MS`, `COMPETITION_MS`,
  `WINDOW_MS`, the eviction watermark, and every test in the safety-invariant
  table;
- classification and detection: no verdict path was touched, so detection
  stays 130/130;
- the rename lookup (both names);
- `_escalate_loop`, `request_termination`, `escalation_action`,
  `escalation_result` (package A);
- both `response_action` blocks;
- unelevated behaviour;
- the chain does not hold a joined notification's hash as its own block.
  Joining requires the same hash, so the opener's `file_event` already holds
  it.
