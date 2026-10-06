## 22. A kill still waited behind another writer's escalations (R16)

Found by the full VM test of 2026-10-05 (R16 in
`VM_TEST_REPORT_2026-10-05_dc089ff.md`). Defect 16 fixed the queue in front of
the question (`_work`); this is the queue behind it.

**Measured:**
- 20 rapid writes by process A, then one write by a fresh process B that
  stays alive.
- B's write to B's PID gone: 5.55, 8.73, 3.01, 5.47 and 2.86 s, then 2.39,
  6.25 and 2.00 s on the re-run. That is 1 of 8 within 2.05 s.
- B's question closed on time (`horizon_closed_at` about 1.55 s after
  `observed_at`). Its `/response/terminate` went out 0.9-8.7 s later.
- In front of it were 4-22 of A's escalations, sent one at a time,
  0.30-0.38 s apart. Only the first succeeded. Every later one was refused
  with "PID ... does not exist". The ledger order was `A+ A- A- ... A- B+ B-`.

Where each refused request's time went, measured here before choosing a fix.
The real Response handler ran in-process against a local ledger stub, with a
PID that does not exist, timed with `perf_counter` (median of 8 runs):

| | on `dc089ff` | this commit |
|---|---|---|
| terminate handler, refusing a dead PID, end to end | **252 ms** | **36 ms** |
| of which the ledger write (`log_action`) | 200 ms | 3-13 ms |
| of which `actions.guard` (mostly `_self_and_ancestors`, a psutil walk of the process tree) | 27 ms | 35 ms (unchanged code) |
| `httpx.Client()` construction alone | 189 ms | 211 ms |

Script: `measure_terminate.py` in this package's scratchpad
(`C:\Users\urds\AppData\Local\Temp\claude\C--URDS\7709ef82-504e-411b-9454-a06c9189ed06\scratchpad\wp-a\`).
A Monitor probe of a PID (`attribution.probe_process`) costs about 0.01 ms
here, live or dead.

**Cause:** there were three, and each one stacked on the others.
1. `_escalate_loop` is one thread. It asked the Response service to kill A
   once for every closed `certain` question naming A, and F6 gives A 2-4
   questions per file. After the first request killed A, every later request
   still made the full round trip and was refused.
2. Each refusal cost about 250 ms in the Response service. Its `log_action`
   called `httpx.post`, which builds a new `httpx.Client` for every block: an
   SSL context plus certifi's CA bundle. That took 200 ms of each refusal on
   this VM. The same POST on a reused client takes 5 ms.
3. When the incident's own blocks were already in the chain, each question's
   `attribution_escalation` block was written inline (`pipeline.escalate`)
   before the next question's action was taken. So even a free action still
   waited behind one ledger write per question queued ahead of it.

`test_escalation_bypasses_backlog.py` stubs the Response call as instant, so
it could not see any of this.

**What changed:**
- `services/monitor/pipeline.py`: the Monitor remembers each kill it has
  already made.
  - `TerminationRegistry` / `pipeline.TERMINATIONS` holds every kill the
    Response service confirmed (`status: terminated`). It is keyed by
    **PID plus the process's start time** and also records the image, the
    incident and when the request went out. It is bounded:
    `MONITOR_MAX_TERMINATIONS` (1024) entries, kept for
    `MONITOR_TERMINATION_MEMORY_S` (600 s, monotonic).
  - Before the request, `escalation_action` probes the start time of the
    process it is about to kill (`_writer_started_at`). The value is recorded
    only if that process could be the writer: started no later than the
    write, plus the tolerance.
  - A later answer is closed without a request (`_killed_earlier`) only if
    both of these hold:
    - its write was made by the killed process (`Termination.wrote`): same
      image, the process started by the time of the write, and the write came
      before the kill was asked for;
    - the PID is now gone, or it now belongs to a process that started after
      the write and so cannot have made it.
  - If the probe fails, or the killed process is somehow still there, the
    request goes out as before.
  - Such a question closes with the new result **`terminated_earlier`**
    (`escalation_result`). Its block names the incident whose kill it was
    (`terminated_earlier: {incident_id, response_dispatched_at,
    process_started_at}`), plus `termination: null` and
    `response_dispatched_at: null`. The answer stays `certain`, so the block
    names the PID, as C-16 allows.
  - Only the escalation thread uses the registry
    (`bind_escalation_thread`, a thread-local probe). `pipeline.escalate`
    called anywhere else, including directly by the safety-invariant tests,
    asks the Response service every time, as before. The `escalate()`
    contract and `escalation_action`'s signature are unchanged.
- `services/monitor/app.py` `_escalate_loop`: actions come before blocks.
  - It binds the attributor's probe.
  - While another question is queued, that question's action is taken before
    any owed block is written (`_escalation_act`, then `_escalation_record`).
  - A question with nothing queued behind it and no blocks owed still closes
    through `pipeline.escalate` (`_escalate_one`).
  - Each block still follows its own action and its incident's
    `response_action` block (`_incident_in_chain`, `_work`), in queue order.
  - A question is `task_done` only once its block is written or queued.
- `services/response/app.py`: `log_action` uses one shared `httpx.Client`
  (`_ledger_client`). It is built on a thread when the service starts, so
  the first kill's block does not pay for it either.
- (b) of the brief, a pool that dispatches different PIDs concurrently, was
  **not built**. (a) and the reordering meet the bound. What is still serial
  is one real kill in flight: about 300 ms in the stub. After the Response
  fix it is expected to be tens of ms on the VM, but that is not measured yet
  (see Check on Windows).

**Tests:** `services/monitor/tests/test_escalation_behind_other_writers.py`
(7).
- Setup: the escalation thread is fed directly with 22 of A's closed
  `certain` questions (2-4 per file over 8 files, the F6 shape), then B's.
  The Response stub takes 300 ms per call and refuses a PID that is not
  running, as the real one does. Ledger writes take 20 ms. The thread's
  client is built before anything is timed, as `/monitor/start` does.
- `test_a_fresh_writers_kill_is_not_queued_behind_a_dead_writers_escalations`:
  B's request must go out within 500 ms of its question closing, and A gets
  exactly one request.
  - **This commit: 0.302 s, 3 runs out of 3** (0.302, 0.302, 0.302). The
    0.30 s is A's own kill, in flight when B closed.
  - **On `dc089ff`: 7.09 s with 22 requests to A, fail** (7.49 s on a first
    run).
- `test_the_later_questions_about_a_killed_process_say_so_truthfully`: the
  later questions say `terminated_earlier`, name A and the first incident,
  and record no dispatch. **On `dc089ff`: fail**, 4 requests for 4 questions.
- `test_a_stale_answer_about_the_killed_process_does_not_kill_the_pids_new_owner`:
  the PID is reused, with the same image, before A's second question is
  dispatched. The new owner must not be killed for A's write. **On
  `dc089ff`: fail, the new owner was killed.** This is a wrong-PID kill on
  the base commit, closed here as a side effect.
- Guards that pass on base by construction and pin what the fix must not
  break:
  - `test_a_fresh_pid_is_never_skipped_because_another_pid_was_killed`: same
    image, different PID;
  - `test_a_reused_pid_is_still_killed_when_its_own_answer_is_certain`: same
    PID number, a later start time, a write after the kill;
  - `test_a_reused_pid_whose_new_owner_also_exited_is_not_called_terminated_earlier`;
  - `test_direct_escalate_callers_are_unchanged`.

`services/response/tests/test_ledger_client_reused.py` (2). Every
`httpx.Client` built is counted, with a mock transport as the ledger.
- 5 ledger writes must build one client.
- 4 refusals of a dead PID must build at most one, and still write 4 blocks.
- **Both fail on `dc089ff`**: "5 httpx clients built for 5 ledger writes"
  and "4 httpx clients built for 4 refusals".

Proof files are in the scratchpad folder named above:
`base_monitor_defect22.txt` and `base_response_defect22.txt`. They come from
the new tests run against a `git archive` of `dc089ff`.

Suites, same venv:
- monitor: 570 before, 577 after (570 + 7).
  - The first full run here had 4 failures while other agents loaded the 4
    vCPUs. Three were latency budgets: `test_detection_latency_under_100ms`,
    `test_b_the_same_twenty_through_one_lane_still_take_one_grace` and
    `test_lock_retry_stays_inside_the_detection_budget`.
  - The fourth was `test_c_response_dispatched_at_is_recorded_when_the_pipeline_asks`,
    where the wall clock read 1 µs earlier than before, in `pipeline.run`'s
    path, which this commit does not touch.
  - All 4 passed when run alone, and the next full run was 577 passed;
- response: 127 before, 129 after (+2 skipped, unchanged);
- gateway 91, ledger 99 and dashboard 4, unchanged.

**Check on Windows** (for the addendum):
- R16: 20 rapid writes by A, then one write by a fresh B. B's write to B's
  PID gone must be ≤ 2.05 s in **8 of 8** runs.
- `e2e_check.py` D1 straight after the D3 burst: about 1.6 s, not 4.03 s.
- In the ledger, the count of `termination_refused_or_unreachable` results
  on `certain` answers should fall sharply (it was 99). `terminated_earlier`
  appears in its place, one per extra question about an already-killed PID.
- The Response service's own `response_action` blocks for refused
  terminates should mostly disappear, because the requests are no longer
  sent.
- Time one real `/response/terminate` that succeeds, on the VM. It is the
  one cost still serial on the escalation thread.

**Not changed:**
- The kill gate (`Attribution.kill_authorised`), `Attributor.verify`, the
  horizon, `COMPETITION_MS`, `WINDOW_MS`, and every test in the
  safety-invariant table.
- A request is skipped only when it is known to be about an already-killed
  process. A PID never killed, a reused PID's own write, and an unprobeable
  PID all make the request as before.
- `pipeline.escalate`'s contract and `escalation_action`'s signature
  (package E2 hooks it).
- C-16: a `terminated_earlier` block names the PID only because the answer
  is `certain`.
- No bound-claim script enumerates escalation results (`claim_matrix.py`,
  `ledger_coverage.py`, `tamper_sweep.py`, `pipeline_governance.py`), and no
  report was regenerated.
- Outside this package, reported rather than changed:
  - `actions.guard` walks the process tree (`_self_and_ancestors`, about
    30 ms) before it checks that the PID exists (Response, package E1's
    file).
  - A PID reused between a question's close and its first kill request is
    still killed. Before this commit the stale-answer test showed the same
    hazard after a kill, and that case is now closed. The narrower window
    remains: closing it means re-applying `verify`'s start-time rule at
    dispatch, which is a gate change for the lead to decide.
