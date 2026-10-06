## 26 (E1). The Response service could not suspend anything (F2b, Response side)

Found by the VM test of 2026-10-05 ("F2b" in its open faults). Package E1 of
the 2026-10-05 fix session; package E2 builds the Monitor side against the same
contract.

**What was wrong:** `POST /response/suspend` returned 404. The Response
service had no suspend, no resume, no lease and no ledger block for either. The
2026-10-04 session left F2b blocked ("F2b: blocked", above), so nothing on
this branch could freeze a writer before the kill gate opened at the horizon.

**Measured** (this VM, unelevated, `dc089ff` and this commit):
- On `dc089ff`: `/response/suspend`, `/response/resume` and `/response/leases`
  are 404 at the Response service and at the gateway.
- `psutil` suspend nests here, as `5cacb70` recorded. A heartbeat child
  suspended twice and resumed once stayed frozen; a second resume woke it; an
  extra resume on a running process did nothing.
- `psutil.Process.status()` reports `running` for a suspended process on
  Windows. The tests judge "frozen" by whether a heartbeat file grows instead.
- Killing the venv launcher kills the interpreter it started (`Popen.pid` is
  not the process that runs the code, as in defect 23).

**Cause:** not implemented.

**What changed:**
- **`services/response/leases.py`** (new): the lease table.
  - One lease per PID. A second suspend of a held PID suspends nothing and
    returns the same lease with `already_held: true`, never a second suspend.
  - `lease_seconds` is capped at `RESPONSE_LEASE_MAX_SECONDS` (default 10).
  - Expiry runs on an injectable monotonic clock, not the slewed wall clock;
    `expires_at` is reported in UTC.
  - A lease ends in one of four states, and each leaves the process running
    or gone, never frozen:
    - `resumed`: by `/resume`, by the reaper when it expires (thread, every
      0.1 s), or at shutdown (FastAPI lifespan, and `atexit` as a backstop);
    - `terminated`: by `/terminate`, without resuming;
    - `gone`: the process exited while held.
  - A resume of a PID the table does not hold touches nothing.
  - One failed resume does not stop the rest; the failed lease stays held,
    so the reaper and the watchdog try again.
- **`services/response/lease_watchdog.py`** (new): the backstop for a Response
  process that dies without running its shutdown.
  - A child process, started at service startup so the first suspend does
    not wait for it.
  - It is told about a lease before the suspend, and when the lease ends,
    one JSON line each on its stdin.
  - It resumes what is still held on stdin EOF, when the service's PID
    disappears, or 2 s (`RESPONSE_WATCHDOG_GRACE_SECONDS`) after a lease's
    own expiry. Before resuming, it checks the PID's start time.
  - It is started through a short-lived intermediate process, so it is not
    a descendant of the service. A process-tree kill of the service then
    does not reach it.
  - While the watchdog is configured but not running, suspends are refused
    (`WATCHDOG_UNAVAILABLE`). `RESPONSE_LEASE_WATCHDOG=0` turns it off, with
    a warning at startup.
- **`services/response/actions.py`**: `vet_suspend`, `suspend_process`,
  `resume_process`, `SuspendRefused`. Every refusal has a code. In order:
  - `PID_NAMESPACE_ISOLATED`: Response is not in the host's PID namespace
    (`/.dockerenv` or `/run/.containerenv`; `RESPONSE_PID_NAMESPACE=host` or
    `=container` overrides).
  - The kill gate's own `guard()`, unchanged, which includes
    `_guard_image_path`. Its messages map to `RESERVED_PID`,
    `RESPONSE_OR_ANCESTOR`, `PID_GONE`, `NOT_INSPECTABLE` and
    `SYSTEM_PROCESS`; anything unmatched is `GUARD_REFUSED`.
  - `LEASE_WATCHDOG`: the watchdog itself.
  - `MONITOR_OR_ANCESTOR`: the Monitor (`URDS_MONITOR_PID`, comma-separated)
    or any of its ancestors.
  - `PID_REUSED`: the live process was created more than 50 ms after
    `started_at`, or runs an image other than `image`.
  - `IDENTITY_UNPROVEN`: neither `image` nor `started_at` was given, or
    neither could be read. This fails closed.
  - `NOT_PERMITTED`: the suspend call itself was refused.
- **`services/response/app.py`**:
  - `POST /response/suspend`, `POST /response/resume` and
    `GET /response/leases`, as in the contract.
  - `/terminate` accepts `lease_id`. After a successful kill, it closes any
    lease held for that PID as `terminated` and returns `lease_id`,
    `lease_released` and, if the named lease was not the one closed, a
    `lease_note`. A refused kill leaves the lease alone, so it still
    expires.
  - The suspend route itself refuses `attribution_confidence: unknown`
    (`NOT_ATTRIBUTED`).
  - Ledger blocks:
    - `process_suspended` for a suspension and for every refusal
      (`outcome: suspended | refused`, `suspended`, `code`);
    - `process_resumed` whenever a lease ends other than by a kill
      (`outcome: resumed | process_gone`, `reason`,
      `requested_by: caller | lease_expiry | shutdown | atexit`).
    - Both carry the PID with the gate that allowed it:
      `attribution_confidence`, `attribution_source`, `attribution_reason`,
      `gate: "suspend_authorised"` (C-16). The three attribution fields are
      required on the request (400 without them).
    - Blocks join by `lease_id` and `incident_id`. The terminate block carries
      `lease_id` and `lease_released`.
- **`services/response/Dockerfile`**: copies `leases.py` and
  `lease_watchdog.py`. Without them, the image would fail at import.
- **`services/gateway/routers/response.py`**: proxies the three new routes.
  They are admin-only, like every response action. `TerminateWithLeaseRequest`
  subclasses the shared `TerminateRequest` (`models.py` is unchanged), and
  forwards `lease_id` only when one is given.
- **`docs/openapi/gateway.yaml`**: the three paths, the five schemas, every
  409 code, and the optional `lease_id`/`lease_released` on terminate.
  **`docs/api_spec.md`**: section 4, the contract and how it is implemented.

**Tests:** `services/response/tests/suspend/` (49) and
`services/gateway/tests/test_response_suspend_proxy.py` (12).
- `test_lease_table.py` (19): fakes that nest like `NtSuspendProcess`, and an
  injected clock. Covers: second suspend is a no-op; cap; no early expiry;
  expiry resumes; idempotent resume; never resumes a stranger; shutdown
  resumes all; one failed resume does not stop the rest; terminate closes
  without resuming; a dead holder is closed before a new lease; the watchdog
  hears before the suspend; no watchdog, no suspend; the reaper thread.
- `test_suspend_real.py` (24): real heartbeat children through the real app.
  Covers:
  - suspended then resumed, with both blocks carrying the gate;
  - second suspend is a no-op, and one resume unfreezes (so it was suspended
    once);
  - an expired lease resumes;
  - leaving the TestClient (lifespan shutdown) resumes two held children;
  - terminate with a lease releases it, and a late terminate says the lease
    was over;
  - refused: wrong `started_at`, wrong image, no identity, a System32 image
    (faked as in TC-26), this process and its ancestors, the Monitor, an
    ancestor of the Monitor (a grandchild plays the Monitor), a PID that does
    not exist, `unknown` attribution, a missing gate field (400), the
    container namespace, the watchdog. Each refusal is recorded.
- `test_lease_watchdog.py` (6), using `_holder.py`, a stand-in service that
  takes a real lease with the real watchdog and never reaps:
  - hard-killed: the child resumes;
  - process-tree-killed: the child resumes, and the watchdog is not in the
    tree;
  - alive but stuck: the watchdog resumes it after lease plus grace;
  - a recycled PID is left alone;
  - the real app starts its watchdog and refuses to suspend it;
  - an unstartable watchdog refuses the suspend.
- No-leftover safety: each child is resumed eight times and then killed in
  the fixture's `finally`, at `pytest_sessionfinish` and at `atexit`
  (`tests/suspend/conftest.py`). No test sleeps more than 1 s at a time.
  After each run, a process scan found 0 children or watchdogs left.
- Run 3 times: 49/49 each time (about 15 s).
- **On `dc089ff`: 30 failed and `test_lease_table.py` failed to collect**
  (`No module named 'leases'`). Most failures are `404 Not Found` (14) and
  `assert 404 == 409` (10). Gateway: **11 of 12 fail on `dc089ff`** (404).
  The one that passes checks that terminate without a lease forwards the same
  body as before. Proofs: `C:\URDS-wp-e1-proofs\e1_base_proof_response.txt`,
  `e1_base_proof_gateway.txt`.
- Suites: response 127 + 2 skipped -> **176 + 2 skipped**; gateway 91 ->
  **103**. The openapi parity tests pass. `claim_matrix.py`: 0 failed.

**Check on Windows** (done here unelevated against a real uvicorn Response
on port 18604, with the venv launcher; `C:\URDS-wp-e1-proofs\e1_live_check_final.txt`):
- A real `python.exe` heartbeat child was suspended: 0 heartbeat bytes and
  0.0 ms CPU over 0.5 s. A second suspend returned `already_held` with the
  same lease. Resume brought the heartbeat back within 0.03 s. A second
  resume returned `resumed: false`.
- A 1.0 s lease expired and the process resumed on its own (state `resumed`).
- A wrong `started_at` was refused with `PID_REUSED`; the child kept running.
- The service was stopped mid-lease (30 s lease) four ways, and each time the
  heartbeat came back within 0.016-0.219 s:

  | How it was stopped | What resumed the process |
  |---|---|
  | `TerminateProcess` on the serving interpreter | the watchdog |
  | killing the venv launcher (x3) | the watchdog |
  | `taskkill /T /F` on the launcher (x3) | the watchdog |
  | CTRL_BREAK, a graceful stop | the lifespan |
- **Before the watchdog was detached,** `taskkill /T /F` took the watchdog
  down with the service, and the child stayed frozen until the test's cleanup
  resumed it (`e1_tree_kill_before_detach.txt`).
- With a ledger that answers (`e1_latency.txt`): the suspend round trip had a
  median of 274 ms (252-351) and resume 208 ms, over 10 each. The suspension
  itself is sub-millisecond and happens before the ledger write. Almost all
  of the round trip is `log_action` (see "Found outside this package").
- Still for the VM: the same check elevated, with E2's Monitor calling it.
  `Get-Process -Id <pid>` CPU staying flat while suspended is the
  operator-visible version of the heartbeat check.

**Not changed:**
- `guard()`, `_guard_image_path`, `terminate_process`, `PROTECTED_NAMES` and
  `PROTECTED_IMAGE_ROOTS`.
- `/terminate`'s kill behaviour. It only accepts and releases a `lease_id`,
  and adds `lease_id`/`lease_released` to its block and its response.
- `/trigger`, `/isolate`, recovery, `models.py`, the Monitor (E2),
  `scripts/ledger_coverage.py` (E2) and README (text below, for the lead).
- No existing test was edited.

**Limits, named rather than left to be found:**
- **Docker.** See the README text below. The refusal is explicit and recorded;
  the service does not try.
- **`URDS_MONITOR_PID` unset.** The Response service cannot tell which process
  is the Monitor, and only the Monitor's own gate keeps it from naming
  itself. Whoever starts the services should set it.
- **What the watchdog cannot survive:** being killed itself; a whole-session
  or job kill that includes it; or a host crash, after which nothing is
  frozen anyway.
- **POSIX.** `terminate_process` sends SIGTERM first. A stopped process does
  not act on it, so a suspended process is killed by the SIGKILL after
  `TERMINATE_GRACE_SECONDS` (1 s). Windows `TerminateProcess` is immediate.
  Not changed, because terminate's behaviour is fixed.

**Contract notes for E2 and the lead:**
- `started_at` is the process's creation time (`psutil create_time()`),
  as epoch seconds or ISO-8601. Sending the write time instead is also safe,
  because both checks are "created no later than".
- The 409 body is the project's error envelope with `code` and `message` also
  at the top level. Through the gateway, it arrives as `DOWNSTREAM_ERROR`
  with that body in `details`.
- Refusals are recorded as `process_suspended` with `outcome: refused`, so
  E2's C-16 scan sees them as gated PID blocks.
- `/resume` of an unknown lease returns 200 `resumed: false`, `state: unknown`.

**Found outside this package:**
- **`log_action` in `services/response/app.py` builds a new `httpx` client
  per ledger write.** That cost a median of 201 ms here, against 11.8 ms on a
  shared client (`e1_httpx_cost.py`): defect 13's cause, in the Response
  service. Every `/terminate` pays it before it returns. It is a plausible
  part of R16's 0.30-0.38 s spacing between terminates. Not changed here,
  because terminate's timing is package A's.
- The Response service's `RequestValidationError` handler cannot serialise a
  validator's `ValueError` (`exc.errors()` carries the exception), which would
  turn a 400 into a 500. `ResumeRequest` checks "lease or PID" in the route
  instead.

### README text for lead

> **Suspend-first response and Docker.** `POST /response/suspend` freezes a
> process under a lease that ends on its own. It is resumed when the lease
> expires, when Response stops, or by a watchdog process if Response is killed
> outright. In Docker Compose the Response container has its own PID
> namespace: the host PID the Monitor names does not exist inside it, or names
> a different process. So Response **refuses every suspend there** with
> `409 PID_NAMESPACE_ISOLATED`, and records the refusal in the ledger as a
> `process_suspended` block with `outcome: refused`. It does not try. To
> suspend host processes, run Response natively on the host, as on the
> Windows VM. A container started with `pid: host` can declare it with
> `RESPONSE_PID_NAMESPACE=host`. When the Monitor runs as a separate process,
> set `URDS_MONITOR_PID` to its PID so Response refuses to suspend the Monitor
> or its ancestors.
