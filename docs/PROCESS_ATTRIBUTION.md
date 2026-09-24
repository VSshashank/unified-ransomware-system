# Process attribution — naming the process behind an alert

**Item AS. Table 9.7 row TC-26.**

> ## What this closes, and what it does not
>
> Before this, URDS could **terminate** a process and could not **find** one.
> `/response/terminate` really did SIGTERM then SIGKILL, guarded, measured at
> 91 ms against a 2 s target — and TC-07 proved it by handing in the PID of a
> process the test had spawned itself. Nothing ever answered the other half.
>
> So `handle_event` set `process_id` to `None` for every filesystem detection,
> and the pipeline downgraded the response from `terminate_process` to
> `isolate_and_log`. Ransomware was detected, scored, adjudicated, chained and
> flagged for isolation — and kept running.
>
> This document is the attribution layer that answers *who*. It does **not**
> change the detection path, the governance layer, or any Phase 5–8 result.

---

## 1. The boundary this ran into first

**Windows will not tell an unprivileged process who wrote a file.** Every route
to that fact is privileged. That is an OS design decision, not a gap in this
project, and it sets the shape of everything below: attribution is available
when the Monitor is elevated and the audit policy is on, and unavailable
otherwise — and the unavailable case has to be a first-class, legible state
rather than a silent null.

### The route that looks obvious and does not work

Asking `psutil` which process holds the file open. Measured on the development
host, against a process that was holding the file open and writing to it:

```
open_files scan: 25180 ms, found=[]
```

**25.2 seconds for one lookup, and no match.** Against a 2-second response
budget. On Windows `psutil.open_files()` enumerates system handles, needs
elevation for other users' processes, and still missed the writer. It is not
implemented here and should not be.

### The three routes that do work

| | Source | Sees in-place encryption? | Install | Latency |
|---|---|---|---|---|
| 1 | ETW `Microsoft-Windows-Kernel-File` | yes — every write | admin + an ETW consumer | sub-ms |
| **2** | **Security channel, Event ID 4663** | **yes** | **admin only, no install** | **tens of ms** |
| 3 | Sysmon Event 11 / 23 | **no** — create and delete only | Sysmon service | ms |

**Route 2 is implemented.** `pywin32` was already available, tens of
milliseconds is nothing against a 2-second budget, and it needs no third-party
software on the host. Route 1 is higher fidelity and is the natural upgrade —
`AttributionSource` exists so that it is a one-class change rather than a
pipeline change. Route 3 cannot see an in-place write at all, so it could only
ever corroborate.

---

## 2. The answer is a confidence, never a bare PID

`resolve()` returns an `Attribution`, because a bare PID cannot distinguish

- *one process wrote this path and nothing else touched it*, from
- *three did, here is the most recent one*

and those two must reach different decisions.

| Confidence | When | Authorises a kill |
|---|---|---|
| `certain` | exactly one PID wrote this exact path inside the window, from a **kernel-grade** source | **yes** |
| `probable` | one PID but an inferring source, **or** several PIDs — most recent reported | no |
| `unknown` | no matching write, or no source available | no |

### Why the asymmetry

Failing to kill leaves an encryptor running for the seconds it takes an
operator to act. Killing the wrong process can take down anything on the host.
**The first failure is recoverable and the second is not**, so only the level
that names exactly one candidate may ask for a kill.

That makes this layer **strictly additive**: `probable` and `unknown` both fall
through to `isolate_and_log`, which is exactly what every filesystem event did
before attribution existed. It can add kills the evidence supports; it cannot
turn a guess into a dead process.

---

## 3. Setup

Two privileged operations, both performed and verified by one script:

```bash
powershell -ExecutionPolicy Bypass -File scripts/setup_attribution_audit.ps1 -WatchPath D:\watched_files
```

It enables the File System audit subcategory for Success, applies a
`WriteData, AppendData` SACL **scoped to the watched directory** (a machine-wide
rule floods the Security log), raises the Security log size, and then **writes a
probe file and confirms a 4663 actually came back** — so a green run means the
pipeline works, not that two commands returned zero.

```bash
# check without changing anything
powershell -File scripts/setup_attribution_audit.ps1 -WatchPath D:\watched_files -Verify

# undo both steps
powershell -File scripts/setup_attribution_audit.ps1 -WatchPath D:\watched_files -Revert
```

Then start the Monitor **from an elevated shell** — the subscription needs the
same privilege — and check:

```bash
curl http://localhost:8001/monitor/attribution
```

Every failure mode here is configuration, and from the outside they all look
identical to a quiet filesystem. That endpoint is what makes the difference
legible:

```json
{
  "source": "windows-security-4663",
  "available": false,
  "kernel_grade": true,
  "error": "could not subscribe to the Security channel: (5, 'EvtSubscribe', 'Access is denied.')",
  "writes_recorded": 0,
  "window_ms": 750,
  "competition_ms": 3000,
  "grace_ms": 0,
  "horizon_ms": 0.0,
  "pending": {"running": false, "open": 0}
}
```

(`horizon_ms` is the *source's* delivery horizon: `0.0` here because the source
that failed to start was replaced by `NullSource`; `1500` once the Security
channel subscription is live.)

### Configuration

Defaults changed with defect 1 of the Windows integration test (`FIXES.md`).
Each one is justified in `services/monitor/attribution.py` against the VM's
measurement of 4663 delivery: 35 writes, min 390 ms, median 1000 ms, max 1032 ms.

| Variable | Default | What it does |
|---|---|---|
| `ATTRIBUTION_SOURCE` | `auto` | `auto`, `security`, or `off` |
| `ATTRIBUTION_WINDOW_MS` | `750` | how far before the event, **on the event's own clock**, a write explains it |
| `ATTRIBUTION_COMPETITION_MS` | `3000` | how far back any *other* writer makes the answer ambiguous (only ever lowers confidence) |
| `ATTRIBUTION_GRACE_MS` | `0` (was `250`) | how long the first look waits, charged from when the event was observed |
| `ATTRIBUTION_HORIZON_MS` | `1500` | how late a record may still arrive; nothing is `certain` until it has closed |
| `ATTRIBUTION_CLOCK_TOLERANCE_MS` | `50` | slack between TimeCreated and the observation time (two 15.625 ms ticks, and margin) |
| `ATTRIBUTION_SWEEP_MS` | `100` | backstop interval of the open-question sweeper |
| `ATTRIBUTION_MAX_PENDING` | `4096` | open questions held at once |
| `ATTRIBUTION_MAX_ENTRIES` | `16384` (was `4096`) | ring-buffer bound; an eviction inside the competition window blocks `certain` |

---

## 4. Where it sits in the path

```
watchdog  ──▶  detection  ──▶  detection_latency_ms recorded
(observer thread)                       │
                                        ▼               suspicious only
                         correlation lane (dispatch.py), sharded by path
                                        │   queue_wait_ms
                                        ▼
                         first look: attribution.resolve(path,
                             observed_at, read_at)  - no waiting by default
                                        │
                        ┌───────────────┴────────────────────┐
              final probable / unknown           pending (records still in flight)
                        │                                    │
                        ▼                                    ▼
                 isolate_and_log                      isolate_and_log  ──▶ ledger
                        │                                    │   (file_event says attribution_pending)
                        ▼                                    ▼
                     ledger                 PendingAttribution: re-asked on every
                                            record, closed when the 1.5 s delivery
                                            horizon has closed
                                                             │
                                  ┌──────────────────────────┴───────────┐
                  exactly one kernel-grade writer,           anything else (no record,
                  PID verified as that writer                two writers, writer exited,
                                  │                          PID reused, unverifiable)
                                  ▼                                       │
                    /response/terminate, same incident                    │
                                  │                                       │
                                  └──▶ ledger: attribution_escalation ◀───┘
                                       (a new block, joined by incident_id)
```

**Attribution runs after `detection_latency_ms` is recorded, deliberately.**
Waiting for the Security channel is response-budget work; charging it to Table
5.9's <100 ms detection target would turn that target into a measurement of the
event log's delivery lag. A non-suspicious event never asks at all, so the
common path costs nothing.

**And not on the watchdog thread** (defect 3, `FIXES.md`). Watchdog delivers
every event on one observer thread, and the first look used to run there, so a
wait for an audit record held the only thread that consumes events. The VM's
locker family made 20 changes in about 0.1 s; their detections were stamped
about one 250 ms grace apart, the last at least 4.77 s after its write, while
`detection_latency_ms` reported 2–17 ms. The first look and the hand-off to the
fan-out now run on four path-sharded correlation lanes
(`services/monitor/dispatch.py`, ported from `agent/dispatch.py` on
fix/evidence-integrity), so one file's events are still handed on in order. A
full lane runs the job inline rather than drop a detection, and the grace is
charged from the observation, so time spent queued is not paid twice. Each event
now carries what `detection_latency_ms` leaves out: `observed_at`,
`queue_wait_ms`, `response_dispatched_at` and `attribution_wait_overrun_ms`.
`/monitor/status` reports the lanes under `correlation`.

### The race, and the delivery horizon

The audit record and the watchdog event describe the same write and arrive by
different paths, and not together. This section used to say the audit record
is usually first and that a bounded 250 ms poll covers the rest. The Windows
integration VM measured otherwise: the Security channel delivered 4663 to the
subscription **390–1032 ms after the write, median 1000 ms**, so 0 of 35 fresh
writes were attributed, and the attributions that were made came from the
*previous* write's record (defect 1, `FIXES.md`).

So records are now stamped with their own `TimeCreated` and matched against the
event's observation time on the same clock; nothing is `certain` until the
1.5 s delivery horizon has closed; and the kill, when the evidence supports one,
is a second action on the same incident rather than the first. The full
reasoning, and why each default is what it is, is in the module docstring of
`services/monitor/attribution.py`. An unavailable source still returns
immediately and never opens a question.

### What reaches the ledger

`process_id` alone is not auditable. A PID with no confidence beside it cannot
tell a later reader whether a kill was declined because nothing was found or
because what was found was not good enough. So the chain carries
`process_image`, `attribution_confidence`, `attribution_reason` and
`attribution_source` alongside it, on the `file_event` block and again on
`response_action`.

---

## 5. The kill guard, widened

Once a PID can arrive from a parsed log record rather than from an operator
typing it, the guard's job changes from catching typos to bounding a blast
radius.

`PROTECTED_NAMES` is a denylist, and a denylist covers only what someone thought
to add — `lsass.exe` was on it, `LsaIso.exe` and `fontdrvhost.exe` were not. So
`_guard_image_path` now also refuses **by location**: anything running from
`%SystemRoot%`, `/usr/sbin`, `/sbin` or `/usr/lib/systemd`. The prefix test is
anchored on a separator, so `C:\Windows-backup\locker.exe` does **not** match
`C:\Windows` — a bare `startswith` would have refused it, and that is exactly
where an attacker who read this guard would put their payload.

**One residual, stated rather than hidden.** A process whose image path cannot
be read is *permitted*, not refused. On Windows that is the ordinary result for
a process owned by another user, and refusing on unreadability would reject most
of what this guard exists to allow. Those still face the name check.
`test_tc26_y` and `test_tc26_z` assert both halves so the choice stays
deliberate.

---

## 6. Evidence

**39 tests** when attribution was added (the first and last rows below; the rows
between them came with the integration-test fixes in `FIXES.md`), in two
services because the gate has two ends — provable where it
is defined is not provable where it is enforced.

| File | Tests | Covers |
|---|---|---|
| `services/monitor/tests/test_tc26_attribution.py` | 28 | confidence ladder, 4663 parser, path normalisation, window expiry, self-exclusion, grace-period race, pipeline gate, bounded buffer, lookup cost |
| `services/monitor/tests/test_attribution_delivery_lag.py` | 50 | event-time matching, pending until the horizon, stale records, competing and late writers, eviction, TimeCreated parsing, records delivered 0/300/1000/1600 ms late (real time), two writers never certain, identity at escalation (exited, reused, unverifiable), the escalation block, end to end through `handle_event`, and the escalation thread started with the watch so the first kill builds no HTTP client |
| `services/monitor/tests/test_rename_attribution.py` | 10 | a rename is looked up under both names (defect 2): write-then-rename by one process is certain, two writers under either name are not, `renamed_from` in the event and on the chain, the VM's locker shape escalating in real time |
| `services/monitor/tests/test_correlation_lanes.py` | 17 | correlation off the watchdog thread (defect 3): 20 suspicious events in 50 ms against a source that never answers finish inside one grace plus margin, on four lanes or one; per-path order; a full lane runs inline instead of dropping; `observed_at`, `queue_wait_ms`, `response_dispatched_at`, the overrun measurement |
| `services/response/tests/test_tc26_kill_guard.py` | 11 | reserved PIDs, self and ancestors, name denylist, location guard, lookalike paths, unreadable-image residual |
| `services/response/recovery/tests/test_snapshot_paths.py` | 6 | verbatim-path separator behaviour, device-object joins, the Linux root left unchanged |

Both run in CI on every pull request, in the matrix and again as named
acceptance rows.

Four properties carry the row:

1. **the writer is the process reported** — `test_tc26_a`
2. **a process that wrote something else is never reported** — `test_tc26_b`
3. **ambiguity degrades and never rounds up to `certain`** — `test_tc26_c`, `test_tc26_h`
4. **only `certain` asks for a kill** — `test_tc26_d` (parametrised over all three levels), `test_tc26_j`, `test_tc26_k2`

Two non-obvious ones worth naming: `test_tc26_p` asserts the ring buffer is
bounded, because `_SEEN_FILES` growing without limit is finding **S-7** in the
security audit and this module is fed by every audited write on the volume.
`test_tc26_q` measures lookup cost on a full buffer, because a correct answer
that arrives after the 2-second budget is not an answer.

---

## 6a. Measured on a live elevated host, 16 September 2026

> **Re-verification pending** (defect 1, `FIXES.md`). The figures below were
> measured under the attribution design that the Windows integration test
> found defective, and they are left exactly as measured. Two things about them
> no longer describe the current code. The attribution wait of 0.158 ms means
> the matching record was already in hand about 7 ms after the write was
> observed. At the delivery lag since measured on the VM (390–1032 ms, 35
> writes) that is far more likely to be the record of an *earlier* write by the
> same process than of this one — fix/evidence-integrity did see occasional
> ~12 ms deliveries on its host — and this run cannot tell which. And the
> current design never kills on a first answer from this source: the kill is
> requested when the 1.5 s delivery horizon closes, so detect → kill is now
> expected at about 1.6 s, inside the 2 s budget, not at ~198 ms. The
> maintainer's re-check list in `FIXES.md` has the run that replaces this one.

Run on Windows 11 `10.0.26200` from an Administrator shell: audit policy
enabled, SACL applied, Monitor and Response native and elevated, ML Engine and
Ledger the running containers.

A real separate process encrypted a real file in the watched directory:

| | |
|---|---|
| verdict | `suspected_encryption`, entropy 7.99, signal `entropy_rise` |
| detection latency | **6.878 ms** |
| attribution wait | **0.158 ms** |
| attributed PID | **22716** |
| the process that actually wrote | **22716** ✅ |
| confidence | **`certain`** |
| reason | *exactly one process wrote this path in the last 750ms, from `windows-security-4663`* |
| termination | `terminated pid=22716 name=python.exe via=sigterm in 190.69ms` |
| writer alive afterwards | **false** |

**Detect → attribute → kill in roughly 198 ms**, against a 2 s budget.

### One thing this run taught, which the tests did not

The first attempt reported the attributed PID as *wrong*. It was not. On
Windows a virtualenv's `python.exe` is a **trampoline** that re-executes the
base interpreter as a child, so `Start-Process` returns one PID and a different
one writes the bytes:

```
Start-Process returned pid : 23380   <- the venv trampoline
the process that WROTE     : 22716   <- what attribution named
```

Attribution named the process that performed the write, which is the only
process it can name and the only one worth naming. The test harness was
asserting against the launcher. This is the same class of problem as limitation
3 below, seen from the other side: **the process you think you started is not
always the process doing the work.** Killing 22716 ended 23380 as well, because
a trampoline whose child is gone has nothing left to wait for.

---

## 7. Limitations

**1. VSS-backed restore is verified; snapshot *scheduling* is not.** The same
elevated run created a real shadow copy on `D:`, encrypted a file, restored it,
and confirmed `restored_sha256 == original_sha256` — closing an acceptance row
that had been carried as "not measured" since Phase 6. Closing it required
fixing a real bug first: `restore_file` joined forward-slash relative paths onto
a `\\?\GLOBALROOT\...` device object, and the `\\?\` prefix disables Windows'
separator normalisation, so every restore from a genuine shadow copy failed with
"not present in the snapshot". See `join_under_snapshot` and
`services/response/recovery/tests/test_snapshot_paths.py`. What is still not
measured is the 6-hour scheduler running unattended over that interval.

**2. Containers.** The Response service runs in its own PID namespace, where a
host PID names an unrelated process or nothing. This is why TC-07 is already
`SKIP` under Compose. Attribution does not change it: **termination requires the
Response service running natively on the host**, as TC-04 and TC-07 already do.
Under Compose, attribution will resolve correctly and the kill will still not
land.

**3. The writer may not be the attacker.** Ransomware often runs as a child of
`powershell.exe` or `wscript.exe`. Killing the writer can leave the orchestrator
alive to respawn it. Subtree termination is a policy decision with a real
operator cost — it is not implemented, and per this project's method it should
be predeclared and measured rather than assumed.

**4. Windows only.** `NullSource` is what Linux gets, and on Linux the
equivalent is `fanotify` with `FAN_REPORT_PIDFD` or an eBPF tracepoint. Neither
is written. The interface is the same shape for both.

**5. Audit volume.** A SACL wider than the watched tree will flood the Security
log, and a wrapped log silently drops the records attribution depends on. The
setup script scopes the rule and raises the log size; neither is enforced at
runtime, and a full Security log presents as `unknown` rather than as an error.
