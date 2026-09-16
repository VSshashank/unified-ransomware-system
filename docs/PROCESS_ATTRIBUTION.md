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
  "grace_ms": 250
}
```

### Configuration

| Variable | Default | What it does |
|---|---|---|
| `ATTRIBUTION_SOURCE` | `auto` | `auto`, `security`, or `off` |
| `ATTRIBUTION_WINDOW_MS` | `750` | how far back a write explains this event |
| `ATTRIBUTION_GRACE_MS` | `250` | how long `resolve()` waits for a record in flight |
| `ATTRIBUTION_MAX_ENTRIES` | `4096` | ring-buffer bound |

---

## 4. Where it sits in the path

```
watchdog  ──▶  detection  ──▶  detection_latency_ms recorded
                                        │
                                        ▼               suspicious only
                              attribution.resolve(path)
                                        │
                        ┌───────────────┴───────────────┐
                   certain                    probable / unknown
                        │                               │
                        ▼                               ▼
              terminate_process                  isolate_and_log
                        │                               │
                        └──────────▶ ledger ◀───────────┘
                         (confidence + reason travel with the PID)
```

**Attribution runs after `detection_latency_ms` is recorded, deliberately.**
Waiting for the Security channel is response-budget work; charging it to Table
5.9's <100 ms detection target would turn that target into a measurement of the
event log's delivery lag. A non-suspicious event never asks at all, so the
common path costs nothing.

### The race the grace period exists for

The audit record and the watchdog event describe the same write and arrive by
different paths. The audit record is usually first — the access check happens
before the write completes — but Security-channel delivery is not instant. So
`resolve()` looks once and, if the source is live and has nothing yet, polls for
a bounded 250 ms. An unavailable source returns immediately and never burns it.

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

**39 tests**, in two services because the gate has two ends — provable where it
is defined is not provable where it is enforced.

| File | Tests | Covers |
|---|---|---|
| `services/monitor/tests/test_tc26_attribution.py` | 28 | confidence ladder, 4663 parser, path normalisation, window expiry, self-exclusion, grace-period race, pipeline gate, bounded buffer, lookup cost |
| `services/response/tests/test_tc26_kill_guard.py` | 11 | reserved PIDs, self and ancestors, name denylist, location guard, lookalike paths, unreadable-image residual |

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

## 7. Limitations

**1. Not measured on a live elevated host.** Every test above drives `WriteLog`
and `parse_4663` directly, or a fake kernel-grade source. The development host
is not elevated, so no test in this repository has observed a real 4663 flow
end to end into a real termination. `test_tc26_i` asserts only that an
unavailable source reports *why*. **Closing this needs one run of
`setup_attribution_audit.ps1` and the Monitor started as Administrator** — it is
the first thing to do on a machine that has both.

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
