# Limitations

**Dated 17 September 2026.** What this system does not do, cannot do, and does
not claim to do.

Every entry names what would close it. Where a limit was measured, the
measurement is cited; where it is a property of the design rather than a
number, it says so. Nothing here is hedging: a reader who installs the agent
and expects any of the following to work will be disappointed, and they should
find that out from this file rather than from an incident.

---

## 1. Nothing is blocked before the write lands

The agent watches for writes that **have already happened**. Both of its
sources are post-hoc: `watchdog` reports a change notification after the
filesystem has applied the change, and Security event 4663 records an access
the kernel has already granted. The response — suspend, then snapshot, then
decide about killing — begins after the first bytes are on disk.

This means **FEBR is never zero by construction.** A number of files equal to
whatever the attacker writes between the first write and the suspension will
be encrypted, and the only honest goal is to make that number small and to
measure it rather than to claim it is nil.

Pre-write blocking needs a filesystem **minifilter driver** sitting in the I/O
path and returning `STATUS_ACCESS_DENIED` before the write is applied. That is
kernel-mode code, it must be signed with a certificate Microsoft issues to
registered hardware vendors, and it cannot be loaded on a normal machine
without disabling driver signature enforcement. It is out of scope here and no
part of this system approximates it.

**Status:** structural. Not closable within this project.

## 2. Attribution is Windows-only, and it is an audit subsystem

`process_id` comes from the Security channel's 4663 records via a
`pywin32` subscription (`services/monitor/attribution.py`). On any other
platform `build_source` returns a `NullSource` carrying the reason, the
confidence stays `unknown`, and **nothing is ever suspended** — because a
suspension requires `CERTAIN` and `CERTAIN` requires a kernel-grade source.

So on Linux and macOS the agent detects, records and reports, and takes no
action on any process. That is the designed behaviour, not a degradation to be
worked around: the alternative is inferring a PID and acting on the inference.

**Status:** structural on this design. Closing it means a per-platform
kernel-grade source (eBPF, EndpointSecurity), each a project of its own.

## 3. Attribution arrives about a second late, and nothing can make it sooner

The Security channel delivers its audit records on a **flush timer**, not on
demand. `scripts/measure_attribution_lag.py` measured it on this host at four
write rates:

| write rate | median lag | max lag | within 250 ms | within 750 ms | within 3 s |
|---|---|---|---|---|---|
| 5/s | 601 ms | 1007 ms | 5/25 | 15/25 | 25/25 |
| 20/s | 512 ms | 1013 ms | 10/40 | 29/40 | 40/40 |
| 100/s | 655 ms | 1010 ms | 0/60 | 37/60 | 60/60 |
| uncapped | 949 ms | 1009 ms | 0/120 | **0/120** | 120/120 |

The ceiling sits at ~1010 ms and **does not move with the rate**, which is the
signature of a timer rather than of queueing: a write landing just before a
flush is visible in about twelve milliseconds, one landing just after waits out
the interval.

This sets a floor on the whole response. **Nothing can be suspended sooner than
its audit record arrives**, so the best achievable time-to-suspend on this
mechanism is roughly the delivery lag — hundreds of milliseconds typically, up
to a second in the worst case — and FEBR is whatever the attacker writes in
that time. The 100 ms figure in Table 5.9 is a *detection* latency and is not a
claim about the response.

The correlation window was 750 ms, which is **below that ceiling**, and under a
burst it matched nothing at all. It is now 3000 ms, calibrated to the
measurement with roughly 3× margin. Widening it does not make attribution
easier to obtain: `lookup` says `CERTAIN` only when exactly one process wrote
the path inside the window, so a longer window admits more candidate writers
and yields `PROBABLE` where a shorter one would have said `CERTAIN` on partial
evidence. The cost is paid in the safe direction.

Four conditions still produce `unknown`, each reported with its reason rather
than as a silent null:

* **auditing is not configured** — no SACL on the path, or the "File System"
  subcategory is off. `scripts/setup_attribution_audit.ps1` fixes this; until
  it is run, the agent watches and names nobody.
* **the record has not arrived yet.** The agent parks the event and re-asks
  every 25 ms (`agent/pending.py`) rather than blocking a worker, but an event
  whose record never comes is answered `unknown` when the window shuts.
* **more than one process wrote the path inside the window** — `PROBABLE`, and
  `PROBABLE` suspends nothing.
* **the Security log is full or throttled.** A full log at default settings
  stops delivering, every subsequent lookup misses, and the system presents as
  `unknown` across the board. `install.ps1` raises the log to 128 MB; that
  reduces the window, it does not remove it.

**Status:** measured. `reports/attribution_delivery_lag.json`,
`reports/attribution_live_run.json`, and the `agent_started` and
`agent_stopped` blocks of any run.

## 4. A process that finishes inside a second cannot be suspended

This is the sharpest limit in the system and it follows directly from §3.

Suspension needs a PID, the PID arrives with the audit record, and the audit
record arrives up to a second after the write. A process that does its work and
exits inside that second is **named correctly and named too late**. The agent
reports it — image, PID, what it did to which file — and the response records
`the response guard refused pid N: PID N does not exist`.

Measured, on a 40-document corpus:

* `7z a -p -sdel` over 60 files: attributed to `7z.exe` at 980 ms, by which
  time 7-Zip had archived everything and exited. Nothing suspended.
* a loop around `openssl enc`, one process per file: each `openssl` lives about
  **65 ms** against roughly **1000 ms** of delivery lag, so the process that
  wrote each ciphertext was gone fifteen times over before it could be named.

The second case is nonetheless stopped, and the reason is worth stating: the
*writer* is short-lived but the **deleter** is not. The loop's driver unlinks
each original, so `DELETE` auditing names the long-lived process running the
campaign rather than the ephemeral one running the cipher. That is why `Delete`
is in the SACL and in the parsed access mask — without it the agent watched
forty documents disappear and could not say who removed them.

It does not rescue the first case, because 7-Zip is both writer and deleter and
is finished before either record lands.

So the honest statement of what suspension can reach: **a campaign that runs
for longer than the audit delivery lag.** Real ransomware working through a
user's documents folder runs for minutes and is well inside that; a tool that
swallows sixty files in under a second is not. FEBR is bounded below by
(delivery lag × the attacker's write rate) and no amount of work on the agent
changes that — only a mechanism that reports the writer synchronously would,
which is §1.

**Status:** measured. `reports/attribution_delivery_lag.json` and
`reports/agent_phase3_acceptance.json`.

## 5. Tamper-evident is not tamper-resistant

The ledger is an unkeyed SHA-256 hash chain. It detects an **in-place edit** of
a block, and that is the whole of the claim. It does not detect an attacker who
can write the database file and recompute the chain, because every input to
every hash is public and the verifier recomputes exactly what the attacker
can. Appending, truncating the tail — including deleting only the newest block
— and rewriting a block and re-chaining everything after it all produce a chain
that verifies.

This is a property of the scheme. Closing it needs something the attacker
cannot recompute: a signing key they do not hold, or an external anchor
recording what the tip was before they arrived. Chapter 9 §9.13 places
anchoring outside this project's scope.

**Status:** measured and stated. `reports/tamper_sweep.json`,
`what_the_chain_cannot_detect`.

## 6. Content-only inspection cannot adjudicate a container it cannot validate

The project's own negative result, and the largest limitation on detection.
On the Phase 5 corpus, all four repair arms collapse to 90/90 on the
**unvalidated** stratum while the validated stratum goes 95 → 0. A benign `.xz`
and ciphertext under a forged header are the same bytes to an entropy test, at
any threshold.

The project has structural validators for **6 of 17** formats. The headline
"100.0 pp" figure is therefore a validator-coverage artefact, not a law about
entropy, and it is what motivates the second axis — *who* wrote the bytes and
*how fast* — rather than a better threshold.

**Status:** measured. `reports/three_arm_experiment.json`,
`reports/admission_recompute.json`.

## 7. One stdlib call puts ciphertext under every entropy threshold

`base64.b64encode(ciphertext)` spends 8 output bits per 6 input bits, so
uniform ciphertext lands at exactly **6.000 bits/byte**. That is under
`HIGH_ENTROPY_BLOCK` (7.9), under the file threshold (7.5), and under
`ENTROPY_RISE_FLOOR` — so `partial_entropy`, `static_entropy` and the rise term
all fail to fire, simultaneously, for an attacker who has done nothing more
sophisticated than call one library function.

No detector for this is implemented. The file is still unreadable to its owner;
it is simply not high-entropy, and the entropy axis has nothing to say about
it. The velocity and canary signals are unaffected, which is the argument for
having them.

**Status:** measured and **open**.
`reports/capability_calibration.json`, level 4.

## 8. Speed is not malice, and the signals that measure speed know it

`path_velocity` and `directory_fanout` fire on a `git clone`, an npm install,
a compiler writing object files and an installer unpacking. They are
corroboration, never a detector: the kill ladder requires two corroborating
signals **and** at least one *discriminating* one — a canary hit, an entropy
rise against the ledger's own baseline for that path, or an attempt on the
recovery infrastructure. A suspension requires none of them, which is why a
suspension is reversible and a kill is gated.

The cost of that gate is the obvious one: an attacker who never touches a
decoy, never raises entropy above its baseline and never goes near
`vssadmin` will be suspended and then resumed, not killed.

**Status:** measured. The `git clone` false positive is recorded in
`reports/agent_phase3_acceptance.json`.

## 9. A per-file-process encryptor defeats per-PID velocity

The velocity window is kept per PID. An encryptor that forks a fresh process
per file — a shell or Python loop around `openssl enc`, which is a real and
common shape — gives every window exactly one write, so no rate, no fan-out and
no churn term can ever reach its threshold. It also defeats suspension of the
writer outright, for the reason in §4.

What works against it is the decoy field, which needs no threshold and no
history, applied to the **deletions** rather than the writes: the campaign's
driver is the process that unlinks each original, it is long-lived, and the
first decoy it removes names it. What does not work is any signal that needs to
see a *pattern* from one process.

**Status:** measured. Arm A2 of the Phase 3 acceptance exists for this case,
and is the arm that is suspended.

## 10. Suspension stops the next write, not the last one

`psutil.Process(pid).suspend()` freezes the process. It does not roll back
bytes already on disk — that is what the VSS snapshot and the hash-verified
restore are for — and it does not prevent anything with sufficient privilege
from resuming the process. Suspension also **nests**: `NtSuspendProcess`
increments a counter, so a process suspended six times needs six resumes, and
the agent tracks the count rather than assuming one.

A suspended process holding an open handle also keeps that handle. Suspension
is a pause on a scheduler, not a revocation.

**Status:** structural.

## 11. Recovery depends on shadow copies that an attacker may reach first

Restore comes from VSS. If shadow storage is unallocated, too small, or the
attacker ran `vssadmin delete shadows` before the guard saw the process
creation, there is nothing to restore from and the system reports that it could
not verify a restore rather than claiming one.

The shadow-copy guard watches `Win32_Process` creation through WMI, which is
itself post-hoc: the process exists by the time the event is delivered. The
guard suspends it, and a fast enough `vssadmin` will have issued its delete
first.

**Status:** structural for the race; the storage sizing is handled by
`install.ps1` and is verifiable. Round-trip restore is measured in
`reports/vss_restore_verified.json`.

## 12. A saturated agent drops writes, and says so

Events queue on four path-sharded lanes of 512 each. Past that the **oldest**
queued event is discarded — it is the one whose attribution window has already
expired, so it is worth less than the event arriving now. Drops are counted per
lane, logged, surfaced in `status()` and written into the `agent_stopped` block
of the chain.

They are still dropped. A drop is a write the agent did not examine, and a run
that reports `dropped > 0` has a coverage gap of exactly that size. The counter
exists so that gap is stated rather than inferred from a quiet log.

**Status:** measured per run.

## 13. One host, one process, no network

The agent protects the configured paths on the machine it runs on. It does not
watch SMB shares from the server side, does not correlate across hosts, has no
notion of lateral movement, and does not detect a campaign that reads over the
network and writes elsewhere. The blast radius is `protected_paths` and nothing
larger; `agent/config.py` refuses a filesystem root or any overlap with a
system directory before the responder is constructed.

**Status:** structural and deliberate.

---

## What is not claimed anywhere in this repository

* That detection is complete. §6 and §7 above are open.
* That the response is pre-emptive. §1.
* That the ledger resists an attacker with write access to it. §5.
* That anything was measured on a platform other than the one named in the
  artefact that reports it.
* That a gate passing means the thing it gates is true. Four of the six
  corrections in [CORRECTIONS.md](CORRECTIONS.md) were **passes**.
