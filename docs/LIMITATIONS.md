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

One further condition *used to* produce a **confident wrong answer**, which is
worse than any of the four above. It was found while building `install.ps1`'s
self-test in Phase 4, recorded here unfixed because the fix changes TTS, and
fixed in Phase 5 with that measurement taken. It is kept in full because the
shape of the defect is the argument for the fix:

* **the previous writer is still in the window and the current one is not yet.**
  `lookup` says `CERTAIN` when exactly one process wrote the path inside the
  window. If process A writes a file at T and process B overwrites it with
  ciphertext at T+Δ where Δ is under the window, then during the ~600–1010 ms
  before B's record is delivered the only audited writer on that path is A.
  One distinct PID, from a kernel-grade source: `CERTAIN`, on A. The agent
  suspends A.

  Measured, block 16095 of `data/agent/ledger.db` on this host:

  ```
  file_event | verdict suspected_encryption | pid 27792 | conf certain
    reason: exactly one process wrote this path in the last 3000ms,
            from windows-security-4663
  ```

  27792 was the self-test process, which had written that file about three
  seconds earlier; the encryptor it had just launched was the actual writer.
  Nothing was guessed and no rule was broken — the answer was correct about the
  evidence and wrong about the world.

  The blast radius is bounded by rule 4: a suspend precedes any kill, the
  escalation resumes on a near miss, and A was resumed 0.7 s later. It is still
  a false positive that freezes a legitimate process, and the shape it takes in
  practice — you save a document, something encrypts it a second later, and
  your editor is what gets suspended — is exactly the shape a user would notice.

  **Fixed in Phase 5.** Every entry in the write log is stamped when its audit
  record was *delivered*, and delivery trails the write. So a record that
  arrived before the event was even observed cannot be a record of that event.
  `WriteLog.lookup` now takes `event_at` — the moment the filesystem event was
  queued — and refuses to answer at all when the newest matching record
  predates it, returning `unknown` with that as the reason. The event parks and
  `agent/pending.py` re-asks, carrying the *original* queued moment on every
  re-ask, so the record the sweep is waiting for is not rejected when it lands.

  The cost is paid only by the events that were previously answered wrongly.
  Where nothing predates the event — every ordinary detection — the log is
  either empty or its newest record postdates the event, and the answer is
  unchanged. The measurement is in `reports/phase5_attack_corpus.json`: TTS
  before and after the fix, over the same third-party corpus.

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

Measured directly by `scripts/measure_encryptor_lifetime.py`, outside any
protected path, with the agent not involved:

| shape | process lifetime | reachable? |
|---|---|---|
| `7z a -p -mhe=on -mx=0 -sdel`, 500 documents / 48 MB | **230-383 ms** | no |
| `openssl enc`, the process writing one ciphertext | **~65 ms** | no |
| `openssl enc`, the loop driver running the campaign | seconds | **yes** |

7-Zip stores 48 MB at 124-200 MB/s and begins unlinking about 130 ms in. Its
whole life measured 230-383 ms across three measurements on this host, so it is gone
two to four times over before the record naming it arrives. The figure moves
with disk cache state between runs; what does not move is that it sits well
under the 601 ms median delivery lag, which is why
`reports/encryptor_lifetime.json` records a *category* - `unreachable` - beside the milliseconds, and why claim C-18 asserts the category. Nothing about the detector enters into this: in the Phase 3
acceptance the decoy tripwire fired 118 ms in, the agent attributed the
deletions to `7z.exe` with `CERTAIN` confidence and said so in the log, and the
response was refused with *the response guard refused pid 29172: PID 29172 does
not exist*. A perfect verdict on the archive's contents would have changed
nothing.

The openssl loop is stopped, and the reason is the asymmetry in the table: the
*writer* is short-lived and the **deleter** is not. The loop's driver unlinks
each original, so `DELETE` auditing names the long-lived process running the
campaign rather than the ephemeral one running the cipher. That is why `Delete`
is in the SACL and in the parsed access mask, and without it the agent watched
the documents disappear and could not say who removed them.

An earlier version of this section, and of
`reports/agent_phase3_acceptance.json`, said that `-sdel` unlinks only after
the archive completes. It does not, and that claim came from an acceptance
harness which sampled the file count only when the set of live PIDs changed,
which for a single-process arm means twice. See
[CORRECTIONS.md](CORRECTIONS.md) correction 10.

The same number bounds what a *benign* arm can prove. A tool that finishes
inside the delivery lag completes untouched whether the detector judged it
correctly or did not judge it at all, so an arm that short is not evidence of
specificity. The benign arms are now sized to outlive the lag and each records
`outlived_the_delivery_lag`; one that did not is reported as inconclusive.

So the honest statement of what suspension can reach: **a campaign that runs
for longer than the audit delivery lag.** Real ransomware working through a
user's documents folder runs for minutes and is well inside that; a tool that
swallows five hundred documents in a fifth of a second is not. FEBR is bounded below by
(delivery lag × the attacker's write rate) and no amount of work on the agent
changes that — only a mechanism that reports the writer synchronously would,
which is §1.

**Status:** measured. `reports/encryptor_lifetime.json`,
`reports/attribution_delivery_lag.json` and
`reports/agent_phase3_acceptance.json`. Claim C-18.

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

Each lane serves two queues and takes the decoys' first. A canary write or
deletion is the least ambiguous signal in the system, and it used to wait in
line behind whatever bulk the agent was working through: in the failed
acceptance, of the events that could have named the attacker, five were parked
and **none** were resolved by re-asking, because every other one reached its
lane after the record explaining it had already arrived. A tripwire wired
through a backlog is not a tripwire. Priority events are never dropped to make
room for ordinary ones, which is why there are two queues rather than one
reordered queue: head-insert and head-drop are otherwise the same end of the
same deque, and the tripwire would be the first thing discarded under exactly
the load that matters.

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

## 14. An attack that produces a *valid* encrypted archive raises nothing

§6 is about containers the detector cannot validate. This is the other end of
the same rule, and it is worse: a container it **can** validate is treated as
benign, so an attacker whose output is well-formed has nothing to hide.

Measured, Phase 5, with 7-Zip pointed at a directory inside the protected path:

```
7z a -pPASSPHRASE -mhe=on -sdel  →  one 39 KB encrypted archive,
                                    twelve documents unlinked
ledger: file_event blocks           0
        file_baseline for the .7z   1   verdict benign
```

Archive-and-delete is a real ransomware pattern and not a contrived one: the
files are gone and the bytes are unrecoverable without the key, exactly as in
the overwrite case. The detector sees one new, structurally valid `.7z` — which
is what a person zipping a folder also produces — and a set of deletions, and a
deletion carries no content to measure. There is no threshold that separates
these two, because on the content axis they are the same event.

What does catch it is the decoy field, and only if the attacker walks somewhere
a decoy lives. Pointed at the protected **root**, the same command tripped all
twenty, the agent named `7z.exe` with `CERTAIN` confidence, and the only reason
nothing was suspended is §4 — 7-Zip had already exited. Pointed at a
subdirectory, which is where an attacker would start, nothing fired at all:
`install.ps1` seeds decoys at the top of each root and not into directories
created afterwards.

Two things follow, and neither is fixed here. Decoys should be seeded through
the tree rather than at its top. And an archive being written *while* files
elsewhere are disappearing is a correlation the system does not currently draw,
because the archive is judged on its own bytes.

**Status:** measured and **open**. `reports/phase5_attack_corpus.json`, the
`sevenzip-archive` and `sevenzip-root` arms.

## 15. A bulk restore looks exactly like the attack it is undoing

The agent suspended and then **killed** the process restoring files from a
shadow copy, 1.4 s in, while it was putting decoys back.

```
agent.log  suspended pid 21208 (python.exe) for !_urds_canary_00.docx
           terminated pid=21208 via=sigterm in 19.93ms
           2 independent signals agreed (canary, path_velocity),
           including canary
ledger     block 16297
```

It was right about the evidence. A process rewriting decoys and dozens of files
a second is the signature the canary and velocity signals exist to detect, and
nothing in the *content* of a restored document distinguishes it from a file
being encrypted — the restored bytes are the original bytes, which is precisely
what makes them indistinguishable from any other write.

This is not a false positive that a better threshold removes. Recovery and
ransomware are the same operation performed for opposite reasons, and the only
things that separate them are provenance — which process, holding what
authority — and intent, neither of which is on the content axis.

What Phase 5 does about it is throttle: `scripts/adversary_corpus.py` restores
below the rate the agent's own configuration treats as a signal, reading
`velocity_path_threshold` and `velocity_window_s` rather than a number typed in.
That makes the published MTTR a real number for this system rather than an
artificial one — **you cannot restore faster than the protection will tolerate
without being stopped by it** — and it does not make the limitation go away. A
restore tool shipped to an operator would need an explicit exemption
(`allowlist_images`), and an allowlist is a key to the protected path; the
decision to grant one is the operator's and belongs in their hands, not in a
default.

**Status:** measured and **open**. `reports/phase5_attack_corpus.json`,
`restore_self_suspensions` and `restore_files_per_second_cap`.

---

## 16. Three of the four Windows T1486 atomics cannot be run here

The build plan names Atomic Red Team's T1486 as a corpus member. Red Canary
publishes ten atomics for that technique and four of them are for Windows. One
is run; the other three are excluded by the blast-radius rule, not by
preference, and the exclusion is a limit on what Phase 5 demonstrates rather
than a judgement about the atomics.

| atomic | what it does | why it is not run |
|---|---|---|
| T1486-5 PureLocker Ransom Note | writes a text file to `%USERPROFILE%\Desktop` | the path is hardcoded and is outside every configured protected path; nothing the agent watches would see it |
| T1486-8 Data Encrypted with GPG4Win | overwrites a file, then `gpg -c` over it | **this is the one that runs**, with `File_to_Encrypt_Location` pointed into the corpus |
| T1486-9 Data Encrypt Using DiskCryptor | encrypts a whole volume | destroys data outside the protected path, and is not reversible from a file-level snapshot |
| T1486-10 Akira Ransomware | writes 100 × 1 MB of random bytes to the root of `C:` | hardcoded to `C:\`, outside every protected path |

Two consequences worth stating plainly. The first is that **the entropy case
this corpus most wants is the one it cannot run**: T1486-10 writes
high-entropy files with a ransomware extension, and it writes them where the
agent is not looking. The second is that T1486-8's executor *ignores its own
`GPG_Exe_Location` input argument* and hardcodes
`C:\Program Files (x86)\GnuPG\bin\gpg.exe`, so the arm depends on GPG4Win
being installed at that exact path — a defect in the atomic that this project
works around rather than patches, because a patched atomic is no longer the
published one.

---

## 17. Whether a suspension can be *timed* is a different question from whether it happened

The harness reports a suspension from two places that do not agree, and the
gap between them is a limit on every timing number in Phase 5.

`SuspendWatch` polls the launcher's PIDs for `STATUS_STOPPED` every 10 ms and
reports only a freeze it saw itself. It is deliberately not allowed to read the
ledger, because a check that reads the ledger cannot corroborate the ledger.
The consequence is that a freeze shorter than one poll, or one landing on a
process already exiting, is invisible to it — and every arm in this corpus
except two is a new process per file that lives about 65 ms.

The agent's chain records the escalation regardless. So there are three states,
and the report names which one each arm is in through
`suspend_moment_source`:

| state | what can be said |
|---|---|
| `observed` | the freeze was seen independently and timed; TTS is a measurement |
| `ledger` | the freeze is in the hash chain, named against the launcher's answer key, and timed from a block stamped *after* the suspend call returned — so TTS is an **upper bound** and FEBR counts at least as many files as really got through |
| `null` | no suspension by either account |

What cannot be produced at all is a timed suspension of a process that was
already gone. That is §4's problem, not this one, and no amount of care in the
harness moves it.

---

## 18. FEBR is counted three ways, and they do not measure the same thing

"Files encrypted before the response fired" sounds like one number. On this
corpus it has three sources, each with a case it gets right and a case it gets
wrong, and the report publishes all of them rather than picking one.

| source | how | fails when |
|---|---|---|
| **mtime** (`febr_files_before_suspend`) | count files whose modification time precedes the suspension | the encryptor **deletes** the original: the mtime goes with it, so the file is counted whole and FEBR reads as the entire corpus |
| **launcher** (`febr_from_launcher_writer_count`) | count the writer processes the runner had started by then | the arm is **one process for many files** — 7-Zip's single process says nothing about how far through it got |
| **whole corpus** (fallback) | every damaged file | nothing was suspended, so it is not a fallback but the right answer |

The launcher count is only computed where the answer key itself shows one
writer started per seeded file, which is a property of the run rather than a
claim about the arm. Where the two computable sources disagree, both are
printed: a gap between them is information about the arm's shape, and
collapsing it into a single headline would throw that away.

None of the three can time a file the encryptor reached *between* the
suspension being ordered and it taking effect. That window is small and it is
not zero, and no instrument here measures it.

---

## 19. The false-positive rate is not zero, and the thing that trips it is git

The build plan asks for zero suspensions over an hour of benign work. Measured
on this host, with the agent running and nine third-party workloads looping
inside the protected path for 60.2 minutes [`reports/phase5_benign_soak.json`]:

```
workload runs                          3,385  over 519 cycles
suspensions of this run's processes        6  = 5.98 per hour
  all six                            git.exe
  all six                            resumed, none terminated
suspensions of anything else               0
file events flagged                    3,204  = 3,194 per hour
chain valid                             true  over 184,841 blocks
```

**Six is not zero and the bound is missed.** What the number is made of matters
as much as the number:

* Every suspension was of one tool, `git.exe`, during `git gc` and `git clone`
  — the workload that writes hundreds of small high-entropy files in a burst,
  which is the velocity signature the agent is built to catch.
* Every suspension ended in `resume`. The agent froze a process, looked, and
  let it go. Nothing benign was terminated, which is the rule in §2 of the
  build plan working as intended: suspend before you kill, so that being wrong
  costs milliseconds rather than a process.
* Nothing outside this run's own processes was suspended at all.

Two things this does not settle. `git gc` failed 247 of its 272 runs with
`Permission denied` on a `.rev` file it had just written, which is consistent
with the detector holding the file open to read its entropy — but *consistent
with* is not *caused by*, no experiment here separates the agent from ordinary
Windows file-locking, and the honest position is that it is unexplained. And
the rate is a lower bound: six of the plan's benign corpus members are not
installable here, and `npm-install` failed all 519 attempts, so it contributed
nothing.

---

## 20. An alert is not a suspension, and the gap between them is 534 to 1

The same hour produced **3,204 flagged file events and 6 suspensions**. Both
are published, because a system that raises three thousand alerts and acts on
six is a different system from one that raises six.

The reasons are worth reading literally:

```
entropy 7.94 >= 7.5; no recognised container header   ← makecab output
entropy 7.9x >= 7.5; no recognised container header   ← .git/objects/*
```

Git's loose objects are raw zlib streams. Cabinet files are a format the
registry does not carry a validator for. Under every content-only predicate
this system has, both are indistinguishable from ciphertext — and that is the
separability result of `docs/THESIS.md` §7.8 arriving from the other
direction. Chapter 7 reached it by showing four repair arms collapse to 90/90
on the unvalidated stratum of a constructed corpus. This reached it by pointing
ordinary tools at a protected directory for an hour and counting.

The response layer is what keeps three thousand alerts from becoming three
thousand incidents: attribution has to reach `CERTAIN`, signals have to agree,
and a suspension is reversible. That is a real defence and it is not the same
as detection being accurate. Anyone reading the 3,204 as a detection figure
would be reading it exactly backwards.

---

## 21. Reading the evidence can stop the evidence being written

The ledger is a SQLite database and it is deliberately **not** in WAL mode, so
that a second writer contends rather than quietly succeeding. The cost of that
choice is that a long *reader* is a wall too: a full-table `SELECT` holds a
SHARED lock, and the agent's appends queue behind it.

Measured on 20 September 2026, with the ledger at 285,632 blocks in a 180 MB
file. The attack corpus verified the whole chain once per arm — six full table
scans with `fetchall`, each recomputing 285,632 hashes — and the agent fell far
enough behind that five of six arms were published as having detected nothing
while the blocks proving otherwise were written minutes later
(`docs/CORRECTIONS.md` correction 16).

Three consequences that outlive that one run:

* **Verification does not scale with the chain.** The cost of asking "is this
  chain intact" is linear in everything that ever happened, and it is paid
  against a lock the writer needs. At 285,632 blocks it is seconds; the ledger
  grew by 184,841 blocks in a single hour of ordinary work.
* **An hour of benign activity is enough to build a real backlog.** §12 covers
  the agent dropping writes under saturation and saying so. This is the quieter
  failure: nothing is dropped, everything is simply late, and anything that
  reads the chain at the moment of an incident sees a system that noticed
  nothing.
* **Nothing here bounds the lag.** The harness now waits for a sentinel and
  refuses to report an arm it could not drain, which makes the *measurement*
  honest. It does not make the agent faster, and a real operator reading a
  dashboard has no sentinel.

---

## 22. Ciphertext below about 356 bytes cannot reach the entropy threshold, ever

The detector flags a file at **7.5 bits per byte**. Shannon entropy over a
256-symbol alphabet is bounded by `min(log2(N), 8)` for a file of N bytes, so
the threshold is not merely hard to reach in a small file — below a certain
size it is **arithmetically unreachable**, whatever the bytes are.

Measured, 200 draws of `os.urandom` at each size:

| bytes | ceiling `log2(N)` | mean H | max H observed | fraction ≥ 7.5 |
|---|---|---|---|---|
| 123 | 6.943 | 6.504 | 6.719 | 0 / 200 |
| 181 | 7.500 | 6.885 | 7.054 | 0 / 200 |
| 256 | 8.000 | 7.174 | 7.293 | 0 / 200 |
| 512 | 8.000 | 7.591 | 7.671 | 200 / 200 |
| 4096 | 8.000 | 7.954 | 7.965 | 200 / 200 |

The smallest file at which a uniform random draw was observed reaching 7.5 is
**356 bytes**. Below that the threshold is unreachable; between 356 and about
512 it is reachable but not reliable.

**This is not hypothetical and it is not a corner case.** Red Canary's
published T1486-8, run unmodified through `Invoke-AtomicTest` against 200 files
in the protected path, produced **zero detections** — 200 baselines, no flagged
events, no attribution, no response. The reason is in the ledger:

```
block 287959  document_0000.csv       entropy 4.73  size 9814  benign
block 288156  document_0000.csv.gpg   entropy 6.52  size  123  benign
```

The atomic's executor overwrites the target with a fixed 37-byte string and
then GPG-encrypts *that*, so its ciphertext is 123 bytes. Across all 199
`.gpg` files the arm produced, entropy ranged 6.02–6.67 with a mean of 6.50.
Not one of them could have crossed 7.5 if the encryption had been perfect,
because 123 bytes cannot carry 7.5 bits per byte.

Two things follow. The first is about this corpus: the arm is reported as
`detected=False` and it is a real miss, not an artefact — the agent behaved
correctly given its threshold and the threshold cannot see this. The second is
general: **an attacker who encrypts in small chunks is invisible to a
per-file entropy threshold by arithmetic**, and no choice of threshold fixes
it, because lowering it far enough to catch a 123-byte ciphertext puts it below
the entropy of ordinary small files.

This is the second measured blind spot in the same signal. The first is
`base64` (§7 of this document), which lands at 6.000 bits per byte by
construction. Both point the same way as `docs/THESIS.md` §7.8: content-only
inspection is the wrong axis, and provenance is the one that is not.

---

## What is not claimed anywhere in this repository

* That detection is complete. §6 and §7 above are open.
* That the response is pre-emptive. §1.
* That the ledger resists an attacker with write access to it. §5.
* That anything was measured on a platform other than the one named in the
  artefact that reports it.
* That a gate passing means the thing it gates is true. Four of the six
  corrections in [CORRECTIONS.md](CORRECTIONS.md) were **passes**.
