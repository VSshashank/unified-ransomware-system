# APPROACH — why the system is built the way it is

Companion to [FLOW.md](FLOW.md), which describes *what* each file does. This one
records *why*, including the decisions that look odd until you know what went
wrong without them.

Every claim with a number behind it was measured on Windows 11 build 26200,
Python 3.13.9, Docker Desktop 4.85.0 (WSL 2). Where something could not be
verified, it says so.

---

## 1. Architecture

### 1.1 Why microservices, and why Docker stays

Six services (gateway 8000, monitor 8001, ml-engine 8002, ledger 8003, response
8004, dashboard 8501) rather than one process. Three reasons, in order of how
much they actually mattered:

1. **The components have genuinely different runtime requirements.** The ML
   engine needs xgboost, scikit-learn and numpy — roughly 600 MB of image. The
   ledger needs nothing but stdlib and SQLite. The response service needs
   `pywin32` and only works properly on Windows. Forcing them into one process
   means every deployment carries every dependency.
2. **Four people worked in parallel.** The API contracts in
   `docs/openapi/gateway.yaml` were fixed in Week 4 precisely so AS, NI, SI and
   SH could work against a stable interface without blocking each other. This is
   the risk-register mitigation for "Integration issues between components"
   (Table 5.7).
3. **Failure isolation.** A model that fails to load takes out classification,
   not detection or auditing. The pipeline in `services/monitor/pipeline.py`
   treats every downstream hop as best-effort for exactly this reason.

Docker stays because Objective 3 names it, and because it is what makes the
project reproducible on a machine nobody on the team owns — a grader runs
`docker compose up -d --build` and gets the pinned dependency set without
touching their Python install.

**The honest caveat:** Docker cannot host the whole system on Windows. A Linux
container cannot see host PIDs and cannot call the Windows VSS API, so real
process termination (TC-07) and real snapshot recovery (TC-04) require the
response service to run natively. This is a documented deployment constraint,
not a defect, and the README prescribes the split. Detection, classification,
auditing and the dashboard all run fine in containers.

### 1.2 Why a hash chain and not a blockchain

Spec §3.2 asks for tamper-evident audit logs. A real blockchain would give
tamper-*resistance* through distributed consensus; a hash chain gives
tamper-*evidence* through cryptographic linkage:

```
current_hash = SHA256(timestamp + event_type + event_data + previous_hash)
```

> **On the formula:** the reference document specifies it three different ways.
> §3.2.2 gives `SHA256(Timestamp + Data + Hash_{N-1})`, Listing 4.7 — the code
> template — computes
> `f"{timestamp}{event_type}{event_data}{previous_hash}"`, and Figure 4.8 shows
> `SHA256(id + data + prev_hash)`. They cannot all be right. The implementation
> follows Listing 4.7, on the grounds that the document's own reference
> implementation is the most authoritative of the three and is the only one
> precise enough to implement without guessing. Figure 4.8's `id` variant is the
> odd one out: including the block id would hash a value the database assigns,
> which is not part of the event. Genesis is 64 zeros, matching the template's
> `"0" * 64`.

Editing any historical row changes its hash, which invalidates the `previous_hash`
of the next block, and the break cascades to the tip. Verification walks the
chain and reports the first block where recomputation disagrees.

This is the right trade for a host-based tool: consensus needs peers, and there
is one host. What the local chain *cannot* do is stop an attacker deleting the
whole database and starting a fresh valid chain — which is exactly the gap
Polygon anchoring (§3.2.3, Weeks 17–24) is meant to close. `blockchain_anchor` is
present in the block schema and always `null`, which is the honest representation
of an unimplemented optional feature rather than a fabricated transaction hash.

---

## 2. Detection

### 2.1 Entropy alone is not a detector

Shannon entropy near 8.0 bits/byte means "these bytes are unpredictable". That is
true of AES ciphertext **and** of a ZIP archive, a JPEG, an MP4 and a PDF. A
detector that flags on entropy alone reports every download folder as an attack.

Table 5.3 lists two Weeks 9–12 tasks against this, and Table 5.7 names both as
mitigations for the false-positive risk. They are separate checks and both are
implemented.

**Magic-byte verification** reads the file's header and asks whether the high
entropy is *explained* by a declared container format. `detection.py` carries 20
container signatures. A file that is high-entropy **and** starts with
`PK\x03\x04` is someone zipping their photos; a `.docx` that is high-entropy and
starts with random bytes is not a `.docx` any more.

Measured: **0 false positives out of 40**, where 32 of the 40 were deliberately
high-entropy legitimate files. Target was <5%.

**Differential entropy analysis** is the other one, and it is what spec §1.4
actually describes: "entropy patterns over time", not a header check. A single
reading cannot separate an archive from ciphertext, because both are near 8.0.
A *sequence* can — ransomware overwrites files that already existed, so the
signature is a large rise on a path already being watched.

`EntropyHistory` keeps the last few readings per path, bounded in both
directions, and `classify` flags a rise of ≥2.0 bits/byte that lands at ≥7.0.
The baseline is the lowest substantive reading in the window rather than the
previous one, so an encryptor writing in several passes cannot walk the entropy
up in steps too small to notice. A reading only becomes a baseline once the file
holds at least 1 KB: watchdog reports a creation the moment the file exists,
usually at zero bytes, so without that floor every file ever written would have
"risen" from 0.0 and creating an archive would look like encrypting one.

The two checks catch different things, which is why the document asks for both.
Magic bytes miss an encryptor that writes a container header over its ciphertext
— the file declares `PK\x03\x04` and gets cleared. The rise still sees it, and
there is an end-to-end test for exactly that case
(`test_differential_entropy_catches_in_place_encryption_end_to_end`). Going the
other way, differential entropy needs a prior reading, so on a file seen once it
reports nothing and magic bytes carry the decision alone.

Validated in both directions: the rise catches in-place encryption behind a
valid ZIP header, and 13 writes across four ordinary file lifecycles — an
archive built in passes, a document edited repeatedly, an office file re-saved,
a large download landing in pieces — produce **no** false positives
(`test_ordinary_file_lifecycles_produce_no_differential_false_positives`). The
static 40-sample benchmark scores each file once and never builds history, so it
cannot exercise this rule; that test exists because the benchmark cannot cover
it.

Ransom extensions (`.locked`, `.wncry`, …) are a *secondary* signal only. Families
rename constantly, so the extension list never decides on its own — it raises
confidence in a verdict entropy already supports.

### 2.2 The polling observer, and the bug that made it necessary

Docker Desktop passes a Windows bind mount into its Linux VM as filesystem type
`9p`. inotify watches on 9p are **accepted and then never fire**. Watchdog
reports the observer alive, `/health` returns healthy, and no event ever arrives.
Silence from a dead watcher is indistinguishable from silence on a quiet disk.

This is the single worst failure mode the project has had: the system reported
itself healthy while detecting nothing at all.

`build_observer()` therefore reads `/proc/mounts`, finds the filesystem backing
the watch path, and selects `PollingObserver` where the mount carries no
notification support and native inotify everywhere else. `/monitor/status`
reports `observer_backend` and `observer_reason` because *a silent native watch
cannot otherwise be distinguished from an idle one*. Overridable with
`MONITOR_OBSERVER=auto|native|polling`.

**Check this first in any demo.** If `/monitor/status` says `native` on a Windows
Docker host, detection is dead and nothing downstream means anything.

### 2.3 A time budget for file locks, not an attempt count

Windows holds files open with deny-share far more often than POSIX. The
encrypting process, Windows Defender scanning the freshly written bytes, and the
search indexer all take a handle at the moment the watchdog event fires.

The first fix retried per read helper, three attempts with 50 ms of backoff.
`handle_event` opens the same file twice, so a locked file cost **303 ms** against
a **100 ms** target — a correctness fix bought at 3× the latency budget.

It is now bounded by a *time* budget (`READ_RETRY_BUDGET_SECONDS`, default 40 ms)
and the lock is probed once per event rather than once per read. An attempt count
is the thing a caller cannot reason about; a budget caps the worst case at a
number that visibly fits inside the target. Measured after the change: **40.9 ms**
locked, 13.9 ms unlocked.

### 2.4 A bounded event buffer

`EVENTS` is a `deque(maxlen=500)`. It was an unbounded list, which is a slow leak
for the lifetime of the process on a busy watch path. The TC-08 memory benchmark
now measures growth explicitly: **+2.5 MB over 137 × 512 KB events**, which is
what "the buffer does not grow with the file count" looks like as evidence.

### 2.5 `process_id` is null, deliberately

Watchdog reports *what* changed, never *who* changed it. The monitor originally
sent its own PID, which would name an unrelated process inside the response
container's PID namespace — worse than useless, because it looks like
attribution. It now sends `null`, and `pipeline.trigger_response()` asks for
`isolate_and_log` rather than `terminate_process` when the PID is unknown.

Real attribution needs eBPF/fanotify on Linux or ETW on Windows. That is Phase 5.

---

## 3. Machine learning

### 3.1 Two models, because there are two feature spaces

`/predict` receives two different shapes and they are not interchangeable:

| Input | Model | Why |
|---|---|---|
| `ember_vector` (2381 floats) | `ember_xgboost` | EMBER's precomputed static-PE vector. **95.8%** accuracy on the 50,000 real EMBER-2018 samples §6.1 specifies (25,000 per class, 7,500 held out). |
| `features` (dict) | `behavioral_xgboost` | The handful of signals the Monitor can actually measure from a file it just saw change. **99.5%** accuracy, ROC AUC 1.000 — and see the warning below about what that number is worth. |

The EMBER classifier cannot score the Monitor's feature dict — different
dimensionality, different semantics. Before the second model existed, that path
returned **501 Not Implemented**, which meant the Monitor → ML hop did not work
at all. One model was not an option; the alternative was leaving half the system
disconnected.

The behavioural corpus is deliberately hard: header-spoofed ciphertext,
LockBit-style intermittent encryption (both leading-run and strided), containers
with no structural validator, and headerless high-entropy benign files.

**Do not read 99.5% as a generalisation claim.** It is an in-distribution split
of a corpus this repository generates itself, so it measures whether the feature
vector can separate classes that were built to be separable — nothing more. The
figure moved from 88.4% not because the model got better but because the corpus
stopped contradicting itself: `photo_N.png` and `spoofed_N.png` were the same
construction with opposite labels, which no model could have learned and none
should have. Correcting that is a corpus fix, and a corpus fix does not earn a
generalisation claim.

The number to lead with is the simulator sweep in
[`reports/simulator_families.json`](../reports/simulator_families.json) —
**13 of 13 families detected, every file, all within 2 s** — because those files
are produced by a separate program, by a separate mechanism, and were never seen
during training. See [DETECTION_HARDENING.md](DETECTION_HARDENING.md).

`services/ml-engine/features.py` exists as its own module solely so the training
script and the serving path agree on feature *order*. A mismatch there does not
raise — it silently scores the wrong columns, which is the worst class of bug a
detector can have.

### 3.2 What the datasets are actually used for

The spec names EMBER, CLEAR and RanSAP. Precisely:

- **EMBER** — trains the static-PE classifier. Real training input.
- **RanSAP and CLEAR** — `src/analyze_behavioral_signals.py` loads all four
  RanSAP CSVs and the CLEAR trace, and produces entropy distributions, write-rate
  comparisons (**WannaCry 4888 writes/sec vs Firefox 213/sec**) and the CLEAR
  WAR/RAR/RAW/WAW behavioural fingerprint. That is NI's Week 1–4 "EDA report"
  deliverable (Table 5.4), and it is met.

**Known divergence from §6.1.** The spec says the model was trained on EMBER
"augmented with behavioral logs from the CLEAR dataset". It is not — CLEAR
informs analysis, not training. The script says so in its own docstring, with the
reason: these are continuous single-process traces, not per-sample rows, so they
do not merge into EMBER's feature matrix without a windowing scheme nobody
specified. Closing this means retraining and restating the headline accuracy
figures, so it was deferred deliberately rather than done quietly.

A second, smaller divergence: the analysis derives a suggested entropy threshold
of **0.3186**, but the Monitor runs at **7.5**. Those are different scales —
RanSAP's `entropy_1` is normalised 0–1, Shannon is 0–8 bits/byte. The calibration
currently informs nothing. Worth reconciling before claiming the operating point
is RanSAP-derived.

### 3.3 The PE feature extractor

Table 5.4 asks for "50+ features from PE files". `services/monitor/pe_features.py`
extracts **70**: DOS/COFF/Optional headers, per-section entropy and
characteristics, import/export counts, resources, and directory presence.

Three decisions worth stating:

- **It lives under `services/monitor`, not `src/`.** The Monitor is what meets
  real files at runtime, and its container ships only its own directory. Training
  scripts can import from there; the reverse does not survive containerisation.
- **It is not EMBER-compatible, and cannot be.** EMBER's 2381 dimensions are not
  reconstructible from a PE without EMBER's exact feature code. This is an
  independent, *interpretable* feature set — `pe_crypto_api_count`,
  `pe_writable_executable_sections`, `pe_shadow_copy_api_count` mean something to
  a human reading an alert, which a raw EMBER index does not.
- **Every failure returns zeros with the same keys.** A model cannot be handed a
  dict whose keys depend on the input, and a hostile PE must not take down the
  Monitor's event thread. Malformed input yields `is_pe: 0` and the full 70-key
  shape.

Its immediate job was closing a contract that had been silently broken:
`gateway.yaml` marks `pe_imports_count` and `api_calls` **required** on
`FeatureSet` and spec §3.4.2 shows both going into `/predict`, but
`extract_features()` returned neither. `/analyze` had been shipping an incomplete
FeatureSet for as long as the route existed. Live through the container, a real
PE now reports **315 imports** and its behavioural API names.

Parsing runs only in `/features`, never on the watchdog event thread — detection
latency re-measured afterwards at **p95 23.7 ms**, unchanged.

---

## 4. Ledger

### 4.1 `journal_mode=DELETE`, not WAL — do not change this back

With the stack running in Compose, editing a block directly in the SQLite file
and calling `/ledger/verify` returned `valid: true`. **The ledger certified a
tampered chain as intact** — a silent failure of the exact guarantee TC-05 exists
to test, in the deployed configuration.

The 39 unit tests missed it because each opens its own connection. Only a
long-lived service process is affected, which is to say: only production.

Cause: WAL coordinates connections through a shared-memory index (`-shm`), and
that coordination does not survive Docker Desktop's bind mount from the host into
its Linux VM. The service answered from a snapshot taken before the edit.

The rollback journal relies on POSIX locks on the database file, which do cross
that boundary. The ledger appends small audit rows and is read by one dashboard,
so WAL's concurrency advantage was never load-bearing and is not worth a hole in
the integrity guarantee. Re-verified on Windows, which uses an entirely different
mechanism: `{"valid": false, "invalid_block_id": 3}`, detected at exactly the
tampered block.

### 4.2 `verify_chain()` always opens a fresh connection

Same reasoning, one level down. An integrity check that answers from its own
connection cache cannot detect the one thing it exists to detect. `verify_chain`
re-reads from disk every time. The <50 ms target is unaffected — **3.1 ms
median per 1000 blocks**, over 50 warm runs.

### 4.3 Canonical JSON is the single definition of what gets hashed

Blocks store the exact text that was hashed, and verification re-hashes that
stored string rather than a re-serialised dict. Without this, key ordering or
whitespace differences would break the chain on read-back — the chain would
report tampering that never happened, which destroys trust in it just as
effectively as missing real tampering.

---

## 5. Response and recovery

### 5.1 Network isolation is off by default, and should stay off

`build_plan()` constructs real `iptables` / `pfctl` / `netsh` rules and reports
them, but only *applies* them when `RESPONSE_ISOLATION_ENABLED=true`.

Applying firewall rules to the wrong host locks the operator out — including
their own RDP or SSH session, on a machine they may not have physical access to.
The response returns `enforced: false` alongside the exact rules it would have
applied, which is more useful and more honest than claiming a block that never
landed.

If this is demonstrated live, it should be on a throwaway VM with console access.

### 5.2 Termination guards

`terminate_process()` refuses PID 0, PID 1, negative PIDs, and its own process.
SIGTERM first, then SIGKILL if `force`. Measured **125.6 ms** against a 2 s target.

`AccessDenied` and `NoSuchProcess` are distinguished: a process that died between
the guard and the signal is a *success* (the goal was "not running"), while one we
are not permitted to kill is a failure that must be reported, not swallowed.

### 5.3 Path portability took two attempts

`to_relative()` re-roots a path inside a snapshot. The first fix stripped the
drive letter with `ntpath` — `os.path.splitdrive` is `posixpath.splitdrive` off
Windows and hands `C:\data\report.doc` back untouched, so in the Linux container
it was never re-rooted.

That fixed half of it. Backslashes are ordinary filename characters on Linux, so
`os.path.join` produced a single file named `data\si_demo\thesis.doc` instead of
descending into `data/`. TC-04 reported a file "not present in the snapshot" that
was sitting right there. Separators are now normalised to `/`, which opens
correctly on both platforms.

Neither half showed up on macOS, because the paths involved were already POSIX.

### 5.4 Unverified restores say so

Integrity verification needs the ledger to already hold a hash for the path. If
nothing ever logged one, the file is still restored but reported as
**unverified** rather than silently passed. Claiming a verification that did not
happen is worse than admitting it could not be done.

---

## 6. Gateway and security

### 6.1 Authentication and authorization are separate

`get_current_user` answers "is this anyone at all" (401). `require_role(*allowed)`
answers "may this someone do this" (403). Before this split the gateway
authenticated but never authorized — it read the role claim and discarded it, so
a `free` token could terminate processes and isolate the network. Nothing in the
project ever raised 403.

| Routes | Required role |
|---|---|
| All `GET` | any authenticated role |
| `POST /monitor/start`, `/analyze`, `/predict`, `/ledger/log` | `admin` or `enterprise` |
| `POST /monitor/stop`, all `/response/*` | `admin` |

`/monitor/stop` sits with the response actions rather than with the other writes
because stopping the monitor blinds detection for the whole host — the same order
of consequence as killing a process.

`/predict` is grouped with `/analyze` rather than with the GET reads: `/analyze`
is that same call with feature extraction and a ledger write around it, so
leaving `/predict` open to `free` would make the `/analyze` gate bypassable for
the ML half.

### 6.2 `/auth/token` is a placeholder, and now says so loudly

An empty POST used to return a working **admin** token to an anonymous caller,
because `TokenRequest.role` defaulted to `"admin"`. Real identity management is
explicitly out of scope for Phase 4 (Table 5.6 puts it in Semester 2), so the fix
was to shrink the blast radius rather than build an IdP:

- defaults are now the least-privileged role
- anything above `free` requires a shared secret in `X-Bootstrap-Secret`
- `ALLOW_DEV_TOKENS=false` removes the endpoint entirely
- the "Phase 4 placeholder" comment is now a banner

Tier is gated alongside role, which is not an afterthought: `resolve_tier()`
prefers the tier claim over the role, so a `free` role carrying tier
`enterprise` bought a 1000 rpm budget instead of 60.

### 6.3 Backend ports bind to loopback

The four backend services carry no authentication of their own — `POST
:8003/ledger/log` with no token returns 200 and appends to the audit trail. They
were published on `0.0.0.0`, so that was reachable from anywhere on the LAN.

They now bind `127.0.0.1`. The gateway (8000) and dashboard (8501) stay published
— they are the intended front doors, and the gateway is the only service that
authenticates. Host tooling is unaffected: `si_demo.py` and `verify_vss.py` talk
to `:8003`/`:8004` over loopback and still work.

A stricter fix — removing publication entirely so the backends are reachable only
over the compose network — additionally requires routing those two scripts through
the gateway. Not done.

### 6.4 Auth-failure auditing is best-effort by design

TC-10 requires an audit entry alongside the 401. `audit_access_denial()` appends
an `auth_failure` block to the same tamper-evident chain as everything else, so
credential probing is visible after the fact.

It is deliberately best-effort: a dead ledger must not turn a clean 401 into a
500. If it could, taking the ledger down would also suppress the rejection —
turning the audit requirement into a denial-of-service lever.

**Known limitation, stated rather than hidden:** this endpoint is unauthenticated
by nature, so a caller spamming bad tokens appends to an append-only chain.
Bounding that with a per-client suppression window is worth doing before this
faces a hostile network, and is not attempted here.

### 6.5 The default JWT secret fails closed outside development

`JWT_SECRET` defaults to a committed value, so any token signed with it can be
forged by anyone holding the repository. The gateway now warns loudly on every
start and **refuses to boot** when the default is still in place and `URDS_ENV`
names a protected environment. Verified: exit code 3, startup aborted.

---

## 7. Testing

### 7.1 Tests live with the service they test

There is no cross-service test suite, because the services are deployed
independently and their suites run independently. TC-11 spans detection and
termination, so it exists as two halves — `services/monitor/tests/test_tc11_concurrent.py`
and `services/response/tests/test_tc11_concurrent.py` — each owning its side.
End-to-end integration is `scripts/attack_chain_demo.py`, which drives the real
stack over HTTP.

### 7.2 Benchmarks assert the spec's numbers and print the measurement

Every numeric target in Table 5.9 has a test that asserts the target and prints
the measured value, so `pytest -m benchmark -s` *is* the evidence. Results are
written to `reports/*.json`.

Two footguns here, both hit and both fixed:

- **`as_benchmarks.json` was overwritten, not merged.** Two suites write to it —
  the monitor's benchmarks and the response service's kill-time test. The monitor
  replaced the whole file, so running its benchmarks alone silently deleted
  `process_kill_time_s`. It only looked harmless because the documented run order
  puts monitor first, which rewrote the key afterwards. Both now merge.
- **Running the suite mutates committed evidence.** A plain `pytest -q` rewrites
  two `reports/*.json` files as a side effect, so contributors get spurious diffs
  and can commit re-measured numbers by accident. Not yet fixed; making the write
  opt-in is the obvious remedy.

### 7.3 The ransomware simulator, and why it is safe

TC-01 names a specific family, and §1.5 requires live samples to run only in
air-gapped sandboxes. `scripts/ransomware_simulator.py` reproduces the *behaviour*
— rapid in-place rewriting of documents with high-entropy content, plus the
extension rename — with no malicious payload.

Four guards, each tested:

- it only rewrites files it created in this run, checked against a manifest and a
  content marker
- it **refuses to run** in a directory holding anything it did not create, so a
  mistyped `--target-dir` is inert rather than destructive
- the transformation is a reversible keystream XOR, and `--restore` puts the
  directory back byte-for-byte
- it is not cryptography and does not claim to be; reversibility is the point

Measured: detected and terminated after **1 file**, against TC-01's "<5 encrypted".

### 7.4 A flaky test is a defect, not bad luck

The TC-11 termination test passed alone and failed intermittently in the full
suite. Two real defects:

- it asserted **batch wall-clock** under 2 s, but the 2 s bound is
  *per termination* (TC-07); TC-11 states no timing requirement. Under full-suite
  load that figure measures how busy the host is, not what the code does.
- liveness was checked with `pid_exists()` then `Process(pid).status()`, which
  races the exit and can observe a **recycled PID** on Windows.

Now asserts `termination_time_ms` per result and uses `process.wait()`, which
reaps the child and is authoritative. Verified with five consecutive full-suite
runs.

---

## 8. Where the implementation departs from the specification

Each of these is a deliberate choice rather than an oversight, and each is a
place a careful reader of the reference document would otherwise find an
unexplained mismatch.

**No TLS between services.** Table 3.1's Security row specifies TLS 1.3. Every
service here speaks plain HTTP. This is a real gap against the stack table, not
a misreading of it. What stands in for it is network placement: only the gateway
(8000) and dashboard (8501) are published on all interfaces, and the four
backends bind to `127.0.0.1`, so the unauthenticated inter-service traffic never
crosses a network boundary (§6.3). That is the right trade for a Weeks 1–16
prototype on a single host, and the wrong one for anything else — §3.7.3 scopes
TLS termination to production deployment, which this is not.

**Intermittent encryption and header spoofing *were* the two blind spots, and
are now closed.** This section previously recorded `partial` (0 of 8) and
`spoofer` (0 of 8) as honest limits of whole-file entropy, with the reasoning
that catching them would cost the 0 % false-positive rate. Both are now detected
on every file, and the false-positive rate is still 0/40. What changed, and why
the trade turned out not to be the trade it looked like, is written up in
[DETECTION_HARDENING.md](DETECTION_HARDENING.md); the short version:

* **Intermittent encryption** is caught by scoring 4 KB blocks separately
  (`detection.block_entropy_profile`). The objection was correct — a `.docx` or
  a PDF does carry compressed blocks with the same profile — so the rule is
  gated on the file *not* being a structurally valid container, which every one
  of those is. The gate is what makes the technique affordable.
* **Header spoofing on a fresh path** is caught by checking whether the declared
  container is actually there (`services/monitor/containers.py`). A file being
  written is separated from a forged one by whether its *leading* structure
  parses, so an archiver mid-write is not an alert.

Six formats have structural validators: ZIP, GZIP, PNG, JPEG, PDF and ISO base
media. **A header from any other format still buys the exemption on four bytes.**
A `Rar!` or `BZh` prefix over ciphertext is not distinguishable from the real
thing by anything in the current feature vector, and the training corpus contains
real bzip2 and XZ streams with no forged counterparts for exactly that reason —
labelling a pair apart that the system cannot tell apart would be manufacturing
the result. That is the residual, and it is a smaller one than "any four bytes at
all", which is what it replaced.

**`POST /response/terminate` can answer 409, which Table 3.2 does not list.**
Table 3.2 enumerates nine status codes and 409 Conflict is not among them. The
termination guard refuses several distinct situations — a PID that does not
exist, PID 0 or 1, the response service's own process or an ancestor of it, a
protected system process, a process this user cannot inspect — and none of
Table 3.2's codes fits. 400 would claim the caller sent something malformed,
which they did not; 403 already means "your role is not permitted" at this
gateway, and reusing it for "that process is off-limits" would collapse an
authorisation failure and a target-selection failure into one code the caller
cannot tell apart. 409 says the request was valid and the server declined, which
is what happened. It is declared on the route in `gateway.yaml`; the deviation
from Table 3.2 is deliberate and recorded here rather than left to be found.

**`FileEvent.hash_md5` is `file_hash`, and holds SHA-256.** §3.5.1 names the
field `hash_md5`. MD5 has practical collision attacks and is unsuitable for the
one job this field has — deciding whether a restored file matches what was last
seen, which an attacker has a direct interest in forging. Table 3.1's own Data
row specifies SHA-256. The field is renamed rather than left as `hash_md5`
holding a SHA-256 digest, because a name that lies about its contents is worse
than a name that differs from the spec.

**Benign events do not reach ML or the ledger.** Figure 3.3 shows a benign file
operation flowing Detect → Predict → Log. Here it stops at Detect and Record.
Fanning out on every benign event means an HTTP round-trip and a ledger append
per file touched, which is what the CPU and ledger-noise numbers in §10 are
avoiding. The documented flow is still reachable on demand: `POST /analyze` runs
Monitor → ML → Ledger for any file regardless of verdict, so the capability
exists and is tested — it simply is not automatic.

**SMOTE is not used.** p. 40 prescribes "SMOTE oversampling + class weights in
XGBoost" as the class-imbalance mitigation. Only the class weights are here
(`scale_pos_weight` in `train_ember_model.py`). The reason is that the condition
the mitigation addresses does not arise: the training set is 25,000 benign and
25,000 malicious, exactly balanced, so synthetic minority oversampling has no
minority to oversample and `scale_pos_weight` computes to ~1.0. Implementing it
would be a no-op that looked like a safeguard.

**CLEAR is used for EDA, not for training.** §6.1 describes the training corpus
as EMBER "augmented with CLEAR behavioral logs". The EMBER classifier is trained
on EMBER alone; CLEAR informs the exploratory analysis and the behavioural
feature design (§3.2). Folding CLEAR into training means retraining and
restating the headline accuracy, and it was deferred rather than half-done.

---

## 9. What is deliberately not built

These are scope decisions, not oversights. Each is deferred by the project's own
timeline (Tables 5.4–5.6, Weeks 17–32).

| Item | Why deferred |
|---|---|
| Polygon anchoring / TC-12 | **Dropped from the core plan** by Chapter 9 §9.2 and retained as future work. The hash chain already provides tamper evidence and TC-05 tests it; anchoring adds an external dependency and no new evidence. The Excellence bullet it occupied is traded for the documented original contribution, per §9.12.3. |
| CI/CD pipeline | Table 5.6, Weeks 17–24. |
| 95% coverage target | §5.6.3, Distinction tier. |
| SHAP served per-prediction | Table 5.4 puts SHAP analysis in Weeks 17–24. `src/shap_analysis.py` exists and produces real evidence offline; `/predict` returns XGBoost gain-based importances, which are global rather than per-alert. |
| Process attribution | Needs eBPF/ETW. Phase 5. |
| Real identity management | §5.6, Semester 2. `/auth/token` is the placeholder. |
| VSS deletion protection | Named in the objectives narrative and §2.5's literature review, but not in any Weeks 1–16 deliverable. Genuinely absent — no ACL hardening, nothing intercepting `vssadmin delete shadows`. |

---

## 10. Calibrating the cost table (Semester 2, Phase 5)

`admissibility.py` decides whether a suppression may cancel a detection by
comparing two numbers. Those numbers were assigned by hand and defended in prose,
and §10 of `CAPABILITY_GOVERNED_EXCEPTIONS.md` says so plainly — *"The scale is a
modelling choice, not a measurement."*

Phase 5 (Chapter 9 §9.4.1) is the measurement. Its rule is that no repair is
written until the cost table is frozen, because a repair chosen before
calibration is a repair the cost table was fitted to justify. Nothing in
`services/` changed during Phase 5; the five harnesses in `scripts/` measure, and
the four documents record.

### 10.1 Why the exemption is measured rather than argued about

The container exemption is the Monitor's most-used evidence-cancelling path and
the one that predates the governance layer. `detection.py:702` reads
`container_valid is not False`, and `None` — which `containers.py` returns for
*no validator*, *still being written* and *unreadable* alike — satisfies it. So
"I could not check" produces the same `benign_compressed` as "I checked and it
passed".

`reports/recf_exemption_evidence.json` reproduces that over all 20 signature
entries: 11 of the 16 registry formats have no validator, 13 of the 20 entries
return `benign_compressed`, and none return suspicious. The argument that this is
acceptable because an attacker "has to ship an encoder" is answered by
`gzip.compress(ciphertext)` — one standard-library call, a structurally perfect
gzip member, `container_status` VALID, verdict `benign_compressed`.

### 10.2 What the calibration found, including the parts that are inconvenient

`reports/capability_calibration.json` builds and runs the cheapest attack against
each strategy and derives its ladder level from the attack's operational facts.
Three levels differ from the table:

| Signal | Declared | Measured | The attack |
|---|---|---|---|
| `structural_mismatch` | moderate | negligible | `gzip.compress(ciphertext)`, or a `ZIP_STORED` member |
| `entropy_rise` | moderate | low | write to a path the Monitor has not measured |
| ML confidence gate | *(absent from the table)* | negligible | a valid container plus intermittent encryption |

Two results run against what the project expected of itself.

**The confidence-gate finding was overstated.** §9.3 says a sub-threshold
confidence silently withholds the response. `pipeline.effective_threat_level`
floors a Monitor-suspicious event at `high`, and `pipeline.run` is only reached
for suspicious events, so on the only live caller that gate cannot withhold. The
finding is restated narrower rather than repeated.

**The real gap is worse and sits elsewhere.** A ZIP_STORED archive whose member
is 40 alternating 4 KB blocks — half ciphertext, half prose — measures 6.84
bits/byte with half its blocks at ciphertext entropy. `partial_entropy` exists
for exactly this and is not reached, because its guard is `container_valid is not
True` and the container is genuinely valid. `classify` returns plain `benign`,
reason *"entropy 6.84 below threshold 7.5"*. Half the file is unrecoverable and
nothing fires, nothing is fanned out, nothing is scored. This was found by
building the file, not by reading the branches — the reading got the mechanism
wrong first.

### 10.3 The calibration exposed a defect in the cost model itself

`docs/ADMISSION_RECOMPUTE.md` recomputes all 20 suppression × signal cells under
four policies. §9.7's D1 anticipated that the path whitelist and training mode
would flip from *cancelled* to *attenuated* — two deployed mitigations turning
out not to be cost-justified. **Zero cells flip that way. Four flip the other
way.**

The forgery side of the table was right: both rules measured LOW, as declared.
What moved is the avoidance side, and under this comparison a signal that is
cheaper to avoid is *easier to cancel*. Applying the measured costs would let a
path whitelist cancel a structural-mismatch alert, which the deployed policy
correctly refuses.

That is a defect, and it is in the model rather than in the measurement. One
number is doing two jobs:

- **avoidance cost** — what an attacker who *wants* to evade the signal spends;
- **evidential weight** — what the signal is worth *when it fires*.

For `structural_mismatch` they point opposite ways. A file that trips it is one
whose author did **not** spend the single standard-library call that would have
avoided it. The signal is cheap to evade and, precisely because of that, strong
evidence when it does fire.

Per D1 nothing is retro-fitted to make this go away. `admissibility.py` is
untouched and every cost in it is unchanged. The refinement is *proposed* as
`cost-policy-v2` in `docs/PHASE5_PREDECLARED_BOUNDS.md` and argued in Phase 6.

### 10.4 Where the audit trail stops

`app.py:491` gates the downstream fan-out on `suppression is None`, and the
ledger is only reachable through that fan-out. So an **attenuated** suppression
is chained with both costs, and a **cancelled** one is not chained at all. The
audit trail holds the decisions that changed nothing and omits the decisions that
removed an alert.

The module docstring's own principle — *"A suppression that vanishes without
saying so is indistinguishable from a detector that never fired"* — is satisfied
in `GET /monitor/events`, which is a bounded in-memory buffer, and not in the
tamper-evident chain. `docs/MITIGATION_INVENTORY.md` records this as M-16; it is
the gap TC-23 is written against, and it is a Phase 6/7 repair.

### 10.5 What predeclaring the bounds caught early

`docs/PHASE5_PREDECLARED_BOUNDS.md` fixes the Phase 6 tolerances before any
repair exists. Writing it surfaced a problem that would otherwise have appeared
in Week 23: Table 9.8 asks for a ≤2 pp non-inferiority bound on validated
formats at one-sided 95%, and the frozen corpus holds 85 validated files. With a
paired design and Arm A at zero, the upper limit for a **perfect** result — zero
new false positives — is 3.46 pp. 149 files are needed.

At the current sample size the bound cannot be met by any repair, however good.
The remedy is predeclared: grow the stratum before Arm C is measured, or report
the criterion as not evaluable — never as met, never as failed, and never
relaxed after the numbers are in.

---

## 11. Summary of measured results

Re-measured at the Week 20 gate by the methods Table 5.9 states, in
`reports/phase5_baseline.json`. Superseded figures are retained below with the
reason, as §9.9's risk row requires.

| Metric (Table 5.9) | Target | Measured (Week 20) | Phase 4 figure |
|---|---|---|---|
| Detection latency | <100 ms | **23.99 ms** p95 — median 11.29, IQR 20.47 | 23.7 ms p95 |
| Response time | <2 s | **52 ms** worst of 10 | 125.6 ms |
| False positive rate | <5 % | **0 %** (0/40) | 0 % (0/40) |
| ML inference | <100 ms | **1.10 ms** | 1.95 ms p95 |
| API response (p95) | <200 ms | **2.53 ms** | 3.22 ms |
| CPU during monitoring | <15 % | **1.278 %** of 14 cores, **over a full hour** | 0.96 % over 5 s |
| RAM peak | <500 MB | **69.79 MB** (+6.73 over 3499 × 512 KB) | 70.3 MB |
| File recovery | 100 % | **13/13** restore round-trips | 100 % |
| Ledger verification | <50 ms | **4.76 ms** worst of 20 / 500 blocks | 3.1 ms median / 1000 |
| Dashboard latency | <1 s | **31.0 ms** worst of 10 | 10.5 ms mean, 11.3 ms worst |

**The CPU row is the only one whose method changed, and it is the reason the file
exists.** `test_benchmarks.py` samples a 5-second loop; Table 5.9 asks for the
average during a *1-hour monitoring period*. The Week 20 figure is 3600 samples at
one per second over a 3732.8-second wall span, with the 132.8 seconds of suspend
recorded separately rather than averaged in, under a realistic 10 % high-entropy /
90 % document load. The Phase 4 figure is not wrong — it is a correct 5-second
measurement of a different thing, and the two agree closely enough that no
conclusion changes.

### What an hour showed that five seconds could not

With the fan-out disabled, RSS ends the hour *lower* than it started — 67.9 MB to
58.4 MB, peak 81.7 MB. No leak in the monitoring path. That is what identified the
116 MB → 233 MB growth in the first (flawed) run as something else, and
`queue_backpressure` pins it down: 4000 events driven, **3999 still queued**, and
`app._work` is `queue.Queue()` with no `maxsize`. A single worker makes three HTTP
calls per event, so when the downstream is unreachable the producer outruns the
consumer without limit. `app._SEEN_FILES` is a second unbounded structure — one
hour of monitoring left **71,797** path strings resident, never trimmed.

Both stay under the 500 MB target. Neither is fixed: §9.4.1 forbids writing repairs
in Phase 5.

Model quality, after retraining on the 50,000 samples §6.1 specifies:

| Model | Accuracy | Precision | Recall | F1 | ROC AUC |
|---|---|---|---|---|---|
| EMBER static-PE (7,500 held out) | 0.9577 | 0.9625 | 0.9525 | 0.9575 | 0.9923 |
| Behavioural (870 held out) | 0.9954 | 1.0000 | 0.9917 | 0.9958 | 0.9999 |

The behavioural row is an in-distribution split of a self-generated corpus and
is reported as such — see §3.1. The held-out evidence for that model's problem
is the simulator sweep, not this row.

Suite: **465 passed, 2 skipped, 0 failed**, measured twice at the Week 20 gate.
The two skips are correct —
`psutil.terminate()` maps to `TerminateProcess` on Windows, which no process can
ignore, so the SIGTERM-escalation tests assert a POSIX guarantee with no Windows
equivalent. A Windows-specific test covers the same ground.

**Hardware these were measured on.** Table 6.1 of the reference document
specifies an i7-12700K / 32 GB / Python 3.9.13. That machine was never used and
the numbers above do not come from it:

| | Table 6.1 | Actually used |
|---|---|---|
| CPU | Intel i7-12700K | Intel Core Ultra 5 225H, 14 cores |
| RAM | 32 GB | 15 GB |
| OS | Windows 11 | Windows 11 Home Single Language, build 26200 |
| Python | 3.9.13 | 3.13.9 (services), 3.13 (training) |

Every target is met with room on this hardware, so the conclusions are unaffected
— but Table 6.1 should be restated to the machine above rather than left
describing one that was not involved.
