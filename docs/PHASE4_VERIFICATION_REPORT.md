# Phase 1–4 Verification Report

**Repo:** `VSshashank/unified-ransomware-system` · **Verified:** 6 August 2026 (macOS), 8 August 2026 (Windows)
**Scope:** Phases 1–4 (Weeks 1–16). Phase 5+ items are flagged as correctly deferred, not as gaps.

> **Second pass, 8 August 2026.** The first pass ran on macOS, which left every
> Windows-only path unexecuted and — as it turned out — hid three defects that
> only appear on Windows. §7 records that pass. The VSS `<30 s` target in §3.1 is
> now **measured, not deferred**, and the headline test count is **227**, not 213.
> Where §1–§6 and §7 disagree, §7 is current.

---

## 0. Starting state — the brief was wrong about it

Two things had to be corrected before any verification meant anything.

**The local checkout was 12 commits behind `origin/main`.** It sat at `c663f6c` (SH's gateway
work only) and was missing *all* of NI's ML work, *all* of SI's ledger and recovery work, and
AS's watchdog integration. Fast-forwarded to `3cdc3c9` before starting. Anything measured
against the local tree before this point would have been measuring a repo that did not exist.

**SI's suite was 91/93, not 93/93.** Two tests in `test_recovery.py` failed on this machine:
`os.path.splitdrive` is `posixpath.splitdrive` off Windows and returns a drive-lettered path
unchanged, so `to_relative("C:\\data\\report.doc")` never stripped the volume. This is not a
test-environment quirk — the Response service runs in a **Linux container**, so a
Windows-sourced path would never have been re-rooted into a snapshot there either.

| Suite | Before | After |
|---|---|---|
| Ledger (SI) | 39 pass | **42 pass** |
| Recovery (SI) | 52 pass / **2 fail** | **54 pass** |
| Gateway (SH) | 7 pass | **17 pass** |
| Monitor (AS) | *no tests* | **54 pass** |
| Response — terminate/isolate (AS) | *no tests* | **27 pass** |
| ML Engine (NI) | *no tests* | **19 pass** |
| **Total** | **98 pass / 2 fail** | **213 pass / 0 fail / 0 skip** |

---

## 1. Verification table

### AS — Endpoint Security (Monitor + Response terminate/isolate)

| Weeks | Target | Before | After | Evidence |
|---|---|---|---|---|
| 1–4 | File monitoring service on 8001 | Watchdog wired in, but **`watchdog` was missing from `requirements.txt`** — the container could not start | Runs; contract fields verified | `services/monitor/tests/test_api.py` (15) |
| 5–8 | Shannon entropy | Real and correct | Unchanged, now tested against known values (uniform = 8.0, single byte = 0.0) | `test_detection.py` (35) |
| 5–8 | False-positive mitigation (magic bytes) | Magic bytes were read but **never used** — no mitigation existed | 20 container signatures; high entropy explained by format is benign | `test_tc03_*` |
| 9–12 | Response terminate/isolate | **Placeholders** returning fixed dicts | Real: SIGTERM → SIGKILL via psutil, with guards; platform-aware isolation | `test_actions.py` (18) |
| 13–16 | `file_hash` in ledger `event_data` | **Absent entirely** — SI's dependency unmet | Present on every event, full 64-char SHA-256 | `reports/attack_chain_evidence.txt` §6 |
| — | Detection latency <100 ms | Unverified | **p95 34.5 ms**, mean 15.1 ms, max 59.9 ms (40 samples, 4 KB–2 MB) | `reports/as_benchmarks.json` |
| — | Process kill time <2 s | Unverified | **0.5 ms** | `reports/as_benchmarks.json` |
| — | False positive rate <5 % | Unverified | **0 % (0/40)**, with 32 of 40 deliberately high-entropy | `reports/as_benchmarks.json` |
| — | CPU <15 % | Unverified | **1.8 %** of 8 cores (14.4 % of one core), 92 writes over 5 s | `reports/as_benchmarks.json` |

Other defects fixed in AS's files: `on_modified` recorded events as `"created"`; `EVENTS` grew
without limit for the process lifetime; `files_monitored` returned the event count, not a file
count; `/features` returned a **random** `pe_imports_count` so two calls for the same file
disagreed; `monitor.py` was an orphaned prototype that `COPY *.py` would have shipped.

### NI — Machine Learning Engine

| Weeks | Target | Before | After | Evidence |
|---|---|---|---|---|
| 1–4 | Dataset + EDA artifact | `class_balance_chart.png` **is genuine** — 800×500 matches `figsize=(8,5)` at 100 dpi in `src/analyze_ember.py` | Confirmed, unchanged | verified, no change needed |
| 5–8 | Feature pipeline, 50+ features | EMBER's **precomputed** 2381-dim vectors. No PE→feature extractor exists | Unchanged — see §3 | — |
| 9–12 | Trained XGBoost model | **`models/` was empty.** Reported 0.9577 had no artifact behind it | **Accuracy 0.9774**, precision 0.9761, recall 0.9775, ROC AUC 0.9964 on 19,480 real EMBER-2018 samples (2,922 held out) | `reports/model_metrics.json` |
| 9–12 | `/predict`, `/model/metrics` | **Deployed service was a stub** with hardcoded `accuracy: 0.92`. NI's real `src/ml_api.py` returned **501** for the `features` dict — the shape Monitor and `/analyze` actually send | Both real; metrics read from disk | `test_ml_api.py` (19) |
| 13–16 | Inference <100 ms/sample | Unverified | **p95 2.37 ms** end-to-end, 0.58 ms model-only | `reports/ni_inference_benchmark.json` |
| — | Accuracy >85 % | Unverified | EMBER **97.7 %**; behavioural model **88.6 %** (ROC AUC 0.956) | `reports/behavioral_model_metrics.json` |

The `features` path needed a second model: the EMBER classifier reads a 2381-feature static-PE
vector and cannot score the handful of signals the Monitor measures. Its corpus is deliberately
hard — header-spoofed ciphertext, LockBit-style intermittent encryption, and headerless
high-entropy benign files. An earlier corpus scored **1.000**, which measured nothing; that is
reported here because the number would otherwise look better than the work.

### SI — Blockchain & Recovery

| Weeks | Target | Before | After | Evidence |
|---|---|---|---|---|
| 1–4 | Hash chain + schema | Complete | Unchanged | `test_hash_chain.py` |
| 5–8 | Tamper detection (TC-05) | Passed **in unit tests only**. Against the running stack, editing a block in the SQLite file returned `valid: true` — **the chain was tampered and the ledger certified it intact** | Detected: `valid: false`, `invalid_block_id: 2` | §2 below |
| 9–12 | Chain verification <50 ms | ~3.7 ms claimed | **2.3 ms / 1000 blocks**, re-measured after the fix | `test_hash_chain.py` benchmark |
| 9–12 | File recovery (TC-04) | Complete | Passes end-to-end over HTTP | `reports/si_demo_evidence.txt` |
| 9–12 | VSS snapshot <30 s | Unverified | **2.8 s** on Windows 11 build 26200, elevated. See §7.4 | `scripts/verify_vss.py` output |
| 13–16 | Cross-platform path handling | **2 failing tests**; broken in the Linux container | Fixed with `ntpath`/`posixpath` | `test_recovery.py` 54/54 |

### SH — Integration & DevOps

| Weeks | Target | Before | After | Evidence |
|---|---|---|---|---|
| 1–4 | Docker Compose, 6 services | Wired with health checks, but **monitor and ml_engine images could not build** (missing `watchdog`; xgboost needs Python ≥3.12) | Clean `up -d --build`, **all six healthy** | `docker compose ps` |
| 5–8 | Gateway routes match OpenAPI | `/ledger/verify` and `/ledger/blocks` **missing** | Added (SI's handlers); parity now asserted **both directions** | `test_gateway.py` |
| 9–12 | Dashboard real-time <1 s (TC-09) | Unverified | Event queryable **78 ms** after write; 1 s auto-refresh | `reports/attack_chain_evidence.txt` §8 |
| 9–12 | Bad/missing JWT → 401 (TC-10) | Missing-token only | Missing, malformed, wrong-secret, expired — all 401 | `test_gateway.py` (4 tests) |
| 13–16 | README accuracy | Described Ledger/Response as "clearly marked stubs" — **stale** | Rewritten per-service with real state | `README.md` |
| 13–16 | `len(hash) == 32` assertions | — | **None exist anywhere.** No change needed | verified |
| 13–16 | `short_hash()` with 64-char | — | Renders `e5e09c8362...dff248`. Correct | verified |

---

## 2. The most important finding

**`/ledger/verify` did not detect tampering against a running service.**

With the stack up in Compose, editing a block directly in the SQLite file and calling
`/ledger/verify` returned `valid: true`. The ledger certified a tampered chain as intact — a
silent failure of the exact guarantee TC-05 exists to test, in the deployed configuration.

The 39 unit tests missed it because each opens its own connection. Only a long-lived service
process is affected, which is to say: only production.

**Cause.** `journal_mode=WAL`. WAL coordinates connections through a shared-memory index
(`-shm`), and that coordination does not survive Docker Desktop's bind mount from the macOS
host into its Linux VM. The service kept answering from a snapshot taken before the edit.

**Fix.** Rollback journal instead — it relies on POSIX locks on the database file, which do
cross that boundary. `verify_chain()` also now reads through a fresh connection: an integrity
check that answers from its own cache cannot detect the one thing it exists to detect. The
`<50 ms` target is unaffected (2.3 ms for 1000 blocks).

```
before fix:  {"valid": true,  "blocks_checked": 3, "invalid_block_id": null}
after fix:   {"valid": false, "blocks_checked": 2, "invalid_block_id": 2}
```

---

## 3. Not done, or not verifiable here

1. ~~**Windows VSS snapshot timing — not measured.**~~ **CLOSED 8 Aug 2026 — see §7.**
   Measured on Windows 11 Home build 26200 from an elevated shell: a real shadow copy of `C:\`
   created in **2.8 s** against the 30 s target, listed, and logged to the ledger. The
   degradation path described here was correct; it is simply no longer the only path exercised.

2. **PE feature extractor — not built.** The system consumes EMBER's *precomputed* 2381-feature
   vectors; it cannot featurise an arbitrary PE file at runtime. The brief scoped NI's
   completion to "a real trained model, a working `/predict` and `/model/metrics`, and the EDA
   artifact," so this was verified and reported rather than built. It is a real gap against
   "50+ features extracted from PE files."

3. **ML Engine container image — slow to build, but it does build.** Docker Desktop's VM network
   repeatedly dropped the scientific wheels; three attempts wedged mid-download before
   `xgboost-cpu` (5.4 MB instead of 57 MB + 216 MB of CUDA) and `pip --retries 10 --timeout 120`
   got it through. Budget ~20 minutes on a slow link. The final run is a clean
   `docker compose up -d --build` with **all six services healthy** and no manual intervention.

4. **TC-07 through the Compose stack — skipped, not failed.** The Response service runs in a
   Linux container and cannot see host PIDs, so a host process is correctly refused with
   `TERMINATION_REFUSED`. Termination is verified directly in `test_actions.py` against real
   spawned processes (0.5 ms, target <2 s).

5. **Network isolation is not enforced by default.** Real `iptables`/`pfctl`/`netsh` rules are
   built and reported, but only applied when `RESPONSE_ISOLATION_ENABLED=true`. Applying
   firewall rules to the wrong host locks out the operator. The response says `enforced: false`
   rather than claiming a block that never landed.

6. ~~**Table 5.8 is reconstructed.**~~ **CLOSED 12 Aug 2026 — see §8.**
   The source document was supplied and `docs/test_cases.md` is now quoted from it. The
   reconstruction had three entries wrong; TC-08, TC-10 and TC-11 were re-implemented against
   the real definitions.

7. **Process attribution is absent.** Watchdog reports *what* changed, never *who* changed it.
   The Monitor now sends `process_id: null` rather than its own PID — the previous behaviour
   would have named an unrelated process in the Response container's PID namespace. Real
   attribution needs eBPF/fanotify or ETW (Phase 5).

**Correctly deferred (Phase 5+, not gaps):** Polygon anchoring and TC-12, production auth and
secret management, CI/CD, load balancing, the 95 % coverage target, SHAP explainability,
adversarial-ML robustness.

---

## 4. Table 5.8 results

| ID | Test case | Result | Evidence |
|---|---|---|---|
| TC-01 | File event detected and captured | **PASS** | `test_api.py::test_tc01_*`; live chain §4 |
| TC-02 | High-entropy write flagged | **PASS** | `test_detection.py::test_tc02_*`; live chain §4 |
| TC-03 | Legitimate compression not flagged | **PASS** | 0/40 false positives; live control file `benign_compressed` |
| TC-04 | File recovery + integrity | **PASS** (native) / **N-A** (Compose on Windows) | `si_demo.py`: restored hash == pre-attack hash. §7.5 |
| TC-05 | Audit-log tamper detected | **PASS** *(was silently failing — §2)* | `valid: false, invalid_block_id: 16` |
| TC-06 | ML classifies ransomware | **PASS** | 97.7 % EMBER / 88.6 % behavioural; live: `ransomware (critical)` |
| TC-07 | Process terminated <2 s | **PASS** (unit) / **SKIP** (Compose) | 0.5 ms; container cannot see host PIDs |
| TC-08 | Chain verifies <50 ms | **PASS** | 2.3 ms / 1000 blocks; live: 19 blocks in 0.17 ms |
| TC-09 | Dashboard reflects event <1 s | **PASS** | 78 ms; 1 s auto-refresh |
| TC-10 | Bad/missing JWT → 401 | **PASS** | 4 gateway tests + live |
| TC-11 | Full attack chain end to end | **PASS** | **18/18** — `reports/attack_chain_evidence.txt` |
| TC-12 | Blockchain anchoring | **OUT OF SCOPE** — Phase 5. Not attempted | — |

**11 of 11 in-scope test cases pass** (TC-07 fully verified at the unit level; skipped through
Compose for a documented platform reason). This clears the 8–10 needed for the "Target Goals /
Good" tier.

### Live end-to-end run

```
2. CONTROL  quarterly_backup.zip     entropy 7.999 → benign_compressed, suspicious: False
3. ATTACK   annual_report.docx.locked entropy 8.000
4. DETECT   verdict suspected_encryption, latency 13.3 ms, file_hash 0ac895f5…b7c7bb
5. PIPELINE ['ml_predicted', 'ledger_logged', 'response_triggered'] → ransomware (critical)
6. LEDGER   block #17 file_event, current_hash 64 chars, chain valid, 19 blocks in 0.172 ms
8. DASHBOARD event queryable 81 ms after write
9. AUTH     no token → 401, bad token → 401
                                                          18/18 checks passed
```

---

## 5. Changes by branch

| Branch | Change | Reason |
|---|---|---|
| `feature/SI-recovery-path-portability` | `to_relative` splits with `ntpath` then `posixpath` | `os.path.splitdrive` is a no-op off Windows; 2 failing tests, and broken in the Linux container |
| `feature/AS-response-engine` | `detection.py` — entropy, magic-byte container ID, classification | The false-positive mitigation did not exist; magic bytes were read and discarded |
| | `pipeline.py` — ML → ledger → response fan-out on a worker thread | Nothing connected detection to the rest of the system |
| | `file_hash` on every ledger event | SI's recovery integrity check depends on it |
| | `actions.py` — real termination with guards; platform-aware isolation | terminate/isolate/trigger were placeholders |
| | `watchdog` + `httpx` added to `requirements.txt`; `COPY *.py` | `app.py` imported `watchdog`; the container could not start |
| | `on_moved` added; `on_modified` no longer mislabels; bounded buffer; correct `files_monitored`; deterministic `/features`; `monitor.py` deleted | Assorted defects found while verifying |
| | Monitor sends `process_id: null` | Its own PID would name an unrelated process in another namespace |
| | 2 of SI's tests updated in place, reason recorded at each | They asserted the old placeholder behaviour |
| `feature/NI-ml-engine-service` | `services/ml-engine/app.py` serves real models | Deployed service was a stub with hardcoded metrics |
| | `features` dict path implemented | Returned 501 — the shape Monitor and `/analyze` send |
| | `train_behavioral_model.py`, `features.py` | EMBER model cannot score the Monitor's feature dict |
| | `fetch_ember_subset.py` | Fetches only the shards holding each class, with resume and retries |
| | `xgboost-cpu`, `python:3.13-slim`, pip retries | GPU build pulls 216 MB of unused CUDA; xgboost 3.4 needs ≥3.12 |
| `feature/SH-gateway-ledger-routes` | `GET /ledger/verify`, `GET /ledger/blocks` | No route through port 8000; SI's handlers adapted |
| | OpenAPI schemas + bidirectional parity tests | A route added to one without the other now fails the suite |
| | TC-10 coverage for malformed/forged/expired tokens | Only a missing token was tested |
| | README service table rewritten | Described real services as "clearly marked stubs" |
| `feature/SI-ledger-tamper-visibility` | Rollback journal instead of WAL; `verify_chain` reads fresh | **Tampering went undetected against the running service (§2)** |
| | `docker-compose.yml`: monitor gets `ML_URL`/`LEDGER_URL`/`RESPONSE_URL` | It drives the pipeline but ran on defaults that only worked by coincidence |

All five branches are merged to `main` and retained for review.

---

## 6. Reproducing

```bash
cp .env.example .env
docker compose up -d --build
python src/train_behavioral_model.py
python src/fetch_ember_subset.py --per-class 10000 && python src/train_ember_model.py
python scripts/attack_chain_demo.py
python scripts/si_demo.py
for s in gateway ledger monitor ml-engine response; do (cd services/$s && python -m pytest -q); done
```

---

## 7. Windows verification pass — 8 August 2026

Windows 11 Home Single Language, build 26200 · Python 3.13.9 · Docker Desktop 4.85.0 (WSL 2)

The first pass ran entirely on macOS. Every Windows-only branch was therefore
unexecuted, and the platform-portability fixes made in that pass had never been run
against the platform they were written for. Three defects surfaced here, one of them
severe enough that the system did nothing at all while reporting itself healthy.

### 7.1 The most important finding

**The Monitor detected nothing on Windows, and said it was healthy.**

Docker Desktop passes a Windows bind mount into the Linux VM as `9p`. inotify watches
on that filesystem are **accepted and then never fire**. Watchdog reports the observer
alive, `/health` returns healthy, and no event ever arrives — silence that is
indistinguishable from a quiet disk.

Isolated with a discriminating test: a host-side write into the watched path produced
**0 events**; the byte-identical write made inside the container produced **10**,
correctly classified `suspected_encryption` at entropy 8.0. Detection, entropy, hashing
and classification were all correct. Only the event source was dead.

```
tc01_detected                FAIL      →  PASS
tc02_flagged_as_ransomware   FAIL      →  PASS
tc03_no_false_positive       FAIL      →  PASS
attack chain                 1/3       →  18/18
```

**Fix.** `services/monitor/app.py` now selects the watchdog backend from the filesystem
backing the watch path, read from `/proc/mounts`: `PollingObserver` where the mount
carries no notifications, native inotify everywhere else, overridable with
`MONITOR_OBSERVER=auto|native|polling`. `/monitor/status` reports the chosen backend and
the reason, because a silent native watch cannot otherwise be told from an idle one.

Live confirmation: `observer_backend: polling`, reason
`/watch is on '9p', which delivers no inotify events to this container`.

### 7.2 Detection latency regression, introduced by the lock fix

The Windows file-lock retry added in the same pass retried **per read helper**, and
`handle_event` opens the same file twice. Measured against a real deny-share handle:

| | Before | After |
|---|---|---|
| `read_magic` | 151.7 ms | — |
| `calculate_entropy` | 151.8 ms | — |
| **`handle_event` (locked)** | **303.5 ms** | **40.9 ms** |
| `handle_event` (unlocked) | 13.9 ms | 13.9 ms |

Target is 100 ms, so the correctness fix had been bought at 3× the budget. The retry is
now bounded by a time budget rather than an attempt count, and the lock is probed once
per event instead of once per read.

### 7.3 Path portability was only half-fixed

The first pass fixed `to_relative` to strip a drive letter with `ntpath`. It did not
normalise separators. A Windows host sends `D:\...\thesis.doc`; in the Linux container
`\` is an ordinary filename character, so `os.path.join` produced a single file named
`data\si_demo\thesis.doc` rather than descending into `data/`. TC-04 reported a file
"not present in the snapshot" that was sitting right there. Separators are now
normalised to `/`, which opens correctly on both platforms.

This never appeared on macOS because the paths involved were already POSIX.

### 7.4 VSS — measured, from an elevated shell

`platform_status()` returned `supported: true` for the first time; every prior run
reported `platform: Darwin`. This exercised the version gate, `client` edition derived
from `CoreSingleLanguage`, and WMI backend selection.

```
supported True · platform Windows · version 10.0.26200 · edition client
backend wmi:Win32_ShadowCopy · elevated True

snapshot id     {F001EA19-04D1-42CB-A3C5-2829F79D27F1}
creation time   2.8s  (target <30s)          PASS
snapshot listed True                          PASS
logged to ledger True                         PASS
```

Ledger block #6 carries `device_object:
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3` and `duration_seconds: 2.427`, which
means `_create_via_wmi()`, `_device_object_for()` and elevated `_list_via_wmi()` all ran
for real. Two supporting defects were fixed on the way: `vssadmin` writes its errors to
**stdout**, not stderr, so the previous code reported a blank reason for every failure
(confirmed: stderr 0 bytes, exit 2); and COM was being torn down while a chained
`com_error` still held a pointer, printing `Win32 exception occurred releasing IUnknown`
once per failed enumeration.

### 7.5 TC-04 — corrected status

TC-04 passes against the Response service **running natively on Windows**, which is the
deployment the README prescribes for real recovery:

```
restored True · integrity_verified True
entropy 7.968 (encrypted) → 4.250 (restored) · hash matches pre-attack
```

It **cannot** pass through Compose from a Windows host. `restore_file` writes to the
literal path it is given, and a Linux container cannot write `D:\...`. This is the same
class as TC-07 — a documented deployment constraint, not a defect. The earlier unqualified
PASS should be read with this caveat.

### 7.6 TC-05 holds on Windows

The §2 fix replaced WAL with a rollback journal to survive Docker Desktop's **macOS**
bind mount. Windows uses an entirely different mechanism, so this needed re-proving:
`{"valid": false, "blocks_checked": 3, "invalid_block_id": 3}` — detected at exactly the
tampered block. The fix is not macOS-specific.

`si_demo.py` also tampered a block and never restored it, leaving the chain permanently
broken so the next run reported false failures downstream of the previous run's damage.
It now restores the row in a `finally`, and two consecutive runs both pass.

### 7.7 Suites — Windows native

| Suite | Result |
|---|---|
| gateway | 17 passed |
| ledger | 42 passed |
| monitor | 68 passed |
| ml-engine | 19 passed |
| response | 81 passed, 2 skipped |
| **Total** | **227 passed, 2 skipped, 0 failed** |

The 2 skips are correct: `psutil.terminate()` maps to `TerminateProcess` on Windows,
which no process can ignore, so the SIGTERM-escalation tests assert a POSIX guarantee
with no Windows equivalent. A Windows-specific test covers the same ground.

The ml-engine skips from the first pass are gone — `models/behavioral_model.pkl` was
absent, not broken. Retrained here: accuracy 0.884, ROC AUC 0.959.

**Not a defect:** a gateway contract test fails under FastAPI ≥ 0.141, which wraps
included routers in `_IncludedRouter` objects and breaks the test's route introspection.
Against the pinned `fastapi==0.115.6` it passes. Pin-drift, not a code fault.

### 7.8 Still open

- ~~**Table 5.8 reconciliation** against the source PDF (§3.6).~~ **CLOSED — §8.**
- ~~**PE feature extractor** (§3.2).~~ **CLOSED — §8.** Built as
  `services/monitor/pe_features.py`, 64 features.
- **The `unreadable` verdict does not escalate.** A file that cannot be read is no longer
  reported `benign` — that fabrication is fixed — but `suspicious` stays `False` and no
  response triggers. Defensible, since most locks are Defender or the search indexer, and
  escalating would be a false-positive firehose. It does mean in-place encryption that
  holds an exclusive handle and keeps the original filename is recorded rather than acted
  on. This is a detection-policy decision and should be made deliberately.

---

## 8. Phase 1–4 completion pass — 12 August 2026

The source document (*Complete Project Documentation* v1.6) was supplied for the first
time. §3.6 had flagged Table 5.8 reconciliation as gating submission; this pass closes
it, and closes the PE feature extractor with it.

### 8.1 The reconstruction was wrong in three places

Reconciling `docs/test_cases.md` against the real Table 5.8 (pp. 55–56):

| ID | Recorded as | Actually specified |
|---|---|---|
| TC-08 | Chain verifies <50 ms | **CPU <15%, RAM <500MB.** Chain verification is a Table 5.9 benchmark, not TC-08. **RAM had never been measured.** |
| TC-11 | Full attack chain end to end | **Multiple simultaneous attacks.** No concurrency test existed anywhere. |
| TC-10 | Bad/missing JWT → 401 | 401 **plus an audit log entry**. The gateway rejected correctly and recorded nothing. |

All three were re-implemented against the real definitions rather than the documentation
being edited to match the code.

### 8.2 What was built

| Gap | Resolution | Measured |
|---|---|---|
| TC-08 RAM unmeasured | `test_memory_usage_under_500mb_during_stress` | **peak 67.6 MB**, +2.6 MB growth over 166 × 512 KB events |
| TC-11 absent | Concurrency tests in monitor **and** response | 12 concurrent detections p95 **25.1 ms**; 8 concurrent terminations, all successful, bystander untouched |
| TC-10 no audit trail | `audit_access_denial()` writes an `auth_failure` block on every 401/403 | Best-effort; a dead ledger cannot turn a 401 into a 500 (tested) |
| API p95 unmeasured (Table 5.9) | `services/gateway/tests/test_benchmarks.py` | **2.87 ms** p95 over 1000 requests, target <200 ms |
| TC-01 had no sample | `scripts/ransomware_simulator.py` | Detected and terminated after **1 file**, bound <5 |
| PE feature extractor (§3.2) | `services/monitor/pe_features.py` — **64 features** | Tested against real system binaries |

### 8.3 A contract that was quietly broken

`gateway.yaml` marks `pe_imports_count` and `api_calls` **required** on `FeatureSet`, and
spec §3.4.2 shows both going into `/predict`. The Monitor's `extract_features()` returned
neither, so `/analyze` had been sending an incomplete FeatureSet to the ML engine for as
long as the route has existed. The PE parser supplies both: real values for an executable,
`0` and `[]` for anything else — which is the honest answer for a `.docx`, not a
fabricated count. The earlier random `pe_imports_count` defect was a symptom of the same
missing capability.

Parsing runs only in `/features`, never on the watchdog event thread. Detection latency
re-measured after the change: **p95 30.6 ms**, unchanged.

### 8.4 A flaky test, found and fixed

`test_tc11_all_simultaneous_attacks_are_terminated` passed alone and failed intermittently
in the full suite. Two real defects, not bad luck:

- it asserted **batch wall-clock** under 2 s, but the 2 s bound is *per termination*
  (TC-07); TC-11 states no timing requirement. Under full-suite load the batch figure
  measures host business, not this code. Now asserts each `termination_time_ms`.
- liveness was checked with `pid_exists()` then `psutil.Process(pid).status()`, which
  races the exit and can observe a **recycled PID** on Windows. Now uses `process.wait()`,
  which reaps the child and is authoritative.

Verified with five consecutive full-suite runs: 84 passed, 2 skipped, every time.

### 8.5 Suites

| Suite | Before | After |
|---|---|---|
| gateway | 17 | **70** |
| ledger | 42 | 42 |
| monitor | 68 | **90** |
| ml-engine | 19 | 19 |
| response | 81 + 2 skip | **84** + 2 skip |
| **Total** | **227** | **305 passed, 2 skipped, 0 failed** |

### 8.6 Still open after this pass

- **CLEAR-augmented training.** §6.1 states the model was trained on EMBER "augmented with
  behavioral logs from the CLEAR dataset". It is not. EMBER trains on EMBER; the
  behavioural model trains on a synthetic corpus. CLEAR and RanSAP *are* used — for EDA and
  threshold characterisation in `src/analyze_behavioral_signals.py`, which is NI's Week 1–4
  deliverable and is met — but not as training input. Deferred deliberately: closing it
  means retraining and restating the headline accuracy figures.
- **The RanSAP-derived threshold is not wired in.** `analyze_behavioral_signals.py`
  computes a suggested threshold of **0.3186**, but the Monitor runs at **7.5**. These are
  different scales — RanSAP's `entropy_1` is normalised 0–1, Shannon is 0–8 bits/byte — so
  the calibration currently informs nothing. Worth reconciling before claiming the threshold
  is RanSAP-derived.
- **TC-12 / blockchain anchoring**, **CI/CD**, **SHAP served per-prediction**: all Weeks
  17–32 in Tables 5.4–5.6. Correctly deferred, not gaps against Phase 1–4.
