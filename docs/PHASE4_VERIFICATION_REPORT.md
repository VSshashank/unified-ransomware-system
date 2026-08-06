# Phase 1–4 Verification Report

**Repo:** `VSshashank/unified-ransomware-system` · **Verified:** 6 August 2026
**Scope:** Phases 1–4 (Weeks 1–16). Phase 5+ items are flagged as correctly deferred, not as gaps.

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
| 9–12 | VSS snapshot <30 s | Unverified | **Not measurable — no Windows hardware.** See §3 | `scripts/verify_vss.py` output |
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

1. **Windows VSS snapshot timing — not measured.** No Windows hardware in this environment.
   `scripts/verify_vss.py --volume C:\` reports `supported: false`, `platform: Darwin`, with a
   clear reason. `VSSManager` degrades correctly rather than faking a snapshot. The `<30 s`
   target is **unverified**, not failed.

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

6. **Table 5.8 is reconstructed.** The source PDF is not in the repo. `docs/test_cases.md`
   documents which definitions are certain (TC-04, TC-05, TC-12, quoted from existing code) and
   which are inferred. **Reconcile against the PDF before submission.**

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
| TC-04 | File recovery + integrity | **PASS** | `si_demo.py`: restored hash == pre-attack hash |
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
