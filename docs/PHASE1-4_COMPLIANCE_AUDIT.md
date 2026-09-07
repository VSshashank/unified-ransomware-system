# Phase 1–4 Compliance Audit — code vs. the reference document

**Reference:** *Unified Ransomware Detection & Recovery System — Complete Project
Documentation*, v1.6, 31 January 2026, 68 pages.
**Repository:** `D:\Unified_Ransomware_Project`, branch `feat/phase4-completion` @ `589cbe8`
**Audit date:** 12 August 2026
**Scope:** Phases 1–4 (Semester 1, Weeks 1–16). Phase 5–8 items are judged against
the document's own timeline, not treated as gaps.

## How this audit was done

The PDF was extracted in full (68/68 pages) and read end to end. Every file in the
repository was then opened and compared against it — not skimmed. Claims made in the
existing project docs (`APPROACH.md`, `FLOW.md`, `PHASE4_VERIFICATION_REPORT.md`,
`test_cases.md`) were treated as assertions to check, not as evidence. Specifically:

- All 5 test suites were re-run from a clean checkout on this machine.
- All 10 Table 5.9 benchmarks were re-measured, not read from `reports/`.
- The spec's own worked API examples (Listings 3.5, 3.6, 3.10–3.16) were replayed
  against the running code.
- The behavioural model's decision boundary was probed directly with real files.

That last step turned up a detection gap that no existing test covers. It is
Finding **F-1** below.

---

## 1. Verdict

| | |
|---|---|
| **Phase 1–4 functional scope** | **Substantially complete.** All 6 services real, all 19 documented endpoints implemented, all 11 in-scope test cases have named tests, all 10 benchmarks met. |
| **Test suite (re-run 12 Aug 2026)** | **305 passed, 2 skipped, 0 failed** — matches the claim in `APPROACH.md` §9 exactly. |
| **Blocking issue** | **1** — F-1, a systematic detection miss on small encrypted files. |
| **Should fix before submission** | **4** — F-2 … F-5. |
| **Documentation inaccuracies** | **5** — D-1 … D-5. |
| **Deviations from spec, defensible** | **8** — V-1 … V-8. |
| **Correctly deferred to Semester 2** | **7** — all traceable to Tables 5.4–5.6, Weeks 17–32. |

The project meets the document's "Target Goals (80–85%)" bar in §5.6.2 and clears
several §5.6.3 Distinction criteria. It does not reach full Distinction because
TC-12 (Polygon anchoring) and CI/CD are Semester 2 by the document's own schedule.

---

## 2. Independently re-run test results

Executed per-service exactly as `README.md` prescribes, using the repo `.venv`.

| Suite | Result | Duration |
|---|---|---|
| `services/gateway` | 70 passed | 6.06 s |
| `services/ledger` | 42 passed | 15.35 s |
| `services/monitor` | 90 passed | 15.83 s |
| `services/ml-engine` | 19 passed | 2.02 s |
| `services/response` | 84 passed, 2 skipped | 33.42 s |
| **Total** | **305 passed, 2 skipped, 0 failed** | |

The 2 skips are legitimate: `psutil.terminate()` maps to `TerminateProcess` on
Windows, which cannot be ignored, so the two SIGTERM-escalation tests assert a POSIX
guarantee that has no Windows equivalent. `test_on_windows_a_stubborn_process_still_dies`
covers the same ground.

### Table 5.9 benchmarks — re-measured, not quoted

| Metric (Table 5.9) | Target | Re-measured today | Verdict |
|---|---|---|---|
| Detection latency | <100 ms | **36.7 ms** p95 (40 samples, 4 KB–2 MB) | PASS |
| Response time (kill) | <2 s | **150 ms** | PASS |
| False positive rate | <5 % | **0 %** (0/40; 32 of 40 deliberately high-entropy) | PASS |
| ML inference time | <100 ms | **2.53 ms** p95 | PASS |
| API response (p95) | <200 ms | **6.79 ms** over 1000 requests | PASS |
| System CPU usage | <15 % | **1.31 %** of 14 cores (95 writes / 5 s) | PASS |
| System RAM usage | <500 MB | **70.6 MB** peak, +1.9 MB growth over 137 × 512 KB | PASS |
| File recovery success | 100 % | **100 %** native (`reports/si_demo_evidence.txt`) | PASS |
| Ledger verification | <50 ms | **2.3 ms** / 1000 blocks | PASS |
| Dashboard update latency | <1 s | **442 ms** (`reports/attack_chain_evidence.txt` §8) | PASS |

All ten targets met, independently. Numbers differ from the committed
`reports/*.json` by a few percent because they are a fresh measurement on this
machine — see **F-4** about that side effect.

---

## 3. Chapter 3 — System Architecture & API Specification

### 3.1 Technology stack (Table 3.1)

| Layer | Document requires | In the repo | Status |
|---|---|---|---|
| Presentation | Streamlit, Plotly, HTML5/CSS3 | `services/dashboard/app.py` — Streamlit 1.41.1, Plotly 5.24.1, inline CSS | ✅ |
| Application | FastAPI, Python 3.9+, Uvicorn, Pydantic | FastAPI 0.115.6, Uvicorn 0.32.1, Pydantic 2.10.4, Python 3.11/3.13 images | ✅ |
| Business Logic | XGBoost, watchdog, SHA-256 | `xgboost-cpu` 3.4.0, `watchdog` 6.0.0, `hashlib.sha256` | ✅ |
| Data | SQLite, file system, Windows VSS | `services/ledger/database.py`, `recovery/vss_manager.py` (WMI `Win32_ShadowCopy`) | ✅ |
| Security | JWT, cryptography library, **TLS 1.3** | JWT via `python-jose[cryptography]`; **no TLS anywhere — all services are plain HTTP** | ⚠️ **V-1** |
| DevOps | Docker, Docker Compose, **GitHub Actions**, pytest | Docker + Compose + pytest present; **no `.github/` directory** | ⚠️ deferred (Table 5.6, Weeks 17–24) |

### 3.2 Hash chain design (§3.2.2, Listing 4.7, Figure 4.8)

The document is internally inconsistent here, and the code follows the correct half.

- §3.2.2 states `Hash_N = SHA256(Timestamp + Data + Hash_{N-1})`
- Listing 4.7 (the code template) computes `f"{timestamp}{event_type}{event_data}{previous_hash}"`
- Figure 4.8 states `SHA256(id + data + prev_hash)` — **contradicts both**

`services/ledger/hash_chain.py:63` implements Listing 4.7 verbatim. That is the
right choice: Figure 4.8's `id` variant is not what the reference implementation in
the same document does. Recorded as **D-5** so it is not mistaken for a code error.

Genesis hash is 64 zeros (`database.py:20`), matching the template's `"0" * 64`.

### 3.3 API contracts (§3.4) — endpoint-by-endpoint

Every endpoint the document specifies exists. Request and response field names were
compared literally against Listings 3.1–3.16.

#### Monitor Service, port 8001 (§3.4.1)

| Endpoint | Document | Implementation | Status |
|---|---|---|---|
| `POST /monitor/start` | req `{watch_path, recursive, file_patterns}` → `{status, monitor_id, start_time}` | `app.py:397` — all 3 request fields, all 3 response fields, echoes `watch_path`/`recursive`/`file_patterns` back | ✅ but see **F-3** |
| `POST /monitor/stop` | req `{monitor_id}` | `app.py:439` — takes **no request body**; stops whatever is running | ⚠️ **V-2** |
| `GET /monitor/status` | `{status, files_monitored, events_captured, uptime_seconds}` | `app.py:453` — all 4 present, plus `monitor_id`, `watch_path`, `observer_backend`, `observer_reason` | ✅ superset |

`GET /monitor/events` and `POST /features` are additions, not in the document —
`/features` is required by the `/analyze` orchestration in Listing 4.9.

#### ML Engine, port 8002 (§3.4.2)

| Endpoint | Document | Implementation | Status |
|---|---|---|---|
| `POST /predict` | req `features{shannon_entropy, file_size, magic_bytes, modification_rate, pe_imports_count, api_calls}` | `app.py:187` accepts all; **`pe_imports_count` and `api_calls` are accepted and silently dropped** — `FEATURE_ORDER` in `features.py:11` has neither | ⚠️ **F-2** |
| `POST /predict` response | `{prediction, confidence, model_version, timestamp, threat_level, features_importance}` | All 6 present, plus `model` and `inference_time_ms` | ✅ superset |
| `GET /model/metrics` | `{accuracy, precision, recall, f1_score, roc_auc, last_trained}` | `app.py:257` — all 6 present, plus `model_version` and a per-model breakdown | ✅ superset |

**Replayed the document's own example.** Listing 3.5 sent verbatim returns:

```
prediction   "benign"      (document Listing 3.6 says "ransomware")
confidence   0.8231        (document says 0.94)
threat_level "low"         (document says "high")
```

This is not a contract violation — the document's numbers are illustrative — but it
is the surface symptom of **F-1**.

#### Ledger Service, port 8003 (§3.4.3)

| Endpoint | Document | Implementation | Status |
|---|---|---|---|
| `POST /ledger/log` | req `{event_type, event_data}` → `{block_id, current_hash, previous_hash, timestamp, tamper_proof}` | `main.py:98` — exact field-for-field match | ✅ |

Returns HTTP **200**; Table 3.2 reserves **201 Created** for "e.g. ledger entry", and
`docs/openapi/gateway.yaml:182` declares 201 as an allowed response. Recorded as **V-3**.

`GET /ledger/verify`, `/ledger/blocks`, `/ledger/entries` are additions required by
TC-05 and the dashboard.

#### Response Engine, port 8004 (§3.4.4, §3.4.5)

| Endpoint | Document request | Document response | Status |
|---|---|---|---|
| `POST /response/terminate` | `{process_id, incident_id, reason, force}` | `{status, process_id, timestamp, exit_code}` | ✅ exact, `actions.py:130` |
| `POST /response/isolate` | `{isolation_level, duration_seconds, allow_localhost}` | — | ✅ exact |
| `POST /response/recover` | `{snapshot_id, files, verify_integrity}` | `{status, files_recovered, integrity_verified, timestamp}` | ✅ exact, `recovery.py:103` |
| `POST /response/trigger` | `{incident_id, process_id, threat_level, action_required}` | `{status, actions_taken[], timestamp}` | ✅ exact, `app.py:192` |

### 3.4 Data models (§3.5)

| Model | Document fields | Implementation | Status |
|---|---|---|---|
| `FileEvent` (§3.5.1) | `event_id, event_type, file_path, timestamp, process_id, user, file_size, entropy, hash_md5` | `monitor/app.py:284` — all present except **`hash_md5`**, which is `file_hash` (SHA-256) instead | ⚠️ **V-4** |
| `Prediction` (§3.5.2) | `prediction, confidence, threat_level, model_version, timestamp, features_importance` | `ml-engine/app.py:243` — exact | ✅ |
| `LedgerBlock` (§3.5.3) | `block_id, timestamp, event_type, event_data, previous_hash, current_hash, blockchain_anchor` | `ledger/models.py:13` — exact, `blockchain_anchor` present and always `null` | ✅ |

`V-4` is an improvement, not a regression — MD5 is broken for integrity work and the
document's own §3.1 stack table specifies SHA-256. Worth stating in the thesis rather
than leaving as an unexplained mismatch.

### 3.5 Sequence diagrams (§3.6)

| Diagram | Document flow | Implementation | Status |
|---|---|---|---|
| Figure 3.3 — Normal file operation | Detect → Extract Features → **Predict (Benign)** → **Log Event** → Hash Added → Update Status | `monitor/app.py:313` only fans out when `verdict["suspicious"]` is True. **A benign event is recorded locally and never reaches ML or the ledger.** | ⚠️ **V-5** |
| Figure 3.4 — Ransomware attack | Modification Event → Calc Entropy → Check Features → RANSOMWARE → Trigger Response → Kill → Alert → Isolate & Restore | `pipeline.py:85` implements exactly this chain | ✅ |

V-5 is a deliberate performance decision (`FLOW.md` §1.1 explains it, and it is what
keeps CPU at 1.3 %), but it does diverge from Figure 3.3. The document's flow *is*
reachable — `POST /analyze` runs Monitor → ML → Ledger for any file regardless of
verdict — so the capability exists; it just is not automatic on benign events.

### 3.6 Deployment (§3.7.1, Listing 3.20)

`docker-compose.yml` is a strict superset of Listing 3.20:

| Listing 3.20 item | Present | Note |
|---|---|---|
| `version: '3.8'` | ✅ | |
| `monitor` / `ransomware_monitor` / 8001 / `./watched_files:/watch` + `./logs:/app/logs` | ✅ | ports bound to `127.0.0.1` — hardening, see V-6 |
| `ml_engine` / `ransomware_ml` / 8002 / `./models:/models` | ✅ | |
| `ml_engine` deploy limits `cpus: '2'`, `memory: 2G` | ✅ | exact |
| `gateway` / `ransomware_gateway` / 8000 / 4 service URLs / `depends_on` | ✅ | `depends_on` upgraded to `condition: service_healthy` |
| `networks: ransomware_net: driver: bridge` | ✅ | exact |
| `restart: unless-stopped` on all | ✅ | |
| *(not in Listing 3.20)* `ledger`, `response`, `dashboard` | ✅ | required by §3.1's four-service architecture + §7.1 dashboard |

Deployment commands (Listing 3.21) and the §A.3 setup steps all work as written.
Dashboard is at `http://localhost:8501` as §A.3.3 states.

### 3.7 Error handling (§3.8)

Listing 3.22's envelope is implemented identically in **all five** services:

```json
{"error": {"code": "...", "message": "...", "timestamp": "...Z", "request_id": "req_..."}, "details": {}}
```

Verified at `gateway/main.py:48`, `monitor/app.py:161`, `ml-engine/app.py:69`,
`ledger/main.py:41`, `response/app.py:79`, `recovery/recovery.py:317`. Asserted by
`test_forbidden_uses_the_project_error_envelope` and equivalents in each suite.

HTTP status codes (Table 3.2): 200, 400, 401, 403, 404, 429, 500, 503 all produced.
**201 is never returned** — see V-3.

### 3.8 Authentication & rate limiting (§3.9)

JWT payload (Listing 3.23) requires `{sub, role, exp, iat}`. `gateway/models.py:20`
has all four plus `tier`. ✅ superset.

Rate limits (Table 3.3) — `gateway/rate_limit.py:9` is an exact transcription:

| Tier | Document req/min | Document burst | Code |
|---|---|---|---|
| Free | 60 | 100 | ✅ 60 / 100 |
| Premium | 300 | 500 | ✅ 300 / 500 |
| Enterprise | 1000 | 2000 | ✅ 1000 / 2000 |

---

## 4. Chapter 4 — Roles, deliverables and code templates

### AS — Endpoint Security (Table 4.1, Table 5.3)

| Weeks | Deliverable | Success criterion | Status |
|---|---|---|---|
| 1–4 | Design document | Architecture approved | ✅ `docs/openapi/gateway.yaml`, `APPROACH.md`, `FLOW.md` |
| 5–8 | File monitor working | Detect modifications <100 ms | ✅ 36.7 ms p95 |
| 9–12 | Entropy calculator | Shannon entropy accurate | ✅ `detection.py:146`; tested against known values (uniform = 8.0, single byte = 0.0, 2-symbol = 1.0) |
| 9–12 | **Differential entropy analysis** | — | ❌ **F-5 — not implemented** |
| 9–12 | Magic byte verification | — | ✅ 20 container signatures, `detection.py:46` |
| 13–16 | Response engine | Terminate <2 s | ✅ 150 ms measured |
| 17–24 | False positives <5 % | — | ✅ 0 % (early) |

Technology stack (Listing 4.2): `watchdog` ✅, `math`/`numpy` ✅, `psutil` ✅,
`pywin32` ✅ (win32-conditional). Code template Listing 4.3 (`RansomwareMonitor`
→ entropy → threshold → ML → terminate) is realised in
`monitor/app.py::MonitorHandler` + `pipeline.py`.

### NI — Machine Learning (Table 4.2, Table 5.4)

| Weeks | Deliverable | Success criterion | Status |
|---|---|---|---|
| 1–4 | EDA report | Dataset characteristics documented | ✅ `src/analyze_ember.py`, `src/analyze_behavioral_signals.py`, `class_balance_chart.png`, `reports/behavioral_analysis_summary.txt` |
| 5–8 | Feature pipeline | **Extract 50+ features from PE files** | ✅ `services/monitor/pe_features.py` — **70 features** (docs say 64; see D-1) |
| 9–12 | Trained model | Accuracy >85 % on test set | ✅ EMBER 97.74 %, behavioural 88.43 % |
| 13–16 | ML API service | Inference <100 ms | ✅ 2.53 ms p95 |
| 17–24 | Optimized model | Accuracy >90 %, F1 >90 % | ✅ EMBER: acc 0.9774, F1 0.9768 (early) |

Technology stack (Listing 4.4): XGBoost ✅, scikit-learn ✅, pandas+numpy ✅,
FastAPI ✅, **SHAP** ✅ offline (`src/shap_analysis.py`, `reports/shap_feature_importance.json`,
`reports/shap_summary_plot.png`) — Table 5.4 schedules SHAP for Weeks 17–24, so this is early.

Code template Listing 4.5 requires `train_test_split(..., stratify=labels)` and
`scale_pos_weight` — both present in `src/train_ember_model.py:64,73`.

**Challenge 1 mitigation (p. 40) is half-implemented.** The document prescribes
"SMOTE oversampling **+** class weights in XGBoost". Class weights are there
(`scale_pos_weight`); **SMOTE is nowhere in the repo** — `imblearn` is not imported,
installed, or listed. See **V-7**.

### SI — Blockchain & Recovery (Table 4.3, Table 5.5)

| Weeks | Deliverable | Success criterion | Status |
|---|---|---|---|
| 1–4 | Ledger schema | Design approved | ✅ `ledger/database.py:24` — matches Listing 4.7's `CREATE TABLE` exactly |
| 5–8 | Hash chain working | Immutable log with validation | ✅ `hash_chain.py`, 42 tests |
| 9–12 | VSS integration | **Automated snapshots every 6 hours** | ✅ `vss_manager.py:36` `DEFAULT_INTERVAL_HOURS = 6`, APScheduler job |
| 13–16 | Recovery module | 100 % file restoration | ✅ native; `reports/si_demo_evidence.txt` |
| 17–24 | Smart contract | Polygon testnet | ⏸ Semester 2 |

Technology stack (Listing 4.6): SQLite ✅, hashlib ✅, pywin32 ✅, web3.py ⏸,
Solidity ⏸ (both Weeks 17–24).

Success metric "Backup creation time < 30 seconds": measured **2.8 s** on Windows 11
build 26200 elevated (`PHASE4_VERIFICATION_REPORT.md` §7.4, ledger block #6).

### SH — Integration & DevOps (Table 4.4, Table 5.6)

| Weeks | Deliverable | Success criterion | Status |
|---|---|---|---|
| 1–4 | API specification | OpenAPI schema complete | ✅ `docs/openapi/gateway.yaml`, 856 lines, 19 paths |
| 5–8 | API gateway | Routes all requests correctly | ✅ bidirectional parity tests (`test_every_documented_path_is_implemented`, `test_every_implemented_route_is_documented`) |
| 9–12 | Dashboard v1 | Shows real-time file events | ✅ but see **F-2** |
| 13–16 | Docker setup | One-command deployment | ✅ `docker compose up -d --build` |
| 17–24 | CI/CD pipeline | Auto-tests on every commit | ⏸ Semester 2 — no `.github/` |

Code template Listing 4.9 (`/analyze`: monitor `/features` → ML `/predict` → ledger
`/log`) is implemented at `gateway/main.py:209` in exactly that order, with a test
asserting the ordering.

Success metrics: API p95 <200 ms ✅ (6.79 ms); dashboard <1 s ✅ (442 ms);
**95 %+ test coverage** — not measured anywhere, and §5.6.3 places it in the
Distinction tier. ⏸

Git workflow (Listing 4.1): branch names and conventional-commit format both
followed — `feat/phase4-completion`, `fix(gateway): ...`, `docs: ...`.

---

## 5. Chapter 5 — Test cases (Table 5.8) and success criteria

Each row was checked against the document text on pp. 55–56 and against the code that
claims to satisfy it.

| ID | Document scenario | Document expected outcome | Where implemented | Verified |
|---|---|---|---|---|
| TC-01 | Detect known ransomware (Jasmin) | Alert, process terminated, <5 files encrypted | `scripts/ransomware_simulator.py`, `monitor/tests/test_tc01_simulator.py`, `test_api.py::test_tc01_*` | ✅ detected after **1 file** |
| TC-02 | Detect zero-day ransomware | Behavioral analysis detects anomaly, response triggered | `test_detection.py::test_tc02_*` | ✅ but see **F-1** |
| TC-03 | Legitimate compression (ZIP) | No alert (magic byte verification passes) | `test_detection.py::test_tc03_*`, `test_benchmarks.py` | ✅ 0/40 false positives |
| TC-04 | File recovery from backup | Restored to pre-attack state, integrity verified | `recovery/tests/test_integration.py::test_tc04_*`, `scripts/si_demo.py` | ✅ native / N-A in Compose |
| TC-05 | Audit log tampering attempt | Chain validation fails, tampering detected and logged | `ledger/tests/test_api.py::test_tc05_*` + 27 chain tests | ✅ `invalid_block_id` = exact block |
| TC-06 | ML model accuracy test | Precision/Recall/F1 all >85 % | `reports/model_metrics.json` | ✅ P 0.9761 / R 0.9775 / F1 0.9768 |
| TC-07 | Response time (detection to action) | Terminated within 2 s of detection | `response/tests/test_actions.py::test_tc07_*` | ✅ 150 ms |
| TC-08 | System resource usage | CPU <15 %, RAM <500 MB | `monitor/tests/test_benchmarks.py` | ✅ 1.31 % / 70.6 MB |
| TC-09 | Dashboard real-time updates | Alert within 1 s of detection | `scripts/attack_chain_demo.py` §8 | ✅ 442 ms |
| TC-10 | API authentication failure | 401, request blocked, **audit log entry created** | `gateway/tests/test_authz.py::test_tc10_*` (5 tests) | ✅ all three parts |
| TC-11 | Multiple simultaneous attacks | All detected and terminated, system stable | `monitor/tests/test_tc11_concurrent.py` + `response/tests/test_tc11_concurrent.py` | ✅ 12 concurrent detections, 8 concurrent kills |
| TC-12 | Blockchain anchoring **(if implemented)** | Hash anchored to Polygon testnet | — | ⏸ correctly out of scope |

**11 of 11 in-scope test cases pass.** `docs/test_cases.md` is an accurate
transcription of Table 5.8 — I checked all 12 rows against the PDF text word for word,
including the parenthetical "(if implemented)" on TC-12, and found no errors.

### Success criteria (§5.6)

| Tier | Criterion | Met |
|---|---|---|
| §5.6.1 (70 %) | File monitoring + entropy | ✅ |
| | ML >70 % accuracy | ✅ 97.7 % |
| | Stops ≥1 ransomware simulator | ✅ |
| | Hash-chain audit trail | ✅ |
| | Basic file recovery | ✅ |
| §5.6.2 (80–85 %) | ML >85 % (P/R/F1) | ✅ |
| | Detects 3+ ransomware simulators | ⚠️ **one** simulator, exercised in 4 modes |
| | False positive rate <5 % | ✅ 0 % |
| | Response time <2 s | ✅ 150 ms |
| | 8–10 test cases passed | ✅ 11 |
| | Functional dashboard with real-time alerts | ✅ |
| §5.6.3 (90 %+) | ML >90 % across all metrics | ✅ EMBER |
| | Blockchain anchoring to Polygon | ⏸ Semester 2 |
| | 12–15 test cases passed | ⚠️ 11 of 12 (TC-12 gates the 12th) |
| | Complete CI/CD pipeline | ⏸ Semester 2 |
| | SHAP documented | ✅ offline |
| | Research paper draft | ⏸ Weeks 25–32 |

### Risk register (Table 5.7) — mitigations actually in place

| Risk | Document mitigation | In the repo |
|---|---|---|
| ML underperforms | Ensemble / Random Forest fallback | ✅ `src/train_baseline_comparison.py`, `reports/baseline_comparison.json` (RF acc 0.939) — this also fills Table 8.1 |
| Integration issues | API contracts by Week 4, Docker Compose | ✅ `gateway.yaml` + bidirectional parity tests |
| High false positives | Differential entropy, magic byte verification, whitelist | ⚠️ magic bytes ✅; **differential entropy ❌ (F-5)**; whitelist ❌ |
| Blockchain costs | Polygon testnet, hash chain as zero-cost fallback | ✅ fallback is the shipped path |
| Dataset access | Smaller subsets | ✅ `src/fetch_ember_subset.py --per-class` |

---

## 6. Chapter 6 — Experimental methodology

| §6.1 requirement | Document | Actual | Status |
|---|---|---|---|
| Total samples | 50,000 PE files | **19,480** (13,636 train + 2,922 test + 2,922 val) | ⚠️ **V-8** |
| Class balance | 25,000 / 25,000 | Balanced, `stratify=y` | ✅ |
| Split ratio | 70 / 15 / 15 | **70 / 15 / 15 exactly** (`train_ember_model.py:64`) | ✅ |
| Training source | EMBER **augmented with CLEAR behavioral logs** | EMBER only; CLEAR used for EDA, not training | ⚠️ **V-8** |

`src/fetch_ember_subset.py` supports `--per-class 25000`, so V-8 is a matter of what
was run, not what the code can do. `data/ember_subset/ember_50k.parquet` (434 MB) is
on disk; `reports/model_metrics.json` records `dataset: ember_subset.parquet`, a file
that is **not present** — so the committed metrics were produced from a different,
smaller extract than the parquet now in `data/`.

§6.2 evaluation metrics (Accuracy, Precision, Recall, F1, ROC-AUC): all five computed
and reported. ✅

§6.3 hardware (Table 6.1) specifies i7-12700K / 32 GB / Windows 11 / Python 3.9.13.
Actual: Windows 11 build 26200, Python 3.13.9, 14 cores. Different hardware — the
thesis needs Table 6.1 updated to the machine that was actually used, or the
benchmarks re-run on the specified one. **D-4**.

---

## 7. Appendix A — directory structure

| §A.1 path | Repo | Note |
|---|---|---|
| `docker-compose.yml` | ✅ | |
| `.env.example` | ✅ | |
| `services/monitor/{Dockerfile, main.py, requirements.txt}` | ✅ | entry point is `app.py`, not `main.py` |
| `services/ml_engine/{Dockerfile, model.pkl, api.py}` | ✅ | directory is `ml-engine` (hyphen); model mounted from `./models`, not baked in |
| `services/ledger/` | ✅ | `main.py` + `app.py` shim |
| `services/gateway/` | ✅ | `main.py` |
| `data/` | ✅ | |
| `docs/` | ✅ | |

Naming differs cosmetically. The Compose *service* name is `ml_engine`, so the
internal DNS name matches the document's `http://ml_engine:8002` exactly.

---

## 8. Findings

### F-1 — Small encrypted files are classified benign, so no response fires 🔴 **BLOCKING**

**Where:** `models/behavioral_model.pkl` + `services/monitor/pipeline.py:105,129`

The Monitor's own heuristic correctly reports `suspected_encryption` for any
high-entropy file. But `pipeline.run()` takes the **ML engine's** `threat_level` to
decide whether to act, and only `{"high", "critical"}` triggers a response. The
behavioural classifier's operating point requires Shannon entropy ≈ **7.995+**, which
ciphertext under roughly 40 KB cannot reach through sampling noise alone.

Measured directly, in-place encryption keeping the original filename, 5 trials each:

| File size | Entropy | Monitor verdict | ML label | threat_level | Response triggered |
|---|---|---|---|---|---|
| 4 KB | 7.96 | `suspected_encryption` | benign | low | **No** |
| 8 KB | 7.98 | `suspected_encryption` | benign | low | **No** |
| 16 KB | 7.99 | `suspected_encryption` | ransomware (1/5) | medium | **No** |
| 24 KB | 7.99 | `suspected_encryption` | ransomware (3/5) | medium | **No** |
| 32 KB | 7.99 | `suspected_encryption` | benign | low | **No** |
| 40 KB | 8.00 | `suspected_encryption` | ransomware (5/5) | critical | Yes |
| 64 KB+ | 8.00 | `suspected_encryption` | ransomware (5/5) | critical | Yes |

The cliff is sharp and it is not a rounding artefact — scoring the same file with
unrounded entropy gives the same answer (7.9938 raw → benign at 0.833).

Two things mask it today:

1. A ransomware **extension** (`.locked`, `.wncry`, …) sets the second-most-important
   feature and flips the verdict, so extension-renaming families are still caught at
   every size. Modern in-place encryptors that keep the filename are not.
2. **Every existing test uses ≥64 KB files** or the `ENCRYPTED` fixture pinned at
   entropy 7.999. Nothing in the 305-test suite exercises the failing region, and
   `scripts/ransomware_simulator.py` writes documents large enough to clear the cliff.

The reported recall of **0.8127** is honest and was never hidden — but the ~19 % of
misses are not randomly distributed, they are systematically the small files, and the
pipeline converts each miss into "no response at all".

**Suggested fix (either alone closes it):**
- Make the response decision `verdict["suspicious"] OR threat_level in {high, critical}`,
  so the Monitor's own detection is not overridden by a low-confidence model. One line
  in `pipeline.py:129`.
- Retrain the behavioural model with size-stratified ciphertext in the 2–64 KB band and
  check the resulting recall by size bucket, not just in aggregate.

Add a regression test at 4 KB / 8 KB / 32 KB with no ransomware extension.

### F-2 — The dashboard scores a partly fabricated feature vector 🟠

**Where:** `services/dashboard/app.py:154–169`

The "System Secure" / "Threat Detected" banner — the single most visible artefact in
the whole project, and §7.1's demonstration evidence — is computed from this:

```python
"features": {
    "shannon_entropy": latest_event.get("entropy", 0),      # real
    "file_size": 1048576,                                    # HARDCODED
    "magic_bytes": "4D5A",                                   # HARDCODED
    "modification_rate": min(1.0, entropy / 8.2),            # real
    "pe_imports_count": 45,                                  # HARDCODED
    "api_calls": ["CreateFile", "WriteFile", "CryptEncrypt"] # HARDCODED
}
```

Those four constants are copied straight out of the document's Listing 3.5 example.
Consequences:

- `magic_bytes` is pinned to `4D5A` (MZ), so `has_container_header` — the model's
  **highest-importance feature** (0.436) — is always 0. A genuine ZIP that the Monitor
  correctly cleared as `benign_compressed` can be rendered as a threat on the dashboard.
- `ransom_extension` is never sent at all, so the second-most-important feature (0.304)
  is always 0.
- `file_size` is always 1 MB regardless of the real file.

The event object already carries `magic_bytes`, `file_size`, `container_format` and
`ransom_extension`. Passing the real values is a small edit and makes the banner mean
what it appears to mean.

**Secondary, same file, line 322:** the Service Health table renders
`service_data.get("placeholder", service_name != "gateway")`. No backend `/health`
returns a `placeholder` key, so the dashboard displays **`Placeholder: True` for
monitor, ml_engine, ledger and response** — directly contradicting `README.md`'s
"Nothing in `services/` is a stub any more". This will be on screen during the demo.

### F-3 — `file_patterns` is accepted, echoed, and never applied 🟠

**Where:** `services/monitor/app.py:150,418,433`

`POST /monitor/start` takes `file_patterns` (Listing 3.1 shows `["*.doc","*.pdf","*.jpg"]`),
stores it in the model, returns it in the response — and never passes it to
`Observer.schedule()` or filters events with it. `MonitorHandler` processes every file
regardless. A caller asking to watch only `*.doc` gets everything and no indication
that the filter was ignored.

`docs/openapi/gateway.yaml:491` marks the field **required**, and
`test_start_returns_contract_fields` asserts only that it is echoed back.

**Fix:** either apply it (`fnmatch` in `handle_event`) or document it as unimplemented
in the OpenAPI description. Silently discarding a required parameter is the worst of
the three options.

### F-4 — Running the test suite rewrites committed evidence 🟡

Confirmed by running it: a plain `pytest -q` across the services leaves

```
 M reports/as_benchmarks.json
 M reports/gateway_benchmarks.json
 M reports/ni_inference_benchmark.json
```

modified in the working tree. Benchmark tests are not marker-gated out of the default
run, so anyone who runs the suite gets spurious diffs and can commit re-measured
numbers by accident — which would silently change the figures the thesis cites.
`APPROACH.md` §7.2 already identifies this and marks it "Not yet fixed".

**Fix:** write to `reports/` only when an env var is set (e.g. `URDS_WRITE_REPORTS=1`),
or only under `-m benchmark`.

### F-5 — "Differential Entropy Analysis" is claimed but not implemented 🟡

The document names this in three places:
- §1.4 Key Innovations: "Distinguishes ransomware encryption from legitimate
  compression by analyzing **entropy patterns over time**"
- Table 5.3, Weeks 9–12: "implement differential entropy analysis" — listed as a task
  **separate from** "magic byte verification"
- Table 5.7: named as a mitigation for the high-false-positive-rate risk

`detection.py` computes entropy **per file, once**. There is no per-file history, no
before/after delta, no time series. `APPROACH.md` §2.1 cites "spec §1.4 Differential
Entropy Analysis" as the justification for the *magic-byte* check — but §1.4 defines
it as temporal analysis, and Table 5.3 lists the two as distinct deliverables.

The false-positive target is met anyway (0 %), so this is a claim-accuracy problem more
than a capability gap. Either implement a genuine delta (the Monitor already sees
create → modify sequences on the same path, and `EVENTS` is right there), or state in
the thesis that magic-byte verification replaced it and why.

---

## 9. Documentation inaccuracies

| ID | Where | Says | Actually |
|---|---|---|---|
| **D-1** | `pe_features.py:4,95,101`; `APPROACH.md:202,217`; `PHASE4_VERIFICATION_REPORT.md:398,436` | "**64** features" (6 places) | **70** — `FEATURE_COUNT` is 70, all unique. The 50+ requirement is exceeded either way, but the stated number is wrong everywhere it appears. |
| **D-2** | `README.md:13` | "verification measured at **~3.7 ms**" | 3.7 ms was the *pre-fix* figure. Current is **2.3 ms / 1000 blocks**. |
| **D-3** | `reports/attack_chain_evidence.txt` | "**18/18** checks passed" | 16 PASS + **2 SKIP**, counted as passes. The skips are shown honestly in the list above the total, but the headline overstates. |
| **D-4** | Table 6.1 vs reality | i7-12700K, 32 GB, Python 3.9.13 | Windows 11 build 26200, Python 3.13.9, 14 cores. Benchmarks are valid; the hardware table describes a machine that was not used. |
| **D-5** | Reference document itself | Figure 4.8: `SHA256(id + data + prev_hash)` | Contradicts §3.2.2 and Listing 4.7. Code follows Listing 4.7 — correct choice, worth a footnote in the thesis. |

Minor: `docs/api_spec.md` (24 lines, Phase 2 era) contradicts the final contract — it
says `entropy` where the field is `shannon_entropy`, and omits most of the FeatureSet.
It is superseded by `docs/openapi/gateway.yaml`; it should say so or be deleted.
`src/ml_api.py` is the superseded stub that still returns **501** for the `features`
path; the live service is `services/ml-engine/app.py`. Both are dead-code hazards for
anyone reading the repo cold.

---

## 10. Deviations from spec — reviewed and defensible

| ID | Deviation | Assessment |
|---|---|---|
| **V-1** | No TLS 1.3 anywhere (Table 3.1 Security layer) | All inter-service traffic is plain HTTP. Mitigated by binding backends to loopback. Real gap against the stack table; ordinary for a Weeks 1–16 prototype. Should be stated, not omitted. |
| **V-2** | `POST /monitor/stop` ignores `monitor_id` (Listing 3.3) | Only one monitor can run per process, so the ID is decorative. Accepting and validating it would be a 3-line change and would match the document exactly. |
| **V-3** | `/ledger/log` returns 200, not 201 (Table 3.2) | Table 3.2 names ledger entries as the 201 example, and `gateway.yaml` already declares 201. One-line fix. |
| **V-4** | `FileEvent.hash_md5` → `file_hash` (SHA-256) | An improvement. MD5 is unsuitable for integrity; §3.1 specifies SHA-256. Justify in the thesis rather than leaving it as an apparent mismatch. |
| **V-5** | Benign events skip ML + ledger (Figure 3.3) | Deliberate; keeps CPU at 1.3 % and the ledger free of noise. The documented flow is still reachable via `POST /analyze`. Worth a sentence in the thesis. |
| **V-6** | Backend ports bound to `127.0.0.1` (not in Listing 3.20) | Security hardening. Backends carry no auth of their own; publishing on `0.0.0.0` exposed unauthenticated `/ledger/log` and `/response/isolate` to the LAN. Correct call. |
| **V-7** | SMOTE not implemented (p. 40, NI Challenge 1) | The document prescribes "SMOTE **+** class weights". Only class weights (`scale_pos_weight`) exist. The dataset is balanced 50/50 so SMOTE would be a no-op — but that reasoning belongs in the thesis, since the document asks for it explicitly. |
| **V-8** | 19,480 samples, not 50,000; CLEAR not used for training (§6.1) | `fetch_ember_subset.py --per-class 25000` would close the sample count. CLEAR augmentation is a bigger change (retraining + restating headline accuracy) and was deferred deliberately — already documented in `APPROACH.md` §3.2. |

---

## 11. Correctly deferred to Semester 2

Each traces to the document's own timeline. None is a Phase 1–4 gap.

| Item | Scheduled by |
|---|---|
| TC-12 / Polygon anchoring / Solidity / web3.py | Table 5.5, Weeks 17–24; TC-12 is written "(if implemented)" |
| CI/CD pipeline (GitHub Actions) | Table 5.6, Weeks 17–24 |
| 95 %+ test coverage | §5.6.3, Distinction tier |
| SHAP served per-prediction | Table 5.4, Weeks 17–24 (offline SHAP already exists — ahead of schedule) |
| Production identity management | §5.6, Semester 2; `/auth/token` is the labelled placeholder |
| Load balancer / PostgreSQL (Figure 3.5) | §3.7.3 is explicitly "for production environments" |
| Research paper draft | Tables 5.3–5.6, Weeks 25–32 |

One item is absent and **not** on any Weeks 1–16 deliverable list, so it is correctly
out of scope but worth naming in the limitations chapter: **VSS deletion protection**.
§2.5 reviews the literature on ransomware running `vssadmin delete shadows` and calls
active defence "a key component of our Response Engine", but nothing in the repo
hardens ACLs or intercepts that command.

---

## 12. What to do before submission

Ordered by impact.

1. **Fix F-1.** Change the response gate in `pipeline.py:129` to honour the Monitor's
   own verdict, and add a regression test at 4 KB / 8 KB / 32 KB with no ransomware
   extension. Without this, a live demo that encrypts a small file will detect it,
   log it, and do nothing — in front of an examiner.
2. **Fix F-2.** Pass the real `magic_bytes`, `file_size`, `container_format` and
   `ransom_extension` from the event into the dashboard's `/predict` call, and drop
   the `placeholder` default that labels four real services as stubs.
3. **Fix F-3.** Apply `file_patterns` or mark it unimplemented in the OpenAPI.
4. **Fix D-1.** Correct "64" → "70" in all six places.
5. **Fix F-4.** Gate the `reports/` writes so the suite stops mutating committed evidence.
6. **Decide on F-5.** Implement differential entropy or state plainly that magic-byte
   verification stands in for it.
7. **Consider the cheap spec-exactness wins:** V-2 (accept `monitor_id`), V-3 (return
   201), and re-running the EMBER fetch at `--per-class 25000` to hit §6.1's 50,000.
8. **Update Table 6.1** in the thesis to the hardware that was actually used, and add
   footnotes for V-4, V-5, V-7 and D-5 so the deviations read as decisions rather than
   oversights.

Items 1–4 are the ones a careful reader of the document would notice.
