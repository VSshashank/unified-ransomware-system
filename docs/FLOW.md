# FLOW — how the system runs, file by file

Companion to [APPROACH.md](APPROACH.md), which records *why* these decisions were
made. This document describes *what* each file does and how a request moves
through the system.

---

## 1. The two flows that matter

### 1.1 Benign file operation (spec §3.6.1)

```
user saves file
   │
   ▼
watchdog observer                    services/monitor/app.py :: MonitorHandler
   │  on_created / on_modified / on_moved
   ▼
handle_event(path, event_type)       services/monitor/app.py
   │  ── timer starts here ──────────────────── detection latency measured over
   │                                            exactly this function
   ├─► read_magic(path)              detection.py  first 16 bytes
   ├─► calculate_entropy(path)       detection.py  Shannon over first 1 MB
   ├─► sha256_file(path)             detection.py  full-file hash
   └─► classify(...)                 detection.py  entropy + magic + extension
   │  ── timer stops: verdict exists ──
   ▼
verdict.suspicious is False
   │
   ▼
_record(event)  →  EVENTS deque (maxlen 500)
   │
   ▼
GET /monitor/events  →  dashboard renders it
```

No ML call, no ledger write, no response. A benign event is recorded and nothing
else happens — this is what keeps CPU near 1% and the ledger free of noise.

This is a deliberate divergence from Figure 3.3, which shows a benign event
reaching ML and the ledger too. The documented flow is still reachable on demand
— `POST /analyze` runs Monitor → ML → Ledger for any file regardless of verdict —
it simply is not automatic on every benign event.

### 1.2 Ransomware attack (spec §3.6.2)

```
attacker encrypts file
   │
   ▼
handle_event()                       verdict.suspicious is True
   │                                 (entropy ≥ 7.5, magic bytes explain nothing)
   ▼
_record(event) → EVENTS              detection path ENDS here (<100 ms)
   │
   ▼
_QUEUE.put(...)                      handed to a worker thread so the watchdog
   │                                 thread returns immediately
   ▼
pipeline.run(event, features, verdict)          services/monitor/pipeline.py
   │
   ├─1─► POST ml_engine:8002/predict            → prediction, threat_level
   │        │
   │        ▼  ml-engine/app.py: features dict → behavioral_xgboost
   │
   ├─2─► POST ledger:8003/ledger/log            → block appended
   │        event_type "file_event", event_data carries file_hash
   │        │
   │        ▼  ledger/hash_chain.py :: add_block()
   │
   └─3─► if threat_level in {high, critical}:
            POST response:8004/response/trigger
               │
               ▼  response/app.py → actions.terminate_process() if PID known
               │                  → actions.isolate_host()   (plan only unless enabled)
               │
               └─► POST ledger/log  event_type "response_action"
```

Each hop is **best-effort and independently reported**. A ledger that is briefly
down must not stop a process being killed; a failed kill must still leave an
audit trail. `pipeline.run()` returns a `stages` list recording which hops
actually completed.

### 1.3 The gateway request path

```
client
  │  Authorization: Bearer <jwt>
  ▼
request_context middleware           main.py — assigns X-Request-ID
  ▼
get_current_user                     auth.py — decode + verify signature   → 401
  ▼
require_role("admin", …)             auth.py — check role claim           → 403
  ▼                                            └─► audit_access_denial() writes
  │                                                 an auth_failure ledger block
  ▼
enforce_rate_limit                   rate_limit.py — token bucket by tier  → 429
  ▼
proxy_request(...)                   routers/proxy.py — forwards + query string
  ▼
downstream service                                                          → 503
```

---

## 2. Gateway — `services/gateway/` (SH)

The only authenticated entry point. Everything else binds to loopback.

| File | Responsibility |
|---|---|
| `main.py` | App assembly, `/health`, `/auth/token`, `/analyze`, the four exception handlers, request-ID middleware, and the startup secret check. |
| `auth.py` | JWT mint/decode, `get_current_user` (401), `require_role` (403), bootstrap-secret comparison, `verify_jwt_secret_configuration`. |
| `models.py` | Pydantic request/response shapes. `TokenRequest` defaults are the least-privileged role. |
| `rate_limit.py` | Token-bucket limiter. `RATE_LIMITS` by tier; `resolve_tier()` maps role→tier. |
| `routers/proxy.py` | `call_downstream()` (httpx, 5 s timeout) and `proxy_request()`, which forwards the query string and converts downstream ≥400 into the project error envelope. |
| `routers/monitor.py` | `/monitor/start` (admin+enterprise), `/monitor/stop` (**admin only**), `/status`, `/events`. |
| `routers/ml.py` | `/predict` (admin+enterprise), `/model/metrics` (any role). |
| `routers/ledger.py` | `/ledger/log` (admin+enterprise), `/entries`, `/verify`, `/blocks` (any role). |
| `routers/response.py` | All four response actions. **Admin only, enforced at the router.** |

**Key functions**

- `main.lifespan()` — runs `verify_jwt_secret_configuration()` before serving.
  Raises `RuntimeError` and aborts startup if the committed secret is in use
  while `URDS_ENV` is production/staging.
- `main.audit_access_denial()` — on any 401/403, appends an `auth_failure` block.
  Wrapped in a bare `except` so a dead ledger cannot escalate a 401 into a 500.
- `main.analyze_file()` — the composite route: `/features` → `/predict` →
  `/ledger/log`, returning the prediction. Each downstream failure maps to a
  distinct error code (`FEATURE_EXTRACTION_FAILED`, `PREDICTION_FAILED`,
  `LEDGER_LOG_FAILED`).
- `auth.require_role(*allowed)` — dependency **factory**. Returns a dependency
  that 403s unless the token's role is in `allowed`.
- `auth.bootstrap_secret_matches()` — constant-time compare on **bytes**
  (Starlette decodes headers latin-1; `compare_digest` raises `TypeError` on
  non-ASCII `str`). Fails closed when no secret is configured.

---

## 3. Monitor — `services/monitor/` (AS)

### `app.py` (570 lines)

The service and the detection loop.

- `filesystem_for(path)` / `build_observer(watch_path)` — reads `/proc/mounts`,
  finds the filesystem backing the watch path, and picks `PollingObserver` when
  that mount carries no inotify (Windows bind mounts arrive as `9p`), native
  otherwise. Returns the backend name and a human reason, both exposed on
  `/monitor/status`.
- `MonitorHandler` — watchdog callbacks (`on_created`, `on_modified`, `on_moved`,
  `on_deleted`) all funnel into `handle_event`. `on_modified` used to mislabel
  events as `"created"`; `on_moved` did not exist.
- `_drain()` / `_ensure_worker()` — the worker thread that runs the downstream
  fan-out, so the watchdog thread returns immediately after the verdict.
- `handle_event(path, event_type)` — **the detection path.** Times itself from
  entry to verdict. Skips anything outside `file_patterns`, reads magic bytes
  once, decides readability, takes entropy and the byte statistics from a single
  read, records the entropy against the path's history, then `classify()`.
  Records the event and, if suspicious, hands the downstream fan-out to a worker
  thread.
- `matches_patterns(path, patterns)` — the `file_patterns` filter from
  `/monitor/start`. Matches the file name and the whole path; an empty list means
  everything.
- `extract_features(path)` — the `/features` payload. Everything `handle_event`
  measures, plus byte statistics, plus `pe_imports_count` and `api_calls` from
  the PE parser. **Only** called by `/features`, never on the event thread.
- `_record(event)` — appends under `_LOCK` to the bounded `EVENTS` deque and the
  `_SEEN_FILES` set.

### `detection.py` (478 lines)

Pure functions, no I/O beyond reading the file under inspection.

- `open_for_read(path, retry)` — retries only `PermissionError`, bounded by a
  **time budget** (40 ms default), excluding directories explicitly (the Windows
  CRT reports both as errno 13).
- `read_sample(path)` / `measure(data)` — one read of the first 1 MB, and both
  measurements derived from a single byte histogram. `calculate_entropy(path)`
  and `byte_statistics(path)` remain as the one-shot wrappers.
- `read_magic(path)` / `get_magic_bytes()` — first 16 bytes; container
  identification against 20 signatures, plus the ISO-base-media `ftyp` check at
  offset 4.
- `EntropyHistory` — **differential entropy analysis** (spec §1.4). Bounded
  entropy readings per path; `observe(path, entropy, size)` returns the rise over
  the lowest substantive reading in the window, or `None` for a file seen once.
  Readings under 1 KB never become a baseline, so a file created empty does not
  look like one that was encrypted.
- `classify(path, entropy, magic, threshold, readable, entropy_delta)` — the
  verdict. A rise of ≥2.0 bits/byte landing at ≥7.0 → `suspected_encryption`,
  checked **before** the container exemption because it is the one signal a
  spoofed header cannot defeat. Otherwise: high entropy **explained** by a
  container → benign; high entropy **unexplained** → `suspected_encryption`;
  unreadable → `unreadable`, not benign.
- `byte_statistics(path)` / `statistics_of(data)` — printable ratio, byte-value
  std, chi-square uniformity. Fed straight to the behavioural model.
- `sha256_file(path)` — full-file SHA-256, the field SI's recovery integrity
  check reads back.

### `pe_features.py` (325 lines)

- `is_pe(path)` — cheap MZ + PE signature check without full parsing.
- `extract_pe_features(path)` — **70 features**. Any failure returns
  `empty_pe_features()` — same keys, zero values, so the vector shape is fixed.
- `suspicious_api_names(path)` — the behaviourally interesting imports
  (`CryptEncrypt`, `WriteFile`, `TerminateProcess`, …) for the `api_calls` field.
- `_collect(pe, path)` — the actual extraction: headers, per-section entropy and
  W+X detection, import grouping by behaviour class, exports, resources,
  directory presence.

### `pipeline.py` (192 lines)

- `run(event, features, verdict, client)` — orchestrates ML → ledger → response
  and returns `{prediction, ledger_block, response, stages}`.
- `effective_threat_level(model_level, suspicious)` — the higher of the model's
  score and the Monitor's own verdict. The ML engine refines the verdict; it does
  not overrule it, so a low-confidence score cannot cancel a detection.
- `trigger_response(...)` — requests `terminate_process` **only** when the PID is
  known; otherwise `isolate_and_log`.

---

## 4. ML Engine — `services/ml-engine/` (NI)

### `app.py` (288 lines)

- Loads both models at import: `_ember_model` and `_behavioral_model`. A missing
  model is not fatal — that path returns **503** with the training command to run.
- `predict()` — dispatches on payload shape. `ember_vector` (2381 floats, length
  validated) → EMBER model; `features` dict → behavioural model. Neither → 400.
- `_importance(model, names)` — top-10 from XGBoost's `feature_importances_`.
  Global gain, not per-prediction SHAP.
- `model_metrics()` — read from `reports/*.json` on disk, never hardcoded. The
  deployed service previously returned a fixed `accuracy: 0.92`.

### `features.py` (69 lines)

- `FEATURE_ORDER` — seven names that **must** match `src/train_behavioral_model.py`
  exactly. Order mismatch silently scores the wrong columns.
- `features_to_vector(payload)` — builds the model row. Interpolates the three
  byte statistics for callers that do not send them, using the two ends measured
  on the training corpus. Uniform random bytes are ~37% printable ASCII (95 of
  256 values), so assuming ciphertext is "unprintable" inverts the feature.

---

## 5. Ledger — `services/ledger/` (SI)

### `database.py` (111 lines)

- `canonical_json(event_data)` — sorted keys, no whitespace. The single
  definition of the bytes that get hashed.
- `json_fragment(value)` — how a value appears *inside* canonical JSON, so
  substring searches match the escaped form (Windows paths gain doubled
  backslashes).
- `decode_event_data(raw)` — degrades to `{"_raw": …}` rather than raising, so
  verification can still report *which* block broke when a tampered row is no
  longer valid JSON.
- `connect(db_path)` — `journal_mode=DELETE` (**not WAL** — see APPROACH §4.1),
  `busy_timeout=5000`, `synchronous=FULL`.

### `hash_chain.py` (221 lines)

- `compute_hash(timestamp, event_type, event_json, previous_hash)` — SHA-256 over
  the concatenation. `event_json` must be the exact stored text.
- `add_block(event_type, event_data)` — the **only** write path. Takes `_lock`,
  reads the tip, computes, inserts, commits. The lock prevents two concurrent
  appends reading the same tip and forking the chain.
- `verify_chain()` — one query, in-memory walk, through a **fresh connection**.
  Detects two independent failures: a row that no longer hashes to its stored
  hash, and a back-pointer that does not match the real prior block (a deleted or
  reordered row). Stops at the first break and reports its id.
- `get_blocks(...)` — paginated read with optional `event_type` / `file_path`
  filters. The SQL `LIKE` is a prefilter; exact matching happens in Python.

### `main.py` (151 lines)

FastAPI routes: `/ledger/log`, `/entries`, `/verify`, `/blocks`, `/health`.
No authentication — the gateway is the authenticated door, and the port binds to
loopback.

---

## 6. Response — `services/response/` (AS + SI)

### `actions.py` (270 lines) — AS

- `guard(pid)` — refuses PID 0, 1, negatives, and self.
- `terminate_process(pid, force)` — SIGTERM, wait `TERM_GRACE_SECONDS`, then
  SIGKILL if `force`. Returns method (`sigterm` / `sigkill` / `already_exited`),
  exit code and elapsed ms. `NoSuchProcess` between guard and signal is a
  **success**; `AccessDenied` is a failure.
- `build_plan(level, allow_localhost)` — platform-dispatched rule construction:
  `iptables` (Linux), `pfctl` (macOS), `netsh` (Windows). Returns the commands
  without running them.
- `isolate_host(...)` — applies the plan **only** when
  `RESPONSE_ISOLATION_ENABLED=true`; otherwise returns `enforced: false` with the
  rules it would have applied.

### `recovery/vss_manager.py` (458 lines) — SI

- `platform_status()` — supported / platform / version / edition / backend /
  elevated. Reports `supported: false` with a reason off Windows.
- `create_snapshot(volume)` — WMI `Win32_ShadowCopy.Create`. Measured **2.8 s**
  against a 30 s target. `vssadmin` writes errors to **stdout**, not stderr, so
  failure reasons are parsed from the right stream.
- `list_snapshots()` / `_device_object_for(id)` — enumerate and resolve to
  `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`.
- `start_scheduler()` — APScheduler, 6-hourly (SI's Weeks 9–12 deliverable).
  Logs why it cannot run off Windows and lets startup continue.
- `ensure_com_apartment()` — COM initialisation, with teardown ordered so a
  chained `com_error` does not outlive its pointer.

### `recovery/recovery.py` (370 lines) — SI

- `to_relative(file_path)` — strips the volume with `ntpath` then `posixpath`,
  and normalises separators to `/`. Both halves are required (APPROACH §5.3).
- `RecoveryManager.resolve_snapshot_root(snapshot_id)` — real VSS device object
  on Windows, or `<RECOVERY_SNAPSHOT_ROOT>/<id>` as the directory-backed stand-in.
- `RecoveryManager.restore_file(...)` — locates the file inside the snapshot and
  copies it back over the damaged one.
- `RecoveryManager._known_hash(path)` — the last hash the ledger recorded for
  that path, via `LedgerClient`.
- `RecoveryManager._recover_one(...)` / `.recover(...)` — per-file restore plus
  integrity comparison, then the aggregate result. Reports **unverified** rather
  than passing when no prior hash exists.
- `recover_files()` → `POST /response/recover`; `recovery_status()` →
  `GET /response/recover/status` (VSS platform status and snapshot root).

### `recovery/ledger_client.py` (102 lines)

Thin HTTP client for the ledger. `last_known_hash(file_path)` queries
`/ledger/blocks` filtered by `file_path` with `newest_first`, returning the most
recent `file_hash`. `try_log_event()` is the non-raising variant used where a
ledger outage must not fail the surrounding operation.

---

## 7. Dashboard — `services/dashboard/app.py` (323 lines) (SH)

Streamlit, 1 s auto-refresh. Mints its own `admin` token directly with `jose`
(lines 18–27) using the shared `JWT_SECRET`, then calls the gateway over HTTP.
Panels: service health, live event feed, entropy timeline, ledger evidence and
chain verification, ML metrics.

---

## 8. Training and analysis — `src/` (NI)

| File | Purpose |
|---|---|
| `fetch_ember_subset.py` | Downloads only the shards holding each class, with resume and retries. |
| `train_ember_model.py` | Trains the static-PE classifier. 95.8% accuracy, 50,000 samples (70/15/15). |
| `train_behavioral_model.py` | Builds the corpus (real files + the same content AES-encrypted) and trains the behavioural model. Labels come from **how each file was produced**, not from an entropy rule, so the model may disagree with the Monitor's heuristic. |
| `analyze_behavioral_signals.py` | **RanSAP + CLEAR EDA.** Entropy distributions, write-rate comparison, CLEAR WAR/RAR/RAW/WAW fingerprint. NI's Weeks 1–4 deliverable. |
| `analyze_ember.py` | Class-balance chart (`class_balance_chart.png`). |
| `shap_analysis.py` | SHAP over the EMBER model, grouped by EMBER's named feature ranges. Offline; not wired into `/predict`. |
| `train_baseline_comparison.py` | Random-forest baseline for comparison. |
| `validate_ransomware_and_latency.py` | Ransomware-specific metrics and inference latency. |
| `verify_phase1.py`, `verify_ransap.py` | Dataset presence checks. |

---

## 9. Scripts — `scripts/`

| File | What it drives | Talks to |
|---|---|---|
| `attack_chain_demo.py` | Full end-to-end chain, 18 checks. Writes `reports/attack_chain_evidence.txt`. | Gateway :8000 and dashboard :8501 **only** |
| `si_demo.py` | TC-04 recovery and TC-05 tamper detection. Restores the tampered row in a `finally` so consecutive runs both pass. | Ledger :8003, response :8004 **directly** |
| `verify_vss.py` | TC-04 / VSS acceptance. Requires an elevated shell. | Ledger :8003 |
| `ransomware_simulator.py` | TC-01 stand-in. Manifest-guarded, reversible. | Filesystem only |

---

## 10. Test map

| Suite | Count | Notable |
|---|---|---|
| `services/gateway/tests/` | 70 | `test_gateway.py` (contract + OpenAPI parity, both directions), `test_authz.py` (roles, token issuance, TC-10 auditing, secret hygiene), `test_benchmarks.py` (API p95) |
| `services/ledger/tests/` | 42 | `test_hash_chain.py` (tamper detection, verification benchmark), `test_api.py` |
| `services/monitor/tests/` | 90 | `test_detection.py` (35), `test_api.py`, `test_benchmarks.py` (latency, FP rate, CPU, RAM), `test_pe_features.py`, `test_tc01_simulator.py`, `test_tc11_concurrent.py` |
| `services/ml-engine/tests/` | 19 | `test_ml_api.py` — both model paths |
| `services/response/tests/` + `recovery/tests/` | 84 + 2 skipped | `test_actions.py` (TC-07), `test_tc11_concurrent.py`, `test_recovery.py` (54), `test_vss_manager.py` |

**361 passed, 2 skipped.** The skips assert a POSIX SIGTERM guarantee with no
Windows equivalent; a Windows-specific test covers the same ground.

Run everything:

```bash
foreach ($s in "gateway","ledger","monitor","ml-engine","response") { Push-Location "services\$s"; python -m pytest -q; Pop-Location }
```

---

## 11. Configuration

| Variable | Default | Effect |
|---|---|---|
| `JWT_SECRET` | `dev-only-change-me` | Warns on every start; **refuses to boot** when `URDS_ENV` is production/staging. |
| `URDS_ENV` | `development` | Only `development` tolerates the committed defaults. |
| `ALLOW_DEV_TOKENS` | `true` | `false` removes `/auth/token` entirely. |
| `DEV_TOKEN_BOOTSTRAP_SECRET` | `dev-bootstrap-change-me` | Required in `X-Bootstrap-Secret` to mint anything above `free`. |
| `ENTROPY_THRESHOLD` | `7.5` | Bits/byte at or above which a file looks encrypted. |
| `MONITOR_OBSERVER` | `auto` | `native` / `polling` override. |
| `MAX_EVENTS` | `500` | Event buffer bound. |
| `READ_RETRY_BUDGET_SECONDS` | `0.04` | Windows file-lock retry ceiling. |
| `RESPONSE_ISOLATION_ENABLED` | *(unset)* | **Do not enable casually** — applies real firewall rules to this host. |
| `RECOVERY_SNAPSHOT_ROOT` | `/app/snapshots` | Directory-backed snapshot stand-in. Leave unset on Windows for real VSS. |
| `PIPELINE_ENABLED` | `true` | Off in unit tests and where downstream services are absent. |

Ports: gateway `8000` and dashboard `8501` publish on all interfaces; monitor
`8001`, ml-engine `8002`, ledger `8003` and response `8004` bind `127.0.0.1`.
