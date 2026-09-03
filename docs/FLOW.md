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
   ├─► measure(head)                 detection.py  Shannon + block statistics,
   │                                               both from one read
   ├─► validate_container(...)       containers.py True / False / None
   ├─► sha256_file(path)             detection.py  full-file hash
   └─► classify(...)                 detection.py  entropy + magic + extension
   │                                               + container_valid → verdict, signal
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
Whitelist.match / TrainingMode.match           suppression.py
   │  the rule that describes this file, or None
   ▼
admissibility.adjudicate(verdict, rule)        admissibility.py
   │  forgery cost of the rule  vs  avoidance cost of the signal
   │
   ├── admitted  → outcome "cancelled"   → alert removed, NO fan-out,
   │                                        NO ledger record of the decision
   └── outranked → outcome "attenuated"  → alert stands, both costs travel
   │                                        with it into the chain
   ▼
_record(event) → EVENTS              detection path ENDS here (<100 ms)
   │
   ▼
_QUEUE.put(...)                      handed to a worker thread so the watchdog
   │                                 thread returns immediately
   │                                 reached only when nothing cancelled it
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

### `app.py` (821 lines)

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
  read, validates the declared container, records the entropy against the path's
  history, then `classify()`. If the verdict is suspicious it asks
  `Whitelist.match` and `TrainingMode.match` for a rule and hands the result to
  `admissibility.adjudicate`, which decides whether that rule is expensive enough
  to fake to be allowed to cancel this detection. Records the event and, if
  suspicious **and nothing cancelled it**, hands the downstream fan-out to a
  worker thread.

  That last conjunction is load-bearing and is where the audit trail stops: the
  ledger is only reachable through the fan-out, so an *attenuated* suppression is
  chained with both costs and a **cancelled** one is not chained at all. See
  M-16 in [MITIGATION_INVENTORY.md](MITIGATION_INVENTORY.md).
- `matches_patterns(path, patterns)` — the `file_patterns` filter from
  `/monitor/start`. Matches the file name and the whole path; an empty list means
  everything.
- `extract_features(path)` — the `/features` payload. Everything `handle_event`
  measures, plus byte statistics, plus `pe_imports_count` and `api_calls` from
  the PE parser. **Only** called by `/features`, never on the event thread.
- `_record(event)` — appends under `_LOCK` to the bounded `EVENTS` deque and the
  `_SEEN_FILES` set.

### `detection.py` (869 lines)

**The container exemption is a policy as of Phase 6 (P6.1).**
`CONTAINER_EXEMPTION_POLICY` selects one of four, and
`container_explains_entropy()` is the single place that decides:

| Setting | Arm | The exemption applies when… |
|---|---|---|
| `legacy` *(default)* | A | a container is declared and the structure did not fail — so `None` and `True` are the same answer |
| `strict-unvalidated` | C1 | a validator actually ran and passed |
| `strict-unvalidated+ratio` | C | …and the container compressed something |
| `strict-unvalidated+ratio+inner` | D | …or what it carries is itself a recognised, non-forged container |
| `off` | B | never — the null control |

The default is `legacy`, so a deployment that sets nothing gets exactly the
behaviour this module had before Phase 6, which is what the 224 monitor tests
assert. An unrecognised value raises at import rather than being coerced. **D5
fires against the repair (100 pp on `unvalidated × incompressible` against a
15.0 pp tolerance), so the default stays `legacy`** — see
`docs/PHASE6_COMPLETION_REPORT.md` §4.

The reason string names the clause that decided, either way, so a verdict says
*which* policy produced it rather than only what it concluded.

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
- `classify(path, entropy, magic, threshold, readable, entropy_delta, container_valid, statistics)`
  — the verdict, plus a `signal` naming which of the five detections fired.
  `signal` is what `admissibility` prices against a suppression. Order: a rise of
  ≥2.0 bits/byte landing at ≥7.0 → `entropy_rise`, checked **before** everything
  else because it is the one signal neither a spoofed header nor a real container
  can defeat; a declared container whose structure is absent → `structural_mismatch`;
  block-level ciphertext under a sub-threshold average → `partial_entropy`; high
  entropy **explained** by a container → `benign_compressed`; high entropy
  **unexplained** → `static_entropy`; unreadable → `unreadable`, not benign.

  Two guards in that order are measured findings rather than incidental detail.
  `container_valid is not False` (`:702`) means "no validator for this format"
  and "I checked and it passed" produce the same benign verdict — 11 of the 16
  registry formats take that branch. And the `partial_entropy` branch (`:690`) is
  guarded by `container_valid is not True`, so a structurally valid container
  disables the intermittent-encryption check entirely.
- `byte_statistics(path)` / `statistics_of(data)` — printable ratio, byte-value
  std, chi-square uniformity. Fed straight to the behavioural model.
- `sha256_file(path)` — full-file SHA-256, the field SI's recovery integrity
  check reads back.

### `containers.py` (698 lines)

Structural validation of a declared container format. Asks the question a magic
byte cannot: is the rest of the file shaped like the format it claims to be?

- `container_status(head, tail, container, size)` — five outcomes by name:
  `VALID`, `FORGED`, `INCOMPLETE` (the format, still being written),
  `UNVALIDATED` (no validator for this format), `UNREADABLE`.
- `validate_container(...)` — the same answer projected to the tri-state
  `classify` consumes: `True` for VALID, `False` for FORGED, **`None` for
  everything else**. That `None` is three different situations collapsed into
  one value, and `classify` cannot tell them apart.
- `_VALIDATORS` — six entries: `zip`, `gzip`, `png`, `jpeg`, `pdf`, `iso-bmff`.
  Five of them correspond to a name in `detection._CONTAINER_SIGNATURES`, which
  holds 16 unique formats. **The other 11 have no validator**: `rar`, `7z`,
  `xz`, `bzip2`, `lz4`, `zstd`, `gif`, `mp3`, `ogg`, `flac`, `riff`.
  `VALIDATED_FORMATS` exposes the set so a caller can state which containers are
  decided and which are taken on trust.
- Each validator separates *does the leading structure parse* from *is the
  terminal structure present*, which is what keeps a large archive mid-write out
  of the forged class. Every walk is bounded — `MAX_WALK_RECORDS`,
  `MAX_WALK_BYTES` — because this runs inside the sub-100ms budget.

**Added in Phase 6 (P6.1).** Two readings that validate nothing — they read what
a container already declares about itself, so §9.13's bar on new structural
validators for the eleven unvalidated formats is untouched. Both are consumed
only by a non-default policy.

- `compression_evidence(head, tail, container, size)` — *did this container
  actually compress what it carries?* For `zip`, the central directory's declared
  compressed/uncompressed sizes; for `gzip`, the yield of the bounded inflate
  `_validate_gzip` already runs. Returns `None` for every format outside
  `COMPRESSION_MEASURED_FORMATS` — deliberately only the general-purpose
  compressors, because holding a photograph to a compression ratio calls JPEG a
  liar for doing its job. **`compressed is None` means "not measured", never
  "did not compress"**: a policy that flags on missing evidence flags on ZIP64
  and on truncated reads.
- `inner_content_evidence(...)` — *what is inside, and does it survive a
  head-level check?* A bounded inflate of the first member, then
  `container_status` on what came out. `gzip.compress(ciphertext)` carries no
  recognised header; `gzip(real JPEG)` carries a valid one; `gzip(JPEG magic +
  ciphertext)` carries a **forged** one. A genuine JPEG marker chain with
  ciphertext behind it passes, and that limit is measured as attack family A7
  rather than left to be discovered.

### `suppression.py` (455 lines)

Table 5.7's two false-positive mitigations. Neither decides whether it is
*allowed* to cancel anything — that is `admissibility`'s job.

- `Whitelist.match(path, hash, verdict)` — returns the matching rule
  (`{"rule": "hash"|"path", "value": …}`) or `None`. Hash is reported ahead of
  path: the bytes are an approved file's bytes, so nothing weaker should shadow
  it.
- `TrainingMode.observe(path, entropy, verdict)` — learns a per-`(extension,
  structural class)` entropy ceiling during an operator's training window. A
  forged container never contributes.
- `TrainingMode.match(...)` — returns the learned rule when the file sits at or
  below the ceiling for its extension, structural class and directory. Refuses
  outright for a ransom extension or a FORGED container.

### `admissibility.py` (165 lines)

One comparison, applied uniformly: **a suppression may cancel a detection only
when forging the suppression costs at least as much as avoiding the detection.**

- `AVOIDANCE_COST` — per `signal`: what an attacker must spend *not to trigger*
  it.
- `FORGERY_COST` — per suppression `rule`: what an attacker must spend to make
  it fire on a file they control.
- Both on a four-point ordinal ladder — `NEGLIGIBLE`, `LOW`, `MODERATE`, `HIGH`
  — whose rungs are kinds of work, not a currency.
- `adjudicate(verdict, suppression)` — returns the record that goes on the event
  and into the ledger: `admitted` (the only field the detector acts on),
  `outcome` (`cancelled` or `attenuated`), both costs, the signal and a reason.
  A suppression that is outranked is **attenuated, not discarded** — the alert
  stands and the operator can see their rule was consulted and lost.
- Unknown defaults fail closed: a new signal with no cost entry is treated as
  the most expensive thing to avoid, a new suppression as the cheapest to forge.
- The comparison is `>=` (`:147`), so an equal-cost tie goes to the suppression.
  Phase 5 recomputed the whole matrix under `>` as well; see
  [ADMISSION_RECOMPUTE.md](ADMISSION_RECOMPUTE.md).

### `pe_features.py` (325 lines)

- `is_pe(path)` — cheap MZ + PE signature check without full parsing.
- `extract_pe_features(path)` — **70 features**. Any failure returns
  `empty_pe_features()` — same keys, zero values, so the vector shape is fixed.
- `suspicious_api_names(path)` — the behaviourally interesting imports
  (`CryptEncrypt`, `WriteFile`, `TerminateProcess`, …) for the `api_calls` field.
- `_collect(pe, path)` — the actual extraction: headers, per-section entropy and
  W+X detection, import grouping by behaviour class, exports, resources,
  directory presence.

### `pipeline.py` (288 lines)

**`log_governance_decision(client, event)` (P6.4)** chains a suppression that
*cancelled* an alert, as a `suppression_decision` block carrying the
adjudication, the verdict it silenced and both costs — with no prediction and no
response, because acting on a cancelled alert would defeat the operator's own
rule. Before it existed, the one decision an auditor most needs to see was the
only one the chain never held, and Table 9.8's ledger row measured **50.0%**. It
now measures **100.0%**.

`trigger_response(...)` carries `admissibility` through to the Response service,
which writes it into its own `response_action` block.

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

### `recovery/recovery.py` (393 lines) — SI

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

## 7. Dashboard — `services/dashboard/app.py` (541 lines) (SH)

**Governance surfacing (P6.4).** Before Phase 6 this file held no governance
vocabulary at all: an alert a whitelist had cancelled and an alert never raised
looked identical on screen. `GOVERNANCE_OUTCOMES`, `governance_outcome()` and
`governance_chip()` now surface `cancelled`, `attenuated` and `deferred` as three
distinct labels — in the banner, in the current-event panel with both costs, and
as a column on the recent-events table. The outcome is read from the adjudication
record and **never inferred from `suspicious`**, because a cancelled alert and a
benign file both report `suspicious: false`.

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
| `simulator_sweep.py` | Every simulated family past a live Monitor. Writes `reports/simulator_families.json`. | Filesystem only |
| `start_monitor.py` | Starts a Monitor against a watch path outside Compose. | Monitor, in-process |

### Phase 5 measurement harnesses

Added for the Semester 2 governance calibration (Chapter 9 §9.4.1). All five
write to `reports/` only when `URDS_WRITE_REPORTS=1`.

| File | Item | Produces |
|---|---|---|
| `phase5_baseline.py` | P5.0 | `reports/phase5_baseline.json` — the measured starting state. Runs the **1-hour** CPU window and the stress-test RSS peak Table 5.9 actually specifies, rather than the 5-second samples `test_benchmarks.py` takes. `--quick` refuses to write, so a short run cannot stand in for the hour. |
| `recf_exemption_evidence.py` | P5.2 | `reports/recf_exemption_evidence.json` — all 20 signature entries, the `gzip.compress` and `ZIP_STORED` witnesses, the `INCOMPLETE` witnesses, and fresh-versus-observed paths. |
| `build_benign_corpus.py` | P5.3 | `reports/benign_corpus_manifest.json` — 149 files by real encoders, stratified {validated, unvalidated} × {compressible, incompressible}, rebuildable byte-identically from a seed. `--verify` proves it. |
| `capability_calibration.py` | P5.4 | `reports/capability_calibration.json` — the attack that defeats each strategy, built and run, with the ladder level derived twice from its operational facts. |
| `admission_recompute.py` | P5.5 | `reports/admission_recompute.json` **and** `docs/ADMISSION_RECOMPUTE.md` — the doc is generated, not written beside the computation. |
| `ledger_coverage.py` | Table 9.8 row 7 | `reports/ledger_coverage.json` — how many governance decisions reach the chain. Counts *decisions*, deduplicated by path: counting writes reported 150% once the response hop began carrying the record too. |

### Phase 6 measurement harnesses

Chapter 9 §9.4.2. Same `URDS_WRITE_REPORTS=1` gate.

| File | Item | Produces |
|---|---|---|
| `three_arm_experiment.py` | P6.2 | `reports/three_arm_experiment.json` — 31 seeded attack cases in 7 families and 275 frozen benign files, scored under all five arms from one reading each. Every benign file is hash-checked against the frozen manifest first; the harness refuses to run against a corpus that is not the corpus that was frozen. |
| `benign_tradeoff.py` | P6.3 | `reports/benign_tradeoff.json` — the predeclared analysis executed, not chosen: paired, per stratum, exact one-sided McNemar on discordant pairs, Clopper–Pearson one-sided 95% with the upper limit as the thing judged. |
| `pipeline_governance.py` | P6.4 | `reports/pipeline_governance.json` — six hop gates plus the dashboard. Real `handle_event`, real `pipeline`, real `RecoveryManager`; only the transport is stood in for. The `deferred` population holds a genuine exclusive Win32 handle. |
| `failure_injection.py` | P6.5 | `reports/failure_injection.json` — five injections against the real components, checked for distinctness, for "none reported as verified", and for every outcome carrying a reason. |

---

## 10. Test map

| Suite | Count | Notable |
|---|---|---|
| `services/gateway/tests/` | 78 | `test_gateway.py` (contract + OpenAPI parity, both directions), `test_authz.py` (roles, token issuance, TC-10 auditing, secret hygiene), `test_benchmarks.py` (API p95) |
| `services/ledger/tests/` | 42 | `test_hash_chain.py` (tamper detection, verification benchmark), `test_api.py` |
| `services/monitor/tests/` | 224 | `test_detection.py`, `test_api.py`, `test_benchmarks.py` (latency, FP rate, CPU, RAM), `test_suppression.py`, `test_baseline.py`, `test_pe_features.py`, `test_pipeline.py`, `test_tc01_simulator.py`, `test_tc11_concurrent.py`, `test_tc13_simulator_families.py`, `test_tc13_suppression_e2e.py` |
| `services/ml-engine/tests/` | 37 | `test_ml_api.py` — both model paths, `test_feature_contract.py`, `test_unscored_features.py` |
| `services/response/tests/` + `recovery/tests/` | 86 + 2 skipped | `test_actions.py` (TC-07), `test_tc11_concurrent.py`, `test_recovery.py`, `test_vss_manager.py`, `test_integration.py` |

**467 passed, 2 skipped**, re-measured on `feat/admissibility-governance-novelty-v2`
at the Week 24 gate — up two from the Week 20 figure of 465, both in
`test_baseline.py`: `test_a_cancelled_alert_queues_its_decision_for_the_ledger`
and `test_an_attenuated_alert_still_fans_out`.

**Two of these are flaky under full-suite load and it is pre-existing.**
`test_benchmarks.py::test_detection_latency_under_100ms` and
`test_tc11_concurrent.py::test_tc11_detection_stays_within_budget_under_load`
each failed once across seven full monitor runs and each passes 6 of 6 in
isolation; the flake reproduces with the Phase 6 changes stashed. Both assert a
wall-clock threshold, so an unrelated test holding the CPU fails them. The skips assert a POSIX SIGTERM guarantee with no Windows
equivalent; a Windows-specific test covers the same ground.

> **Test-ID collision to resolve before Phase 7.** `test_tc13_suppression_e2e.py`
> already labels its training-mode cases **TC-14**. Chapter 9 Table 9.7 assigns
> TC-14 to the unvalidated-format witness. The two must not both be TC-14.

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
| `CONTAINER_EXEMPTION_POLICY` | `legacy` | Which container-exemption policy the detector runs. `legacy`, `strict-unvalidated`, `strict-unvalidated+ratio`, `strict-unvalidated+ratio+inner`, `off`. **The repair is off by default**: D5 fired against it in Phase 6. An unrecognised value raises at import rather than being coerced, so a typo cannot become a silent policy change. |
| `URDS_WRITE_REPORTS` | *(unset)* | Benchmarks and harnesses always measure and always assert; this gates whether they **write** to `reports/`. Committed evidence is refreshed deliberately, never as a test side effect. |

Ports: gateway `8000` and dashboard `8501` publish on all interfaces; monitor
`8001`, ml-engine `8002`, ledger `8003` and response `8004` bind `127.0.0.1`.
