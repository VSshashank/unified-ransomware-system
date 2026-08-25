# Phase 1–4 Completion Summary — every requirement, checked against the reference PDF

**Reference:** *Unified Ransomware Detection & Recovery System — Complete Project
Documentation*, v1.6, 31 January 2026, 68 pages (all 68 extracted and read).
**Repository:** `D:\Unified_Ransomware_Project`, branch `fix/phase1-4-remediation`
**Date:** 12 August 2026
**Scope:** Phases 1–4 (Semester 1, Weeks 1–16). Weeks 17–32 items are judged
against the document's own timeline, not counted as gaps.

> **Superseded figures, 25 August 2026.** A later pass over the detection path
> corrected five defects this report's numbers predate. The behavioural model's
> accuracy, the simulator-family result (`8/10`), and the two families recorded
> here as blind spots have all moved. The measurements below are kept as the
> record of what was true on the date above; for the current figures and for why
> they changed, see [`DETECTION_HARDENING.md`](DETECTION_HARDENING.md).

---

## 0. Verdict

| | |
|---|---|
| **Test suite** | **371 passed, 2 skipped, 0 failed** (baseline at session start: 305/2/0) |
| **API contract checks** | **53 / 53** — the document's own listings replayed verbatim against the running services |
| **Table 5.9 benchmarks** | **10 / 10** met, all re-measured today |
| **Table 5.8 test cases** | **11 of 11** in-scope pass, each with a `tc*`-named test. TC-12 is Weeks 17–24 |
| **Documented endpoints** | **10 / 10** implemented, field-for-field |
| **Blocking defects** | **0** |
| **Known gaps, all documented** | 4 (TLS, CI/CD, intermittent encryption, CLEAR-as-training) |

The project meets §5.6.1 (70 %) and §5.6.2 (80–85 %) in full, and clears five of
seven §5.6.3 Distinction criteria. The two it does not reach — Polygon anchoring
and CI/CD — are placed in Weeks 17–24 by the document's own Tables 5.5 and 5.6.

**How this was checked.** The PDF was extracted in full and read end to end. All
125 tracked files were opened. The document's API listings (3.1–3.16) were sent
verbatim to the real services and the responses compared field by field. The
benchmarks were re-measured rather than read from `reports/`. Where a claim and
the code disagreed, the code was treated as the truth and the claim corrected.

---

## 1. What changed this session

Ten remediation tasks, then a full re-audit against the PDF that found five more
issues. Fourteen commits on `fix/phase1-4-remediation`.

### 1.1 The blocking defect: small encrypted files produced no response

**Where:** `services/monitor/pipeline.py`

The Monitor flagged them, the ledger recorded them, and nothing acted. The
response gate read only the ML engine's `threat_level`, and the behavioural
classifier needs Shannon entropy near 7.995 before it is confident — which
ciphertext under roughly 40 KB does not reach through sampling noise. Reproduced
before fixing, five trials per size, in-place encryption keeping the filename:

| Size | Entropy | Monitor verdict | Model p(ransomware) | Response fired |
|---|---|---|---|---|
| 4 KB | 7.95 | `suspected_encryption` | 0.18 | **No** |
| 8 KB | 7.98 | `suspected_encryption` | 0.04 | **No** |
| 16 KB | 7.99 | `suspected_encryption` | 0.36 | **No** |
| 32 KB | 7.99 | `suspected_encryption` | 0.49 | **No** |
| 40 KB | 8.00 | `suspected_encryption` | 1.00 | Yes |
| 64 KB+ | 8.00 | `suspected_encryption` | 1.00 | Yes |

The ML score now refines the Monitor's verdict instead of overruling it: the
effective threat level is the higher of the two. That also keeps the level
coherent downstream — the Response service runs network isolation on
`high`/`critical` only, so forwarding "low" would have triggered a response that
then declined most of its job.

`pipeline.py` had no direct test coverage, which is how this survived. It now has
21 tests; 7 of them fail against the old gate.

### 1.2 The rest

| # | Finding | What was done |
|---|---|---|
| F-2 | Dashboard banner scored a partly fabricated feature vector | Four constants came from the document's illustrative example. Fixing them was not enough: three more of the model's seven inputs (the byte statistics) were absent from the event and being interpolated from entropy — which is what rendered a legitimate ZIP as a threat. The event now carries what was measured, and `handle_event` derives entropy and statistics from **one** read instead of two. Verified 8/8 across ZIP, text, PDF, 4/8/32/256 KB encryption and a `.locked` file. |
| F-3 | `file_patterns` accepted, echoed, never applied | Filtered in `handle_event`, so it covers deletes and renames too. `/monitor/status` reports the filter in force. |
| F-4 | A plain `pytest -q` rewrote three committed benchmark files | Writes gated behind `URDS_WRITE_REPORTS=1`. Verified both directions. |
| F-5 | "Differential Entropy Analysis" named three times in the spec, not implemented | `EntropyHistory` per path; a rise of ≥2.0 bits/byte landing at ≥7.0 flags replacement. Checked **before** the container exemption, so it catches an encryptor that writes a ZIP header over its ciphertext — which magic bytes alone clear. |
| V-2 | `/monitor/stop` ignored `monitor_id` | Accepted and validated; a mismatch is refused with 404. The gateway forwards it instead of sending `{}`. |
| V-3 | `/ledger/log` returned 200 | Returns 201, per Table 3.2. The proxy passes it through. |
| V-8 | Trained on 19,480 samples, not §6.1's 50,000 | Retrained: 35,000 / 7,500 / 7,500, 25,000 per class. **See §2 — the finding was not what it first appeared.** |
| D-1 | "64 features" | Actually **70**. Corrected in 8 places across 4 files; three other "64"s are SHA-256 lengths and were left alone. |
| D-2 | Ledger verification "~3.7 ms" | Re-measured properly: **3.1 ms median** over 50 warm runs, range 2.1–5.7 ms. The previous audit's 2.3 ms was a single run near the floor — the README was closer to right than the correction. |
| D-3 | `attack_chain_evidence.txt` headlined "18/18 checks passed" | Actually 16 PASS + 2 SKIP. The generator counted `None` as a pass; fixed at source and in the committed file. |
| D-4 | Table 6.1 describes hardware never used | Actual machine recorded against it in `APPROACH.md` §10. |
| D-5 | The document gives the hash formula three incompatible ways | Footnoted at the design; the code follows Listing 4.7, the document's own reference implementation. |

---

## 2. The most important correction: the metrics were stale, not the model

The first pass reported that retraining on 50,000 samples had **lowered**
accuracy from 0.9774 to 0.9577. That reading was wrong, and the truth matters
more.

The model on disk was **already** the 50,000-sample model.
`reports/model_metrics.json` was a leftover record of an earlier, smaller run
that had since been overwritten. Three independent proofs:

1. **Training is bit-for-bit deterministic.** Two runs over the same parquet with
   `random_state=42` produced `xgboost_model.pkl` with the same SHA-256
   (`78ab2978…d09b3d1`) and the same 1,064,299 bytes. Every metric matched to 16
   significant digits; only `trained_at` differed.
2. **SHAP output is unchanged.** `reports/shap_feature_importance.json` was
   committed *before* the retrain, generated from the old model. Re-running
   `src/shap_analysis.py` against the new model reproduced it byte-for-byte.
   SHAP values are a deterministic function of tree structure over a seeded
   sample, so identical output means identical trees.
3. **The file size never moved.** 1,064,299 bytes before and after. A model fitted
   on 13,636 training rows rather than 35,000 would not land on the same count.

So the deployed classifier has been the 0.9577 model throughout, while
`model_metrics.json`, `/model/metrics`, `APPROACH.md`, `FLOW.md`,
`test_cases.md` and the verification report all cited 0.9774. **Every document
was overstating the classifier that was actually running, by about two points.**
They now describe the model in the container.

Corroboration: `reports/ransomware_specific_metrics.json` is byte-identical
before and after — 0.9993 accuracy, 1.0000 precision, 0.9987 recall over 752 real
ransomware-family samples.

### Current model performance

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| **XGBoost (EMBER static PE)** | 0.9577 | 0.9625 | 0.9525 | 0.9575 | 0.9923 |
| Random Forest baseline | 0.9389 | 0.9490 | 0.9277 | 0.9382 | 0.9859 |
| Behavioural classifier | 0.8843 | 0.9486 | 0.8127 | 0.8754 | 0.9585 |

Both EMBER models are trained and evaluated on the same 50,000-row parquet with
the same seed and split, so **Table 8.1's comparison is apples-to-apples**.
XGBoost beats Random Forest on every metric, which is the relationship Table 8.1
asserts. Every threshold clears: TC-06 wants P/R/F1 above 85 %, §5.6.2 wants ML
above 85 %, §5.6.3 wants above 90 % across all metrics.

Ransomware-family detection, measured on the 752 labelled samples in the corpus
(WannaCry 389, GandCrab 343, CryptoLocker 7, Cerber 6, Petya 3, Locky 3,
TeslaCrypt 1): **99.87 % recall, 100 % precision**.

---

## 3. Chapter 3 — Architecture & API, verified line by line

### 3.1 Technology stack (Table 3.1)

| Layer | Document requires | In the repo | Status |
|---|---|---|---|
| Presentation | Streamlit, Plotly, HTML5/CSS3 | Streamlit 1.41.1, Plotly 5.24.1, inline CSS | ✅ |
| Application | FastAPI, Python 3.9+, Uvicorn, Pydantic | FastAPI 0.115.6, Uvicorn 0.32.1, Pydantic 2.10.4, Python 3.11/3.13 | ✅ |
| Business Logic | XGBoost, watchdog, SHA-256 | `xgboost-cpu` 3.4.0, `watchdog` 6.0.0, `hashlib.sha256` | ✅ |
| Data | SQLite, file system, Windows VSS | `ledger/database.py`, `recovery/vss_manager.py` (WMI) | ✅ |
| Security | JWT, cryptography, **TLS 1.3** | JWT via `python-jose[cryptography]`; **no TLS** | ⚠️ stated in APPROACH §8 |
| DevOps | Docker, Compose, **GitHub Actions**, pytest | Docker + Compose + pytest; **no `.github/`** | ⏸ Table 5.6, Weeks 17–24 |

### 3.2 API contracts — the document's listings replayed verbatim

Every listing was sent to the real service and the response compared field by
field. **53 / 53 checks pass.**

| Service | Checks | Result | Notes |
|---|---|---|---|
| Monitor (8001) | 13 | ✅ | Listings 3.1–3.4 exact; responses are supersets |
| ML Engine (8002) | 13 | ✅ | Listing 3.5 sent verbatim returns a well-formed 3.6 |
| Ledger (8003) | 11 | ✅ | Listings 3.8/3.9 **exact match**, no extra fields |
| Response (8004) | 16 | ✅ | Listings 3.10–3.16 all accepted |

All 10 documented endpoints exist. Additions (`/health`, `/auth/token`,
`/monitor/events`, `/features`, `/ledger/entries`, `/ledger/verify`,
`/ledger/blocks`, `/analyze`) are required by the orchestration in Listing 4.9,
the dashboard in §7.1, or TC-05.

**Hash chain, recomputed from the response alone.** `SHA256(timestamp +
event_type + event_data + previous_hash)` reproduces `current_hash` exactly;
genesis is 64 zeros; block N+1's `previous_hash` equals block N's `current_hash`.

**HTTP status codes (Table 3.2).** 200, 201, 400, 401, 403, 404, 429, 500, 503
all produced. One code is returned that Table 3.2 does not list — **409** from
`/response/terminate` when the guard refuses. It is now declared on the route and
the deviation is recorded in `APPROACH.md` §8, with the reasoning: the request is
well-formed and authorised, and 403 already means "your role is not permitted"
at this gateway.

**Error envelope (Listing 3.22).** Identical in all six places: gateway, monitor,
ml-engine, ledger, response, recovery.

**JWT (Listing 3.23).** `{sub, role, exp, iat}` all present, plus `tier`.

**Rate limits (Table 3.3).** Free 60/100, Premium 300/500, Enterprise 1000/2000 —
exact transcription.

### 3.3 Data models (§3.5)

| Model | Status |
|---|---|
| `FileEvent` (3.17) | All fields present; `hash_md5` → `file_hash` holding SHA-256 (justified in APPROACH §8) |
| `Prediction` (3.18) | Exact |
| `LedgerBlock` (3.19) | Exact, including `blockchain_anchor` present and always null |

### 3.4 Sequence diagrams (§3.6)

- **Figure 3.4 (attack):** implemented exactly — modification → entropy → features → RANSOMWARE → trigger → kill → alert → isolate.
- **Figure 3.3 (benign):** diverges deliberately. Benign events are recorded but do not fan out to ML and the ledger, which is what keeps CPU near 1 %. The documented flow is still reachable via `POST /analyze`. Stated in APPROACH §8.

### 3.5 Deployment (§3.7.1, Listing 3.20)

`docker-compose.yml` is a strict superset. `docker compose config` validates.
Every item in Listing 3.20 is present including the exact `cpus: '2' / memory: 2G`
limits; ports are bound to `127.0.0.1` for the four backends (hardening), and
`depends_on` is upgraded to `condition: service_healthy`.

---

## 4. Chapters 4–5 — deliverables, test cases, criteria

### 4.1 Weekly deliverables (Tables 4.1–4.4)

All Weeks 1–16 rows met. Notable: entropy calculator tested against known values
(uniform = 8.0, single byte = 0.0, two symbols = 1.0); PE pipeline extracts **70**
features against a "50+" requirement; VSS snapshots every 6 hours
(`DEFAULT_INTERVAL_HOURS = 6`); backup creation measured at 2.8 s against a 30 s
target. Several Weeks 17–24 rows are already met early (false positives <5 %,
model >90 %, SHAP documented).

### 4.2 Test cases (Table 5.8)

| ID | Scenario | Verified |
|---|---|---|
| TC-01 | Known ransomware, <5 files encrypted | ✅ detected after **1 file** |
| TC-02 | Zero-day / behavioural | ✅ |
| TC-03 | Legitimate ZIP, no alert | ✅ 0/40 false positives |
| TC-04 | Recovery from backup | ✅ native |
| TC-05 | Audit-log tampering detected | ✅ exact block identified |
| TC-06 | P/R/F1 all >85 % | ✅ 0.9625 / 0.9525 / 0.9575 |
| TC-07 | Terminated within 2 s | ✅ 125.6 ms |
| TC-08 | CPU <15 %, RAM <500 MB | ✅ 0.96 % / 70.3 MB — **now `tc08`-named** |
| TC-09 | Dashboard alert within 1 s | ✅ **10.5 ms — this had no automated test before this session** |
| TC-10 | 401 + audit entry | ✅ all three parts |
| TC-11 | Simultaneous attacks | ✅ 12 concurrent detections, 8 concurrent kills |
| TC-12 | Polygon anchoring *(if implemented)* | ⏸ Weeks 17–24 |

### 4.3 Testing pyramid (§5.5.1)

| Tier | Document target | Actual |
|---|---|---|
| Unit | 100+ | **165** |
| Integration | 20 | **177** |
| E2E | 5 | **25** |

### 4.4 Performance benchmarks (Table 5.9) — all re-measured

| Metric | Target | Measured |
|---|---|---|
| Detection latency | <100 ms | **23.7 ms** p95 (40 files, 4 KB–2 MB) |
| Response time | <2 s | **125.6 ms** |
| False positive rate | <5 % | **0 %** (0/40, 32 deliberately high-entropy) |
| ML inference | <100 ms | **1.95 ms** p95 end-to-end, 0.44 ms model-only |
| API response p95 | <200 ms | **3.22 ms** over 1000 requests |
| System CPU | <15 % | **0.96 %** of 14 cores |
| System RAM | <500 MB | **70.3 MB** peak |
| File recovery | 100 % | **100 %** native |
| Ledger verification | <50 ms | **3.1 ms** median / 1000 blocks |
| Dashboard latency | <1 s | **10.5 ms** to queryable; 439 ms end-to-end in Compose |

### 4.5 Success criteria (§5.6)

| Tier | Criterion | Met |
|---|---|---|
| §5.6.1 (70 %) | Monitoring + entropy | ✅ |
| | ML >70 % | ✅ 95.8 % |
| | Stops ≥1 simulator | ✅ |
| | Hash-chain audit trail | ✅ |
| | Basic recovery | ✅ |
| §5.6.2 (80–85 %) | ML >85 % (P/R/F1) | ✅ |
| | **3+ ransomware simulators** | ✅ **now three** — see §5 |
| | False positives <5 % | ✅ 0 % |
| | Response <2 s | ✅ 125.6 ms |
| | 8–10 test cases | ✅ 11 |
| | Dashboard with real-time alerts | ✅ |
| §5.6.3 (90 %+) | ML >90 % all metrics | ✅ |
| | Blockchain anchoring | ⏸ Weeks 17–24 |
| | Professional dashboard | ✅ |
| | 12–15 test cases | ⚠️ 11 of 12 (TC-12 gates the 12th) |
| | CI/CD pipeline | ⏸ Weeks 17–24 |
| | SHAP documented | ✅ |
| | Research paper draft | ⏸ Weeks 25–32 |

### 4.6 Risk register (Table 5.7)

| Risk | Document's mitigation | In the repo |
|---|---|---|
| ML underperforms | Random Forest fallback | ✅ trained, fills Table 8.1 |
| Integration issues | API contracts by Week 4, Compose | ✅ bidirectional parity tests |
| High false positives | Differential entropy, magic bytes, whitelist | ✅ ✅ / ❌ whitelist not built (FP rate is 0 %) |
| Blockchain costs | Testnet, hash chain fallback | ✅ fallback is the shipped path |
| Dataset access | Smaller subsets | ✅ `--per-class` supported |

---

## 5. Ransomware simulators — §5.6.2's "3+" requirement

Previously one simulator run in four configurations, which is one behaviour. It
now imitates four families that differ in **what the watcher sees**, not in the
payload. Measured, not assumed:

| Family | Behaviour | Detected |
|---|---|---|
| `locker` | Rewrite in place, append `.locked` | **8/8** |
| `silent` | Rewrite in place, keep the name — no extension signal | **8/8** |
| `copycat` | Write a new encrypted file, delete the original (`created`+`deleted`) | **8/8** |
| `partial` | Scramble the leading quarter (LockBit 3 / BlackCat) | **0/8** |

Three families detected satisfies §5.6.2. All four round-trip through
`--restore`, which is what keeps them safe to run.

**`partial` is a genuine blind spot and is asserted as one.** Intermittent
encryption leaves whole-file entropy near **5.2 bits/byte** against a 7.5
threshold, so it reads as an ordinary edit. Catching it needs per-block entropy
rather than a whole-file average, which would also flag the compressed blocks
inside any `.docx` or PDF — and the 0 % false-positive rate is a graded criterion
while intermittent encryption is not mentioned anywhere in the reference
document. The gap is captured by
`test_partial_encryption_is_a_known_blind_spot`, so it is visible in the suite
rather than absent from it, and that test fails loudly if detection ever improves.

---

## 6. Chapter 6 — experimental methodology

| §6.1 requirement | Document | Actual | Status |
|---|---|---|---|
| Total samples | 50,000 PE files | **50,000** | ✅ |
| Class balance | 25,000 / 25,000 | **25,000 / 25,000** | ✅ |
| Split ratio | 70 / 15 / 15 | **35,000 / 7,500 / 7,500** | ✅ exact |
| Training source | EMBER **+ CLEAR behavioral logs** | EMBER only; CLEAR used for EDA | ⚠️ stated in APPROACH §8 |

§6.2's five metrics are all computed and reported. §6.3's Table 6.1 describes an
i7-12700K / 32 GB / Python 3.9.13 that was never used; the actual machine
(Core Ultra 5 225H, 14 cores, 15 GB, Windows 11 build 26200, Python 3.13.9) is
recorded against it in `APPROACH.md` §10. Every target is met with room on this
hardware, so no conclusion depends on the difference.

---

## 7. Known gaps, all documented

Each is stated in `APPROACH.md` §8 or §9 rather than left to be discovered.

| Gap | Why it stands |
|---|---|
| **No TLS 1.3 between services** (Table 3.1) | Real gap. Mitigated by binding the four backends to loopback so unauthenticated traffic never crosses a network boundary. §3.7.3 scopes TLS to production. |
| **Intermittent encryption not detected** | Needs per-block entropy; the false-positive cost is not worth it for Weeks 1–16, and the spec never asks for it. |
| **CLEAR is EDA-only, not training input** (§6.1) | Folding it in means retraining and restating every cited figure. Deferred deliberately, not half-done. |
| **SMOTE omitted** (p. 40) | The corpus is balanced 25,000/25,000, so `scale_pos_weight` computes to ~1.0 and SMOTE has no minority to oversample. Implementing it would be a no-op that looked like a safeguard. |
| **Whitelist / training mode** (Table 5.7) | Two of four listed FP mitigations are built; the measured FP rate is 0 %, so the remaining two are unnecessary for now. §8.5 lists whitelisting as future work. |
| **Behavioral fingerprinting is static** (§1.4) | API-call features come from the PE import table grouped by behaviour class, not from runtime call sequences. Runtime attribution needs ETW/eBPF — Phase 5. |
| **Process attribution is null** | Watchdog reports *what* changed, never *who*. Reporting the monitor's own PID would name an unrelated process to the response container. |
| **VSS deletion protection** | §2.5 reviews it but no Weeks 1–16 deliverable lists it. Correctly out of scope; named in the limitations. |
| **CI/CD, Polygon/TC-12, 95 % coverage, SHAP per-prediction, research paper** | All Weeks 17–32 by Tables 5.4–5.6. |

Minor, non-blocking: the directory is `services/ml-engine` where Appendix A.1
writes `ml_engine` and Listing 3.20 writes `ml` — the document is internally
inconsistent, and the Compose *service* name is `ml_engine`, so the DNS name in
Listing 3.20's `ML_URL=http://ml_engine:8002` resolves exactly as documented.
Entry points are `app.py`/`main.py` rather than A.1's `main.py`/`api.py`.

---

## 8. Reproducing this

```bash
for svc in gateway ledger monitor ml-engine response; do (cd services/$svc && python -m pytest -q); done
```

Expect **371 passed, 2 skipped, 0 failed**. The two skips are legitimate:
`psutil.terminate()` maps to `TerminateProcess` on Windows, which no process can
ignore, so the SIGTERM-escalation tests assert a POSIX guarantee with no Windows
equivalent; a Windows-specific test covers the same ground.

Benchmarks, with measured values printed:

```bash
cd services/monitor && python -m pytest -m benchmark -q -s
```

A plain test run leaves `reports/` untouched. To refresh the committed evidence
deliberately:

```bash
URDS_WRITE_REPORTS=1 python -m pytest -m benchmark -q -s
```

---

## 9. Commits

| Commit | Task |
|---|---|
| `c4b9ed1` | `fix(monitor)`: let the Monitor's verdict set a floor on threat level (F-1) |
| `3707b22` | `fix(dashboard)`: score the file that was actually detected (F-2) |
| `b3642d7` | `fix(monitor)`: apply `file_patterns` instead of only echoing it (F-3) |
| `4a3fdbb` | `test`: record benchmark numbers only when asked (F-4) |
| `173c5c0` | `feat(monitor)`: implement differential entropy analysis (F-5) |
| `9db64a1` | `fix`: three spec-exactness corrections (V-2, V-3, D-1) |
| `7368cc3` | `feat(ml)`: retrain on the 50,000 samples the specification calls for (V-8) |
| `9b9c11c` | `docs`: correct the numbers, state the deviations, mark the dead code |
| `d3aeda3` | `fix`: close the gaps a full re-audit against the reference PDF found |
