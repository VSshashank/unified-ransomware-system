# Table 5.8 — Test Cases

> **Reconciled against the source document, 12 August 2026.**
> Definitions below are quoted from Table 5.8 of *Unified Ransomware Detection &
> Recovery System — Complete Project Documentation*, v1.6 (31 January 2026),
> pages 55–56. This supersedes the earlier reconstruction, which was inferred
> from numeric targets while the PDF was unavailable and which got **TC-08** and
> **TC-11** wrong and **TC-10** incomplete. See "Corrections" at the bottom.

| ID | Test scenario (as written in Table 5.8) | Expected outcome (as written) | Owner | Status | Where it is verified |
|---|---|---|---|---|---|
| TC-01 | Detect known ransomware (Jasmin) | Alert triggered, process terminated, <5 files encrypted | AS | **PASS** (simulated) | `scripts/ransomware_simulator.py`, `services/monitor/tests/test_api.py::test_tc01_*` |
| TC-02 | Detect zero-day ransomware | Behavioral analysis detects anomaly, response triggered | AS + NI | **PASS** | `services/monitor/tests/test_detection.py::test_tc02_*`; behavioural model scores unseen shapes |
| TC-03 | Legitimate file compression (ZIP) | No alert triggered (magic byte verification passes) | AS | **PASS** | `test_detection.py::test_tc03_*`, `test_benchmarks.py::test_false_positive_rate_under_5_percent` — 0/40 |
| TC-04 | File recovery from backup | Encrypted files restored to pre-attack state, integrity verified | SI | **PASS** (native) / **N-A** (Compose) | `services/response/recovery/tests/test_integration.py`, `scripts/si_demo.py` |
| TC-05 | Audit log tampering attempt | Hash chain validation fails, tampering detected and logged | SI | **PASS** | `services/ledger/tests/test_hash_chain.py`, `test_api.py`, `scripts/si_demo.py` |
| TC-06 | ML model accuracy test | Test set: Precision >85%, Recall >85%, F1-score >85% | NI | **PASS** | `reports/model_metrics.json` — precision 0.9625, recall 0.9525, F1 0.9575 on 7,500 held-out samples |
| TC-07 | Response time (detection to action) | Process terminated within 2 seconds of detection | AS | **PASS** (unit/native) / **SKIP** (Compose) | `services/response/tests/test_actions.py::test_tc07_*` — 125.6 ms native |
| TC-08 | System resource usage | CPU <15%, RAM <500MB during normal operation | AS | **PASS** | `test_benchmarks.py::test_cpu_usage_*` and `::test_memory_usage_*` — CPU 1.0%, peak RSS 67.6 MB |
| TC-09 | Dashboard real-time updates | Alert appears on dashboard within 1 second of detection | SH | **PASS** | `scripts/attack_chain_demo.py` step 8 — 439 ms |
| TC-10 | API authentication failure | HTTP 401 returned, request blocked, audit log entry created | SH | **PASS** | `services/gateway/tests/test_authz.py::test_tc10_*` |
| TC-11 | Multiple simultaneous attacks | All processes detected and terminated, system remains stable | All | **PASS** | `services/monitor/tests/test_tc11_concurrent.py`, `services/response/tests/test_tc11_concurrent.py` |
| TC-12 | Blockchain anchoring (if implemented) | Hash successfully anchored to Polygon testnet | SI | **OUT OF SCOPE** | Semester 2 (Weeks 17–24). The spec's own "(if implemented)" makes this conditional. Not attempted. |

**11 of 11 in-scope test cases pass.** Table 5.6.2 requires 8–10 for the
"Target Goals / Good" tier; Table 5.6.3 requires 12–15 for Distinction, which
TC-12 gates and which is Semester 2 work.

## Performance benchmarks — Table 5.9

| Metric | Target | Measured | Where |
|---|---|---|---|
| Detection latency | <100 ms | **23.7 ms** p95 | `reports/as_benchmarks.json` |
| Response time | <2 s | **125.6 ms** (native), 794 ms for 8 concurrent | `reports/as_benchmarks.json`, TC-11 |
| False positive rate | <5 % | **0 %** (0/40, 32 high-entropy) | `reports/as_benchmarks.json` |
| ML inference time | <100 ms | **1.95 ms** p95 | `reports/ni_inference_benchmark.json` |
| API response time (p95) | <200 ms | **3.22 ms** over 1000 requests | `reports/gateway_benchmarks.json` |
| System CPU usage | <15 % | **0.96 %** of 14 cores | `reports/as_benchmarks.json` |
| System RAM usage | <500 MB | **70.3 MB** peak (+2.7 MB growth) | `reports/as_benchmarks.json` |
| File recovery success | 100 % | **100 %** (native) | `reports/si_demo_evidence.txt` |
| Ledger verification time | <50 ms | **3.1 ms** median / 1000 blocks | `services/ledger/tests/test_hash_chain.py` |
| Dashboard update latency | <1 s | **439 ms** | `reports/attack_chain_evidence.txt` |

All ten Table 5.9 targets are measured and met.

## Notes on individual cases

**TC-01 — "Jasmin".** The spec names a specific ransomware family, and §1.5
(Ethical Considerations) requires live samples to be run only in "isolated,
air-gapped sandbox environments". This machine is not one. `scripts/ransomware_simulator.py`
reproduces the *behaviour* Table 5.8 tests for — rapid in-place rewriting of
document files with high-entropy content — without any malicious payload, and
asserts the "<5 files encrypted" bound. Running the real sample in a proper lab
would strengthen this; the detection path exercised is identical either way.

**TC-02 — "zero-day".** Verified in the sense the spec means: detection with no
signature and no prior knowledge of the sample. The behavioural classifier scores
entropy/size/magic-byte shape rather than matching a hash, and the corpus it was
trained on deliberately includes header-spoofed ciphertext and LockBit-style
intermittent encryption.

**TC-04 and TC-07 through Compose.** Both pass natively and are constrained, not
failing, under Docker on Windows: a Linux container cannot write `D:\...` or see
host PIDs. See `docs/PHASE4_VERIFICATION_REPORT.md` §7.5.

**TC-12.** Table 5.8 writes it as "Blockchain anchoring (if implemented)", and
Table 5.5 places the smart contract in Weeks 17–24. `blockchain_anchor` is
present in the block schema and always null, which is the honest representation
of an unimplemented optional feature.

## Corrections to the previous reconstruction

The earlier version of this file was assembled without the PDF and carried a
provenance warning saying so. Three entries were wrong:

| ID | Previously recorded as | Actually |
|---|---|---|
| TC-08 | "Event is written to the hash chain and the chain verifies, <50 ms" | **System resource usage: CPU <15%, RAM <500MB.** Chain verification time is a Table 5.9 benchmark, not TC-08. RAM had never been measured. |
| TC-11 | "Full attack chain runs end to end as one flow" | **Multiple simultaneous attacks: all processes detected and terminated, system remains stable.** No concurrency test existed. |
| TC-10 | "Missing / bad JWT is rejected, HTTP 401" | Also requires **"audit log entry created"**. The gateway returned 401 but wrote nothing to the ledger. |

The end-to-end attack chain that was recorded as TC-11 remains valuable and is
still run by `scripts/attack_chain_demo.py` — it is simply integration evidence
rather than a Table 5.8 row.
