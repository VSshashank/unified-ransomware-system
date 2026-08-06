# Table 5.8 — Test Cases

> **Provenance note.** The source PDF containing Table 5.8 is not in this
> repository. The definitions below were reconstructed from the numeric targets
> stated in the Phase 1–4 verification brief and from the TC references already
> present in the code (`README-SI.md`, `scripts/si_demo.py`,
> `services/ledger/tests/`, `services/response/recovery/tests/test_integration.py`).
> TC-04, TC-05 and TC-12 are quoted directly from those existing references and
> are certain; the rest are inferred and should be reconciled against the PDF
> before the report is submitted.

| ID | Test case | Target | Owner | Where it is verified |
|---|---|---|---|---|
| TC-01 | File event on the watched path is detected and captured | Detection latency <100ms | AS | `services/monitor/tests/test_api.py::test_tc01_*`, `test_benchmarks.py::test_detection_latency_under_100ms` |
| TC-02 | High-entropy write with no recognised container is flagged | Flagged as suspicious | AS | `services/monitor/tests/test_detection.py::test_tc02_*` |
| TC-03 | Legitimate compressed file is **not** flagged | False positives <5% | AS | `test_detection.py::test_tc03_*`, `test_benchmarks.py::test_false_positive_rate_under_5_percent` |
| TC-04 | File recovery from snapshot, restored to pre-attack state | 100% restore + integrity verified | SI | `services/response/recovery/tests/test_integration.py`, `scripts/si_demo.py` |
| TC-05 | Audit log tampering attempt is detected | Chain validation fails on tamper | SI | `services/ledger/tests/test_hash_chain.py`, `test_api.py`, `scripts/si_demo.py` |
| TC-06 | ML model classifies a ransomware sample correctly | Accuracy >85%, inference <100ms | NI | `services/ml-engine/tests/test_ml_api.py::test_tc06_*` |
| TC-07 | Detected ransomware process is terminated | Kill time <2s | AS | `services/response/tests/test_actions.py::test_tc07_*` |
| TC-08 | Event is written to the hash chain and the chain verifies | Verification <50ms | SI | `services/ledger/tests/test_hash_chain.py` (benchmark), `scripts/attack_chain_demo.py` |
| TC-09 | Dashboard reflects a new event | Visible within 1s | SH | `scripts/attack_chain_demo.py` step 8 |
| TC-10 | Missing / bad JWT is rejected | HTTP 401 | SH | `services/gateway/tests/test_gateway.py` (4 tests) |
| TC-11 | Full attack chain runs end to end as one flow | All stages complete | All | `scripts/attack_chain_demo.py` |
| TC-12 | Blockchain anchoring to Polygon | — | SI | **Out of scope — Phase 5.** Not attempted. |

## Numeric targets

| Metric | Target | Owner |
|---|---|---|
| Detection latency | <100 ms | AS |
| Process kill time | <2 s | AS |
| False positive rate | <5 % | AS |
| CPU during monitoring | <15 % | AS |
| ML accuracy | >85 % | NI |
| ML inference time | <100 ms/sample | NI |
| Chain verification | <50 ms | SI |
| VSS snapshot creation | <30 s | SI |
| Dashboard refresh | <1 s | SH |
