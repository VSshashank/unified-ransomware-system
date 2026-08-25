# Project Implementation Record

## Purpose

This record documents the components designed and implemented by the project team in the Unified Ransomware Detection and Recovery System (URDS). It is evidence of project authorship and integration, not a claim that every underlying algorithm or security technique is novel in the literature.

## Authored component inventory

| Component | Location | Team-built work | Verification artifact |
|---|---|---|---|
| Entropy and block-profile detector | `services/monitor/detection.py` | Whole-file entropy, block profiles, entropy-rise history, structural branches, verdict schema, and bounded reads. | Monitor detection tests and fixed simulator sweep. |
| Container recognition and validation | `services/monitor/containers.py` | Recognized-format registry, tri-state validation, bounded validators, incomplete/unreadable states, and format dispatch. | Container tests, API tests, and exemption evidence. |
| False-positive mitigations | `services/monitor/suppression.py` | Hash/path whitelist matching, training mode, dwell constraints, structural profiles, and poisoning controls. | Suppression and end-to-end tests. |
| Cost-ordered admissibility | `services/monitor/admissibility.py` | Forgery-versus-avoidance comparison, attenuation, audit reasons, cost tables, and fail-closed defaults. | Admissibility and suppression tests. |
| Monitor orchestration | `services/monitor/app.py` | File observation, event construction, suppression routing, and policy decision propagation. | Monitor integration tests. |
| Pipeline contract | `services/monitor/pipeline.py` | Monitor-to-ML/ledger/response/recovery handoff and event metadata preservation. | Pipeline tests and API contract tests. |
| ML service integration | `services/ml-engine/app.py`, `services/ml-engine/features.py` | Feature extraction contract, model/backstop integration, and feature completeness handling. | ML API and feature-contract tests. |
| Response layer | `services/response/app.py`, `services/response/actions.py` | Response action boundary, isolation behavior, and suspicious-event handling. | Response API and action tests. |
| Recovery layer | `services/response/recovery/` | Snapshot selection, trusted hashes, restore verification, unverified outcomes, and recovery interfaces. | Recovery integration and recovery-unit tests. |
| Tamper-evident ledger | `services/ledger/hash_chain.py` | Hash-chain construction, verification, and audit record integrity. | Hash-chain tests. |
| Reversible ransomware simulator | `scripts/ransomware_simulator.py` | Owned-directory contract, manifests, deterministic mutations, restoration, and 13 behavior families. | Simulator-family report and tests. |
| Fixed benchmark sweep | `scripts/simulator_sweep.py` | Reproducible family execution, detection timing, restoration checks, and summary report. | `reports/simulator_families.json`. |
| Characterization and evidence harnesses | `scripts/recf_probe.py`, `scripts/recf_exemption_evidence.py` | Detector-dependent witness generation, capability-relevant evidence, hashes, and gated reports. | Probe and exemption reports. |

## How to state authorship

The final report should use:

> **The project team designed and implemented the URDS components listed in this record, including the Monitor detector, container validation, suppression and admissibility layers, pipeline contracts, ML integration, response actions, trusted recovery, tamper-evident ledger, reversible simulator, and verification suite. The novelty claim is not that entropy, format validation, recovery, or hash chains were invented here. The contribution is the team’s unified implementation, the capability-calibration protocol, the measured mitigation-governance finding, and the repaired end-to-end behavior.**

## Evidence rules

Authorship should be supported by repository commits, tests, design documents, and reproducible commands. Literature comparisons should be used to distinguish known ingredients from the team’s specific integration and measured technical effect. The record must not be used to claim that a component is legally novel merely because the team implemented it.
