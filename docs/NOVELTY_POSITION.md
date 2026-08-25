# URDS Novelty Position

This is the executive entry point for the current project position. Earlier RECF-DR-first and Monitor-only drafts are superseded.

## Primary contribution

The project team designed and implemented the Unified Ransomware Detection and Recovery System, including the Monitor detector, container validation, whitelist and training-mode suppressions, cost admissibility, ML integration, tamper-evident ledger, response actions, trusted recovery, reversible simulator, and verification suite.

The primary novelty candidate is the team’s **locked, reproducible attacker-capability calibration protocol** and its integrated application to URDS false-positive mitigation governance. The protocol searches available tooling in a fixed order, records commands, versions, sources, licenses, fixture validity, hashes, and independent reproduction, and assigns the lowest capability level supported by the record.

Applied to URDS, the protocol exposes a concrete architectural finding: the Monitor’s container exemption bypasses the common admissibility path and treats `container_valid=None` as sufficient because it tests `container_valid is not False`. The current recognized-signature registry contains 16 unique formats, 11 of which lack a structural validator. The final proof must compare the current behavior, a no-exemption null control, and a repair selected only after capability calibration and admission recomputation.

The final claim is deliberately scoped: it concerns the **reviewed URDS implementation and evaluated corpus**, not every ransomware detector, and it is not a patentability determination.

## Canonical documents

Read [`NOVELTY_PROOF_PLAN.md`](NOVELTY_PROOF_PLAN.md) for the complete research questions, threat model, capability-search protocol, admission-recompute matrix, current/null/repair experiment, stratified benign corpus, full-pipeline integration gates, schedule, acceptance criteria, authorship framing, and claim discipline.

Read [`COST_CALIBRATION_PROTOCOL.md`](COST_CALIBRATION_PROTOCOL.md) for the locked capability search and reproducibility schema.

Read [`EXEMPTION_EVIDENCE.md`](EXEMPTION_EVIDENCE.md) for the 20-signature/16-format evidence and its reproduction steps.

Read [`PROJECT_IMPLEMENTATION_RECORD.md`](PROJECT_IMPLEMENTATION_RECORD.md) for the project-built component and authorship record.

## Scope rule

Use “URDS Monitor” for the primary evidence unless the ML, ledger, response, and recovery gates in the final plan have passed. Use “unified detection-and-recovery system” only for outcomes actually traced through the complete pipeline. Do not claim universal ransomware-detector improvement or legal novelty without separate evidence and formal review.
