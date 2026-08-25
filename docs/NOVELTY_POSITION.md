# URDS Novelty Position

This file is the executive entry point for the project’s novelty position. The earlier RECF-DR-first drafts are superseded.

## Current position

The project’s primary contribution is **cost-ordered governance of false-positive mitigations** in the URDS Monitor. A mitigation may cancel suspicious evidence only when the attacker’s auditable capability to forge the mitigation is not lower than the capability required to avoid the detection signal. Unvalidated or unavailable evidence must not be treated as positive validation, and ambiguous decisions must fail closed or remain attenuated and auditable.

The key implementation finding is that whitelist and training-mode suppressions reach the common admissibility policy, while the container exemption is a direct branch in `detection.classify()`. That branch tests `container_valid is not False`, which treats `None`—no validator or no definitive result—as equivalent to `True`. The current registry recognizes 16 unique formats through 20 signature entries, while 11 unique formats have no structural validator. The multi-format evidence script reproduces the resulting fresh-path high-entropy acceptance behavior.

RECF-DR remains the supporting characterization and calibration workflow. Adaptive search, Pareto optimization, and a large repair framework are optional extensions only if a non-predictable interaction survives source-level characterization and deterministic witnesses.

## Canonical plan

Read [`ADMISSIBILITY_GOVERNANCE_PLAN.md`](ADMISSIBILITY_GOVERNANCE_PLAN.md) for the complete contribution statement, threat model, tooling-availability cost scale, evidence protocol, surgical repair, mitigation audit, recovery/audit extension, external validation, statistical plan, milestones, acceptance criteria, and claim discipline.

Read [`EXEMPTION_EVIDENCE.md`](EXEMPTION_EVIDENCE.md) for the reproducible 11-of-16-format finding and its exact reproduction steps.

## Scope disclaimer

The evidence currently supports a **URDS Monitor-level** architectural claim. It should not be generalized to all ransomware detectors or represented as a patentability determination without independent validation and formal prior-art/legal review.
