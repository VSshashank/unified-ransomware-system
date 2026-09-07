# Final Novelty-Proof Plan for the Unified Ransomware Detection and Recovery System

## Document status

This is the canonical novelty-proof plan for the URDS project. It supersedes earlier RECF-DR-first, Monitor-only, and documentation-only plans.

**Repository:** `VSshashank/unified-ransomware-system`

**Working branch:** `feat/admissibility-governance-novelty-v2`

**Baseline:** `origin/feat/detection-hardening`

**Primary result:** an empirical, capability-calibrated evaluation and repair of false-positive mitigation governance across the unified URDS path.

**Important limitation:** this plan can produce strong evidence of a project-specific technical contribution. It cannot guarantee patentability or legal novelty. Those require formal prior-art and legal review.

## Executive decision

The project should not claim that the cost-ordered admissibility principle itself is new. That principle is already implemented in `services/monitor/admissibility.py`. The project should also not make adaptive RECF-DR search the headline. The current detector’s major boundary cases can be obtained from source inspection and threshold arithmetic, so guided-search superiority is not a credible primary claim.

The final contribution should be framed as an **empirical cost-of-defense protocol and integrated repair result**:

> **We designed and implemented a unified ransomware detection-and-recovery system, then developed a locked protocol that empirically calibrates the minimum attacker capability required to forge each false-positive mitigation or avoid each detection signal. Applying the protocol to URDS revealed that an unvalidated container claim could cancel high-entropy evidence across 11 of 16 recognized formats, and that the existing equality-based admissibility rule lacks resolution at the one-public-primitive boundary. We compared the current system with a no-exemption null control and a calibration-selected repair across the Monitor, ML, ledger, response, and recovery path, preserving validated benign behavior and trusted recovery within predeclared bounds.**

This statement claims an implemented system, a reproducible method, a measured architectural finding, a repair, and an integrated evaluation. It does not claim that the abstract policy or every individual subsystem is new in the literature.

## 1. What the project team built

The final report must explicitly distinguish **authored implementation** from **literature novelty**. The following components are project-built engineering work and should be claimed as such:

| Project-built component | Repository location | Authored contribution to describe |
|---|---|---|
| Entropy and block-profile detection | `services/monitor/detection.py` | Detector signals, thresholds, history handling, structural branch ordering, and verdict schema. |
| Container recognition and validation | `services/monitor/containers.py` | Tri-state validation model, bounded parsers, supported-format registry, and incomplete/unreadable handling. |
| Suppression mechanisms | `services/monitor/suppression.py` | Path/hash whitelist, training mode, dwell constraints, structural profiles, and poisoning boundaries. |
| Cost admissibility | `services/monitor/admissibility.py` | Forgery-versus-avoidance decision record, attenuation behavior, cost tables, and fail-closed defaults. |
| Monitor/pipeline orchestration | `services/monitor/app.py`, `services/monitor/pipeline.py` | Observation, event construction, ML handoff, ledger handoff, and policy-decision propagation. |
| ML feature and scoring service | `services/ml-engine/app.py`, `services/ml-engine/features.py` | Feature contract, model/backstop integration, and unscored-feature handling. |
| Response service | `services/response/app.py`, `services/response/actions.py` | Response action boundary and enforcement behavior. |
| Trusted recovery | `services/response/recovery/` | Snapshot selection, trusted hashes, restore verification, and explicit unverified outcomes. |
| Tamper-evident ledger | `services/ledger/hash_chain.py` | Chain construction and verification used by recovery/audit evidence. |
| Reversible ransomware-like simulator | `scripts/ransomware_simulator.py` | Owned-directory, manifest, mutation, restore, and family fixtures. |
| Fixed family sweep | `scripts/simulator_sweep.py` | Reproducible 13-family baseline and restoration verification. |
| Characterization evidence | `scripts/recf_probe.py`, `scripts/recf_exemption_evidence.py` | Detector-dependent witness generation, multi-format evidence, and gated reports. |

The team should state: **“These components were designed and implemented by the project team. We do not claim that every underlying technique is individually novel; our contribution is the project-specific integration, capability-calibration protocol, measured governance failure, and repair across the unified system.”**

A detailed implementation record should be maintained in [`PROJECT_IMPLEMENTATION_RECORD.md`](PROJECT_IMPLEMENTATION_RECORD.md).

## 2. Final novelty hypothesis

The primary hypothesis is:

> **A security exception should not cancel detection evidence merely because it matches. It should be admitted only when the attacker capability required to forge the exception is strictly greater than the capability required to avoid the evidence, or when an independently justified safety rule overrides the tie. This policy must be calibrated through a locked, reproducible capability search and must preserve recovery and audit integrity across the unified pipeline.**

This hypothesis contains two contributions:

1. a reusable measurement protocol for attacker-capability calibration; and
2. its implemented application to a unified ransomware detector, where the protocol exposes and repairs an ungoverned multi-format exemption.

The protocol is not presented as a universal attacker-economics model. It is a conservative, auditable method for the declared threat model and repository environment.

## 3. Research questions

| ID | Research question | Required evidence |
|---|---|---|
| RQ1 | Can the capability-search protocol assign reproducible levels to avoidance and forgery strategies? | Locked search log, versions, source URLs, licenses, fixture hashes, and second-reviewer reproduction. |
| RQ2 | Which URDS paths cancel or weaken suspicious evidence? | Complete source/call-site inventory across Monitor, ML, ledger, response, and recovery. |
| RQ3 | Does the current container exemption accept unvalidated recognized-format claims? | 20 signature-entry/16-format deterministic evidence report. |
| RQ4 | Does the existing equality rule authorize equal-capability mitigation and avoidance strategies? | Admission-recompute matrix under the frozen calibrated table. |
| RQ5 | Does the calibrated repair close the bypass without simply preserving a different public-primitive attack? | Current/null/repair experiment including validated-format forgery and incomplete validation. |
| RQ6 | Does the repair preserve the unified system’s behavior? | ML, ledger, response, recovery, and fixed-family regression gates. |
| RQ7 | What false-positive cost does the repair impose in the deployment-relevant corpus? | Stratified benign corpus and paired statistics. |

An external detector comparison is future work. It is not required for the core capstone claim, provided the report clearly scopes the result to URDS.

## 4. Threat model and valid case domain

The attacker can write or modify files in the monitored environment, choose paths and filenames, and use public software available under the declared environment. The attacker cannot forge a cryptographic preimage, access unavailable secrets, or alter the experiment’s manifests and reports without that alteration being recorded as a safety failure.

A test case is valid only if:

1. the operations and tool versions are recorded;
2. the case achieves a declared attacker objective;
3. the structural label matches the actual construction;
4. the case does not depend on an observer or infrastructure failure;
5. the original bytes restore exactly from the manifest; and
6. the result is classified separately as `attacker_valid`, `mutation_control`, `invalid`, or `safety_failure`.

For the project fixture, the attacker objective is defined by an application-level integrity check. A container may remain syntactically valid while its protected member fails the recorded digest or usability check. A harmless re-encoding that leaves the protected objective intact is not an attack witness.

## 5. Capability calibration before repair

Calibration must precede repair design. The team must not choose `container_valid is True`, a provenance rule, an inner-content rule, or a tie rule and only afterward assign costs that justify it.

### 5.1 Locked tooling search

For each mitigation-forgery and signal-avoidance strategy:

1. search the Python standard library and installed system utilities;
2. search approved packages and installed packages;
3. search public repositories and official documentation;
4. search the literature;
5. record the exact command/API, tool version, URL, license/status, required inputs, output hash, and fixture result;
6. assign the lowest reproducible capability level; and
7. have a second reviewer repeat the search from the record.

The search protocol is frozen before the final repair comparison. If a lower-level method is discovered later, it is recorded as a protocol finding and the affected policy decision is recomputed rather than silently ignored.

### 5.2 Capability ladder

| Level | Meaning | Example |
|---:|---|---|
| 0 | Direct attacker control | Write bytes, choose a path, rename a file, or prefix a recognized magic value. |
| 1 | Public primitive | Standard-library call, installed command, or mature public package performs the operation without format-specific engineering. |
| 2 | Format-aware capability | Additional format-specific structural or semantic constraints must be satisfied. |
| 3 | New engineering or unavailable privilege | Material new implementation or out-of-model privileged access is required. |
| 4 | Secret/preimage | Protected secret, signing material, or cryptographic preimage is required. |

This scale is categorical, not monetary. Runtime, CPU, memory, and changed bytes are secondary measurements and cannot promote a Level 1 public primitive to Level 2 merely because the output appears sophisticated.

### 5.3 Strict tie policy

Let:

```text
C_avoid(signal) = lowest level of a valid strategy that avoids the signal
C_forge(mitigation) = lowest level of a valid strategy that makes the mitigation match
```

The calibrated policy is:

```text
admit only if C_forge(mitigation) > C_avoid(signal)
otherwise attenuate, defer, or require independent evidence
```

Strict inequality is necessary because equal capability does not demonstrate that the mitigation is harder to forge. A documented independent-evidence exception may override a tie only if it was declared before outcome inspection.

For the current finding, an unvalidated magic prefix is Level 0, base64 and basic standard-library container generation are Level 1, and a content-provenance-preserving format-aware construction is Level 2 unless the public primitive already satisfies the requirement. These are calibration hypotheses until the locked search record is complete.

## 6. Admission recomputation is a required result

After the capability table is frozen and before repair coding, recompute every existing admission decision. Do not only identify that a tie exists; show which current decisions change.

The matrix must cover every relevant pair:

```text
{hash, path, training_mode, container_exemption}
×
{ransom_extension, static_entropy, entropy_rise,
 partial_entropy, structural_mismatch, container-exemption evidence}
```

For each pair, record:

```text
current_forgery_cost
current_avoidance_cost
calibrated_forgery_level
calibrated_avoidance_level
current rule (>=)
calibrated rule (>)
flipped or unchanged
reason
```

The expected result must not be pre-written as a conclusion. In particular, if path and training-mode forgery are both Level 1 and static-entropy avoidance is also Level 1, the strict rule changes those entries from admitted to attenuated. The final report must show whether that happens under the locked evidence, because it may demonstrate that two deployed mitigations were previously cost-unjustified or that the scale needs a documented refinement.

This recomputation is a central evidence table, not an appendix.

## 7. The required three-arm experiment

All final repair claims use the same locked attack and benign cases under three arms.

| Arm | Definition | Why required |
|---|---|---|
| A — Current | Existing URDS behavior, including the current container exemption. | Establishes the actual baseline. |
| B — Null | Container exemption removed or disabled. | Measures the cost of deleting the mitigation entirely. |
| C — Calibrated repair | Repair selected after calibration and admission recomputation. | Tests the proposed governance result. |

The null control is essential. If Arm B’s false-positive cost is acceptable, a governance layer may not be necessary. If Arm B is costly while Arm C closes the attack at lower benign cost, the policy has a measured technical purpose.

### 7.1 Candidate repair variants

The team may test multiple candidates, but the final winner is selected only after calibration:

| Variant | Purpose |
|---|---|
| Positive validation gate | Refuse `None` and `INCOMPLETE` as positive structural proof. |
| Strict capability tie | Do not admit when `C_forge == C_avoid`. |
| Content provenance | Require trusted baseline, inner-content integrity, or independent evidence in addition to outer structure. |
| Inner-content/recursive validation | Prevent an attacker from placing changed content inside a valid outer container. |
| Explicit deferred state | Represent unavailable validation without silently treating it as benign. |

The repair is not automatically `container_valid is True`. That candidate must face the validated-format public-primitive witness.

## 8. Corrected witness set and corpus

### 8.1 Required attack witnesses

The evidence harness must include:

1. the 20 recognized signature entries representing 16 unique formats;
2. the 11 unvalidated-format fresh high-entropy witnesses;
3. a genuinely valid container constructed with a public primitive around protected content that fails application-level integrity;
4. an `INCOMPLETE` or equivalent undecidable validator case;
5. the same format on fresh and observed paths; and
6. forged supported-format cases that should produce structural mismatch.

The validated-format forgery witness must appear in the acceptance table. Arm C fails if it continues to accept that witness without a separately justified provenance, history, or independent-evidence control.

### 8.2 Stratified benign corpus

The benign corpus must be stratified by:

```text
(validation state: validated | unvalidated)
×
(payload compressibility: compressible | incompressible)
```

The deciding cell is **unvalidated × incompressible**, because that is where positive validation gating can turn a benign-compressed outcome into a suspicion. Text archives belong to the compressible cell and must not be treated as evidence that the repair has no cost.

Select **five or six formats before collecting outcomes**, based on the project’s deployment story. A reasonable default is ZIP, GZIP, PDF, PNG, JPEG, and one operationally relevant unvalidated format such as XZ or Zstandard. Do not claim 16-format statistical coverage when the deployment corpus contains only five or six formats.

For each selected format, collect up to 100 locked benign fixtures where available, with the exact count reported. Include:

- ordinary archive creation and extraction;
- package downloads and installation;
- version-control clones;
- browser or service downloads;
- backup creation;
- document export;
- media processing; and
- ordinary benign encryption or compression workloads where operationally relevant.

The corpus must include both compressible text/document payloads and incompressible media or already-compressed payloads. The latter is the cell that measures the repair’s real false-positive cost.

## 9. Acceptance criteria that cannot self-certify

The repair is accepted only if all required rows pass.

| Criterion | Required result |
|---|---|
| Unvalidated-format closure | Arm C produces no silent `benign_compressed` result for the 11 unvalidated-format attacker-valid witnesses. |
| Validated public-primitive witness | Arm C explicitly evaluates it. If it remains benign, the plan adds provenance/history/independent evidence or rejects the repair as insufficient. |
| Incomplete validation | No silent benign cancellation; result is `deferred` or `unverified`. |
| Current/null comparison | Arm A, B, and C outcomes are all reported; Arm B quantifies the maximum cost of deleting the exemption. |
| Validated benign controls | Arm C is non-inferior to Arm A within the predeclared bound on the selected validated deployment corpus. |
| Unvalidated benign controls | False-positive cost is reported separately for compressible and incompressible payloads; no zero-cost assumption is allowed. |
| Admission recomputation | Every existing mitigation/signal pair is recomputed and any flipped admission is reported. |
| Fixed detector baseline | Existing 13-family sweep remains 13/13 detected within the project’s detection deadline and restores correctly. |
| ML preservation | Existing ML feature/API contract tests pass and no policy metadata is silently discarded. |
| Ledger preservation | Every repaired decision reaches the ledger with mitigation ID, validation state, capability levels, policy version, and reason. |
| Response preservation | Suspicious cases still produce the expected response action; no response loss is hidden by isolation settings. |
| Recovery preservation | Cases with trusted snapshots achieve 100% verified restoration; missing or mismatched trust is never reported as verified. |
| Tamper handling | Every injected ledger-tamper case fails verification and remains traceable. |
| Safety | All cases restore exactly, and no unrelated target content is modified. |

The first six rows establish the Monitor contribution. The ML, ledger, response, and recovery rows are required because the project presents itself as a unified system; if any are deferred, the final claim must explicitly say “Monitor-scoped.”

## 10. Statistical design

The multi-format bypass itself is a deterministic code-path result and does not require a prevalence estimate. Statistics are required for benign trade-offs, timing, and any noisy pipeline measurement.

For each selected corpus format, use the same fixtures under Arms A, B, and C. For paired binary outcomes, report discordant pairs, absolute risk difference, and exact or mid-p confidence intervals. Use McNemar’s test only as a paired comparison; do not treat events from one file as independent samples.

Predeclare a validated-benign non-inferiority bound, for example:

```text
FPR(C) − FPR(A) ≤ 2 percentage points
```

The one-sided 95% confidence bound must be evaluated against that bound. For unvalidated formats, do not impose the same non-inferiority claim; report the measured trade-off and use it to decide whether a real validator or explicit operator policy is justified.

Use at least 10 repetitions per case for timing claims and report median and IQR. Timing is secondary to policy correctness.

## 11. Full-system integration is required

The core project result must traverse the existing unified path at least once for every repaired decision class:

```text
Monitor → ML Engine → Ledger → Response → Recovery
```

The integration test must prove that:

1. the Monitor’s mitigation decision and capability metadata survive the ML handoff;
2. the ML result does not silently overwrite the policy outcome;
3. the event and policy record enter the tamper-evident ledger;
4. the response layer takes the expected action for suspicious outcomes;
5. the recovery layer uses the trusted-hash policy correctly; and
6. the final operator/audit view can distinguish `cancelled`, `attenuated`, `deferred`, `restored_verified`, and `restored_but_unverified`.

The full-system extension is not a request to build new ML or mobile technology. It is an integration and evidence requirement for the technologies already present in this repository.

## 12. Implementation sequence

### P0 — Freeze baseline and authorship record

Record the branch, commit, environment, existing test result, component inventory, and project-built modules. Run the fixed 13-family simulator and the existing ML, ledger, response, and recovery tests.

**Exit gate:** baseline is reproducible and the report states exactly which layers are in scope.

### P1 — Audit all mitigation paths

Trace every branch that suppresses, cancels, attenuates, downgrades, or prevents response. Mark whether it reaches common admissibility, whether it has a capability entry, and whether its decision reaches the ledger.

**Exit gate:** no evidence-cancellation path remains unclassified.

### P2 — Run current evidence and build the locked corpus

Run the multi-format evidence script, valid-container public-primitive witness, incomplete-validation witness, and the stratified benign corpus. Freeze inputs and hashes.

**Exit gate:** the 11/16 unvalidated result, the validated-forgery result, and the four benign strata are reproducible.

### P3 — Calibrate capability and recompute admissions

Complete the locked tooling search, obtain independent reproduction, freeze the capability table and strict tie rule, then recompute every existing mitigation/signal admission.

**Exit gate:** the admission-flip table is complete and no repair has yet been selected on the basis of post-hoc pricing.

### P4 — Implement and evaluate the repair in shadow

Implement the repair candidate selected from P3 behind a configuration or shadow switch. Run Arms A, B, and C on the locked attack and benign sets.

**Exit gate:** the repair closes the unvalidated witness, faces the validated public-primitive witness, and passes or fails according to the predeclared table.

### P5 — Integrate through ML, ledger, response, and recovery

Propagate the policy record through the existing unified pipeline. Add failure injections for missing trusted baseline, mismatched restored hash, corrupted snapshot, ledger tampering, and response-isolation behavior.

**Exit gate:** numerical full-system gates pass, or the final claim is reduced to Monitor scope.

### P6 — Regression and final evaluation

Add regression tests for the multi-format witness, all admission flips, benign strata, fixed families, and recovery/audit failures. Run the paired statistics and generate the final claim-to-artifact matrix.

**Exit gate:** every headline sentence maps to implementation, test, report, or explicit assumption.

## 13. Time-boxed schedule

The core plan is approximately **8–10 focused working days**, not 15–24 days. The first result is not complete until the repair and measurement exist.

| Day | Deliverable |
|---:|---|
| 1 | Baseline freeze, authorship record, mitigation inventory. |
| 2 | Multi-format evidence, valid-forgery and incomplete-validation witnesses. |
| 3 | Deployment-format selection and stratified benign corpus assembly. |
| 4 | Capability-search records and second-reviewer reproduction. |
| 5 | Admission-recompute table and frozen strict tie policy. |
| 6 | Shadow repair and current/null/repair attack comparison. |
| 7 | Benign paired evaluation and false-positive trade-off analysis. |
| 8 | ML → ledger → response → recovery integration and failure injection. |
| 9 | Regression suite, audit verification, and final statistics. |
| 10 | Thesis/report writing, limitations, reproducibility package, and review. |

Adaptive RECF-DR search, Pareto optimization, eleven new validators, external-detector comparison, Polygon anchoring, and mobile support are future work. They must not displace the evidence required for the core result.

## 14. Final claim-to-evidence matrix

| Claim | Evidence required | Allowed wording |
|---|---|---|
| The capability-search protocol is reproducible | Locked protocol, source trail, hashes, second reviewer | “We introduce a reproducible capability-calibration protocol…” |
| The team built the URDS integration | Component record, commits, tests, architecture | “The project team designed and implemented…” |
| The container exemption is ungoverned | Source/call-site audit and deterministic evidence | “In the reviewed URDS Monitor…” |
| 11/16 recognized formats are unvalidated | Registry and 20-entry evidence report | “The current registry contains…” |
| The policy had a resolution problem | Frozen capability table and admission-flip matrix | “Under the declared capability model…” |
| The repair closes the tested bypass | Arms A/B/C and regression results | “The repair closed the evaluated bypass…” |
| Benign cost is acceptable | Stratified deployment corpus and non-inferiority analysis | “On the evaluated corpus…” |
| The unified pipeline preserves trust | ML, ledger, response, recovery gates | “In the evaluated URDS pipeline…” |
| General ransomware-detector improvement | External detector comparison | Do not claim without it. |
| Patentability or legal novelty | Formal legal/prior-art review | Never infer from this plan alone. |

## 15. Final contribution statement

Use this statement in the thesis or final report:

> **The project team designed and implemented a unified ransomware detection-and-recovery system and a locked protocol for calibrating attacker capability in detector policy. The protocol searches available tooling in a fixed order, records executable evidence, versions, sources, licenses, fixture validity, and independent reproduction, and assigns the lowest capability level supported by the record. Applied to the URDS Monitor and then traced through the ML, ledger, response, and recovery path, it exposed an ungoverned container exemption that treated unvalidated format claims as explanations for high entropy across 11 of 16 recognized formats. A current/null/repair experiment and a complete admission-recompute table measured the policy trade-off, while a calibration-selected repair was accepted only if it closed the tested witnesses, preserved deployment-relevant benign behavior within a predeclared bound, maintained fixed-family detection, and preserved trusted recovery and auditable policy outcomes.**

The words “in the reviewed URDS implementation,” “under the declared capability model,” and “on the evaluated corpus” are mandatory. They preserve scientific honesty while clearly claiming the team’s own integrated engineering work and the measured method/result.
