# Final Novelty-Proof Plan: Reproducible Attacker-Capability Calibration for URDS

## Executive position

The project should not claim that cost-ordered admissibility is newly invented. The principle is already present in `services/monitor/admissibility.py` and in the existing hardening documentation. The project should also not claim that adaptive RECF-DR search is the primary novelty. The current detector’s important boundary cases are substantially characterizable from source-level thresholds and decision branches.

The strongest remaining novelty candidate is the **locked capability-search protocol** used to calibrate attacker cost:

> **A reproducible protocol for empirically calibrating the minimum attacker capability required to forge a security mitigation or avoid a detection signal, using an ordered search over available tooling, versioned commands, public sources, licenses, required inputs, fixture validity, and independent reproduction.**

URDS is the case study. The protocol is then applied to the URDS Monitor’s false-positive mitigations, where it produces a measurable result:

1. the current container exemption treats `container_valid=None` as sufficient evidence;
2. 11 of 16 unique recognized formats have no structural validator;
3. unvalidated-format high-entropy payloads can therefore reach `benign_compressed` with a directly controllable magic prefix;
4. a standard-library valid-container construction shows that positive structural validation is itself low capability, not automatically a high-cost trust signal;
5. the cost policy’s equal-capability tie must therefore fail closed or require additional evidence; and
6. a repair designed **after** calibration closes the tested bypass without being allowed to preserve the attack merely to satisfy a self-written acceptance criterion.

This is an engineering-evaluation contribution with a clear technical effect. It is not a universal theorem, a guarantee of patentability, or proof that all ransomware detectors share the behavior.

## 1. Final contribution structure

| Layer | What the project contributes | What it does not claim |
|---|---|---|
| Method | Locked, auditable search protocol for minimum attacker capability. | That the five-level ladder is a universal attacker-economics theory. |
| Case study | Application to URDS Monitor false-positive mitigations. | That the existing admissibility principle itself is new. |
| Finding | Container exemption is ungoverned and treats unvalidated claims as validated explanations. | That every external detector has the same defect. |
| Repair | Calibration-gated policy that refuses unvalidated or cost-tied cancellation. | That adding `is True` alone is always sufficient. |
| Evaluation | Current policy versus no-exemption null control versus calibrated repair, with benign, recovery, and audit outcomes. | That a report and JSON file alone prove novelty. |
| Optional extension | Full-pipeline governance or external detector comparison. | That deferred layers are already validated. |

The core result must contain a **code change, regression tests, and measured before/after outcomes**. Source inspection and deterministic evidence establish the vulnerability, but they do not complete the contribution by themselves.

## 2. Claim boundary

The primary claim is scoped to the URDS Monitor:

> **In the reviewed URDS Monitor implementation, a false-positive mitigation can bypass the common admissibility policy when a recognized container has no validator. A locked capability-search protocol identifies this bypass as directly controllable, exposes the insufficient resolution of an equal-cost policy tie, and guides a repair that refuses unvalidated or cost-tied cancellation while preserving positively validated benign controls within a predeclared bound.**

Use “URDS Monitor” in the primary report. Use “unified detection-and-recovery system” only for tests that actually traverse:

```text
Monitor → ML Engine → Ledger → Response → Recovery
```

The ML confidence layer, response-isolation configuration, trusted recovery hash selection, and ledger verification are not silently covered by a Monitor-only experiment. They require a later pipeline gate with numerical acceptance criteria.

## 3. Research questions and hypotheses

| ID | Question | Hypothesis |
|---|---|---|
| RQ1 | Can a locked capability-search protocol produce reproducible attacker-capability levels? | Independent reviewers can reproduce the assigned lowest level from the recorded search trail. |
| RQ2 | Does the current URDS Monitor contain mitigation paths outside common admissibility governance? | The container exemption bypasses `admissibility.adjudicate()`. |
| RQ3 | Is the container exemption exploitable across the recognized-format registry? | The 11 unvalidated unique formats accept fresh high-entropy witnesses through `container_valid=None`. |
| RQ4 | Is an equality rule sufficient at the decision boundary? | No. A one-primitive forgery and one-primitive avoidance tie cannot establish safe dominance. |
| RQ5 | Does the calibrated repair improve security without unacceptable benign cost? | The repair closes the unvalidated witness; its benign cost is measured against the current and null controls. |
| RQ6 | Does the repair preserve URDS reliability? | Fixed detection, restoration, and audit regression suites remain within predeclared bounds. |

## 4. Define the valid attack domain

A behavior vector is:

```text
v = (format, payload construction, file size, changed fraction,
     block placement, path history, structural state, timing)
```

A case is an **attacker-valid witness** only when:

1. the attacker-controlled operations are fully recorded and reproducible;
2. the transformation makes the protected content fail a declared application-level integrity or usability objective;
3. the structural label matches the actual construction;
4. the case does not depend on a missing observer event, test failure, or infrastructure error;
5. original bytes restore exactly from a recorded manifest; and
6. the outcome is not classified as an attack if it is only a byte mutation control.

For the current decoy, the objective is explicit: a checksum or manifest digest for the protected member must fail after transformation. A syntactically valid ZIP is therefore not automatically a successful attack; it must also fail the protected-content integrity check. This avoids calling harmless re-encoding an evasion.

## 5. Complete mitigation audit

The first audit maps every mechanism that can cancel, suppress, downgrade, or prevent action on suspicious evidence.

| Mechanism | Repository location | Common adjudication? | Required proof |
|---|---|---:|---|
| Hash whitelist | `services/monitor/suppression.py`, `app.py` | Yes | High-capability preimage claim and exact-hash tests. |
| Path whitelist | `services/monitor/suppression.py`, `app.py` | Yes | Low-capability path-forgery tests and attenuation tests. |
| Training mode | `services/monitor/suppression.py`, `app.py` | Yes | Dwell, structure, history, and poisoning tests. |
| Container exemption | `services/monitor/detection.py` | **No** | Multi-format evidence, capability calibration, and repair. |
| Low-entropy fall-through | `services/monitor/detection.py` | No | Mutation-control and attacker-objective classification. |
| ML confidence/backstop | ML service and pipeline | Separate | Explicitly deferred or separately audited. |
| Response isolation | Response/pipeline configuration | Separate | Numerical pipeline test if claimed. |
| Trusted recovery hash | Recovery ledger client | Separate | Integrity and recovery gate if claimed. |
| Ledger-chain verification | Ledger/recovery path | Separate | Tamper-injection gate if claimed. |

The audit is documentation, not the result. The result begins when the protocol measures the cost of the mitigation, the current/null/repair experiment shows the trade-off, and the repair is committed with regression tests.

## 6. The locked capability-search protocol

The protocol is the primary method contribution. It must be written before the repair is selected and frozen before the final outcomes are examined.

### 6.1 Ordered search

For each avoidance or forgery strategy, execute the following ordered search:

| Search order | Source | Record |
|---:|---|---|
| 1 | Python standard library and installed system utilities | Package/runtime version, exact API or command, result. |
| 2 | Approved package index and installed packages | Package version, license, API/command, result. |
| 3 | Public repositories and official documentation | URL, commit/release, license, inputs, result. |
| 4 | Academic and technical literature | Citation, described method, required assumptions, result. |
| 5 | New project implementation | New code, engineering effort category, validation result. |

The first reproducible source that achieves the objective determines the lowest capability level. The protocol must not skip a standard-library search because the operation “looks sophisticated.”

### 6.2 Capability ladder

| Level | Definition | Example |
|---:|---|---|
| 0 — Direct control | A write, rename, path choice, or magic-prefix operation is enough. | Prefix ciphertext with an unvalidated recognized signature. |
| 1 — Public primitive | A standard-library call, installed command, or mature public package performs the operation without format-specific implementation. | `gzip.compress()` or a basic `ZIP_STORED` container construction. |
| 2 — Format-aware capability | The attacker must satisfy format-specific structural or semantic invariants beyond a public primitive. | Produce an application-acceptable protected file whose content semantics remain plausible. |
| 3 — New engineering/privilege | Material new implementation, unavailable privilege, or out-of-model system capability is needed. | Implement an unsupported validator or obtain privileged telemetry. |
| 4 — Secret/preimage | An unavailable secret, cryptographic preimage, or protected signing/key material is required. | Forge an approved SHA-256 whitelist preimage. |

The ladder is not a currency. Adjacent levels are categories, not equal monetary distances.

### 6.3 Equality rule

The policy must not authorize an equality tie by default:

```text
admit mitigation m only if C_forge(m) > C_avoid(s)
otherwise attenuate, defer, or require independent evidence
```

The strict inequality is a deliberate improvement over the existing `forging >= avoiding` rule. If both forging the mitigation and avoiding the signal are demonstrably achievable at Level 1, the policy has no evidence that the mitigation is safer. It must not admit solely on equality.

If the team chooses to retain `>=` for a specific mitigation, that must be a separately justified exception with an independent evidence requirement and a predeclared reason. It cannot be introduced after observing the desired outcome.

### 6.4 Reproduction and audit trail

Every cost assignment must include:

```text
record_id
avoidance_or_forgery
signal_or_mitigation
strategy_description
attacker_objective
capability_level
exact_command_or_API
tool/runtime/package version
source URL or repository commit
license/status
required information
resource measurements
fixture input hash
output hash
validity classification
reviewer reproduction
policy version
```

A second reviewer must repeat the search from the record without relying on the original author’s interpretation. Disagreement produces an unresolved or conservative level; it does not get averaged away.

## 7. Current evidence and decisive witnesses

### 7.1 Multi-format unvalidated witness

The current detector recognizes 20 signature entries corresponding to 16 unique formats. Five unique offset-zero formats have validators in the registry—ZIP, GZIP, PNG, JPEG, and PDF—while 11 do not. The unvalidated formats are 7z, RAR, XZ, BZip2, LZ4, Zstandard, GIF, MP3, OGG, FLAC, and RIFF.

The evidence harness runs a fresh 64 KiB high-entropy payload with every recognized signature entry. Its current output records 13 unvalidated entries returning `benign_compressed` and zero unvalidated entries returning suspicious. The duplicate entry count is expected because ZIP, GIF, and MP3 have multiple signatures.

This is a deterministic code-path result, not a random-sample estimate. The claim is scoped to the reviewed registry and current implementation.

### 7.2 Validated-format public-primitive witness

The study must also include a genuinely valid container constructed through a public primitive, with an application-level integrity failure in the protected member. This witness prevents the plan from treating “positive validation” as synonymous with “safe benign provenance.”

The acceptance table must include this witness explicitly. Arm C fails if it continues to accept a malicious but positively validated container solely because `container_valid=True`. That failure is not a defect in the experiment; it tells the team that structural validation alone is insufficient and that the repair must add content provenance, trusted history, or an independent signal.

### 7.3 Incomplete-validation witness

A supported format whose validator returns `INCOMPLETE` or an equivalent non-decision must not be silently converted into positive validation. The policy output must distinguish:

```text
VALID      → eligible for exemption review
FORGED     → evidence against the claim
INCOMPLETE → deferred/unverified
UNVALIDATED→ no structural evidence; fail closed
UNREADABLE → observation failure or unverified state
```

## 8. The three-arm experiment

Every final security claim must compare the same locked cases under three arms.

| Arm | Definition | Purpose |
|---|---|---|
| A — Current | Existing behavior, including `container_valid is not False`. | Measures the deployed baseline. |
| B — Null | Container exemption disabled completely. | Measures the maximum false-positive cost of removing the mitigation. |
| C — Calibrated repair | Repair selected after capability calibration; at minimum, no silent cancellation for `None`, `INCOMPLETE`, or capability ties. | Tests whether the measured policy improves security at lower cost than deleting the exemption. |

Arm B is not optional. It bounds whether the governance mechanism is necessary. If Arm B’s false-positive cost is acceptable, a complex governance layer may not be justified. If Arm B is expensive while Arm C closes the witness and preserves validated benign behavior within the predeclared bound, governance has a measurable technical purpose.

## 9. Repair-selection rule

The repair must be selected **after** calibration and before the final outcome comparison. Candidate repairs include:

| Candidate | When justified |
|---|---|
| Positive-validation gate | When unvalidated `None` is the only cause of the bypass and benign cost is acceptable. |
| Strict tie handling | When `C_forge == C_avoid` occurs and equality provides no safety margin. |
| Content-provenance or trusted-history requirement | When a public primitive can create a valid container around attacker-controlled content. |
| Inner-content or recursive validation | When outer-container validity is insufficient for the protected member. |
| Explicit `unverified/deferred` result | When validation cannot decide without false certainty. |
| Additional independent signal | When the exemption is safe only in the presence of corroborating evidence. |

Do not promise that `container_valid is True` alone is the final answer. It is one candidate repair whose acceptance depends on the public-primitive witness, benign controls, and policy margin.

## 10. Correct acceptance criteria

The plan must not allow Arm C to pass while preserving its own attack. The following criteria are mandatory:

| Criterion | Required outcome |
|---|---|
| Unvalidated-format witness | Arm C does not return silent `benign_compressed` for the 11 unvalidated unique formats under the attacker-valid high-entropy objective. |
| Validated-format forgery witness | Arm C’s result is explicitly evaluated; if it remains benign, the plan must add provenance/history/independent-evidence governance or mark the repair insufficient. |
| Incomplete validation | No silent benign cancellation; result is `deferred` or `unverified`. |
| Null-control comparison | Arm B quantifies the false-positive cost of removing the exemption. |
| Validated benign corpus | Arm C remains non-inferior to Arm A within a predeclared bound for the selected deployment formats. |
| Fixed ransomware suite | Existing 13-family baseline remains 13/13 detected and restored. |
| Recovery | No case counts as a successful repair if trusted restoration fails. |
| Audit | Every decision contains mitigation ID, validation state, cost levels, margin rule, policy version, and reason. |
| Safety | Original hashes restore exactly; no unrelated directory content is touched. |

The validated-format forgery row is the most important correction. It prevents the plan from certifying a repair that still accepts the public-primitive attack it was supposed to govern.

## 11. Benign corpus and statistical design

The 100-files-per-format requirement is too broad for the project window. Scope the corpus to formats in the deployment story. The project should choose **five or six formats** before collecting outcomes, for example ZIP, GZIP, PDF, PNG, JPEG, and one format that the intended deployment actually handles. If a sixth format is not operationally relevant, do not add it merely for symmetry.

For each selected format, use up to 100 locked benign fixtures where available. Include ordinary archive creation/extraction, downloads, version-control clones, package installation, backups, media operations, and document exports as applicable. If a format cannot reach the target count, report the exact count and treat its result descriptively.

Use the same files or replay traces under Arms A, B, and C. For paired binary outcomes, use McNemar’s test and report discordant pairs, exact confidence intervals, and absolute risk difference. Use a predeclared non-inferiority bound, such as:

```text
FPR(C) − FPR(A) ≤ 2 percentage points
```

The bound must be selected before reviewing outcomes and justified by the project’s operational tolerance. For timing, use 10 repetitions per case and report median/IQR; timing is secondary to policy correctness.

## 12. Minimal implementation plan

The primary contribution must be achievable without building a premature `recf_dr/` framework.

### Work package 1 — Audit and baseline

Produce the mitigation-path table, freeze the branch and environment, run the existing 13-family suite, and document the Monitor-only claim boundary.

**Exit gate:** every cancellation path has a source location, test identifier, current governance status, and scope decision.

### Work package 2 — Evidence harness

Run the 20-signature/16-format evidence script, add the valid-container public-primitive witness and the incomplete-validation witness, and record attacker-objective validity.

**Exit gate:** the current vulnerability is reproduced with hashes, exact commands, and no safety failures.

### Work package 3 — Capability calibration

Execute the locked tooling search for each relevant avoidance and forgery strategy. Have a second reviewer reproduce the records. Freeze the cost table and tie rule before repair coding.

**Exit gate:** every cost level is backed by a reproducible source trail, and equal-cost cases are identified.

### Work package 4 — Null control

Implement the no-exemption arm behind a test or configuration switch. Run it on the locked benign corpus and attack witnesses.

**Exit gate:** the false-positive cost of deleting the exemption is quantified.

### Work package 5 — Calibrated repair

Implement the repair chosen from Work Package 3, initially in shadow or behind a switch. It must govern `None`, `INCOMPLETE`, structural validity, provenance/history, and cost ties as specified by the frozen policy.

**Exit gate:** Arm C closes the unvalidated witness and does not pass the validated-format forgery witness without an explicitly accepted additional safeguard.

### Work package 6 — Regression and selected benign evaluation

Run the fixed simulator suite, recovery/audit tests, and the selected five-or-six-format benign corpus under all three arms.

**Exit gate:** no fixed-family regression, restoration failure, audit loss, or unreported false-positive trade-off.

### Work package 7 — Final claim package

Write the method, case study, evidence, repair, negative results, limitations, and reproducibility commands. Include a claim-to-artifact matrix.

**Exit gate:** every sentence in the headline contribution maps to code, a test, a report, or a clearly labeled assumption.

## 13. Timeline

The first five packages should fit approximately **6–8 working days** for a focused capstone implementation. Work Package 6 may extend the schedule depending on benign-corpus collection.

| Day | Output |
|---:|---|
| 1 | Mitigation audit, branch/environment freeze, baseline. |
| 2 | Multi-format and valid-container evidence package. |
| 3 | Capability-search records and independent reproduction. |
| 4 | Null-control measurements and cost table freeze. |
| 5 | Shadow calibrated repair and decisive-witness comparison. |
| 6 | Regression, recovery/audit, and selected benign controls. |
| 7 | Paired statistics, figures, and claim-to-artifact matrix. |
| 8 | Final thesis/report revision and reproducibility review. |

Full-pipeline extension and external-detector comparison are future work unless the core result finishes early. Adaptive RECF-DR search is not part of the primary plan.

## 14. Final claim-to-evidence matrix

| Claim | Minimum evidence | Allowed wording |
|---|---|---|
| Protocol is reproducible | Search log, versions, sources, second-reviewer reproduction | “We define a reproducible capability-search protocol…” |
| Container exemption is ungoverned | Source inspection and call-site trace | “In the reviewed URDS Monitor…” |
| 11/16 recognized formats are unvalidated | Registry and deterministic evidence report | “The current registry contains…” |
| Bypass is low capability | Recorded direct-prefix strategy and objective-valid witness | “Under the declared capability model…” |
| Equal-cost governance is insufficient | Capability calibration identifies a tie and policy outcome | “The calibrated policy treats the tie as insufficient for cancellation…” |
| Repair closes the tested bypass | Arm A/B/C paired experiment and regression tests | “The repair closed the evaluated bypass…” |
| Benign cost is acceptable | Selected corpus and non-inferiority result | “On the evaluated deployment corpus…” |
| Full pipeline is improved | Monitor, ML, ledger, response, recovery gates | Do not claim unless all pass. |
| External generalization | Independent detector comparison | Do not claim without it. |
| Patentability/legal novelty | Formal review | Never infer from this plan alone. |

## 15. Final contribution statement

Use the following wording in the thesis or final report:

> **We introduce a locked, reproducible protocol for calibrating the minimum attacker capability required to forge a detector mitigation or avoid a detection signal. The protocol searches available tooling in a fixed order, records executable evidence, versions, sources, licenses, fixture validity, and independent reproduction, and assigns the lowest capability level supported by the record. Applied to the URDS Monitor, the protocol exposes an ungoverned container exemption that accepts unvalidated format claims as explanations for high entropy across 11 of 16 recognized formats, identifies an equal-capability policy tie at the decision boundary, and guides a repair evaluated against the current policy and a no-exemption null control. The repaired system closes the tested bypass while preserving selected validated benign workloads, fixed-family detection, trusted recovery, and auditable policy outcomes within predeclared bounds.**

The words “in the evaluated URDS Monitor,” “under the declared capability model,” and “on the selected corpus” are essential. They keep the result rigorous without overclaiming universal detector security or legal novelty.

## References

[1]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/detection.py "URDS Monitor detection and container-exemption branch"
[2]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/containers.py "URDS validator registry and tri-state validation"
[3]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/admissibility.py "URDS existing cost-ordered admissibility principle"
[4]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/suppression.py "URDS whitelist and training-mode paths"
[5]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/scripts/recf_exemption_evidence.py "URDS deterministic multi-format evidence harness"
[6]: https://arxiv.org/abs/2601.18216 "Rhea: Detecting Privilege-Escalated Evasive Ransomware Attacks Using Format-Aware Validation in the Cloud"
[7]: https://arxiv.org/abs/2603.19204 "Robustness, Cost, and Attack-Surface Concentration in Phishing Detection"
[8]: https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0273804 "MalFuzz: Coverage-guided fuzzing on deep learning-based malware classification model"
