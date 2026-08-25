# Canonical Novelty-Proof Plan for URDS

## Executive decision

The project should present the final work as an **empirical cost-of-defense evaluation**, not as an adaptive-search invention and not as a proof that the existing admissibility principle itself is novel. The cost-ordered principle is already present in `services/monitor/admissibility.py` and in the hardening documentation. The novelty-bearing result must therefore be the complete sequence:

> **We priced the defenses using an auditable capability scale, attempted to defeat every false-positive mitigation, found that the container exemption accepted unvalidated format claims at negligible attacker cost, repaired that path with positive-validation governance, and measured the resulting security/false-positive trade-off against both the original system and a no-exemption null control.**

This plan is designed to produce a real engineering evaluation with a defensible technical effect. It does not claim that the policy is universally novel, that URDS is secure against all ransomware, or that the result is patentable without formal prior-art and legal review.

## 1. Final claim boundary

The primary claim is **Monitor-scoped**:

> **In the URDS Monitor, every mechanism that cancels suspicious evidence must be governed by an auditable admissibility decision. Treating an unvalidated container claim as equivalent to positive structural validation creates a low-capability bypass; requiring positive validation closes that bypass without changing the semantics of governed whitelist and training-mode suppressions.**

The word “unified” describes the project architecture, but the novelty proof must not imply that ML confidence thresholds, response isolation, trusted recovery hashes, and ledger verification have been proven under the same policy unless those paths are separately evaluated. The report should say “URDS Monitor” for the primary result and reserve “full unified system” for a later extension that satisfies the pipeline evidence gate.

## 2. What is and is not the contribution

| Item | Status in the final argument |
|---|---|
| Cost-ordered admissibility as an abstract principle | Existing project foundation, not claimed as newly invented. |
| Fixed ransomware simulator and safe reversible execution | Engineering foundation and reproducibility mechanism. |
| Adaptive RECF-DR search and Pareto optimization | Dropped from the primary claim; the current boundary cases are source-characterizable. |
| Multi-format unvalidated exemption finding | Empirical architectural finding in the current URDS Monitor. |
| Tooling-availability cost scale | New measurement protocol that makes the policy auditable rather than declarative. |
| Positive-validation governance repair | New implementation result to be tested against null and current controls. |
| Recovery/audit integration | Required preservation evidence; a separate claim only after pipeline testing. |
| Patentability or universal ransomware-detector improvement | Not claimed; requires independent legal and external technical review. |

The core result must include **code that changes the behavior**, regression tests that prevent recurrence, and measured before/after outcomes. A spreadsheet, source-inspection table, and JSON file alone are not sufficient.

## 3. Research questions

The project should answer the following questions in order:

| ID | Research question | Evidence needed |
|---|---|---|
| RQ1 | Which URDS Monitor paths can suppress, cancel, downgrade, or prevent action on suspicious evidence? | Complete mitigation-path inventory with call sites. |
| RQ2 | What is the least auditable attacker capability required to make each mitigation match or to avoid each signal? | Tooling-availability calibration record. |
| RQ3 | Does the current container exemption accept unvalidated claims across the recognized-format registry? | Deterministic 20-entry/16-format evidence run. |
| RQ4 | Does a positive-validation repair close the bypass? | Current-vs-null-vs-repair paired test. |
| RQ5 | What false-positive cost does the repair impose on genuine benign containers? | Locked benign corpus and paired statistics. |
| RQ6 | Does the repair preserve the existing URDS detector, recovery, and audit behavior? | Regression, recovery, and audit test results. |
| RQ7 | Does the result generalize beyond the team’s detector? | Optional external comparison; do not make a general claim without it. |

## 4. Define the attack and objective domain before measuring cost

The cost model is meaningless unless its domain is defined. The project should use the following test-case definition.

A **behavior vector** is a tuple:

```text
v = (format, payload construction, file size, changed fraction,
     block placement, path history, structural status, timing)
```

A case is **attacker-valid** only if all of the following hold:

1. The transformation is deterministic or uses a recorded seed.
2. The attacker controls the bytes and path used by the case.
3. The declared file format and structural status are consistent with the construction. A valid container is created by a format-aware encoder; a broken or magic-only case is not labeled valid.
4. The protected content fails a declared application-level integrity or usability test. For the decoy fixture, this is a checksum or manifest comparison; for a valid archive, the container may remain syntactically valid while its protected member fails the integrity check.
5. The case does not rely on an accidental infrastructure error, missing observation, or failed restoration.
6. The original bytes restore exactly, and the restoration hash matches the manifest.

A case that merely changes bytes without defeating the declared content objective is a **mutation control**, not an attack witness. A case that cannot be restored is a **safety failure**, not a detector finding.

## 5. Inventory every evidence-cancellation path

The first work package is a source-level audit, not a general code refactor. It must enumerate every branch that can cause suspicious evidence to disappear or lose authority.

| Path | Current location | Current governance | Final question |
|---|---|---|---|
| Hash whitelist | `services/monitor/suppression.py` and `app.py` | Reaches `admissibility.adjudicate()` | Does the exact hash remain the high-capability case? |
| Path whitelist | `services/monitor/suppression.py` and `app.py` | Reaches adjudication | Does it remain lower-cost and attenuated when outranked? |
| Training-mode ceiling | `services/monitor/suppression.py` and `app.py` | Reaches adjudication | Do dwell, structure, and history remain visible? |
| Container exemption | `services/monitor/detection.py` | **Bypasses adjudication** | Does a validated/unvalidated distinction govern it? |
| Low-entropy fall-through | `services/monitor/detection.py` | No positive evidence formed | Is the content objective still represented in the test result? |
| ML confidence or model backstop | ML service and pipeline | Separate path | Is it in scope or explicitly deferred? |
| Response isolation | Response/pipeline configuration | Separate enforcement control | Is it being tested or only preserved? |
| Trusted recovery hash | Recovery ledger client | Governance of restored evidence | Is it included in the full-system extension? |
| Ledger-chain verification | Ledger/recovery path | Integrity governance | Does tampering alter acceptance? |

The audit is complete only when every evidence-cancellation branch has a source location, a test identifier, an owner, a policy status, and an explicit scope decision. The audit table is supporting evidence; the novelty proof still requires the repair and outcome measurements below.

## 6. Calibrate cost before designing the repair

The repair must not be designed before the capability scale is measured. Runtime, bytes changed, CPU, and memory remain useful secondary measurements, but they price the transformation rather than the ability to forge the mitigation.

### 6.1 Primary capability scale

Use a discrete, auditable tooling-availability scale:

| Level | Name | Definition | Example for this project |
|---:|---|---|---|
| 0 | Directly controllable | Achievable by writing attacker-controlled bytes, a path, filename, or magic prefix. | Prefix ciphertext with a recognized unvalidated signature. |
| 1 | Public primitive | Available in the standard library, installed command, or mature public package with no format-specific implementation. | Call a standard compression/encoding primitive. |
| 2 | Format-aware capability | Requires integrating a parser/encoder and satisfying format-specific structural or semantic invariants. | Produce a valid, application-acceptable container around changed content. |
| 3 | New engineering or privileged access | Requires substantial new implementation, unavailable privileges, or a capability outside the tested environment. | Build a new parser for an unsupported format or obtain a required privileged trace. |
| 4 | Secret/preimage capability | Requires an unavailable secret, cryptographic preimage, or equivalent protected capability. | Forge a content hash whitelist entry under the stated threat model. |

The level is assigned only after a locked search protocol:

1. Search the Python standard library and installed system tools.
2. Search the project’s approved public-package sources.
3. Search public repositories and package documentation for a reusable implementation.
4. Search the literature for a documented method.
5. Record the command, version, URL, license, required inputs, and whether the method works on the declared fixture.
6. Assign the lowest level whose evidence is reproducible.

The protocol must be run before repair implementation. Setup time, CPU, memory, and bytes changed are secondary fields. They cannot override the primary capability level.

### 6.2 Cost comparison

For a detection signal `s`, define:

```text
C_avoid(s) = lowest capability level of a valid strategy that avoids s
```

For a mitigation `m`, define:

```text
C_forge(m) = lowest capability level of a valid strategy that makes m match
```

The admissibility rule is:

```text
admit m only when C_forge(m) >= C_avoid(s)
otherwise attenuate m and retain the alert
```

The comparison is performed over attacker-valid strategies, not arbitrary byte edits. If two strategies are incomparable because one is cheaper in capability but more expensive in runtime, preserve both records and fail closed or require review. Do not silently force a total order.

For the container exemption, the initial calibration should show that an unvalidated magic claim is Level 0, while positive validation and application-level format preservation are Level 1–2 depending on the format and tool. That distinction must be recorded under `C_forge(container_exemption)`, not incorrectly under `C_avoid(static_entropy)`.

## 7. The decisive evidence set

The evidence harness must reproduce two related findings:

### 7.1 Multi-format unvalidated exemption

Run the current detector on a fresh 64 KiB high-entropy payload prefixed with every recognized signature entry. Report both 20 signature entries and 16 unique formats. The expected current result is that the 11 unvalidated unique formats can receive `benign_compressed` because `container_valid=None` is accepted by `container_valid is not False`.

This is a deterministic architectural witness, not an inferential sample. The evidence must record format, magic, validator status, entropy, verdict, signal, reason, payload hash, and fresh-path state.

### 7.2 Validated-format forgery witness

Add a valid-container construction that uses a standard/public primitive and makes the protected member fail the application-level integrity objective. This is not automatically a novel attack. Its purpose is to measure the actual cost level of positive format validation and test whether the exemption is safe when structural validation is true but content provenance is not.

Add an incomplete-read or `INCOMPLETE` witness for a supported format where the validator cannot yet decide. The policy must not silently treat `INCOMPLETE` as positive validation. It should produce a distinct `unverified` or `deferred` result.

## 8. The three-arm repair experiment

The plan must include the missing null control. Run three policy arms against the same locked cases.

| Arm | Definition | Purpose |
|---|---|---|
| A — Current | Existing container exemption, including `container_valid is not False`. | Measures current vulnerability and benign behavior. |
| B — Null control | Container exemption removed or disabled; high-entropy content is not explained by a container. | Measures the maximum false-positive cost of removing the mitigation entirely. |
| C — Governed repair | Container exemption allowed only when positive validation is `True`; `False`, `None`, and `INCOMPLETE` cannot silently cancel evidence. | Tests whether governance closes the bypass while preserving validated benign behavior. |

The null control is essential. If Arm B has an acceptable false-positive cost, a complex governance layer may not be justified. If Arm B has an unacceptable cost while Arm C preserves validated benign behavior and closes the witness, the governance layer has a measurable technical purpose.

### 8.1 Correct acceptance criteria

The repair must not be accepted merely because it preserves the current benign result for the very attack that should be closed. The acceptance criteria are:

| Criterion | Required result |
|---|---|
| Unvalidated-format witness | Arm C produces no `benign_compressed` for the 11 unvalidated unique formats under the fresh high-entropy objective-valid case. |
| Current-vs-null distinction | Arm A retains the current acceptance; Arm B and Arm C do not. |
| Validated benign controls | Arm C matches Arm A on genuinely benign, positively validated containers within the predeclared non-inferiority bound. |
| Forged supported containers | Arm C preserves structural-mismatch detection. |
| Incomplete validation | Arm C refuses silent benign cancellation and records `unverified`/`deferred`. |
| Existing simulator baseline | The 13 fixed families remain 13/13 detected and restored. |
| Recovery | No repaired case is counted as successful when trusted restoration fails. |
| Audit | Every repaired decision records mitigation ID, validation state, cost level, policy version, and outcome. |
| Safety | All cases restore byte-for-byte and no unrelated target content is touched. |

The key success is not “keep benign compressed behavior.” It is **preserve true positive validation while eliminating unvalidated evidence cancellation**.

## 9. Benign corpus and statistical design

### 9.1 Corpus

Use a locked benign corpus with at least 100 files per format where licensed, reproducible files are available. The corpus should contain real project artifacts, public samples with compatible licenses, and ordinary generated outputs from documented tools. If a format cannot reach 100 legitimate examples, report the result descriptively and do not claim inferential generalization for that format.

Include ordinary workloads that can resemble encryption or compression:

- archive creation and extraction;
- software/package downloads;
- version-control clones;
- browser downloads;
- media transcoding;
- backup creation;
- document export;
- ordinary encryption where the workload is explicitly benign.

The same files and event traces must be replayed under Arms A, B, and C.

### 9.2 Primary endpoints

The primary endpoints are:

1. closure of the unvalidated-format witness;
2. false-positive-rate difference between Arm C and Arm A on benign validated formats;
3. false-positive-rate difference between Arm C and the null Arm B;
4. number of mitigation paths governed before and after the change;
5. recovery verification rate; and
6. audit-decision completeness.

### 9.3 Statistical test

For paired binary outcomes, use McNemar’s test on the same file/event under two arms. Report the discordant-pair counts, exact or mid-p confidence intervals, and absolute risk difference. Do not treat individual events from one file as independent.

Use a predeclared non-inferiority bound for validated benign controls, for example:

```text
Arm C false-positive rate − Arm A false-positive rate ≤ 2 percentage points
```

The final bound must be chosen before looking at outcomes and justified by the project’s operational tolerance. For unvalidated formats, do not assume the repair has zero false-positive cost; report its measured cost and compare it with Arm B.

For timing, use at least 10 repetitions per case when latency is reported and present medians with interquartile ranges. Timing remains secondary to the policy outcome.

## 10. Pipeline scope and optional extension

The core novelty proof is Monitor-scoped and should be completed first. A pipeline-wide extension may then test whether the governance record remains intact through:

```text
Monitor → ML Engine → Ledger → Response → Recovery
```

The extension must define numerical gates rather than listing qualitative tests:

| Pipeline measure | Minimum evidence |
|---|---|
| Detection preservation | No regression on the fixed simulator suite. |
| Response preservation | No unexplained loss of response action for suspicious cases. |
| Recovery | 100% trusted-hash verification on successful restore cases; untrusted restores explicitly classified. |
| Audit | 100% of repaired decisions carry policy version, mitigation ID, and validation state. |
| Tamper handling | All injected ledger tamper cases fail verification and remain traceable. |
| Failure handling | Ledger outage, missing baseline, and corrupted snapshot are distinct outcomes. |

If this extension cannot be completed, the final document must retain the Monitor scope. The project must not use the word “unified” to imply evidence that was not collected.

## 11. What is deliberately dropped

The following items are not part of the primary result:

- adaptive RECF-DR search;
- guided-versus-random search claims;
- Pareto-frontier novelty;
- a large `recf_dr/` framework;
- automatic repair promotion;
- external-detector generalization as a required gate;
- adding eleven new format validators in the first repair;
- Polygon anchoring or mobile support.

These may be future work. They must not delay the core result or be used to compensate for a weak measurement design.

## 12. Time-boxed execution plan

The first five work packages produce the defensible contribution. The later packages improve strength but do not block the core result.

| Priority | Time box | Work package | Required output | Stop/continue gate |
|---|---:|---|---|---|
| P0 | 0.5 day | Freeze baseline and scope | Commit, environment, current 13/13 result | Baseline reproduced. |
| P1 | 1 day | Complete mitigation-path audit | Call-site inventory and scope table | Every evidence-cancellation path classified. |
| P2 | 0.5–1 day | Run multi-format current/null characterization | 20-entry/16-format evidence report | 11 unvalidated formats reproduced. |
| P3 | 1 day | Calibrate tooling-availability costs | Locked capability records and cost table | Every tested strategy has auditable evidence. |
| P4 | 1–2 days | Implement governed exemption in shadow | Arm C policy switch and decision record | `None`/`INCOMPLETE` cannot cancel evidence. |
| P5 | 1–2 days | Run null/current/repair regression matrix | Test report and repaired code | Witness closes; validated controls preserved. |
| P6 | 2–3 days | Build benign corpus and paired evaluation | Confusion tables and confidence intervals | Non-inferiority bound assessed. |
| P7 | 1–2 days | Add recovery/audit failure injection | Integrity and failure report | Full-system scope either passes or remains explicitly deferred. |
| P8 | 1 day | Package thesis evidence | Figures/tables/commands/limitations | Every headline claim maps to an artifact. |
| Optional | Future | External detector or adaptive extension | Separate study | Must not alter the core claim. |

The core result is therefore **P0–P6**, not P0–P2. It includes a code repair and measured trade-off, not only documentation.

## 13. Final evidence-to-claim matrix

| Claim | Evidence required | Allowed wording |
|---|---|---|
| URDS has an unvalidated container-exemption path | Source inspection plus deterministic multi-format run | “In the reviewed URDS Monitor implementation…” |
| 11 of 16 recognized formats lack a validator | Registry inspection and report | “The current registry contains…” |
| The bypass is low-capability | Tooling search protocol and reproducible prefix witness | “Under the declared capability model…” |
| Positive-validation governance closes the bypass | Arm A/B/C regression matrix | “The repair closed the tested bypass…” |
| The repair has acceptable benign cost | Locked corpus, paired test, non-inferiority result | “On the evaluated corpus…” |
| Recovery and audit remain trustworthy | Full pipeline failure-injection evidence | “In the evaluated URDS pipeline…” |
| The method improves ransomware detection generally | External detector evidence | Do not claim without it. |
| The work is patentable or legally novel | Formal patent/prior-art review | Do not claim from this plan alone. |

## 14. Final contribution statement

Use the following statement in the thesis or final report:

> **We present an empirical cost-of-defense evaluation for false-positive mitigations in a ransomware detection-and-recovery system. In the URDS Monitor, we audit every evidence-cancellation path, measure the least auditable attacker capability required to forge each mitigation, and identify a multi-format container exemption that treats unvalidated format claims as sufficient explanations for high entropy. We compare the existing policy with a no-exemption null control and a positive-validation repair. The repair closes the tested unvalidated-format bypass, preserves positively validated benign-container behavior within a predeclared non-inferiority bound, and maintains trusted recovery and auditable policy outcomes on the evaluated corpus.**

This statement is strong because it claims a **measured technical effect** rather than claiming that an already-written principle, a generic search framework, or a list of combined components is inherently novel.

## References

[1]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/detection.py "URDS Monitor decision branches and container exemption"
[2]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/containers.py "URDS container validator registry"
[3]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/admissibility.py "URDS existing cost-ordered admissibility principle"
[4]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/suppression.py "URDS whitelist and training-mode mitigation paths"
[5]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/scripts/recf_exemption_evidence.py "URDS multi-format exemption evidence harness"
[6]: https://arxiv.org/abs/2601.18216 "Rhea: Detecting Privilege-Escalated Evasive Ransomware Attacks Using Format-Aware Validation in the Cloud"
[7]: https://arxiv.org/abs/2603.19204 "Robustness, Cost, and Attack-Surface Concentration in Phishing Detection"
[8]: https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0273804 "MalFuzz: Coverage-guided fuzzing on deep learning-based malware classification model"
