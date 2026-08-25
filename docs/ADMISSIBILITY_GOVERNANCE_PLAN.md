# Canonical Novelty Plan: Cost-Ordered Governance of Ransomware Detector Mitigations

## Document status

This is the canonical novelty and implementation plan for the Unified Ransomware Detection and Recovery System (URDS). It supersedes earlier RECF-DR-first drafts and should be used for the thesis, project review, implementation backlog, and evidence package.

**Repository baseline:** `VSshashank/unified-ransomware-system`

**Baseline branch:** `feat/detection-hardening`

**Working branch:** `claude/novelty-claim-existing-projects-kau2ng`

**Reviewed implementation commits:** `fba11bf5af063b32a49894a1034262d7546492ce`, `7d96fbc`, and `932bc69`

**Primary scope:** URDS Monitor-level false-positive mitigation governance.

**Optional extension:** ML, response, recovery, and ledger governance after the Monitor result is complete and independently evidenced.

## Executive decision

The project should no longer present adaptive RECF-DR search as the primary novelty claim. In the current detector, several blind-spot outcomes are derivable directly from threshold constants and decision branches. A reviewer can therefore reject the statement that guided search discovers what fixed testing cannot find, because the decisive cases can be found by source inspection.

The defensible contribution is instead:

> **URDS introduces a cost-ordered governance policy for false-positive mitigations in ransomware detection. A mitigation may cancel detection evidence only when the attacker’s auditable cost to forge that mitigation is not lower than the attacker’s cost to avoid the evidence. Unknown, unvalidated, or incomparable claims fail closed or remain attenuated, and every decision is recorded with its policy version and recovery/audit consequences.**

The central technical result is a concrete architectural asymmetry: whitelist and training-mode suppressions reach `admissibility.adjudicate()`, while the container exemption cancels high-entropy evidence directly inside `classify()`. The exemption also treats `container_valid=None` as sufficient because it tests `container_valid is not False`. The current recognized-signature table contains **16 unique formats**, of which **11 have no structural validator**. A deterministic evidence run reproduced **13 unvalidated signature entries** returning `benign_compressed` and **zero** returning suspicious for fresh 64 KiB high-entropy payloads.

This is a Monitor-level result. The project must not generalize it to all ransomware detectors until an independent detector comparison exists.

## 1. The contribution is governance, not framework size

The original RECF-DR direction combined safe mutation, adversarial search, Pareto selection, repair evaluation, and regression generation. Those are useful engineering mechanisms, but they are individually established techniques and do not become novel merely by being connected. The project should not claim novelty from “fuzzing plus Pareto plus recovery.”

The improved contribution is a **policy invariant**:

> **No false-positive mitigation may cancel stronger evidence merely because the mitigation matches. Its authority must be justified by an auditable estimate of the attacker’s cost to forge it, compared with the cost of avoiding the evidence.**

This policy is demonstrated by a mitigation that violates the invariant in the current architecture: the container exemption.

## 2. Evidence already established

The repository contains two different classes of mitigation.

| Mitigation | Current behavior | Governance status |
|---|---|---|
| Content-hash whitelist | Matches exact approved bytes and reaches the common adjudication path. | Governed; high forgery cost is plausible because a preimage is required. |
| Path whitelist | Matches an approved path and reaches adjudication. | Governed; lower forgery cost is recognized. |
| Training-mode ceiling | Matches learned extension/structure/path/entropy conditions and reaches adjudication. | Governed; dwell and structure reduce poisoning risk, but the rule is still priced as low. |
| Container exemption | High entropy plus recognized container and `container_valid is not False` returns `benign_compressed` directly from `classify()`. | **Ungoverned; `None` is treated like `True`.** |
| Recovery trusted-hash decision | Determines whether restored content is verified. | Must be included in the optional pipeline-wide governance audit. |
| ML confidence/response isolation | Can influence whether downstream action occurs. | Must be scoped explicitly or audited before making a full-system claim. |

The container finding is not limited to ZIP. The detector recognizes 16 unique signature formats through 20 signature entries. Five unique formats in that table have validators: ZIP, GZIP, PNG, JPEG, and PDF. Eleven do not: 7z, RAR, XZ, BZip2, LZ4, Zstandard, GIF, MP3, OGG, FLAC, and RIFF. ISO-BMFF is handled through a separate `ftyp` path and is not one of the 20 offset-zero signature entries.

The full reproduction is recorded in [`docs/EXEMPTION_EVIDENCE.md`](EXEMPTION_EVIDENCE.md), generated by [`scripts/recf_exemption_evidence.py`](../scripts/recf_exemption_evidence.py), with raw results in [`reports/recf_exemption_evidence.json`](../reports/recf_exemption_evidence.json).

## 3. Exact problem statement

The problem is not simply that the detector misses encrypted archives. The sharper problem is:

> **How can a ransomware detector govern false-positive mitigations when a mitigation’s apparent evidence is incomplete, unvalidated, or unavailable under the current path state?**

For the current URDS Monitor, the container exemption claims that high entropy is explained by the declared format. That claim has different strength depending on `container_valid`:

| `container_valid` | Meaning | Should it authorize exemption? |
|---|---|---:|
| `True` | The registered structural validator accepted the format. | Potentially yes, subject to independent evidence and policy. |
| `False` | The registered validator rejected the declared format. | No; structural mismatch remains evidence. |
| `None` | No validator exists, validation is not definitive, or the format is not covered. | **No; an unchecked claim cannot cancel evidence.** |

The defect is therefore a **tri-state governance error** combined with an **architectural bypass**. The system has a cost-ordering principle, but not every evidence-cancellation path is subject to it.

## 4. Final novelty hypothesis

The novelty hypothesis to test is:

> **A ransomware detection-and-recovery system can be made more robust by governing every false-positive mitigation through a common, fail-closed admissibility policy whose primary cost scale is the attacker’s available tooling and capability, whose decision sees both present and unavailable evidence, and whose outcomes preserve recovery and audit integrity.**

The hypothesis has four testable parts:

1. The current Monitor contains mitigation paths that bypass common governance.
2. The bypass is exploitable with a low-capability, auditable witness across multiple recognized formats.
3. A surgical governance repair closes the bypass while preserving validated benign workloads.
4. The result can be independently reproduced and scoped honestly to URDS unless external evidence supports a broader claim.

This is a plausible capstone contribution and a reasonable workshop-level systems result if the repair and external comparison are completed. It is not a guaranteed patent claim or a universal ransomware-detection theorem. Formal IP review remains necessary for any patent decision.

## 5. Primary cost scale: tooling availability

Runtime, bytes changed, and CPU time are secondary measurements. They describe the transformation, not the difficulty of forging the mitigation. The primary scale must therefore be **tooling availability and attacker capability**, because that is the part of the cost that explains why an unvalidated magic prefix is cheap while producing and validating a real protected format is harder.

### 5.1 Auditable capability ladder

| Level | Name | Operational definition | Evidence required |
|---:|---|---|---|
| 0 | Directly controllable | Achievable by writing attacker-controlled bytes, a filename, a path, or a recognized magic prefix. | Reproduced from the repository or standard file operation. |
| 1 | Publicly available | Achievable with a standard-library primitive, installed command, or mature public implementation without format-specific engineering. | Versioned tool, package, or public source reference. |
| 2 | Format-aware implementation | Requires integrating a format specification, encoder, parser, or validator and satisfying format-specific invariants. | Reproducible implementation and format-validation output. |
| 3 | Novel engineering or privileged capability | Requires substantial new implementation, unavailable privileges, persistent system access, or a capability not present in the tested environment. | Threat-model justification and controlled experiment. |
| 4 | Secret or preimage dependent | Requires an unknown secret, cryptographic preimage, or equivalent capability assumed unavailable to the attacker. | Formal cryptographic or access-control assumption. |

The current repository’s four-value ordinal constants can be migrated to this five-level capability ladder without pretending that the numerical gaps are currency. The policy compares levels; it does not interpret a level-4 cost as four times a level-1 cost.

### 5.2 Cost of avoidance and cost of forgery

For a detector signal `s` and mitigation `m`, define:

```text
C_avoid(s) = minimum capability level needed to avoid signal s
C_forge(m) = minimum capability level needed to make mitigation m match
```

The minimum is taken over **attacker-valid strategies**, not over arbitrary byte edits. Each strategy must satisfy the declared ransomware objective and the file/application integrity test.

The policy rule is:

```text
admit mitigation m only if C_forge(m) >= C_avoid(s)
otherwise attenuate the mitigation and retain the alert
```

If multiple signals are present, the policy must evaluate the strongest independently supported evidence, not only the signal that happened to be selected by the first branch. If evidence is unavailable because the path is fresh, that unavailability is a state in the policy input; it is not equivalent to evidence of benign history.

If two strategies are incomparable under the declared dimensions, the policy fails closed or requires review. It must not force a total order without justification.

### 5.3 Applying the scale to the finding

For the current container exemption:

| Claim | Capability level |
|---|---:|
| Add a recognized magic prefix to attacker-controlled bytes | 0, directly controllable. |
| Use an existing public encoder/parser for a recognized format | 1 or 2, depending on the validator and format constraints. |
| Produce a valid format while preserving application-level semantics | 2, format-aware implementation. |
| Match a SHA-256 whitelist preimage | 4, secret/preimage dependent under the threat model. |

The current implementation has no format-dependent forgery-cost field for the container exemption. The repair must introduce one or, more safely, refuse to authorize the exemption when `container_valid` is `None`.

## 6. Surgical repair: fail closed on unvalidated containers

The first repair must be narrow and low risk. Replace the current condition:

```python
container_valid is not False
```

with an explicit positive-validation condition:

```python
container_valid is True
```

Conceptually:

```python
if high_entropy and container and container_valid is True and not ransom_ext:
    return benign_compressed
```

This repair is preferable to a blanket fresh-path rule. It does not reject all fresh archives. It rejects only a container claim for which URDS has no validator result. It also directly tests the principle that **an unchecked claim cannot cancel evidence**.

The repair must be implemented behind a configuration or shadow-evaluation switch first. The default production behavior should change only after the complete regression suite passes and the false-positive trade-off is measured.

### 6.1 Required repair outcomes

| Case | Expected repaired outcome |
|---|---|
| Genuinely valid ZIP/GZIP/PNG/JPEG/PDF accepted by its validator | Preserve the existing benign behavior where no stronger evidence exists. |
| High-entropy 7z/RAR/XZ/BZip2/LZ4/Zstandard/GIF/MP3/OGG/FLAC/RIFF prefix with `container_valid=None` | Do not return `benign_compressed`; retain suspicious/static evidence or an explicit unvalidated state. |
| Forged ZIP/GZIP/PNG/JPEG/PDF with `container_valid=False` | Preserve structural-mismatch detection. |
| Observed-path valid container with large entropy rise | Preserve entropy-rise detection. |
| Path whitelist, hash whitelist, and training-mode cases | Preserve existing admissibility semantics and audit records. |
| Missing trusted recovery baseline or ledger integrity failure | Preserve `restored_but_unverified`/audit-failure distinctions. |

The first patch should not add validators for eleven formats. Adding validators is a separate future work package, and each validator must be evaluated for parser safety, bounded resource use, incomplete reads, and false positives.

## 7. Evidence protocol

The evidence package must contain four linked artifacts.

| Artifact | Purpose |
|---|---|
| `docs/EXEMPTION_EVIDENCE.md` | Human-readable claim, scope, reproduction, and interpretation. |
| `scripts/recf_exemption_evidence.py` | Deterministic reproduction against the repository’s own classifier and registry. |
| `reports/recf_exemption_evidence.json` | Raw machine-readable output with hashes, status, verdict, and reason. |
| Regression tests | Prevent the repaired governance path from reopening. |

The evidence run must use a fresh temporary directory, deterministic payload seed, 64 KiB payloads, and every recognized signature entry. The report must record both signature-entry count and unique-format count because ZIP, GIF, and MP3 have duplicate signatures.

The evidence is not a random sample and does not require inferential statistics to establish the code-path asymmetry. It is a deterministic program analysis plus execution witness. Statistical testing becomes relevant for benign-workload trade-offs and timing, not for the existence of the branch condition.

## 8. Complete mitigation audit

The Monitor audit is the minimum required scope. The audit should enumerate every code path that can suppress, cancel, downgrade, or prevent response to suspicious evidence.

The first audit deliverable is a table with:

```text
mitigation_id
source_file and line range
matching condition
evidence canceled or reduced
whether it reaches adjudicate()
forgery-capability level
avoidance-capability level
recovery impact
audit impact
regression-test identifier
```

The audit must cover hash whitelist, path whitelist, training mode, container exemption, low-entropy fall-through, unreadable-file handling, and any operator/API path that changes whitelist or training state.

Only after this table is complete should the project decide whether to extend the headline claim beyond the Monitor. The ML confidence threshold, response-isolation setting, recovery trusted-hash allowlist, and ledger-chain verification are governance decisions, but they are not automatically evidence of the same defect. If they are not audited before submission, the thesis must state that the novelty claim is Monitor-scoped.

## 9. Recovery and audit integration

The improved contribution must retain the recovery and audit strengths of URDS without pretending they are already part of the Monitor proof. Add the following controlled tests after the surgical Monitor repair:

| Test | Required interpretation |
|---|---|
| Valid detection followed by trusted restore | `restored_verified`. |
| Restore without trusted baseline | `restored_but_unverified`; never counted as verified success. |
| Corrupted snapshot | Recovery-integrity failure. |
| Tampered ledger block | Audit failure; event remains traceable. |
| Ledger unavailable | Detection outcome remains separate from audit availability. |
| Repair increases benign false positives | Repair is not accepted without an explicit trade-off decision. |
| Repair closes detection witness but breaks recovery | Repair is rejected. |

The repair decision must include recovery and audit fields even when the first finding is Monitor-only. This demonstrates how the governance policy can be extended without claiming that the first experiment already proves full-pipeline novelty.

## 10. External validation

The current result uses one team-written simulator and one team-written detector. The minimum external-validity experiment is one independently implemented reference detector or one external detector interface tested with the same safe prefix and payload vectors.

The comparison should answer:

| Result | Scope conclusion |
|---|---|
| URDS and reference detector both accept unvalidated-format high-entropy payloads | The limitation may be common to entropy/history-based detectors. |
| Only URDS accepts them | The finding supports a URDS-specific architectural claim. |
| Detectors disagree by format or history | Report the policy as system-specific and avoid universal wording. |

Rhea must be engaged as related work, not cited as decoration. Rhea addresses privilege-escalated evasive ransomware, including intermittent and low-entropy behavior, with format-aware validation over mutation snapshots [6]. The URDS contribution is not “format-aware validation exists.” The distinction is the **common governance policy for every evidence-cancelling mitigation**, the explicit treatment of unvalidated claims, and the cost calibration used to decide whether a mitigation may cancel evidence in a local detection-and-recovery architecture.

## 11. Evaluation plan

### 11.1 Primary deterministic evaluation

Run the evidence script across all 20 signature entries before and after the repair.

Acceptance criteria are:

- all 11 unvalidated unique formats no longer receive `benign_compressed` for the fresh high-entropy witness;
- validated benign controls that pass their validator retain their expected benign classification;
- forged validated-format payloads retain structural-mismatch detection;
- the 13 fixed simulator families remain 13/13 detected and restored; and
- all evidence artifacts contain deterministic hashes and no sensitive payload contents.

### 11.2 Benign trade-off evaluation

For each format supported by the intended deployment corpus, collect at least 30 paired benign files or deterministic benign fixtures. Run baseline and repaired policy on the same files. Report the paired confusion table, false-positive delta, validation failures, latency, and resource use.

For binary benign outcomes, use McNemar’s test on paired baseline-versus-repair decisions and report the absolute false-positive change with a 95% confidence interval. The project should not promise zero false positives for unvalidated formats; it should report the trade-off and decide whether a validator or an explicit operator policy is required.

### 11.3 Timing evaluation

For each witness and benign control, use at least five repetitions when timing is a claimed outcome. Report median and interquartile range. Timing is a secondary metric and must not be confused with the primary tooling-availability cost.

### 11.4 Optional adaptive search

Do not implement guided search, Pareto frontiers, or a large `recf_dr/` package for the primary result. Reintroduce them only if the completed mitigation audit leaves a genuinely non-predictable interaction that cannot be derived from source inspection and threshold arithmetic.

If that gate opens, run 30 paired campaigns per method—fixed, random, and guided—using the same seeds and budgets. Use the campaign as the statistical unit. Require a predeclared effect threshold of at least a 20-percentage-point absolute improvement in valid non-predictable discoveries, with a 95% confidence interval excluding zero, before claiming guided-search superiority.

## 12. Time-boxed implementation roadmap

The first three work packages are the complete defensible result. Later packages are extensions and must not block submission of the core contribution.

| Priority | Time box | Work package | Deliverable | Gate |
|---|---:|---|---|---|
| P0 | 0.5–1 day | Freeze baseline and scope | Commit hash, test result, Monitor-only claim boundary | Baseline reproduced. |
| P1 | 1–2 days | Complete mitigation-path inventory | Governance audit table | Every cancellation path mapped. |
| P2 | 1 day | Reproduce multi-format finding | Evidence document and raw JSON report | 11/16 unvalidated-format finding reproduced. |
| P3 | 1–2 days | Implement surgical `None` fail-closed repair | Small classifier patch behind a switch | Decisive witness closes without service crash. |
| P4 | 1–2 days | Add regression and benign controls | Tests for 20 signature entries, fixed families, valid controls | No baseline regression. |
| P5 | 2–3 days | Add explicit mitigation decision record | Container exemption decision with policy version and reason | No hardcoded cancellation bypass remains in the claimed scope. |
| P6 | 2–3 days | Implement tooling-availability calibration | Versioned capability evidence table | Every cost level has a reproducible basis. |
| P7 | 2–3 days | Add recovery/audit failure cases | Controlled failure-injection tests | Recovery and audit affect acceptance decisions. |
| P8 | 3–5 days | External detector comparison | Paired outcome table and scope conclusion | Generalization boundary documented. |
| P9 | 1–2 days | Final thesis and reproducibility package | Report, diagrams, commands, limitations, and review checklist | Every headline claim maps to an artifact. |
| Optional | Only if P9 gate opens | Adaptive RECF-DR extension | Guided search around residual non-predictable interactions | Must not delay the core result. |

## 13. Claim discipline

The final report should use the following claim hierarchy.

| Claim | Allowed status |
|---|---|
| URDS has an unvalidated-container exemption path that treats `None` as sufficient | Supported by source inspection and deterministic evidence. |
| The path affects 11 of 16 unique signature-recognized formats in the current registry | Supported by the registry and evidence script. |
| A positive-validation gate closes the specific bypass | Supported after repair tests pass. |
| Cost-ordered governance is a useful design principle for URDS mitigations | Supported as a system design contribution if policy and tests are complete. |
| The method improves ransomware detection generally | Not allowed without external detector evidence. |
| The method is novel for patent purposes | Requires formal prior-art and legal review; do not state as established fact. |
| Adaptive RECF-DR search is superior to random search | Not allowed unless the optional search gate and statistical plan are completed. |

## 14. Final contribution statement

Use this as the primary thesis/project statement:

> **We introduce a cost-ordered admissibility policy for false-positive mitigations in a unified ransomware detection-and-recovery system. The policy requires every mitigation to justify cancellation of evidence through an auditable comparison between the attacker’s capability to forge the mitigation and the capability to avoid the detection signal. In URDS, a deterministic multi-format analysis exposes an ungoverned container exemption that treats unvalidated format claims as benign explanations of high entropy. A surgical positive-validation repair closes this 11-of-16-format governance gap while preserving validated benign controls, detection coverage, trusted recovery, and auditability.**

RECF-DR is the supporting characterization and calibration workflow. It should not be the headline unless a later experiment demonstrates a residual, non-predictable interaction that genuinely requires adaptive search.

## References

[1]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/detection.py "URDS Monitor detection and container-exemption branch"
[2]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/containers.py "URDS container validator registry"
[3]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/admissibility.py "URDS cost-ordered admissibility implementation"
[4]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/suppression.py "URDS whitelist and training-mode mitigations"
[5]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/scripts/recf_exemption_evidence.py "URDS multi-format exemption evidence script"
[6]: https://arxiv.org/abs/2601.18216 "Rhea: Detecting Privilege-Escalated Evasive Ransomware Attacks Using Format-Aware Validation in the Cloud"
[7]: https://arxiv.org/abs/2603.19204 "Robustness, Cost, and Attack-Surface Concentration in Phishing Detection"
[8]: https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0273804 "MalFuzz: Coverage-guided fuzzing on deep learning-based malware classification model"
