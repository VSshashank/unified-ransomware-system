# Novelty Position v2: Closed-Form Characterization and Cost Calibration

**Repository:** `VSshashank/unified-ransomware-system`

**Working branch:** `claude/novelty-claim-existing-projects-kau2ng`

**Evidence baseline:** `origin/feat/detection-hardening`, commit `fba11bf5af063b32a49894a1034262d7546492ce`

## Executive decision

The original RECF-DR proposal should be improved again by changing its central question. The first version asked whether a large adaptive search could discover blind spots. That framing is too strong for the current detector because several important outcomes are analytically predictable from `services/monitor/detection.py`.

The improved project should begin with **detector characterization**, not adaptive search:

> **Derive the detector’s evasion regions from its actual thresholds, confirm the important boundaries with a small safe witness set, then use the resulting evidence to calibrate cost-ordered admissibility and design targeted repairs.**

This is not a retreat. It is a stronger and more honest result. It prevents the project from spending a large implementation window on a search problem that may not exist, while still producing a concrete contribution through cost calibration, active recovery/audit constraints, and targeted defensive repair.

The preferred headline should now be **Position B: cost-ordered admissibility with detector-aware cost calibration**. RECF-DR should be presented as the supporting measurement and repair workflow. Position A—RECF-DR as the headline adaptive-search method—should remain a conditional fallback only if a non-predictable, reproducible weakness survives the characterization stage.

## 1. Why adaptive search is not the first step

The current Monitor has explicit threshold-based signals:

| Signal | Condition in the current detector |
|---|---|
| Static entropy | Whole-file entropy `H(x) ≥ 7.5`. |
| Entropy rise | `ΔH ≥ 2.0` and final entropy `H(x) ≥ 7.0`. |
| Partial entropy | At least four measurable blocks, at least 15% of blocks at or above `7.9`, and block-entropy spread at least `2.0`; the rule is used when whole-file entropy is below `7.5` and the container is not structurally valid. |
| Structural mismatch | A recognized container header is structurally invalid while high entropy or partial entropy is present. |
| Ransom extension | The file extension is in the configured ransomware-extension set. |

These conditions are visible in [`services/monitor/detection.py`](https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/detection.py). Therefore some payload modes are not search discoveries; they are threshold consequences.

For example, standard base64 uses at most 64 symbols, so its Shannon entropy is bounded by `log₂(64) = 6` bits per byte. It therefore cannot satisfy the static threshold of `7.5`, the entropy-rise floor of `7.0`, or the high-entropy block threshold of `7.9`, unless a separate signal such as a ransomware extension fires. A byte-position permutation preserves the byte histogram and therefore the whole-file entropy, while its effect on block boundaries remains an interaction to measure. The guaranteed base64 consequence and the histogram-preserving whole-file consequence can be derived before executing the raw 1,152-case product.

A keyed permutation of byte positions is a better transformation than a fixed byte substitution because it represents a real keyed rearrangement rather than a simple frequency-preserving mapping. However, it must be analyzed carefully: whole-file entropy is preserved, but block-level entropy can change when bytes move across block boundaries. It is therefore a valid witness mode, not a guaranteed miss.

The right conclusion is not that every blind spot is analytically known. It is that the **first probe must separate analytically predicted boundary cases from genuinely interaction-dependent cases**. Only the latter can justify an adaptive-search novelty claim.

## 2. Detector characterization before falsification

For a file byte sequence `x`, define `H(x)` as whole-file Shannon entropy, `ΔH(x)` as the rise from the trusted path baseline, `B(x)` as the number of measurable blocks, `q(x)` as the fraction of blocks with entropy at least `7.9`, and `S(x)` as block-entropy spread.

The current detector’s entropy-related decision region can be described as:

```text
static_entropy(x)       := H(x) >= 7.5
entropy_rise(x)         := ΔH(x) >= 2.0 and H(x) >= 7.0
partial_entropy(x)      := B(x) >= 4
                           and q(x) >= 0.15
                           and S(x) >= 2.0
                           and H(x) < 7.5
structural_mismatch(x)  := recognized_container(x)
                           and container_valid(x) is False
                           and (static_entropy(x) or partial_entropy(x))
```

This derivation yields immediate testable boundaries:

| Boundary | Analytical expectation |
|---|---|
| Base64-like full rewrite | Entropy signals should remain below thresholds; extension or unrelated structural conditions may still alert. |
| Full high-entropy rewrite of a 4 KB file | Static entropy can still fire; file size alone does not imply a miss. |
| 5% rewrite of a 4 KB file | Likely remains below static and partial thresholds; it is a useful boundary witness. |
| Partial rewrite below 14–16 KB | May not have four measurable 4 KB blocks, so partial entropy cannot activate. |
| Observed path with large entropy rise | Entropy-rise can fire even when static entropy is below `7.5`, provided final entropy is at least `7.0`. |
| Fresh path with no history | Entropy-rise is unavailable; other signals must carry detection. |
| Valid high-entropy container | Container exemption may apply; entropy-rise is checked before the exemption on an observed path. |
| Magic-only or forged container | Structural mismatch can fire when its entropy prerequisites are met. |

A case is interesting for RECF-DR only if its outcome is not fully explained by these conditions. The probe should therefore report both the observed result and an `analytical_prediction` such as `guaranteed_below_entropy_threshold`, `partial_profile_unavailable`, `history_required`, or `interaction_dependent`.

## 3. Corrected behavior space

The original 1,152-cell product incorrectly treated payload mode and structural validity as independent. A valid format-preserving container cannot simultaneously be broken or merely magic-only. The corrected model records rejected combinations with explicit reasons.

With four payload modes, four payload sizes, four changed fractions, three block patterns, three structural labels, and two history modes, the raw product is 1,152 combinations. The constrained space contains **672 meaningful combinations** before attacker-objective filtering: 576 non-format-preserving combinations with broken or magic-only structure, plus 96 format-preserving combinations with valid structure. The remaining **480 combinations are rejected with reasons**.

The probe now uses a small **20-case witness set** for the first executable characterization and supports `--all` for the full constrained space. The witness set should not be described as a random sample. It is a boundary-covering set selected to include threshold crossings, predicted misses, observed history, fresh history, magic-only structure, and real valid containers.

| Axis | Values | Notes |
|---|---|---|
| Payload mode | Keystream, base64-like, keyed position shuffle, format-preserving valid ZIP | Position shuffle replaces the earlier fixed byte substitution. |
| Payload size | 4 KB, 12 KB, 64 KB, 1 MB | The report must also record final observed file size, especially for valid ZIP cases. |
| Changed fraction | 5%, 10%, 25%, 100% | Must be interpreted together with payload mode and file size. |
| Block pattern | Leading, strided, scattered | Block placement can affect partial entropy even when whole-file entropy is unchanged. |
| Structural validity | Broken, magic-only, valid | Valid is available only through a format-aware construction. |
| Prior history | Fresh path, observed path | Separates entropy-rise behavior from single-reading behavior. |

### 3.1 Attacker-objective validity

A byte change is not automatically a ransomware objective. Every case must record whether the protected content remains usable after transformation. The improved probe uses an application-level checksum in its decoy and stores the original digest in the valid-container manifest. A valid ZIP can therefore remain syntactically valid while the protected report content fails its integrity objective.

The probe must report `attacker_objective_met` separately from `detected`. Cases that merely change bytes without making the protected content fail its declared integrity or usability check are not counted as meaningful attack cases. This prevents the study from manufacturing evasions that no attacker would deploy.

## 4. Characterization probe, not a search framework

The first implementation should remain one script, `scripts/recf_probe.py`. It should not yet include adaptive controllers, Pareto sorting, shadow-repair orchestration, or regression generation.

The probe must:

1. run only in an explicitly supplied dedicated directory;
2. reject non-empty or non-owned targets and unsafe paths;
3. record an ownership manifest and original SHA-256 before mutation;
4. run Monitor-only with `PIPELINE_ENABLED=false` for attribution;
5. observe the detector using the repository’s observer-first ordering;
6. record analytical prediction, observed signal, latency, objective validity, and restoration result;
7. preserve rejected behavior combinations and their reasons in the report; and
8. write `reports/recf_probe_findings.json` only when `URDS_WRITE_REPORTS=1`.

The probe should support:

```bash
python scripts/recf_probe.py --dry-run
python scripts/recf_probe.py --target-dir /tmp/urds-recf-witness
python scripts/recf_probe.py --target-dir /tmp/urds-recf-full --all
python scripts/recf_probe.py --target-dir /tmp/urds-recf-witness --restore
```

A successful case requires both `restore_verified: true` and `attacker_objective_met: true`. A restoration failure is a probe defect or safety failure, not a detector finding.

## 5. Position A: conditional RECF-DR headline

Position A remains possible, but it now has a stricter entry condition. A case may justify adaptive search only when all of the following hold:

| Validity condition | Requirement |
|---|---|
| Reproducibility | The same case reproduces the same detector outcome across repeated runs and seeds where randomness is relevant. |
| Safety | Original bytes restore exactly and the case satisfies the attacker-objective validity check. |
| Observation | Monitor state, event timing, and detector health are complete; infrastructure failure is not misclassified as a miss. |
| Non-predictability | The miss is not derivable solely from the detector threshold constants and declared input features. |
| Technical significance | The case exposes an interaction or boundary that a fixed baseline did not test and that a targeted repair could address. |

If these conditions are met, the headline can be:

> **A detector-aware, recovery-constrained ransomware-resilience workflow that characterizes detector boundaries, searches non-predictable interaction regions, evaluates targeted repairs in shadow, and preserves accepted findings as regression tests.**

The evidence burden remains high. Guided search must be compared with fixed and random baselines under equal budgets. Recovery and audit must alter selection or repair decisions. Results must use repeated seeded campaigns rather than one favorable run.

## 6. Position B: cost-ordered admissibility as the preferred headline

The preferred headline is the cost-ordered admissibility principle already implemented in [`services/monitor/admissibility.py`](https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/admissibility.py):

> **A suppression may cancel a detection only when the cost of forging the suppression is at least as high as the cost of avoiding the detection signal. Otherwise, the evidence is attenuated and the losing rule remains in the audit record.**

This is a better foundation because it has a crisp decision rule in the live URDS path. RECF-DR becomes the offline calibration instrument that estimates real behavior-avoidance costs and checks whether the declared ordinal ordering remains defensible.

### 6.1 Formal cost model

Let `s` be a safe behavior vector and `d(s)` the detector signal that it attempts to avoid. Define an attacker avoidance cost as an ordered tuple rather than an unjustified single scalar:

```text
C_avoid(s) = (
    content_transform_cost,
    application_compatibility_cost,
    changed_data_cost,
    timing_and_persistence_cost,
    operational_complexity_cost
)
```

Let `r` be a suppression rule and `C_forge(r)` the cost of making that rule match an attacker-controlled file or event. Compare costs lexicographically or through a predeclared ordinal mapping. The admissibility decision is:

```text
admit suppression r if C_forge(r) >= C_avoid(s)
otherwise attenuate the suppression and keep the detection alert
```

The cost table must be calibrated offline, versioned, and human-approved. It must not be updated online from attacker-controlled observations. Each calibration record should include the behavior vector, measured effort proxy, variance, environment, detector signal, suppression rule, and resulting admissibility decision.

### 6.2 How Rhea changes the repair claim

Rhea directly addresses the low-entropy, intermittent, and imitation cases that this probe surfaces, using cloud-offloaded mutation snapshots and format-aware validation [6]. Therefore “we add format-aware validation” is not a sufficient novelty claim. The project’s distinction must be explicit:

- Rhea is a ransomware defense architecture centered on replicated snapshots and format-aware validation.
- URDS already contains local structural validators and a trusted recovery/audit path.
- The improved contribution is the cost-ordered admissibility policy, calibrated by safe detector-boundary measurements, and coupled to trusted recovery and tamper-evident audit outcomes.
- Any structural-validation repair must be evaluated as a comparison against Rhea-like capability, not presented as an unprecedented idea.

## 7. Active recovery and audit constraints

Recovery and audit must affect decisions, not merely appear in reports. Add controlled cases for missing trusted baselines, corrupted snapshots, tampered ledger blocks, ledger outages, and repairs that trade detection gains for recovery or audit failures.

| Situation | Required classification |
|---|---|
| File restored without a trusted baseline | `restored_but_unverified`, never verified success. |
| Snapshot content corrupted | Recovery integrity failure. |
| Ledger block edited | Audit failure; not a detector miss. |
| Ledger unavailable during detection | Detection result retained; audit availability separately marked. |
| Repair improves detection but raises benign false positives | Repair rejected or placed lower on the repair frontier. |
| Repair breaks recovery or chain verification | Repair rejected. |

This is essential for Position B as well. A suppression that is admissible only because its cost estimate ignores recovery or audit consequences is not a safe policy.

## 8. Statistical plan if adaptive search is justified

Do not run a large search or claim “guided beats random” until the characterization gate is positive. If it is positive, predeclare the following design:

| Design element | Requirement |
|---|---|
| Methods | Fixed baseline, random search, guided local search. |
| Campaigns | 30 paired campaigns per method using the same 30 seeds and equal case/resource budgets. |
| Primary endpoint | Proportion of campaigns discovering at least one reproducible, non-predictable, attacker-valid miss. |
| Primary test | Paired McNemar test between guided and random discovery outcomes. |
| Effect threshold | At least a 20 percentage-point absolute improvement, with a 95% confidence interval excluding zero. |
| Secondary endpoints | Time-to-first valid miss, unique detector-boundary cases, CPU-seconds per useful finding, and restoration rate. |
| Repair evaluation | Same discovered cases and benign controls for every candidate repair; no case leakage. |
| Negative result | Report zero discoveries with an upper confidence bound; do not convert absence of evidence into universal detector security. |

The statistical unit is the campaign, not the individual mutated file. Treating thousands of correlated cases as independent observations would overstate evidence.

## 9. Revised implementation sequence

The improved scope is intentionally smaller and evidence-gated.

| Stage | Deliverable | Promotion condition |
|---|---|---|
| 1 | Closed-form detector characterization | Threshold derivation reviewed against `detection.py`. |
| 2 | 20-case witness probe | All cases safe, restorable, and attacker-objective-valid. |
| 3 | Constrained full characterization | 672 valid combinations and 480 rejected combinations recorded with reasons. |
| 4 | Cost calibration | Measured avoidance-cost proxies and admissibility outcomes are reproducible. |
| 5 | Targeted repair | One or more repairs evaluated against exact misses, nearby cases, benign controls, recovery, and audit. |
| 6 | Regression fixtures | Approved repair and discovered boundary become deterministic tests. |
| 7 | Optional adaptive RECF-DR | Build only if a non-predictable miss survives Stage 3. |
| 8 | External detector comparison | Run an independently implemented or external reference detector before generalizing claims. |

## 10. Final improved contribution statement

The strongest current statement is:

> **We introduce a detector-aware ransomware-resilience methodology that derives the evasion boundaries of an entropy- and structure-based detector, validates those boundaries with safe attacker-objective-preserving witnesses, measures the operational cost of avoiding each detection signal, and uses those measurements to enforce cost-ordered admissibility while preserving trusted recovery and audit integrity. Validated boundary cases and accepted repairs are retained as reproducible regression tests.**

If the characterization stage discovers a genuinely interaction-dependent weakness that cannot be derived from threshold constants alone, the statement can be extended with the adaptive RECF-DR loop. If it does not, the project should report the negative characterization result and keep adaptive search as future work rather than making a weak novelty claim.

## References

[1]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/detection.py "URDS Monitor detection logic"
[2]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/containers.py "URDS structural container validation"
[3]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/admissibility.py "URDS cost-ordered admissibility"
[4]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/scripts/simulator_sweep.py "URDS fixed simulator sweep"
[5]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/scripts/ransomware_simulator.py "URDS reversible simulator"
[6]: https://arxiv.org/abs/2601.18216 "Rhea: Detecting Privilege-Escalated Evasive Ransomware Attacks Using Format-Aware Validation in the Cloud"
[7]: https://arxiv.org/abs/2606.05252 "From Attack Simulation to SIEM Rule"
[8]: https://arxiv.org/abs/2603.19204 "Robustness, Cost, and Attack-Surface Concentration in Phishing Detection"
[9]: https://link.springer.com/article/10.1007/s00521-022-07096-6 "Evading behavioral classifiers: a comprehensive analysis on evading ransomware detection techniques"
[10]: https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0273804 "MalFuzz: Coverage-guided fuzzing on deep learning-based malware classification model"
[11]: https://trustial.org/publications/continella_shieldfs_2016/continella_shieldfs_2016.pdf "ShieldFS: A Self-healing, Ransomware-aware Filesystem"
