# Improved Plan: Cost-Ordered Admissibility as the URDS Contribution

## Executive decision

The project should stop planning around Position A—RECF-DR as an adaptive-search headline. The first real finding was obtained by reading the detector’s decision branches, not by discovering a non-obvious search path. That means the main research problem is not “can guided search beat random search?” for the current entropy-derived detector. The stronger direction is **governance of false-positive mitigations through measured attacker cost**.

The revised contribution is:

> **Every false-positive mitigation in a ransomware detector must be governed by a common cost-ordering policy: a mitigation may cancel evidence only when the attacker’s cost to forge that mitigation is at least as high as the attacker’s cost to avoid the detection signal. The costs are calibrated offline from safe, reproducible behavior measurements, and the policy preserves recovery and audit integrity.**

RECF-DR is retained, but demoted to the **measurement and calibration instrument**. It characterizes detector boundaries, measures avoidance costs, exposes ungoverned mitigation paths, evaluates targeted repairs, and creates regression evidence. It is no longer presented as a generic search framework that is assumed to produce novel blind spots.

## 1. The architectural finding

The current URDS architecture contains two classes of false-positive mitigation.

The first class is governed. Whitelist and training-mode matches are passed to `admissibility.adjudicate()`, where the forgery cost of the suppression is compared with the avoidance cost of the detector signal. If the suppression is cheaper to forge, it is attenuated and the alert remains visible; the losing rule is recorded rather than silently discarded.

The second class is not governed. The container exemption is a hardcoded branch in `detection.classify()`. When a file has high entropy and a recognized container that is not structurally forged, the classifier can return `benign_compressed` without routing that exemption through the admissibility policy. `AVOIDANCE_COST` contains entries for detection signals such as `static_entropy`, `structural_mismatch`, `partial_entropy`, and `entropy_rise`, but there is no explicit policy object for the container exemption itself.

This creates a specific architectural claim:

> **URDS applies cost-ordered governance to some false-positive mitigations but not to all of them. The ungoverned container exemption can accept a high-entropy valid container on a fresh path because entropy-rise history is unavailable and the exemption bypasses the common admissibility decision point.**

The claim is more valuable than a generic statement that the detector has a ZIP hole. It generalizes the hardening pattern already present in the repository: trust should be determined by the cost of forgery and avoidance, not by the mere presence or recency of an apparently benign condition.

## 2. Immediate implementation objective

Before building any adaptive RECF-DR package, complete a **false-positive mitigation governance audit**. The audit should enumerate every code path that can convert suspicious evidence into a benign result, suppress an alert, lower its severity, or prevent response.

| Mitigation path | Current location | Reaches common adjudication? | Required action |
|---|---|---:|---|
| Content-hash whitelist | `services/monitor/suppression.py` | Yes, with a high forgery cost | Retain; verify exact-hash semantics and audit fields. |
| Path whitelist | `services/monitor/suppression.py` | Yes | Retain; test against every detection signal. |
| Training-mode ceiling | `services/monitor/suppression.py` | Yes | Retain; test dwell, structure, history, and poisoning boundaries. |
| Container exemption | `services/monitor/detection.py` | **No** | Route through an explicit mitigation-policy decision or make its precedence explicit and audited. |
| Benign low-entropy fall-through | `services/monitor/detection.py` | Not a suppression match | Record as a negative detector outcome when the test harness expects malicious objective validity. |
| Unreadable-file handling | `services/monitor/detection.py` | Not a suppression match | Keep as a separate evidence state; never classify unreadable as benign without evidence. |
| Operator whitelist/training API updates | `services/monitor/app.py` and Gateway | Indirectly | Audit authorization, change logging, and policy-version correlation. |

The first implementation milestone is not to force all paths into one function mechanically. It is to identify the semantic difference between **a detector signal not firing** and **a mitigation actively canceling a signal**, then give every cancellation path a policy record.

## 3. Revised policy model

### 3.1 Separate evidence formation from evidence governance

The detector should first produce an evidence set rather than immediately returning a benign or suspicious verdict. For example:

```text
Evidence {
    static_entropy: observed or absent,
    entropy_rise: observed or absent,
    partial_entropy: observed or absent,
    structural_mismatch: observed or absent,
    ransom_extension: observed or absent,
    container_exemption_candidate: observed or absent,
    path_history: fresh or observed,
    structural_status: valid, forged, incomplete, unknown
}
```

The policy layer then evaluates which mitigation, if any, may reduce or cancel that evidence. This prevents a hardcoded exemption from bypassing the same governance model used by whitelist and training mode.

### 3.2 Represent mitigation decisions explicitly

Add a decision record with the following fields:

```text
MitigationDecision {
    mitigation_id,
    matched,
    evidence_signals,
    attacker_forgery_cost,
    attacker_avoidance_cost,
    admitted,
    outcome: cancelled | attenuated | not_applicable,
    policy_version,
    reason,
    recovery_impact,
    audit_impact
}
```

The existing `admissibility.adjudicate()` function can remain compatible initially, but it should accept a typed mitigation/evidence record rather than only one detector signal. That is necessary for the subtle case where a stronger signal **could** have fired but did not because the path was fresh. A state-blind comparison of only the signal that happened to fire is insufficient.

### 3.3 Govern the container exemption without blindly admitting it

The container exemption should not simply be added to `adjudicate()` with a negligible cost and automatically admitted. That would preserve the problem. The policy must represent the exemption as a mitigation that claims:

```text
container_exemption := “the high entropy is explained by a valid format”
```

Its admissibility should require evidence proportional to the claim:

- structural validation must succeed, not merely a magic header;
- the path/history state must be visible;
- no independent replacement evidence may exist;
- the content must satisfy the supported format’s integrity/semantic checks where feasible;
- the exemption decision must be logged and versioned; and
- if the path is fresh and no replacement evidence is available, the outcome should be `benign_unverified` or `deferred`, not silently equivalent to a trusted benign classification.

The exact runtime policy should be selected through tests and threat-model review. The contribution is the **governance boundary and explicit decision record**, not an arbitrary threshold change.

## 4. Formal cost-measurement protocol

The existing ordinal constants are a useful starting hypothesis, but they are not yet a measurement methodology. The revised plan must define what is measured and what is only declared.

### 4.1 What not to use as cost

Do not use lines of code, developer hours, or an unbounded subjective score. They are too easy to manipulate and do not represent the attacker’s operational burden. Do not claim that a cost table is empirically calibrated merely because a few values were assigned after observing two cases.

### 4.2 Observable cost components

Measure attacker cost using reproducible proxies tied to the safe behavior vector:

| Cost component | Measurement proxy | Interpretation |
|---|---|---|
| Content transformation | Fraction of bytes changed; number of modified blocks; number of writes | How much data the attacker must transform. |
| Format compatibility | Whether a valid parser/validator accepts the result; number of format-specific constraints satisfied | Work required to preserve an apparently legitimate format. |
| Timing/persistence | Delay duration, number of rounds, required pre-observation dwell | Operational patience and persistence required. |
| Namespace/path cost | Rename, recreate, new path, extension change, directory access | Cost of abandoning a familiar path or changing metadata. |
| Computation | CPU time and memory for the transformation | Resource burden of the evasion. |
| Information requirement | Need for detector source knowledge, history knowledge, or a suppression secret/preimage | Attacker knowledge and capability. |
| Recovery impact | Changed bytes, restore success, trusted-hash match | Whether the evasion causes recoverable or unrecoverable damage. |

These proxies should not automatically be collapsed into a scalar. Preserve the vector and use a declared comparison policy.

### 4.3 Use partial orders before scalarization

A lexicographic order is too strong unless justified because it declares that any amount of one dimension dominates every amount of another. The first implementation should use a **partial order**:

```text
x dominates y iff:
    x is no easier for the attacker on every declared cost dimension, and
    x is strictly harder on at least one dimension.
```

If two strategies are incomparable, retain both and report the trade-off. Only use a scalar operator score as a secondary presentation layer, with weights declared before evaluation.

For suppression governance, the policy should compare the minimum attacker strategy needed to avoid the active evidence with the minimum strategy needed to forge the mitigation. If multiple strategies exist, use the attacker’s cheapest valid strategy, not the cost of a hand-picked strategy:

```text
C_avoid(signal) = min C(strategy)
                  over valid strategies that avoid signal

C_forge(mitigation) = min C(strategy)
                      over valid strategies that make mitigation match
```

A mitigation is admissible only when the forgery strategy is not cheaper than the avoidance strategy under the declared partial order. Incomparable cases should fail closed or require review, not be silently admitted.

### 4.4 Calibration protocol

For each signal/mitigation pair, run a locked set of valid behavior vectors with at least five repetitions per vector where timing or system noise matters. Record medians and interquartile ranges for measurable dimensions. Keep the cost policy versioned and update it offline through review; never learn policy costs online from attacker-controlled events.

The output should be a calibration table containing the strategy, detector signal, mitigation, raw measurements, validity status, cost vector, policy decision, and reviewer approval.

## 5. Corrected probe requirements

The current probe should be retained as a characterization tool, but its role must be changed in the documentation and output.

It must:

1. include the decisive `format_preserving × 100% × valid × fresh` witness;
2. distinguish valid, magic-only, and broken structural constructions;
3. record rejected combinations and rejection reasons;
4. use keyed position shuffling rather than a fixed byte substitution;
5. record whether the attacker objective is actually achieved;
6. record an analytical prediction for each case;
7. classify a miss as policy-relevant only when it is not fully explained by threshold arithmetic;
8. verify byte-for-byte restoration for every case; and
9. preserve the current safety and `PIPELINE_ENABLED=false` attribution contract.

The first run should use a small witness set. The constrained full space can be enumerated later for coverage, but it must not be confused with a search discovery.

## 6. Targeted repair experiment

The first repair should address the ungoverned container exemption. Do not begin with a generic ensemble model or a large ML retraining effort. Implement two policy variants in shadow:

| Variant | Description |
|---|---|
| Baseline | Existing hardcoded container exemption. |
| Governed exemption | Container exemption emits an explicit mitigation decision with structural validity, path history, independent evidence, policy version, and audit outcome. |
| Strict fresh-path policy | A valid container on a fresh path is not silently treated as trusted benign without an additional evidence condition. |

Test every variant against:

- the decisive valid-container fresh-path witness;
- the same valid container on an observed path;
- forged magic-only containers;
- genuinely valid benign ZIP/PDF/PNG/JPEG files;
- high-entropy legitimate compression/encryption workloads;
- all thirteen fixed simulator families; and
- controlled missing-baseline, ledger-tamper, and recovery-failure cases.

The repair is successful only if it closes the witness while preserving benign-container behavior and trusted recovery/audit semantics.

## 7. External validity plan

The current evidence uses one team-written simulator against one team-written detector. The cheapest credibility improvement is an independent reference detector implemented separately from the production detector, or one external detector with an accessible interface and permitted testing terms.

The external comparison should use the same safe behavior vectors and report only metadata and outcomes. Its purpose is not to claim that the external detector is a universal ground truth. It is to distinguish a URDS-specific governance flaw from a general weakness of entropy-derived detection.

Report three possible outcomes:

| Outcome | Interpretation |
|---|---|
| Both detectors accept the same fresh valid-container witness | The issue may be a broader entropy/history limitation. |
| Only URDS accepts it | The issue supports a URDS-specific architectural claim. |
| Detectors disagree across cases | The governance and cost model must be reported as system-specific, not universal. |

## 8. Evaluation and statistical plan

Because the primary contribution is governance rather than guided search, the central unit of evaluation is the **signal/mitigation pair**, not the number of generated cases.

### Primary endpoints

The primary endpoints should be:

1. number of false-positive mitigation paths identified;
2. number of mitigation paths governed by the common policy before and after the change;
3. number of reproducible policy violations or ungoverned acceptances;
4. closure rate of the decisive witness;
5. benign-workload false-positive change; and
6. recovery and audit integrity preservation.

### Statistical requirements

For repeated timing measurements, use at least five repetitions per case and report median and interquartile range. For repair comparisons, use paired cases across baseline and repair variants. For external-detector comparisons, report a paired outcome table rather than treating cases as independent random samples.

If the project later reintroduces guided search, use 30 paired campaigns per method and the same seeds. Use the campaign—not the individual case—as the statistical unit. A guided-search claim should require at least a 20-percentage-point absolute improvement in the proportion of campaigns finding a valid non-predictable weakness, with a 95% confidence interval excluding zero. Otherwise report the result as inconclusive.

## 9. Implementation sequence for the remaining project window

| Order | Work package | Stop/continue gate |
|---|---|---|
| 1 | Audit all mitigation paths and evidence-cancellation branches | Complete inventory with call-site coverage. |
| 2 | Add the decisive valid-container fresh-path witness | Witness reproduces safely and restores exactly. |
| 3 | Separate evidence formation from mitigation governance | Every cancellation produces a typed decision record. |
| 4 | Add multi-signal/state-aware policy evaluation | Fresh history and unavailable evidence are visible to policy. |
| 5 | Implement partial-order cost vectors and offline calibration artifacts | Costs are reproducible and incomparable cases fail closed. |
| 6 | Evaluate governed container exemption in shadow | Witness closes without benign-container regressions. |
| 7 | Add failure-injection tests for recovery and audit | Recovery/audit affect policy outcomes. |
| 8 | Run independent detector comparison | Scope of claim is established. |
| 9 | Generate regression fixtures and update paper/thesis | Every claimed improvement is replayable. |
| 10 | Optional: adaptive RECF-DR search | Only if a non-predictable interaction remains after characterization. |

## 10. Final contribution statement

The project should lead with governance, not framework size:

> **URDS introduces a cost-ordered admissibility policy for false-positive mitigations. The policy compares the least attacker cost required to forge a mitigation with the least cost required to avoid the detection evidence, preserves ambiguous or weaker suppressions through attenuation and audit, and accounts for path history, trusted recovery, and ledger integrity. A detector-aware characterization study exposes an existing ungoverned container exemption, and a shadow policy repair closes the resulting fresh-path acceptance without sacrificing valid benign-container behavior.**

RECF-DR remains the supporting workflow for safe characterization, cost measurement, targeted repair, and regression preservation. This positioning is narrower than the original proposal, but it is more defensible, less vulnerable to an obviousness-by-aggregation objection, and achievable within a constrained project window.

## References

[1]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/admissibility.py "URDS cost-ordered admissibility implementation"
[2]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/detection.py "URDS detector decision branches"
[3]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/suppression.py "URDS whitelist and training-mode mitigations"
[4]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/containers.py "URDS format and structural validation"
[5]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/scripts/recf_probe.py "URDS detector-characterization probe"
[6]: https://arxiv.org/abs/2601.18216 "Rhea: Detecting Privilege-Escalated Evasive Ransomware Attacks Using Format-Aware Validation in the Cloud"
[7]: https://arxiv.org/abs/2603.19204 "Robustness, Cost, and Attack-Surface Concentration in Phishing Detection"
[8]: https://arxiv.org/abs/2606.05252 "From Attack Simulation to SIEM Rule"
[9]: https://link.springer.com/article/10.1007/s00521-022-07096-6 "Evading behavioral classifiers: a comprehensive analysis on evading ransomware detection techniques"
[10]: https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0273804 "MalFuzz: Coverage-guided fuzzing on deep learning-based malware classification model"
