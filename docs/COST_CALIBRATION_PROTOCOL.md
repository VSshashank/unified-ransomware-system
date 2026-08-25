# Cost Calibration Protocol for URDS Mitigation Governance

## Purpose

This protocol defines how URDS will measure the attacker capability required to forge a false-positive mitigation or avoid a detection signal. It is the primary methodological contribution proposed for the project. The URDS Monitor and its container-exemption defect are the case study.

The protocol must be run **before** the repair is designed. A repair cannot be justified by a cost table that was assigned after observing which repair the team preferred.

## Scope

The protocol covers the URDS Monitor’s evidence-cancellation and suppression paths:

- content-hash whitelist;
- path whitelist;
- training-mode ceiling;
- container exemption;
- structural validation state;
- path-history-dependent entropy rise; and
- any new mitigation discovered by the source audit.

The ML, response, recovery, and ledger layers are not silently included in the Monitor claim. They receive a separate extension protocol if the final report claims full-pipeline governance.

## Definitions

A **detection signal** is an evidence condition emitted by the Monitor, such as `static_entropy`, `entropy_rise`, `partial_entropy`, or `structural_mismatch`.

A **mitigation** is any condition that can suppress, cancel, attenuate, downgrade, or prevent action on suspicious evidence. A mitigation includes both explicit suppressions, such as a path whitelist, and implicit exemptions, such as `benign_compressed`.

A **strategy** is a reproducible sequence of attacker-controlled operations applied to a declared fixture. A strategy is not valid merely because it changes bytes. It must satisfy the attacker objective and the fixture’s integrity/usability test.

An **attacker-valid strategy** must meet all of the following conditions:

1. It is executable with the declared attacker capabilities and no unrecorded operator assistance.
2. It makes the protected content fail the declared application-level integrity or usability test.
3. It preserves the structural status claimed by the behavior vector, or records the result as broken or incomplete rather than valid.
4. It does not rely on a test-harness failure, missing observation, or failed restoration.
5. Its command, tool version, input, output hash, and license/source evidence are recorded.

## Primary capability scale

The primary scale is a discrete capability ladder based on tooling availability. It is not a currency and does not assume that the difference between adjacent levels is equal.

| Level | Name | Evidence standard |
|---:|---|---|
| 0 | Direct byte/path control | A standard file write, rename, path selection, or magic-prefix operation is sufficient. |
| 1 | Public primitive | A standard-library call, installed command, or mature public package performs the operation without format-specific adaptation. |
| 2 | Format-aware capability | The attacker must integrate a format specification, parser, encoder, or semantic validator and satisfy format-specific invariants. |
| 3 | New engineering or privileged capability | The capability requires material new implementation, unavailable privileges, or a system capability outside the declared threat model. |
| 4 | Secret/preimage capability | The capability requires an unavailable secret, cryptographic preimage, or protected signing/key material. |

The protocol records the lowest level supported by reproducible evidence. If a standard-library call is enough, the result cannot be described as requiring novel format engineering merely because the output is sophisticated.

## Locked search procedure

For every strategy, perform the following search in order and save the result:

1. Search the Python standard library and installed system utilities.
2. Search the project’s approved package index and installed packages.
3. Search public repositories and official package documentation.
4. Search the academic and technical literature.
5. Record the exact command, version, URL, license, required inputs, and whether the method worked on the declared fixture.
6. Assign the lowest capability level for which the evidence is reproducible.
7. Have a second reviewer independently repeat the search from the recorded protocol.

The search log is part of the evidence. A prose claim that “this requires a format encoder” is not sufficient when `gzip.compress()` or `zipfile.ZipFile(..., ZIP_STORED)` performs the relevant operation.

## Cost objects and tie handling

For a signal `s`, define:

```text
C_avoid(s) = the lowest capability level among valid strategies that avoid s
```

For a mitigation `m`, define:

```text
C_forge(m) = the lowest capability level among valid strategies that make m match
```

The policy must not authorize equality by default. Use a margin rule:

```text
admit m only if C_forge(m) > C_avoid(s)
otherwise attenuate m or require independent evidence
```

The strict inequality is necessary because equal capability levels do not establish that the mitigation is harder to forge than the evidence is to avoid. For example, if both a container exemption and an entropy-avoidance strategy are achievable with one public standard-library primitive, `1 > 1` is false; the mitigation cannot cancel the evidence on cost alone.

If multiple cost dimensions remain relevant, retain a vector alongside the primary level:

```text
C(v) = (
    capability_level,
    adaptation_steps,
    required_information,
    resource_cost,
    persistence_requirement
)
```

The primary governance comparison uses capability level and strict margin. The remaining dimensions are reported as secondary evidence and used to resolve or explain incomparable cases. They must not be used to invent a total order after seeing the result.

## Calibration examples for the current finding

| Operation | Expected lowest level | Reason |
|---|---:|---|
| Prefix attacker-controlled ciphertext with a recognized magic value | 0 | Direct byte control is sufficient. |
| Encode attacker-controlled bytes with base64 | 1 | Public standard-library primitive. |
| Produce a syntactically valid ZIP/GZIP container | 1 | Public standard-library primitive for the tested construction. |
| Produce a semantically acceptable application file with changed protected content | 2 unless a public primitive already does so | Requires application-level format/provenance constraints. |
| Forge an approved SHA-256 whitelist preimage | 4 under the declared threat model | Requires a cryptographic preimage. |

These measurements do not automatically prove that a valid container is malicious. They prove that **structural validity alone is not a high-cost signal**. The policy must therefore distinguish structural validation from content provenance and avoid admitting a mitigation on a cost tie.

## Calibration output schema

Each record must contain:

```json
{
  "record_id": "stable identifier",
  "target": "avoidance or forgery",
  "signal_or_mitigation": "static_entropy or container_exemption",
  "strategy_description": "human-readable description",
  "attacker_objective": "declared objective identifier",
  "capability_level": 1,
  "tool": "python standard library",
  "tool_version": "3.x",
  "command_or_api": "exact invocation",
  "source_url": "documentation or repository URL",
  "license": "license or standard-library status",
  "required_information": "source knowledge, path history, etc.",
  "resource_measurements": {
    "cpu_seconds": 0.0,
    "memory_bytes": 0,
    "bytes_changed": 0
  },
  "validity": "attacker_valid | mutation_control | invalid | safety_failure",
  "output_sha256": "hash",
  "reviewer_reproduction": true,
  "policy_version": "cost-policy-v1"
}
```

## Policy decision record

Every mitigation decision must retain:

```text
mitigation_id
matched
validation_state
present_signals
unavailable_signals
C_forge
C_avoid
margin_rule
admitted
outcome: cancelled | attenuated | deferred | not_applicable
policy_version
reason
recovery_impact
audit_impact
```

The `unavailable_signals` field is required. A fresh path is not evidence that entropy did not rise; it is evidence that entropy-rise history was unavailable.

## Falsification criteria

The cost-calibration contribution is falsified or weakened if any of the following occurs:

- a lower-level valid strategy is found after the policy table is frozen and the protocol did not provide a way to record it;
- two independent reviewers cannot reproduce a claimed capability level;
- the policy admits a mitigation when `C_forge == C_avoid` without an explicitly documented independent-evidence exception;
- the repair decision depends on an undocumented subjective weight;
- the protocol produces a result that changes when the reviewer knows which repair the team prefers; or
- the measured policy decision does not alter the treatment of the demonstrated container-exemption witness.

## Interpretation

This protocol does not claim that the capability ladder is a universal measure of attacker cost. It claims that the project can replace undocumented cost assertions with a locked, reproducible capability search and a conservative tie rule. The result is a defensible method for governing security exceptions, with URDS as the case study.
