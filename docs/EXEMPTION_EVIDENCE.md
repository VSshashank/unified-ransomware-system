# Evidence Record: URDS Container-Exemption Governance Gap

## Scope and status

This document records a **URDS Monitor-level** result. It does not claim that all ransomware detectors, all archive formats, or the downstream ML/response/recovery layers behave identically.

The result was reproduced from the repository’s current working branch:

```text
branch: feat/admissibility-governance-novelty-v2
base: origin/feat/detection-hardening
```

The evidence harness is [`scripts/recf_exemption_evidence.py`](../scripts/recf_exemption_evidence.py), and its raw report is [`reports/recf_exemption_evidence.json`](../reports/recf_exemption_evidence.json).

## Finding

The current Monitor recognizes **20 signature entries representing 16 unique formats**. The structural validator registry covers five unique offset-zero formats—ZIP, GZIP, PNG, JPEG, and PDF. The separate ISO-BMFF `ftyp` path is not one of those 20 offset-zero signature entries.

The remaining **11 unique signature-recognized formats are unvalidated**:

| Format | Signature entries | Validator in registry | Current fresh high-entropy result |
|---|---:|---:|---|
| ZIP | 3 | Yes | Validator result depends on construction. |
| GZIP | 1 | Yes | Validator result depends on construction. |
| PNG | 1 | Yes | Validator result depends on construction. |
| JPEG | 1 | Yes | Validator result depends on construction. |
| PDF | 1 | Yes | Validator result depends on construction. |
| 7z | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| RAR | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| XZ | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| BZip2 | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| LZ4 | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| Zstandard | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| GIF | 2 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| MP3 | 2 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| OGG | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| FLAC | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |
| RIFF | 1 | No | `container_valid=None`; exemption can return `benign_compressed`. |

The table contains 16 unique formats because ZIP, GIF, and MP3 have duplicate signatures. It contains 20 entries because the evidence harness evaluates every signature entry.

## Code-path cause

`containers.validate_container()` is tri-state:

```text
True  = validator accepted the structure
False = validator rejected the structure
None  = no validator or no definitive result
```

The current `detection.classify()` exemption is effectively:

```python
if high_entropy and container and container_valid is not False and not ransom_ext:
    return verdict_of(False, "benign_compressed", ...)
```

Therefore `None` is accepted in the same branch as `True`. For an unvalidated recognized format, a directly controlled magic prefix is enough to reach the exemption. No parser call, semantic check, or common admissibility decision is required.

The existing whitelist and training-mode suppressions do reach `admissibility.adjudicate()`. The container exemption does not. This is the architectural governance gap.

## Reproduction

From the repository root, run:

```bash
URDS_WRITE_REPORTS=1 \
  python3 scripts/recf_exemption_evidence.py --write-report
```

The script:

1. obtains the detector’s own recognized-signature table;
2. creates deterministic 64 KiB high-entropy payloads in a temporary directory;
3. prefixes each payload with one recognized signature;
4. evaluates `identify_container`, `container_status`, `validate_container`, and `classify`;
5. records hashes, entropy, validator status, verdict, signal, and reason; and
6. deletes the temporary directory automatically.

The script does not start a filesystem watcher, invoke response actions, change production service code, or write a report unless `URDS_WRITE_REPORTS=1` is explicitly set.

## Observed evidence

The recorded run produced:

| Measure | Result |
|---|---:|
| Recognized signature entries | 20 |
| Unique recognized formats | 16 |
| Validated formats in the signature table | 5 |
| Unvalidated formats | **11** |
| Validated entries returning `benign_compressed` | 1 |
| Validated entries returning suspicious | 6 |
| Unvalidated entries returning `benign_compressed` | **13** |
| Unvalidated entries returning suspicious | 0 |
| Payload entropy | Approximately 8.0 bits/byte |
| Path state | Fresh |

The result is deterministic for the recorded payload seed and code state. It is not a prevalence estimate and should not be presented as one.

## The repair is not assumed in advance

A simple candidate repair is:

```diff
- container_valid is not False
+ container_valid is True
```

This is a candidate, not the final success condition. It closes the 11 unvalidated-format path by refusing to treat `None` as positive validation. However, a standard-library construction can produce a syntactically valid container around attacker-controlled content. Therefore positive structural validation alone may not establish benign provenance.

The final repair experiment must compare:

| Arm | Meaning |
|---|---|
| A — Current | Existing exemption behavior. |
| B — Null | Container exemption removed. |
| C — Calibrated repair | Repair selected after capability calibration, including strict handling of unvalidated, incomplete, and equal-cost cases. |

Arm C fails if it continues to accept the validated-format public-primitive witness without an additional provenance, history, or independent-evidence safeguard. The plan is not allowed to certify a repair that preserves the attack it was designed to close.

## Acceptance criteria

The core result is accepted only when all of the following are measured:

- Arm C does not silently return `benign_compressed` for the 11 unvalidated-format witnesses.
- The validated-format public-primitive witness is explicitly evaluated and either closed or documented as a residual limitation requiring an additional safeguard.
- The null Arm B quantifies the false-positive cost of deleting the exemption.
- Selected benign deployment formats remain within the predeclared non-inferiority bound relative to Arm A.
- The 13 fixed simulator families remain detected and restored.
- Recovery verification and audit records remain intact.
- Every repair decision records mitigation ID, validation state, capability levels, policy version, and reason.
- All evidence cases restore exactly and contain no sensitive payload contents.

## Claim discipline

The supported claim is:

> **In the reviewed URDS Monitor implementation, an unvalidated recognized-container claim can cancel high-entropy evidence because `None` is treated as sufficient by a direct exemption branch. A locked capability-search protocol identifies the bypass as directly controllable and provides the basis for selecting and evaluating a conservative repair.**

The evidence does not by itself prove that the repaired policy is universally secure, that other detectors have the same defect, or that the project is legally patentable. Those claims require separate evidence and formal review.

## References

[1]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/detection.py "URDS Monitor decision branch"
[2]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/containers.py "URDS tri-state validator registry"
[3]: https://github.com/VSshashank/unified-ransomware-system/blob/feat/detection-hardening/services/monitor/admissibility.py "URDS admissibility policy"
[4]: https://arxiv.org/abs/2601.18216 "Rhea: format-aware validation for evasive ransomware"
