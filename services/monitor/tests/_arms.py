"""Scoring one file under one container-exemption policy - shared by TC-14…TC-19.

Not a test module. `classify` takes eight arguments that all have to agree with
each other, and a regression test that assembled them slightly differently from
`app.handle_event` would be testing its own assembly. This is the one place they
are assembled, and it mirrors `app._detect` exactly.

The policies are the experiment arms of `scripts/three_arm_experiment.py`:

    ARM_A   legacy                          the deployed default
    ARM_B   off                             the null control, exemption deleted
    ARM_C1  strict-unvalidated              the repair without its ratio clause
    ARM_C   strict-unvalidated+ratio        the selected repair
    ARM_D   strict-unvalidated+ratio+inner  the post-hoc refinement

Table 9.7's rows are written against Arm C, so that is what these tests assert
against unless a row names another arm. Arm A is asserted alongside wherever the
deployed default differs, because the repair does not ship - D5 fired at 100.0 pp
against a 15.0 pp tolerance - and a test that only checked Arm C would read as if
it did.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import containers  # noqa: E402
import detection  # noqa: E402

ARM_A = detection.CONTAINER_POLICY_LEGACY
ARM_B = detection.CONTAINER_POLICY_OFF
ARM_C1 = detection.CONTAINER_POLICY_STRICT
ARM_C = detection.CONTAINER_POLICY_RATIO
ARM_D = detection.CONTAINER_POLICY_INNER

ALL_ARMS = (ARM_A, ARM_B, ARM_C1, ARM_C, ARM_D)


def score(path: Path, policy: str = ARM_C, entropy_delta: float | None = None) -> dict:
    """One file, one policy, through the same calls `app._detect` makes."""
    size = path.stat().st_size
    head, tail = detection.sample_file(str(path), size)
    entropy, statistics = detection.measure(head)
    magic = detection.read_magic(str(path))
    fmt = detection.identify_container(magic)
    status = containers.container_status(head, tail, fmt, size)

    verdict = detection.classify(
        str(path),
        entropy,
        magic,
        detection.DEFAULT_ENTROPY_THRESHOLD,
        readable=True,
        entropy_delta=entropy_delta,
        container_valid=containers.tristate(status),
        statistics=statistics,
        compression=containers.compression_evidence(head, tail, fmt, size),
        inner_content=containers.inner_content_evidence(head, tail, fmt, size),
        policy=policy,
        container_status=status,
    )
    return {**verdict, "container_status": status, "size": size}


def write(directory: Path, name: str, payload: bytes) -> Path:
    path = directory / name
    path.write_bytes(payload)
    return path
