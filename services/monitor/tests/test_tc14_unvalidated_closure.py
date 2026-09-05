"""TC-14 (AS): the eleven unvalidated formats, closed under Arm C.

Table 9.7 row: *each of the 11 unvalidated formats, given a fresh high-entropy
attacker-valid payload, does not return a silent `benign_compressed` under Arm C.*

"Attacker-valid" is the whole point. The registry recognises seventeen container
names and `containers._VALIDATORS` decides six of them, so for eleven the answer
to "is this really a RAR?" is `None` - no validator exists. Under the deployed
`legacy` policy that `None` is read as an explanation, and the exemption fires on
the header alone. `scripts/capability_calibration.py` measured what that costs an
attacker: one statement, and on the plan's §5.2 ladder it is Level 0, the same
rung as choosing a filename.

The list of eleven is derived here rather than written down, so a format added to
the registry without a validator is caught by this test rather than by a reader
noticing the count no longer says eleven.

Arm A is asserted alongside Arm C on purpose. **The repair does not ship** - D5
fired at 100.0 pp against a 15.0 pp tolerance and `CONTAINER_EXEMPTION_POLICY`
still defaults to `legacy` - so a test that only proved the closure would leave a
reader thinking the deployed system has it.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import containers  # noqa: E402
import detection  # noqa: E402
from _arms import ARM_A, ARM_C, score, write  # noqa: E402

PAYLOAD_BYTES = 120_000


def _registry_formats() -> list[str]:
    """Every container name `identify_container` can return, in registry order."""
    names: list[str] = []
    for _signature, name in detection._CONTAINER_SIGNATURES:
        if name not in names:
            names.append(name)
    names.append("iso-bmff")  # ftyp sits at offset 4, so it is matched separately
    return names


def _first_magic(name: str) -> bytes:
    for signature, candidate in detection._CONTAINER_SIGNATURES:
        if candidate == name:
            return signature
    raise AssertionError(f"no signature in the registry for {name}")


UNVALIDATED = [n for n in _registry_formats() if n not in containers.VALIDATED_FORMATS]


def ciphertext(tag: str, size: int = PAYLOAD_BYTES) -> bytes:
    """Uniform bytes, deterministic per tag. shake_256 is a stand-in for AES-CTR."""
    return hashlib.shake_256(tag.encode()).digest(size)


def test_tc14_the_registry_still_has_exactly_eleven_unvalidated_formats():
    """The count every claim in this project is written against.

    If this fails, either a validator was added - in which case the eleven-format
    finding is narrower than the write-up says - or a format was registered
    without one, and the finding is wider. Both matter and neither should be
    discovered by reading a report.
    """
    assert len(UNVALIDATED) == 11, UNVALIDATED
    assert sorted(UNVALIDATED) == [
        "7z",
        "bzip2",
        "flac",
        "gif",
        "lz4",
        "mp3",
        "ogg",
        "rar",
        "riff",
        "xz",
        "zstd",
    ]
    assert len(containers.VALIDATED_FORMATS) == 6


@pytest.mark.parametrize("fmt", UNVALIDATED)
def test_tc14_an_unvalidated_format_is_not_silently_benign_under_arm_c(fmt, tmp_path):
    """The row itself: header + ciphertext, and Arm C must not clear it."""
    payload = _first_magic(fmt) + ciphertext(f"tc14:{fmt}")
    path = write(tmp_path, f"payload_{fmt}.bin", payload)

    result = score(path, ARM_C)

    assert result["container_format"] == fmt, "the registry no longer identifies this"
    assert result["container_status"] == containers.UNVALIDATED
    assert result["verdict"] != "benign_compressed", result["reason"]
    assert result["suspicious"] is True, result["reason"]
    assert result["signal"] == "static_entropy"
    # The reason has to name the gap, not just refuse. An operator reading
    # "suspicious" with no cause cannot tell this from any other alert.
    assert "no structural validator" in result["reason"]


@pytest.mark.parametrize("fmt", UNVALIDATED)
def test_tc14_the_deployed_default_still_clears_all_eleven(fmt, tmp_path):
    """Arm A, which is what ships. This is the finding, not a regression.

    Recorded so the closure above is never read as a property of the running
    system. `CONTAINER_EXEMPTION_POLICY` defaults to `legacy`, and under `legacy`
    every one of these eleven is `benign_compressed` for the price of the header.
    """
    payload = _first_magic(fmt) + ciphertext(f"tc14:{fmt}")
    path = write(tmp_path, f"payload_{fmt}.bin", payload)

    result = score(path, ARM_A)

    assert result["verdict"] == "benign_compressed"
    assert result["suspicious"] is False
    assert detection.DEFAULT_CONTAINER_POLICY == ARM_A, (
        "the repair has started shipping; D5's ruling in "
        "docs/PHASE6_COMPLETION_REPORT.md says it must not, and this test is the "
        "record of that"
    )


def test_tc14_the_closure_is_not_a_blanket_alert_on_every_container(tmp_path):
    """Arm C must still clear a real archive, or it is not a repair.

    The failure mode this rules out is the one that makes the row trivial: a
    policy that flags every unvalidated header would pass the eleven rows above
    and be useless. A genuine gzip of compressible content stays benign.
    """
    import gzip

    prose = (b"quarterly deployment report, section body text. " * 4000)[:PAYLOAD_BYTES]
    path = write(tmp_path, "genuine.gz", gzip.compress(prose))

    result = score(path, ARM_C)

    assert result["suspicious"] is False, result["reason"]
    assert result["container_status"] == containers.VALID
