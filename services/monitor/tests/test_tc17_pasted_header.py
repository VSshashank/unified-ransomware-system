"""TC-17 (AS): a pasted header over ciphertext still returns `structural_mismatch`.

Table 9.7 row: *a pasted header over ciphertext still returns
`structural_mismatch`.*

This is the regression guard on the check that already worked. Before structural
validation existed, `spoofer` in `scripts/ransomware_simulator.py` bought the
container exemption for four bytes and went undetected 8 times out of 8. The fix
is `containers`: for the six formats a validator decides, a header with nothing
behind it is FORGED, and FORGED is evidence rather than an explanation.

The row matters most because of what the Phase 6 repair *did* change. The
exemption's other two branches - unvalidated formats, incomplete containers -
were both rewritten, and a policy that changed how FORGED is handled while doing
it would have traded a fixed hole for a new one. Every arm is asserted, including
the null control: deleting the exemption must not delete the evidence either.

The `signal` is asserted and not only the verdict. `structural_mismatch` is
priced MODERATE in the deployed cost table where `static_entropy` is NEGLIGIBLE,
so the two conclusions differ by two rungs in what a suppression is allowed to
cancel. Reaching the right verdict on the wrong signal would let a path whitelist
cancel it.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import containers  # noqa: E402
import synthetic_corpus  # noqa: E402
from _arms import ALL_ARMS, ARM_A, ARM_C, score, write  # noqa: E402

PAYLOAD_BYTES = 120_000

# The six formats a validator decides. A pasted header is only ever detectable
# for these; for the other eleven there is nothing to contradict.
SPOOFED = {
    "zip": (b"PK\x03\x04", "spoofed.zip"),
    "gzip": (b"\x1f\x8b\x08\x00", "spoofed.gz"),
    "png": (b"\x89PNG\r\n\x1a\n", "spoofed.png"),
    "jpeg": (b"\xff\xd8\xff\xe0", "spoofed.jpg"),
    "pdf": (b"%PDF-1.7\n", "spoofed.pdf"),
}


def ciphertext(tag: str, size: int = PAYLOAD_BYTES) -> bytes:
    return hashlib.shake_256(tag.encode()).digest(size)


@pytest.mark.parametrize("fmt", sorted(SPOOFED))
@pytest.mark.parametrize("arm", ALL_ARMS)
def test_tc17_a_pasted_header_is_structural_mismatch_under_every_arm(fmt, arm, tmp_path):
    magic, name = SPOOFED[fmt]
    path = write(tmp_path, name, magic + ciphertext(f"tc17:{fmt}"))

    result = score(path, arm)

    assert result["container_format"] == fmt
    assert result["container_status"] == containers.FORGED
    assert result["container_valid"] is False
    assert result["suspicious"] is True, result["reason"]
    assert result["verdict"] == "suspected_encryption"
    assert result["signal"] == "structural_mismatch", (
        "reaching the right verdict on the wrong signal changes what a "
        "suppression may cancel"
    )
    assert "not there behind it" in result["reason"], result["reason"]


@pytest.mark.parametrize("fmt", sorted(SPOOFED))
def test_tc17_the_simulators_own_spoof_construction_is_caught(fmt, tmp_path):
    """The same four bytes, built the way the simulator builds them.

    `synthetic_corpus.spoof` is what `scripts/ransomware_simulator.py`'s spoofer
    family uses, so this asserts against the attack as it is actually generated
    rather than against a construction written for the test.
    """
    magic, name = SPOOFED[fmt]
    path = write(tmp_path, name, synthetic_corpus.spoof(magic, PAYLOAD_BYTES))

    result = score(path, ARM_A)

    assert result["suspicious"] is True
    assert result["signal"] == "structural_mismatch"


def test_tc17_the_genuine_article_is_not_flagged(tmp_path):
    """The control. A real file of each format stays benign under Arm A and C.

    Without this the rows above are satisfied by flagging every file that has a
    magic number, which is what the exemption exists to avoid.
    """
    builders = {
        "real.zip": synthetic_corpus.build_zip,
        "real.gz": synthetic_corpus.build_gzip,
        "real.png": synthetic_corpus.build_png,
        "real.jpg": synthetic_corpus.build_jpeg,
        "real.pdf": synthetic_corpus.build_pdf,
    }
    for name, builder in builders.items():
        path = write(tmp_path, name, builder(PAYLOAD_BYTES))
        for arm in (ARM_A, ARM_C):
            result = score(path, arm)
            assert result["container_status"] != containers.FORGED, (name, arm)
            assert result["signal"] != "structural_mismatch", (name, arm)


def test_tc17_a_ransom_extension_does_not_change_the_signal(tmp_path):
    """Both signals present, and the stronger one is what is reported.

    `structural_mismatch` costs MODERATE to avoid and `ransom_extension` costs
    NEGLIGIBLE. If a renamed file downgraded the signal, appending `.locked`
    would make an alert *easier* for an operator rule to cancel - the opposite of
    what a second piece of evidence should do.
    """
    path = write(tmp_path, "spoofed.zip.locked", b"PK\x03\x04" + ciphertext("tc17:ext"))
    result = score(path, ARM_C)

    assert result["ransom_extension"] is True
    assert result["signal"] == "structural_mismatch"
    assert result["suspicious"] is True
