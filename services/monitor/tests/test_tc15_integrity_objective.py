"""TC-15 (AS): a genuine container that carries content failing its own objective.

Table 9.7 row: *a `gzip.compress` / `ZIP_STORED` container carrying content that
fails its integrity objective is evaluated explicitly - closed, or recorded as an
accepted residual limitation.*

This is the witness the plan calls "validated public-primitive" in §8.1, and it
is the one that makes `container_valid is True` insufficient as a repair. The
archive is real: `gzip.compress` produces a stream that inflates, `zipfile`
produces framing that walks. Every structural check passes, because the attacker
used the standard library rather than pasting a header. `capability_calibration`
measured that at one statement and no dependencies - Level 1 on the plan's
ladder, the rung §5.3 names outright.

What the archive *fails* is the objective the format exists for. A compressor
that emits more bytes than it consumed has compressed nothing, and a `ZIP_STORED`
member never claimed to. The ratio clause reads exactly that and nothing else,
which is why it closes the row and why C1 - the same repair without the clause -
does not.

Both outcomes the row allows are asserted: closed under Arm C, and the residual
recorded under Arm C1.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import containers  # noqa: E402
from _arms import ARM_A, ARM_C, ARM_C1, score, write  # noqa: E402

PAYLOAD_BYTES = 120_000


def ciphertext(tag: str, size: int = PAYLOAD_BYTES) -> bytes:
    return hashlib.shake_256(tag.encode()).digest(size)


def zip_of(payload: bytes, name: str, method: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=method) as archive:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = method
        info.create_system = 0
        archive.writestr(info, payload)
    return buffer.getvalue()


CASES = {
    # gzip.compress on incompressible input: the DEFLATE stream is real and
    # inflates, and it is 0.05% larger than what went in.
    "gzip_of_ciphertext.gz": lambda: gzip.compress(ciphertext("tc15:gzip")),
    # ZIP_STORED never compresses. The framing is genuine; the member is not
    # transformed at all.
    "zip_stored_ciphertext.zip": lambda: zip_of(
        ciphertext("tc15:stored"), "payload.bin", zipfile.ZIP_STORED
    ),
    # ZIP_DEFLATED on ciphertext: the method *declares* compression and achieves
    # nothing, which is the harder of the two to argue about.
    "zip_deflated_ciphertext.zip": lambda: zip_of(
        ciphertext("tc15:deflated"), "payload.bin", zipfile.ZIP_DEFLATED
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_tc15_the_container_really_is_valid(name, tmp_path):
    """Before anything else: this is not a forgery, and the test would be empty
    if it were. Every structural check passes."""
    path = write(tmp_path, name, CASES[name]())
    result = score(path, ARM_C)

    assert result["container_status"] == containers.VALID
    assert result["container_valid"] is True


@pytest.mark.parametrize("name", sorted(CASES))
def test_tc15_arm_c_closes_it(name, tmp_path):
    """The row, closed. The ratio clause withdraws the exemption."""
    path = write(tmp_path, name, CASES[name]())
    result = score(path, ARM_C)

    assert result["verdict"] != "benign_compressed", result["reason"]
    assert result["suspicious"] is True, result["reason"]
    assert result["signal"] == "static_entropy"
    # The reason must name the clause that decided, not just the outcome.
    assert "the format transformed nothing" in result["reason"], result["reason"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_tc15_the_residual_under_c1_is_recorded(name, tmp_path):
    """The other half of the row: the residual, stated rather than left implicit.

    C1 is `strict-unvalidated` - the repair's positive-validation gate with no
    ratio clause. It closes all eleven unvalidated formats and leaves every one
    of these three `benign_compressed`, because the container really is valid.
    That is the measurement in `reports/three_arm_experiment.json` (family A2,
    0/3 under C1, 3/3 under C) and it is why C1 is not the repair.
    """
    path = write(tmp_path, name, CASES[name]())
    result = score(path, ARM_C1)

    assert result["verdict"] == "benign_compressed"
    assert result["suspicious"] is False


@pytest.mark.parametrize("name", sorted(CASES))
def test_tc15_the_deployed_default_leaves_it_benign(name, tmp_path):
    """Arm A. The finding, not a regression - the repair does not ship."""
    path = write(tmp_path, name, CASES[name]())
    assert score(path, ARM_A)["verdict"] == "benign_compressed"


def test_tc15_a_container_that_did_compress_stays_benign_under_arm_c(tmp_path):
    """The clause reads compression yield and not "is this an archive".

    Without this, the three rows above are satisfied by a policy that flags every
    container, which would have a false-positive cost of 100% and answer nothing.
    """
    prose = (b"quarterly deployment report, section body text. " * 4000)[:PAYLOAD_BYTES]
    for name, blob in (
        ("real.gz", gzip.compress(prose)),
        ("real.zip", zip_of(prose, "report.txt", zipfile.ZIP_DEFLATED)),
    ):
        result = score(write(tmp_path, name, blob), ARM_C)
        assert result["suspicious"] is False, (name, result["reason"])
