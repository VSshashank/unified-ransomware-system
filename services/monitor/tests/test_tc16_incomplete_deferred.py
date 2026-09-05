"""TC-16 (AS): an incomplete validation defers; it never cancels silently.

Table 9.7 row: *a validator returning `INCOMPLETE` yields `deferred` or
`unverified`, never a silent benign cancellation.*

`containers.container_status` has five answers and `validate_container` projects
three of them onto `None`. INCOMPLETE is the one that means the validator ran and
could not finish - a file still being written, or a truncated one - and it is not
the same fact as UNVALIDATED, which means no validator exists for this format.
The tri-state cannot tell them apart, and until P6.6 neither could the ledger.

Two halves, and the row needs both:

  * no silent benign cancellation - the alert stands;
  * the result is *named*, so a reader can tell a deferral from a conclusion.

The second half is `NOVELTY_PROOF_PLAN.md` §7.1's "explicit deferred state"
variant, built in P6.7. `suspicious` stays True and the signal is unchanged, so
`admissibility.py` ranks a deferral exactly as it ranked the conclusion it
replaced - the verdict name is a statement about evidence, not a third truth
value.

Under `legacy` an INCOMPLETE container is exempted on its header alone. That *is*
the silent cancellation the row forbids, it is what Arm A of the Phase 6
experiment measured, and it is asserted here rather than quietly left out.
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
import detection  # noqa: E402
from _arms import ARM_A, ARM_B, ARM_C, ARM_C1, ARM_D, score, write  # noqa: E402

PAYLOAD_BYTES = 120_000
DEFERRING_ARMS = (ARM_C1, ARM_C, ARM_D)


def ciphertext(tag: str, size: int = PAYLOAD_BYTES) -> bytes:
    return hashlib.shake_256(tag.encode()).digest(size)


def truncated_zip(tag: str) -> bytes:
    """A ZIP whose central directory has not been written yet.

    What a real archiver's output looks like mid-write, and what an encryptor
    gets for free by stopping early. `_validate_zip` finds a well-formed local
    header and no end-of-central-directory, which is INCOMPLETE and not FORGED -
    nothing about it is wrong, it is unfinished.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("payload.bin", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 0
        archive.writestr(info, ciphertext(tag))
    full = buffer.getvalue()
    return full[: len(full) - 200]


def test_tc16_the_fixture_really_is_incomplete(tmp_path):
    """FORGED would make every assertion below true for the wrong reason."""
    path = write(tmp_path, "half_written.zip", truncated_zip("tc16:setup"))
    result = score(path, ARM_C)

    assert result["container_status"] == containers.INCOMPLETE
    assert result["container_valid"] is None
    assert result["validation_state"] == containers.INCOMPLETE


@pytest.mark.parametrize("arm", DEFERRING_ARMS)
def test_tc16_incomplete_yields_the_named_deferred_state(arm, tmp_path):
    """The row. Named `deferred`, and still suspicious."""
    path = write(tmp_path, "half_written.zip", truncated_zip("tc16:defer"))
    result = score(path, arm)

    assert result["verdict"] == detection.DEFERRED
    assert result["verdict"] != "benign_compressed"
    assert result["suspicious"] is True
    assert "could not finish" in result["reason"], result["reason"]


@pytest.mark.parametrize("arm", DEFERRING_ARMS)
def test_tc16_deferring_does_not_change_how_admissibility_ranks_it(arm, tmp_path):
    """A deferral is a statement about evidence, not a new severity.

    If the signal moved, every cell of the admission matrix for this case would
    move with it, and the deferred state would have quietly become a policy
    change. It has not: the signal is what it was before P6.7.
    """
    path = write(tmp_path, "half_written.zip", truncated_zip("tc16:signal"))
    assert score(path, arm)["signal"] == "static_entropy"


def test_tc16_the_deployed_default_cancels_it_silently(tmp_path):
    """Arm A, and the row's own failure mode, recorded.

    Under `legacy` the exemption fires on the header, so a half-written archive
    full of ciphertext is `benign_compressed`. The reason string at least now
    says which of the two gaps it is - it claimed "this format has no structural
    validator" until P6.7, which was false for zip.
    """
    path = write(tmp_path, "half_written.zip", truncated_zip("tc16:legacy"))
    result = score(path, ARM_A)

    assert result["verdict"] == "benign_compressed"
    assert result["suspicious"] is False
    assert "structure is incomplete" in result["reason"], result["reason"]
    assert "no structural validator" not in result["reason"]


def test_tc16_the_null_arm_flags_it_without_calling_it_deferred(tmp_path):
    """Arm B deletes the exemption, so the deferral is not what decided.

    Deliberate: `off` reaches its answer without consulting validation at all,
    and naming that outcome `deferred` would attribute it to a reading the policy
    never took.
    """
    path = write(tmp_path, "half_written.zip", truncated_zip("tc16:null"))
    result = score(path, ARM_B)

    assert result["suspicious"] is True
    assert result["verdict"] == "suspected_encryption"


@pytest.mark.parametrize("arm", DEFERRING_ARMS)
def test_tc16_unvalidated_is_not_renamed_to_deferred(arm, tmp_path):
    """The distinction the row depends on.

    "No validator exists for RAR" is a permanent gap in coverage. "The ZIP
    validator could not finish" is a temporary condition. Calling both `deferred`
    would hide the first behind a word that sounds like the second, and eleven
    formats' worth of missing coverage would read as a transient.
    """
    path = write(tmp_path, "payload.rar", b"Rar!\x1a\x07" + ciphertext("tc16:rar"))
    result = score(path, arm)

    assert result["container_status"] == containers.UNVALIDATED
    assert result["verdict"] == "suspected_encryption"
    assert result["verdict"] != detection.DEFERRED
    assert result["suspicious"] is True


def test_tc16_a_complete_container_is_never_deferred(tmp_path):
    """A finished archive reaches a conclusion, either way."""
    prose = (b"quarterly deployment report, section body text. " * 4000)[:PAYLOAD_BYTES]
    # A gzip of prose compresses, so it lands below the entropy threshold and
    # never reaches the exemption at all - the verdict is plain `benign`, not
    # `benign_compressed`. Either way it is a conclusion.
    benign = score(write(tmp_path, "done.gz", gzip.compress(prose)), ARM_C)
    assert benign["container_status"] == containers.VALID
    assert benign["verdict"] != detection.DEFERRED
    assert benign["suspicious"] is False

    forged = score(write(tmp_path, "forged.zip", b"PK\x03\x04" + ciphertext("tc16:f")), ARM_C)
    assert forged["verdict"] == "suspected_encryption"
    assert forged["signal"] == "structural_mismatch"
