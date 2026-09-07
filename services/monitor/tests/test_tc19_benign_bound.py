"""TC-19 (AS): genuine formats stay benign, and the bound that does not hold.

Table 9.7 row: *genuine ZIP, GZIP, PNG, JPEG and PDF stay benign; the Arm C −
Arm A false-positive difference stays within the predeclared bound.*

The row has two halves and **neither passes cleanly**.

The first half holds under the deployed policy: every genuine file here is benign
under Arm A. Under Arm C it holds for five of the six - GZIP, PNG, JPEG, PDF and
MP4 - and fails for a stored ZIP of incompressible content, which is a real
archive that compressed nothing and is therefore exactly what the ratio clause
was written to catch.

The second half fails outright. Arm C's false-positive difference on validated
formats has a one-sided 95% upper limit of **25.3235 pp** against a predeclared
tolerance of **2.00 pp**, so Bound 1 fails, `NOVELTY_PROOF_PLAN.md` §9 row 5
fails, and on the plan's own terms the repair is not accepted.

The two halves are the same fact seen twice. The one flagged ZIP above is one of
the 30 false positives that produce the 25.3235 pp, so this file asserts the
mechanism and the number it adds up to in the same place.

P7.1 asks for a test that *asserts the recorded outcome rather than observing it
incidentally*. The recorded outcome here is a failure, so this test asserts the
failure - with the measured number, from the artefact that measured it. That is
not a test written to pass. It is the thing that stops the number being quietly
improved in a report without the experiment being re-run, and it fails loudly if
the repair ever does become non-inferior, which is the point at which every
document saying it is not needs rewriting.

The predeclared tolerance is read from `docs/PHASE5_PREDECLARED_BOUNDS.md`'s
frozen figure via the analysis artefact, never from a constant typed here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import synthetic_corpus  # noqa: E402
from _arms import ARM_A, ARM_C, score, write  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
TRADEOFF = REPO_ROOT / "reports" / "benign_tradeoff.json"

PAYLOAD_BYTES = 120_000

GENUINE = {
    "report.zip": synthetic_corpus.build_zip,
    "report.docx": synthetic_corpus.build_docx,
    "archive.gz": synthetic_corpus.build_gzip,
    "photo.png": synthetic_corpus.build_png,
    "photo.jpg": synthetic_corpus.build_jpeg,
    "manual.pdf": synthetic_corpus.build_pdf,
    "clip.mp4": synthetic_corpus.build_mp4,
}

# Which of them Arm C flags, and it is not none. `build_zip` stores its member
# rather than deflating it - deflating random bytes is pure cost for no size
# change, which is what a real archiver does too - so the archive is genuine,
# structurally valid, and compressed nothing. The ratio clause reads exactly that
# and withdraws the exemption. This is not a defect in the test: it is one of the
# 30 false positives Arm C introduces on 155 validated-format files, and it is
# the whole reason Bound 1 fails.
FLAGGED_BY_ARM_C = {"report.zip"}


@pytest.mark.parametrize("name", sorted(GENUINE))
def test_tc19_a_genuine_file_stays_benign_under_the_deployed_policy(name, tmp_path):
    """The first half of the row, under what actually ships."""
    path = write(tmp_path, name, GENUINE[name](PAYLOAD_BYTES))

    result = score(path, ARM_A)

    assert result["suspicious"] is False, (name, result["reason"])
    assert result["verdict"] in {"benign", "benign_compressed"}, name


@pytest.mark.parametrize("name", sorted(GENUINE))
def test_tc19_arm_c_keeps_four_of_five_named_formats_benign(name, tmp_path):
    """The first half under the repair, and the exception, both asserted.

    GZIP, PNG, JPEG, PDF, MP4 and DOCX survive Arm C. A stored ZIP of
    incompressible content does not, and that single case is the shape of the
    repair's entire benign cost - a legitimate archive of already-compressed
    content, flagged because the format transformed nothing.

    Written as an exact set rather than an inequality: if a format joins or
    leaves this list, the false-positive cost changed and the experiment needs
    re-running before any number in the report is quoted again.
    """
    path = write(tmp_path, name, GENUINE[name](PAYLOAD_BYTES))

    result = score(path, ARM_C)

    assert result["suspicious"] is (name in FLAGGED_BY_ARM_C), (
        name,
        result["reason"],
    )
    if name in FLAGGED_BY_ARM_C:
        assert "the format transformed nothing" in result["reason"]


def test_tc19_the_flagged_case_is_a_legitimate_archive_and_not_a_forgery(tmp_path):
    """It matters that Arm C's false positives are real archives.

    A repair whose cost fell on malformed files would be uninteresting. This one
    is paid entirely by legitimate backups of already-compressed content, which
    is why §9.13's ban on new validators leaves no cheap way out of it.
    """
    import containers

    path = write(tmp_path, "report.zip", synthetic_corpus.build_zip(PAYLOAD_BYTES))
    result = score(path, ARM_C)

    assert result["container_status"] == containers.VALID
    assert result["container_valid"] is True
    assert result["suspicious"] is True


@pytest.mark.skipif(
    not TRADEOFF.exists(),
    reason="reports/benign_tradeoff.json is absent; run scripts/benign_tradeoff.py",
)
def test_tc19_the_predeclared_bound_is_not_met_and_that_is_the_record():
    """The second half. It fails, and this asserts the failure it produced.

    If this test ever fails, one of two things happened: the experiment was
    re-run and the repair became non-inferior - in which case D5's ruling, the
    Phase 6 report and the acceptance table all need revisiting - or the
    artefact was edited without the experiment being re-run. Both need a person.
    """
    report = json.loads(TRADEOFF.read_text(encoding="utf-8"))
    bound = report["bound_1"]
    arm_c = bound["by_arm"]["C"]

    assert bound["tolerance_pp"] == 2.0
    assert "PHASE5_PREDECLARED_BOUNDS.md" in bound["source"]
    assert bound["n_validated"] == 155
    assert bound["predeclared_arm"] == "C"
    assert arm_c["judged_against_the_predeclared_bound"] is True
    assert arm_c["new_false_positives"] == 30
    assert arm_c["upper_limit_pp"] == pytest.approx(25.3235, abs=0.001)
    assert arm_c["meets_bound"] is False


@pytest.mark.skipif(
    not TRADEOFF.exists(),
    reason="reports/benign_tradeoff.json is absent; run scripts/benign_tradeoff.py",
)
def test_tc19_the_arms_that_do_meet_the_bound_are_not_the_repair():
    """C1 and D both clear 2 pp on validated formats. Neither is the answer.

    C1 clears it by leaving all three standard-library-container witnesses
    benign, which is the attack the repair exists to close. D clears it by
    appealing to inner content, and misses two of three A7 witnesses doing so.
    Recorded here so "an arm met the bound" is never quotable on its own.
    """
    report = json.loads(TRADEOFF.read_text(encoding="utf-8"))
    arms = report["bound_1"]["by_arm"]

    assert arms["C1"]["meets_bound"] is True
    assert arms["D"]["meets_bound"] is True
    assert arms["B"]["meets_bound"] is False
    assert arms["C"]["meets_bound"] is False
    # ...and neither C1 nor D is judged against the bound, because neither was
    # the arm the bound was predeclared for.
    for arm in ("B", "C1", "D"):
        assert arms[arm]["judged_against_the_predeclared_bound"] is False, arm


@pytest.mark.skipif(
    not TRADEOFF.exists(),
    reason="reports/benign_tradeoff.json is absent; run scripts/benign_tradeoff.py",
)
def test_tc19_d5_still_fires_on_the_unvalidated_stratum():
    """Bound 2, which is what actually keeps the repair from shipping.

    Bound 1 fails at 25.3 pp against 2 pp. Bound 2 fails at 100.0 pp against
    15.0 pp - every file in the stratum - and it fails for every arm including
    the null control, because none of them has a validator for bzip2, xz, GIF or
    RIFF and §9.13 puts writing one out of scope.
    """
    report = json.loads(TRADEOFF.read_text(encoding="utf-8"))
    bound = report["bound_2"]

    assert bound["tolerance_pp"] == 15.0
    assert bound["stratum_files"] == 90
    for arm in ("B", "C1", "C", "D"):
        cell = bound["by_arm"][arm]
        assert cell["within_tolerance"] is False, arm
        assert cell["rate_pp"] == pytest.approx(100.0, abs=0.001), arm
        assert cell["alone_exceeds_corpus_budget"] is True, arm

    assert report["d5"]["fires"] is True
    assert report["d5"]["measured_rate_pp"] == pytest.approx(100.0, abs=0.001)
    assert report["d5"]["tolerance_pp"] == 15.0
