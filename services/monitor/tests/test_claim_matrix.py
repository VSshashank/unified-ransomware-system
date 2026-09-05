"""TC-26: every claim in the matrix still matches the artefact it cites (P8.2).

`docs/CLAIM_MATRIX.md` maps each claim to a report and a figure inside it. That
mapping is only worth something if something re-checks it, so these tests import
the matrix and run its checks. A report that changes under a claim fails here,
which is the point: the failure lands on the claim rather than on the number.

Three of these tests assert things that are *not* claimed and things that came
out badly. They are here for the same reason the negative results are in the
thesis - a suite that only asserts the favourable rows cannot show that the
unfavourable ones were left standing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load():
    """Import scripts/claim_matrix.py by path, without a package on sys.path."""
    spec = importlib.util.spec_from_file_location(
        "urds_claim_matrix", ROOT / "scripts" / "claim_matrix.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["urds_claim_matrix"] = module
    spec.loader.exec_module(module)
    return module


claim_matrix = _load()


@pytest.mark.parametrize(
    "claim", claim_matrix.CLAIMS, ids=[c["id"] for c in claim_matrix.CLAIMS])
def test_claim_still_matches_its_artefact(claim):
    """Every claim's cited figure is the figure the report holds."""
    result = claim_matrix.check_claim(claim)
    assert result["status"] == "ok", (
        f"{claim['id']} ({claim['table_9_9_row']}): {result['detail']}")


def test_every_table_9_9_row_is_present():
    """All eight rows Table 9.9 fixes the wording of are in the matrix."""
    rows = {c["table_9_9_row"] for c in claim_matrix.CLAIMS}
    for required in (
        "The team built the system",
        "The exemption is ungoverned",
        "11 of 16 formats are unvalidated",
        "Structural validation is low-capability",
        "The repair closes the bypass",
        "Benign cost is acceptable",
        "The pipeline preserves trust",
        "Ransomware detection improved generally",
        "Patentability or legal novelty",
    ):
        assert required in rows, f"Table 9.9 row absent from the matrix: {required}"


def test_the_two_forbidden_claims_are_recorded_as_not_claimed():
    """C-08 and C-09 stay NOT CLAIMED.

    Table 9.9 forbids claiming general detection improvement or patentability.
    Removing the rows would look the same as never having considered them, so
    they are in the matrix carrying the evidence they would have required.
    """
    forbidden = {c["id"]: c for c in claim_matrix.CLAIMS
                 if c["table_9_9_row"] in ("Ransomware detection improved generally",
                                           "Patentability or legal novelty")}
    assert set(forbidden) == {"C-08", "C-09"}
    for claim in forbidden.values():
        assert claim["claim"] == claim_matrix.NOT_CLAIMED
        assert claim["wording"] == claim_matrix.NOT_CLAIMED
        assert claim["artefact"] is None, (
            "a forbidden claim must cite no supporting artefact")


def test_the_benign_cost_claim_is_recorded_as_not_made():
    """C-06 is the row this work does not get to claim.

    Table 9.9 permits "On the evaluated corpus..." for a claim that benign cost
    is acceptable. Bound 1 failed at 25.323 pp against 2.00, so the claim is not
    made. If someone ever softens this row into a positive claim, this fails.
    """
    c06 = next(c for c in claim_matrix.CLAIMS if c["id"] == "C-06")
    assert c06["claim"].startswith("NOT MADE")
    assert "25.323" in c06["claim"]
    assert "2.00" in c06["claim"]


def test_the_structural_tamper_claim_stays_zero():
    """C-12 asserts 0 of 8, not a number that might improve on its own.

    The chain cannot detect a rewrite that recomputes the hashes, so 0 is the
    correct and permanent answer for an unkeyed chain. A run reporting a
    non-zero count means the sweep changed, not that the chain got stronger.
    """
    c12 = next(c for c in claim_matrix.CLAIMS if c["id"] == "C-12")
    _, path, expected = c12["check"]
    assert list(path) == ["structural", "detected"]
    assert expected == 0


def test_every_made_claim_names_an_artefact():
    """A claim that cites nothing is an assertion, and the matrix rejects one."""
    for claim in claim_matrix.CLAIMS:
        if claim["claim"] == claim_matrix.NOT_CLAIMED:
            continue
        assert claim["artefact"], f"{claim['id']} makes a claim with no artefact"
        assert (ROOT / claim["artefact"]).is_file(), (
            f"{claim['id']} cites a missing artefact: {claim['artefact']}")


def test_mandatory_wording_is_carried_verbatim():
    """Each Table 9.9 row's permitted phrase appears in the claim it governs."""
    for claim in claim_matrix.CLAIMS:
        if not claim["wording_required"]:
            continue
        if claim["wording"] == claim_matrix.NOT_CLAIMED:
            continue
        phrase = claim["wording"].removesuffix("...").strip()
        assert phrase in claim["claim"], (
            f"{claim['id']} does not carry its mandatory wording: {phrase!r}")
