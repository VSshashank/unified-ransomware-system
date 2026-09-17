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


# --------------------------------------------------------------------------
# Provenance. Everything above asks whether the artefact says what the claim
# quotes. These ask the question that was missing until 2026-09-17: whether the
# artefact came from this line of development at all.
#
# The failing cases build their own one-commit repository in tmp_path rather
# than reaching into this one. That keeps them hermetic, and it means they
# still run where the checkout is shallow and the real repository's older
# commits are not present.
# --------------------------------------------------------------------------

import json
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace


@pytest.fixture
def repo(tmp_path):
    """A repository with one ancestor commit and one commit off to the side."""
    def git(*args):
        done = subprocess.run(["git", *args], cwd=tmp_path,
                              capture_output=True, text=True)
        assert done.returncode == 0, f"git {' '.join(args)}: {done.stderr}"
        return done.stdout.strip()

    git("init", "--quiet")
    git("config", "user.email", "provenance@example.invalid")
    git("config", "user.name", "provenance test")
    git("config", "commit.gpgsign", "false")
    (tmp_path / "reports").mkdir()
    (tmp_path / "seed.txt").write_text("seed\n")
    git("add", "-A")
    git("commit", "--quiet", "-m", "seed")
    trunk = git("rev-parse", "--abbrev-ref", "HEAD")
    ancestor = git("rev-parse", "HEAD")

    # A commit that exists but is not in HEAD's history: an artefact generated
    # on a branch that was never merged is exactly this case.
    git("checkout", "--quiet", "-b", "never-merged")
    (tmp_path / "side.txt").write_text("side\n")
    git("add", "-A")
    git("commit", "--quiet", "-m", "off to the side")
    orphan = git("rev-parse", "HEAD")

    git("checkout", "--quiet", trunk)
    (tmp_path / "more.txt").write_text("more\n")
    git("add", "-A")
    git("commit", "--quiet", "-m", "move HEAD on")

    return SimpleNamespace(path=tmp_path, ancestor=ancestor, orphan=orphan)


def _artefact(root, name="evidence.json", **fields):
    (root / "reports" / name).write_text(json.dumps(fields), encoding="utf-8")
    return f"reports/{name}"


def _verdict(repo, rel):
    context = claim_matrix.git_context(root=repo.path)
    assert context["available"], "the fixture repository should be a git checkout"
    return claim_matrix.check_provenance(rel, context, root=repo.path)


def test_a_stamped_ancestor_commit_passes_provenance(repo):
    """The shape every generated artefact is supposed to have."""
    rel = _artefact(repo.path, generated_at="2026-01-01T00:00:00Z",
                    commit=repo.ancestor)
    assert _verdict(repo, rel)["status"] == "ok"


def test_an_artefact_from_an_unmerged_branch_fails(repo):
    """The hole this guard was added to close.

    The commit resolves, so nothing about the file looks wrong. It is simply
    not in HEAD's history, which means the figure it holds was measured against
    code that is not the code being claimed about.
    """
    rel = _artefact(repo.path, generated_at="2026-01-01T00:00:00Z",
                    commit=repo.orphan)
    result = _verdict(repo, rel)
    assert result["status"] == "FAIL"
    assert "not an ancestor of HEAD" in result["detail"]


def test_an_unstamped_artefact_fails(repo):
    """No stamp is not a pass. It is the condition the guard replaces."""
    rel = _artefact(repo.path, round_trip_verified=True)
    result = _verdict(repo, rel)
    assert result["status"] == "FAIL"
    assert "generated_at" in result["detail"] and "commit" in result["detail"]


def test_a_partially_stamped_artefact_fails(repo):
    """A date without a commit cannot be checked against anything."""
    rel = _artefact(repo.path, generated_at="2026-01-01T00:00:00Z")
    assert _verdict(repo, rel)["status"] == "FAIL"


def test_an_unknown_commit_fails(repo):
    """A plausible-looking hash that no object matches."""
    rel = _artefact(repo.path, generated_at="2026-01-01T00:00:00Z",
                    commit="0" * 40)
    result = _verdict(repo, rel)
    assert result["status"] == "FAIL"
    assert "not in this repository" in result["detail"]


def test_a_generated_at_in_the_future_fails(repo):
    """A clock ahead of the run that wrote the file is a red flag, not a detail."""
    ahead = datetime.now(timezone.utc) + timedelta(days=30)
    rel = _artefact(repo.path, generated_at=ahead.isoformat(),
                    commit=repo.ancestor)
    result = _verdict(repo, rel)
    assert result["status"] == "FAIL"
    assert "future" in result["detail"]


def test_an_unparseable_generated_at_fails(repo):
    rel = _artefact(repo.path, generated_at="last Tuesday", commit=repo.ancestor)
    assert _verdict(repo, rel)["status"] == "FAIL"


def test_provenance_covers_every_json_artefact_the_matrix_reads():
    """The guard's scope is the matrix's evidence, with nothing quietly exempt."""
    covered = set(claim_matrix.provenance_artefacts())
    for claim in claim_matrix.CLAIMS:
        checks = claim["check"]
        if checks is None:
            continue
        if isinstance(checks, tuple):
            checks = [checks]
        for rel, _, _ in checks:
            if rel.endswith(".json"):
                assert rel in covered, f"{claim['id']} reads {rel} unchecked"


@pytest.mark.parametrize("rel", claim_matrix.provenance_artefacts())
def test_this_repositorys_evidence_carries_verifiable_provenance(rel):
    """Every artefact this matrix actually cites, in this actual repository."""
    context = claim_matrix.git_context()
    if not context["available"]:
        pytest.skip("not a git checkout; provenance is undefined here")
    if context["shallow"]:
        pytest.skip("shallow clone: older commits are absent, so ancestry "
                    "cannot be decided. Run with fetch-depth 0.")
    result = claim_matrix.check_provenance(rel, context)
    assert result["status"] == "ok", f"{rel}: {result['detail']}"
