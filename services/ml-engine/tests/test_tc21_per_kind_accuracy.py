"""TC-21 (NI): every class is reported; none hides beneath an aggregate.

Table 9.7 row: *per-kind accuracy reported for every class; no class hides
beneath an aggregate.*

An aggregate accuracy over a corpus with seventeen constructions can be 99.5%
while one construction is at 50%, and the one at 50% is usually the one that
matters - the hard benign cases a detector has to get right to be deployable, or
the intermittent-encryption shapes an attacker actually uses. The headline number
does not distinguish "this model works" from "this model has learned the majority
kind".

So the requirement is not a threshold, it is *disclosure*: `per_kind_accuracy` in
`reports/behavioral_model_metrics.json` must cover every kind the corpus can
produce, with its sample count, and this test derives the list of kinds from the
corpus builder rather than from the report - so a kind added to the corpus and
left out of the report fails here rather than going unreported.

The one kind below the aggregate is asserted by name. `partial` - intermittent
encryption - is the lowest, and it should be: it is the shape that is hardest to
tell from a real archive of mixed content, and it is why `detection.measure`
carries block statistics at all. Naming it is the point of the row.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "src"))

METRICS = REPO_ROOT / "reports" / "behavioral_model_metrics.json"

pytestmark = pytest.mark.skipif(
    not METRICS.exists(),
    reason="reports/behavioral_model_metrics.json is absent; run src/train_behavioral_model.py",
)


@pytest.fixture(scope="module")
def metrics() -> dict:
    return json.loads(METRICS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def corpus_kinds() -> set[str]:
    """The kinds the builder can produce, taken from the builder."""
    np = pytest.importorskip("numpy")
    train = pytest.importorskip("train_behavioral_model")
    train.rng = np.random.default_rng(42)
    _rows, _labels, kinds = train.build_corpus(samples_per_kind=2)
    return set(kinds)


def test_tc21_per_kind_accuracy_is_reported_at_all(metrics):
    assert "per_kind_accuracy" in metrics
    assert metrics["per_kind_accuracy"], "the block is present and empty"


def test_tc21_every_kind_the_corpus_produces_is_reported(metrics, corpus_kinds):
    """The row. Derived from the builder, so a new kind cannot go unreported."""
    reported = set(metrics["per_kind_accuracy"])
    missing = corpus_kinds - reported
    assert missing == set(), f"kinds absent from the report: {sorted(missing)}"


def test_tc21_each_kind_carries_its_sample_count(metrics):
    """An accuracy without an n is not a measurement.

    A kind with three test samples can read 1.00 and mean nothing; the count is
    what lets a reader tell that from a kind with 261.
    """
    for kind, cell in metrics["per_kind_accuracy"].items():
        assert "accuracy" in cell, kind
        assert "samples" in cell, kind
        assert cell["samples"] > 0, kind
        assert 0.0 <= cell["accuracy"] <= 1.0, kind


def test_tc21_the_per_kind_samples_add_up_to_the_test_set(metrics):
    """No class hides: every test sample belongs to exactly one reported kind."""
    total = sum(cell["samples"] for cell in metrics["per_kind_accuracy"].values())
    assert total == metrics["test_samples"], (total, metrics["test_samples"])


def test_tc21_the_worst_kind_is_named_and_it_is_the_one_that_should_be(metrics):
    """Disclosure with a name on it.

    `partial` is intermittent encryption - part ciphertext, part original - and
    it is the shape closest to a legitimate archive of mixed content. It sits
    below the aggregate, which is the honest outcome and the reason the aggregate
    alone is not reportable.
    """
    per_kind = metrics["per_kind_accuracy"]
    worst = min(per_kind, key=lambda k: per_kind[k]["accuracy"])

    assert worst == "partial", (worst, per_kind[worst])
    assert per_kind[worst]["accuracy"] < metrics["accuracy"], (
        "the worst kind is at or above the aggregate, which would mean the "
        "aggregate is no longer hiding anything - re-read the report before "
        "loosening this"
    )


def test_tc21_the_aggregate_is_reported_alongside_and_not_instead(metrics):
    """Both, so neither can be quoted without the other being available."""
    for field in ("accuracy", "precision", "recall", "f1_score", "test_samples"):
        assert field in metrics, field
    assert metrics["test_samples"] > 0
