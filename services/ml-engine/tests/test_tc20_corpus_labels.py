"""TC-20 (NI): no construction carries opposite labels, and the corpus is seeded.

Table 9.7 row: *no two training samples share a construction with opposite
labels; the corpus rebuilds byte-identically from its recorded seed.*

The row exists because of a defect that was found and fixed, and §9.6.2 makes
writing it up NI's deliverable. `src/train_behavioral_model.py`'s own header
records it: `photo_N.png` was a PNG magic followed by `os.urandom`, labelled
benign, and `spoofed_N.png` was the same construction labelled ransomware. Two
classes drawn from one distribution with opposite labels. No model can separate
them, and the accuracy figure that came out of it was measuring nothing.

What makes the corpus honest now is that **the label comes from the
construction** - `build_corpus` labels each sample by which builder made it,
never by an entropy rule - so the label and the bytes cannot disagree. This test
asserts the invariant directly over a rebuilt corpus rather than trusting the
comment.

The second half is reproducibility. `_entropy_source` draws from a seeded
generator instead of `os.urandom` precisely so that every metric derived from the
corpus is re-derivable; if it were not, the per-kind accuracies in TC-21 would be
unrepeatable and the ransomware/benign split would drift between runs.

`samples_per_kind` is small here. The invariant is a property of the builders, not
of the sample count, and the full corpus takes minutes.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "src"))

np = pytest.importorskip("numpy")
train = pytest.importorskip("train_behavioral_model")

SAMPLES_PER_KIND = 3
RECORDED_SEED = 42


def build(seed: int = RECORDED_SEED, samples: int = SAMPLES_PER_KIND):
    """Rebuild from the recorded seed.

    The generator is module state, so a rebuild has to reset it - which is also
    the thing being asserted: the corpus is a function of the seed and nothing
    else.
    """
    train.rng = np.random.default_rng(seed)
    return train.build_corpus(samples_per_kind=samples)


@pytest.fixture(scope="module")
def corpus():
    return build()


def test_tc20_no_construction_carries_both_labels(corpus):
    """The row, and the defect it was written for.

    A `kind` is the construction: which builder produced the bytes. If any kind
    appeared with both labels, the model would be asked to separate a
    distribution from itself, and whatever accuracy came out would be noise.
    """
    _rows, labels, kinds = corpus

    labels_by_kind = defaultdict(set)
    for kind, label in zip(kinds, labels):
        labels_by_kind[kind].add(int(label))

    conflicting = {k: sorted(v) for k, v in labels_by_kind.items() if len(v) > 1}
    assert conflicting == {}, conflicting
    assert len(labels_by_kind) >= 15, "the corpus lost kinds; coverage is narrower"


def test_tc20_both_classes_are_present_and_neither_is_a_rounding_error(corpus):
    """A corpus that is 99% one class makes accuracy meaningless on its own."""
    _rows, labels, _kinds = corpus

    ransomware = int((labels == 1).sum())
    benign = int((labels == 0).sum())
    assert ransomware > 0 and benign > 0
    minority = min(ransomware, benign) / len(labels)
    assert minority > 0.2, f"class balance {benign}/{ransomware} is too skewed to read"


def test_tc20_the_corpus_rebuilds_identically_from_the_recorded_seed(corpus):
    """The second half of the row. Same seed, same bytes, same labels."""
    rows, labels, kinds = corpus
    again_rows, again_labels, again_kinds = build()

    assert np.array_equal(rows, again_rows)
    assert np.array_equal(labels, again_labels)
    assert kinds == again_kinds


def test_tc20_a_different_seed_produces_a_different_corpus(corpus):
    """Guards the test above against being satisfied by a constant corpus.

    If the builders ignored their entropy source, the rebuild assertion would
    pass for the wrong reason and the seed would be decoration.
    """
    rows, _labels, kinds = corpus
    other_rows, _other_labels, other_kinds = build(seed=RECORDED_SEED + 1)

    assert kinds == other_kinds, "the kinds are structural and must not move"
    assert not np.array_equal(rows, other_rows)


def test_tc20_the_benign_and_ransomware_kinds_are_the_ones_recorded(corpus):
    """Which constructions carry which label, stated rather than counted.

    `bzip2` and `xz` are benign and deliberately have no forged counterpart: a
    `BZh` followed by random bytes and a real bzip2 stream are identical on every
    feature in this vector, so labelling them apart would be a claim the model
    cannot support. That is a stated limit of the structural check, and this
    assertion is where it would break if someone added the forged twin.
    """
    _rows, labels, kinds = corpus

    by_label = defaultdict(set)
    for kind, label in zip(kinds, labels):
        by_label[int(label)].add(kind)

    assert by_label[1] == {"victim", "spoofed", "partial", "strided"}
    assert {"bzip2", "xz"} <= by_label[0]
    assert by_label[0] & by_label[1] == set()
