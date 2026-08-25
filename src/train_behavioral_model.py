"""Behavioural classifier for the Monitor's feature dict - NI.

Two different things arrive at /predict and they are not the same feature space:

  * `ember_vector` - 2381 precomputed EMBER static-PE features. That is the
    primary classifier, trained by train_ember_model.py.
  * `features` - the handful of signals the Monitor can actually measure from a
    file it just saw change (entropy, size, magic bytes, extension, and now the
    shape of the container and the profile of its 4KB blocks). The EMBER model
    cannot score these, which is why that path used to return 501 and the
    Monitor -> ML hop did not work at all.

This trains the second model.

What the corpus is, stated plainly
----------------------------------
It is **synthetic and procedurally generated**. Nothing in it is a real
photograph, document, recording or ransomware artefact. The previous version of
this docstring claimed "real archives, images, PDFs and documents for the benign
class, and the same content actually AES-encrypted for the malicious class", and
all three parts of that were wrong: there is no AES anywhere (the malicious
samples are `os.urandom`), the malicious samples are not encrypted copies of the
benign ones, and several of the "images" were a magic number followed by random
bytes.

That last one was not only inaccurate, it made the corpus **self-contradictory**.
`photo_N.png` was `\\x89PNG\\r\\n\\x1a\\n` + `os.urandom` and labelled benign;
`spoofed_N.png` was the same construction labelled ransomware. The two classes
were the same distribution with opposite labels, so no model could separate them
and none should have been able to. Measured per-kind accuracy on the model that
resulted: `spoofed` 15.2%, dragging `archive` to 66.7% and `clip` to 80%.

The fix is not to drop a class. It is to make the benign files genuinely be the
format they claim - real deflate streams, real CRCs, real marker chains, a real
cross-reference table - so that `container_structurally_valid` has something to
separate them by. scripts/synthetic_corpus.py builds them; the forgeries stay
exactly as they were. The pair is the experiment.

Why the features are computed by the Monitor's own code
-------------------------------------------------------
`detection.measure` and `containers.container_status` are imported from
services/monitor rather than reimplemented here. A second implementation of
"what is this file's block-entropy profile" is precisely how a training corpus
and a detector end up disagreeing about the same file, and the model is then
scoring columns that mean something slightly different from the ones it was
fitted on. The service-side mapping from a request dict to this vector lives in
services/ml-engine/features.py and has to be kept in step with FEATURE_NAMES
below - it is checked by test_feature_contract in the ml-engine suite.

    python src/train_behavioral_model.py
"""

import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = REPO_ROOT / "models"
REPORTS_DIR = REPO_ROOT / "reports"

# The detector's own measurement code, and the sample builders both this and the
# Monitor's benchmarks use. See the docstring for why these are imported rather
# than reimplemented.
sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import synthetic_corpus  # noqa: E402
from containers import CONTAINER_TAIL_BYTES, FORGED, VALID, container_status  # noqa: E402
from detection import ENTROPY_SAMPLE_BYTES, identify_container, measure  # noqa: E402

# Must match FEATURE_ORDER in services/ml-engine/features.py, in order.
FEATURE_NAMES = [
    "shannon_entropy",
    "log_file_size",
    "has_container_header",
    # Tri-state, encoded as an ordinal because that is what it is: -1 the
    # declared format is not there, 0 nothing was checked, +1 the structure
    # holds. A boolean would have to fold "no validator for RAR" into one of the
    # two real answers, and either choice is a lie about a third of the corpus.
    "container_structurally_valid",
    "ransom_extension",
    "printable_ratio",
    "byte_value_std",
    "chi_square_uniformity",
    # The block profile. Whole-file entropy is a mean, and intermittent
    # encryption is exactly the case a mean hides.
    "entropy_max_block",
    "entropy_block_spread",
    "high_entropy_block_fraction",
]

RANSOM_EXTENSIONS = {".encrypted", ".locked", ".crypt", ".wncry", ".ryuk", ".lockbit", ".enc"}

STRUCTURE_SCORE = {VALID: 1.0, FORGED: -1.0}

rng = np.random.default_rng(42)


def _entropy_source(size: int) -> bytes:
    """Randomness for the sample builders, drawn from the seeded generator.

    `os.urandom` would make the corpus - and therefore every metric derived from
    it - different on every run. The builders take the source as an argument for
    this reason.
    """
    return rng.integers(0, 256, size=size, dtype=np.uint8).tobytes()


# ------------------------------------------------------------------- features


def has_container(data: bytes) -> int:
    return 1 if identify_container(data[:16]) else 0


def featurise(data: bytes, filename: str) -> list[float]:
    """Exactly what the Monitor sends, measured by the Monitor's own code."""
    head = data[:ENTROPY_SAMPLE_BYTES]
    tail = data[-CONTAINER_TAIL_BYTES:] if len(data) > len(head) else head
    entropy, statistics = measure(head)
    status = container_status(head, tail, identify_container(data[:16]), len(data))

    return [
        entropy,
        math.log10(max(len(data), 1)),
        float(has_container(data)),
        STRUCTURE_SCORE.get(status, 0.0),
        float(os.path.splitext(filename)[1].lower() in RANSOM_EXTENSIONS),
        statistics["printable_ratio"],
        statistics["byte_value_std"],
        statistics["chi_square_uniformity"],
        statistics["entropy_max_block"],
        statistics["entropy_block_spread"],
        statistics["high_entropy_block_fraction"],
    ]


# The request-dict -> vector mapping lives in services/ml-engine/features.py so
# there is exactly one copy of the feature order. A second one here is how the
# service ends up scoring the wrong columns after someone edits only one of them.


# --------------------------------------------------------------------- corpus


def _firmware_image(size: int) -> bytes:
    """Compressed payload, embedded strings and padding runs - the shape a real
    firmware blob has. High entropy, no header, but not uniform."""
    import gzip

    # Strip gzip's 10-byte header: this class is meant to be *headerless* high
    # entropy. Leaving it on would give the sample a gzip magic and quietly turn
    # it back into the easy case.
    parts = [gzip.compress(synthetic_corpus.build_text(size, _entropy_source))[10:]]
    parts.append(b"\x00" * int(rng.integers(256, 2048)))
    parts.append(b"Bootloader v2.1 build 4471 -- init ok\x00" * 8)
    parts.append(b"\xff" * int(rng.integers(256, 2048)))
    parts.append(_entropy_source(max(size // 4, 1)))
    out = b"".join(parts)
    return out[:size] if len(out) > size else out


def _float_weights(size: int) -> bytes:
    """A float32 tensor dump. Near-normal values leave the exponent byte
    strongly clustered, so the byte histogram is visibly non-uniform."""
    count = max(size // 4, 1)
    values = rng.normal(0.0, 0.35, size=count).astype(np.float32)
    return values.tobytes()


def _headerless_deflate(size: int) -> bytes:
    import gzip

    return gzip.compress(synthetic_corpus.build_text(size, _entropy_source))[10:]


def _partial(size: int) -> bytes:
    """Intermittent encryption, leading run - the `partial` simulator family."""
    original = synthetic_corpus.build_text(size, _entropy_source)
    cut = min(4096, max(len(original) // 2, 1))
    return _entropy_source(cut) + original[cut:]


def _strided(size: int) -> bytes:
    """Intermittent encryption, strided - the `strider` simulator family.

    LockBit 3.0 and BlackCat encrypt a repeating fraction rather than a leading
    run. Included as its own kind so the model cannot learn "the front of the
    file is random" as a proxy for intermittent encryption.
    """
    out = bytearray(synthetic_corpus.build_text(size, _entropy_source))
    offset = 0
    while offset < len(out):
        chunk = min(4096, len(out) - offset)
        out[offset : offset + chunk] = _entropy_source(chunk)
        offset += 4096 + 8192
    return bytes(out)


def build_corpus(samples_per_kind: int = 200) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """One sample of every kind per iteration, labelled by how it was produced.

    Labels come from construction, never from an entropy rule, so the model is
    free to disagree with the Monitor's heuristic.
    """
    rows: list[list[float]] = []
    labels: list[int] = []
    kinds: list[str] = []

    def add(data: bytes, filename: str, label: int, kind: str) -> None:
        rows.append(featurise(data, filename))
        labels.append(label)
        kinds.append(kind)

    source = _entropy_source

    for index in range(samples_per_kind):
        size = int(rng.integers(8_000, 400_000))

        # --- benign, and genuinely the format they claim ------------------
        add(synthetic_corpus.build_text(size, source), f"notes_{index}.txt", 0, "text")
        add(synthetic_corpus.build_docx(size // 4, source), f"report_{index}.docx", 0, "office")
        add(synthetic_corpus.build_gzip(size, source), f"backup_{index}.gz", 0, "gzip")
        add(synthetic_corpus.build_zip(size, source), f"archive_{index}.zip", 0, "archive")
        add(synthetic_corpus.build_png(size, source), f"photo_{index}.png", 0, "photo")
        add(synthetic_corpus.build_jpeg(size, source), f"scan_{index}.jpg", 0, "scan")
        add(synthetic_corpus.build_pdf(size, source), f"manual_{index}.pdf", 0, "manual")
        add(synthetic_corpus.build_mp4(size, source), f"clip_{index}.mp4", 0, "clip")

        # --- benign, container present but unvalidatable -------------------
        # Real bzip2 and XZ streams. Both carry a header the Monitor recognises
        # and neither has a structural validator, so
        # `container_structurally_valid` is 0 - the middle of the ordinal, and a
        # value nothing else in the corpus would take.
        #
        # Leaving that region unrepresented is not neutral. It was tested: with
        # every container-bearing sample scoring +1 or -1, a caller that sent a
        # ZIP without the structural check landed on a 0 the model had never
        # seen and was classified ransomware - a legitimate archive, called an
        # attack, because a field was absent. These samples put the honest
        # answer there instead, and it is the same answer the detector gives:
        # no validator means the container exemption still applies.
        #
        # Forged counterparts are deliberately *not* included. A `BZh` followed
        # by random bytes and a real bzip2 stream are identical on every feature
        # in this vector, so labelling them apart would only add noise - and
        # claiming the model could tell them apart would be the same kind of
        # untrue thing this corpus was rebuilt to remove. That is a real limit
        # of the structural check and it is stated in containers.py.
        add(synthetic_corpus.build_bzip2(size, source), f"bundle_{index}.bz2", 0, "bzip2")
        add(synthetic_corpus.build_xz(size, source), f"bundle_{index}.xz", 0, "xz")

        # --- benign, but hard --------------------------------------------
        # The real false-positive risk: legitimate files that are high entropy
        # AND carry no recognised header, so neither the magic-byte check nor
        # the structural check has anything to say. Only the byte statistics
        # separate these from ciphertext.
        add(_firmware_image(size), f"firmware_{index}.bin", 0, "firmware")
        add(_float_weights(size), f"weights_{index}.dat", 0, "weights")
        add(_headerless_deflate(size), f"headerless_{index}.blob", 0, "headerless")

        # --- ransomware-encrypted ----------------------------------------
        # A stream cipher's output is indistinguishable from random, which is
        # what an encrypted document looks like on disk. Half of these keep the
        # original extension and half take a ransom one, because the extension
        # is a signal the model should be able to use without depending on it.
        for suffix, extension in (
            ("docx", ""), ("xlsx", ""), ("pdf", ""), ("jpg", ""),
            ("docx", ".locked"), ("txt", ".encrypted"), ("pdf", ".wncry"), ("png", ".crypt"),
        ):
            add(source(size), f"victim_{index}.{suffix}{extension}", 1, "victim")

        # --- ransomware, but hard ----------------------------------------
        # Header spoofing: a valid container magic so a magic-byte check waves
        # the file through, ciphertext behind it. One per format that has a
        # structural validator, so `container_structurally_valid` is exercised
        # across all of them rather than only on ZIP.
        for magic, extension in synthetic_corpus.SPOOF_TARGETS:
            add(synthetic_corpus.spoof(magic, size, source),
                f"spoofed_{index}{extension}", 1, "spoofed")

        # Intermittent encryption, both shapes.
        add(_partial(size), f"partial_{index}.docx", 1, "partial")
        add(_strided(size), f"strided_{index}.docx", 1, "strided")

    return np.array(rows, dtype=np.float32), np.array(labels, dtype=int), kinds


# ------------------------------------------------------------------ training


def per_kind_accuracy(kinds: list[str], y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """Accuracy broken out by how each sample was built.

    The headline accuracy hid the corpus defect completely: a class that was
    unlearnable by construction scored 15.2% while the aggregate read 88.4%,
    because it was one kind in twenty-two. This is the number that made the
    contradiction visible, so it is now produced on every run rather than
    reconstructed by hand afterwards.
    """
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for kind, actual, predicted in zip(kinds, y_true, y_pred):
        totals[kind][1] += 1
        totals[kind][0] += int(actual == predicted)
    return {
        kind: {"accuracy": round(correct / total, 4), "samples": total}
        for kind, (correct, total) in sorted(totals.items())
    }


def main() -> int:
    MODEL_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)

    print("Building synthetic corpus (structurally valid containers + forgeries)...")
    X, y, kinds = build_corpus()
    print(f"  {X.shape[0]} samples, {X.shape[1]} features "
          f"({(y == 0).sum()} benign / {(y == 1).sum()} encrypted), "
          f"{len(set(kinds))} kinds")

    indices = np.arange(len(y))
    train_idx, temp_idx = train_test_split(indices, test_size=0.30, stratify=y, random_state=42)
    val_idx, test_idx = train_test_split(
        temp_idx, test_size=0.50, stratify=y[temp_idx], random_state=42
    )
    X_train, y_train = X[train_idx], y[train_idx]
    X_val, y_val = X[val_idx], y[val_idx]
    X_test, y_test = X[test_idx], y[test_idx]
    print(f"  train {len(X_train)}  val {len(X_val)}  test {len(X_test)}")

    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1_score": float(f1_score(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "test_samples": int(len(y_test)),
        "feature_names": FEATURE_NAMES,
        "corpus": "synthetic, procedurally generated by scripts/synthetic_corpus.py",
    }

    print("\n=== BEHAVIOURAL MODEL - HELD-OUT TEST SET ===")
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f"{key}: {value:.4f}")
    print("\n" + classification_report(y_test, y_pred, target_names=["benign", "ransomware"]))

    by_kind = per_kind_accuracy([kinds[i] for i in test_idx], y_test, y_pred)
    metrics["per_kind_accuracy"] = by_kind
    print("per-kind accuracy on the held-out set:")
    for kind, entry in by_kind.items():
        print(f"  {kind:<12s} {entry['accuracy']:>7.1%}  ({entry['samples']} samples)")

    importance = dict(zip(FEATURE_NAMES, (float(v) for v in model.feature_importances_)))
    metrics["feature_importance"] = importance
    print("\nfeature importance:")
    for name, value in sorted(importance.items(), key=lambda pair: -pair[1]):
        print(f"  {name:<30s} {value:.4f}")

    metrics["trained_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    joblib.dump(model, MODEL_DIR / "behavioral_model.pkl")
    payload = json.dumps(metrics, indent=2)
    # models/ is the directory mounted into the ML container, so the metrics go
    # there as well as reports/ - otherwise /model/metrics has nothing to read.
    (MODEL_DIR / "behavioral_model_metrics.json").write_text(payload)
    (REPORTS_DIR / "behavioral_model_metrics.json").write_text(payload)
    print(f"\nModel  -> {MODEL_DIR / 'behavioral_model.pkl'}")
    print(f"Metrics -> {MODEL_DIR / 'behavioral_model_metrics.json'} (+ reports/)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
