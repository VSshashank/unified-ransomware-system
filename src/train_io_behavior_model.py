"""I/O behaviour classifier trained on CLEAR and RanSAP - NI.

Spec 6.1: *"The model was trained and evaluated using a subset of the EMBER
dataset ..., augmented with behavioral logs from the CLEAR dataset."* Until this
script existed that sentence was not true of anything in the repository: CLEAR
was read once to calibrate a threshold and RanSAP was only checked for
existence. This makes it true, by training a real classifier on both.

Why a second model rather than a merged feature matrix
------------------------------------------------------
An EMBER row is one PE file described by 2,381 static features. A CLEAR row and
a RanSAP row are each one I/O operation. There is no key that joins them, and
§6.1's own bullet list fixes the corpus at "50,000 PE files" - so adding I/O
rows to it would contradict the paragraph it is meant to satisfy. The honest
reading is that the *system's* detection draws on both, which is what this
implements: a static classifier over EMBER, and this one over the behavioural
logs.

What a sample is
----------------
One window of `WINDOW_OPERATIONS` consecutive operations from one trace. A
single I/O operation carries almost no signal - the EDA report shows why: the
ransomware trace's per-write entropy is bimodal, so any per-operation threshold
misclassifies either its zero-fill writes or its ciphertext. A window has a
*shape*, and the shape is what separates.

Evaluation
----------
Two numbers are reported and they answer different questions.

  * **Held-out split** - each trace's windows cut 70/15/15 in time order, never
    shuffled. Answers "does the signal hold up later in the same run".
  * **Leave-one-source-out** - train on every source but one, test on the one
    held out. Answers the question that actually matters: does a model that has
    never seen this process still classify it. With two ransomware families
    (WannaCry via RanSAP, BlackMatter via CLEAR) and five benign processes, this
    is the honest generalisation estimate, and it is the lower of the two.

Random shuffling would leak: consecutive windows from one run are strongly
correlated, so a shuffled split scores how well the model memorised a run.

    python src/train_io_behavior_model.py
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
MODEL_DIR = REPO_ROOT / "models"
REPORTS_DIR = REPO_ROOT / "reports"

# 256 operations is ~0.05s of the WannaCry trace and ~1.2s of the Firefox one.
# Small enough that a detector could form one in near-real-time, large enough
# that the entropy tail is estimated from a few hundred readings rather than a
# handful.
WINDOW_OPERATIONS = 256

# RanSAP's normalised entropy scale. "High" is the ciphertext mode and "low" is
# the zero-fill mode; both thresholds come from the measured distributions in
# reports/eda_report.md rather than being chosen for a nice result.
ENTROPY_HIGH = 0.9
ENTROPY_LOW = 0.05

RANSAP_READ_COLS = ["timestamp", "interval_gap", "offset", "size"]
RANSAP_WRITE_COLS = ["timestamp", "interval_gap", "offset", "size", "entropy_1", "entropy_2"]

# Order matters: the service builds its vector from this list.
FEATURE_NAMES = [
    "write_fraction",
    "ops_per_second",
    "mean_size",
    "size_4k_fraction",
    "size_std",
    "sequential_fraction",
    "distinct_offset_ratio",
    "offset_span_log",
    "entropy_mean",
    "entropy_std",
    "entropy_high_fraction",
    "entropy_low_fraction",
    "war_mean",
    "rar_mean",
    "raw_mean",
    "waw_mean",
]

# Features no source can supply for every window. XGBoost routes NaN down a
# learned default branch, so a window that genuinely has no entropy reading is
# scored on the features it does have rather than on an invented zero. Imputing
# zero here would mean "entropy was measured and it was zero", which is a
# different and false claim.
OPTIONAL_FEATURES = {
    "entropy_mean", "entropy_std", "entropy_high_fraction", "entropy_low_fraction",
    "war_mean", "rar_mean", "raw_mean", "waw_mean",
}


def _safe_std(values: np.ndarray) -> float:
    return float(np.std(values)) if len(values) > 1 else 0.0


def window_features(
    timestamps: np.ndarray,
    sizes: np.ndarray,
    offsets: np.ndarray,
    is_write: np.ndarray,
    entropy: np.ndarray | None = None,
    access_patterns: dict[str, np.ndarray] | None = None,
) -> dict[str, float]:
    """Aggregate one window of I/O operations into the model's feature row.

    Shared with the serving path: `services/ml-engine/io_features.py` imports
    the feature order from the metrics file and builds the same row, so training
    and inference cannot drift apart on column order.
    """
    count = len(timestamps)
    span = float(timestamps.max() - timestamps.min()) if count > 1 else 0.0

    # Consecutive operations that continue exactly where the previous one ended.
    # Sequential streaming is what a copy or a download looks like; scattered
    # rewriting is what encrypting a tree in place looks like.
    if count > 1:
        expected = offsets[:-1] + sizes[:-1]
        sequential = float(np.mean(expected == offsets[1:]))
    else:
        sequential = 0.0

    offset_span = float(offsets.max() - offsets.min()) if count > 1 else 0.0

    row: dict[str, float] = {
        "write_fraction": float(np.mean(is_write)),
        # +1 keeps a zero-duration window finite rather than infinite.
        "ops_per_second": float(count / (span + 1.0)),
        "mean_size": float(np.mean(sizes)),
        "size_4k_fraction": float(np.mean(sizes == 4096)),
        "size_std": _safe_std(sizes),
        "sequential_fraction": sequential,
        "distinct_offset_ratio": float(len(np.unique(offsets)) / count),
        "offset_span_log": math.log10(offset_span + 1.0),
    }

    if entropy is not None and len(entropy):
        row["entropy_mean"] = float(np.mean(entropy))
        row["entropy_std"] = _safe_std(entropy)
        row["entropy_high_fraction"] = float(np.mean(entropy > ENTROPY_HIGH))
        row["entropy_low_fraction"] = float(np.mean(entropy < ENTROPY_LOW))
    else:
        for name in ("entropy_mean", "entropy_std", "entropy_high_fraction", "entropy_low_fraction"):
            row[name] = math.nan

    for key, column in (("war_mean", "WAR"), ("rar_mean", "RAR"),
                        ("raw_mean", "RAW"), ("waw_mean", "WAW")):
        if access_patterns and column in access_patterns:
            row[key] = float(np.mean(access_patterns[column]))
        else:
            row[key] = math.nan

    return row


def _merge_run(read_path: Path, write_path: Path) -> pd.DataFrame | None:
    """One process's reads and writes, interleaved back into a single stream.

    RanSAP ships the two directions as separate files, but they are one process
    doing one job. Windowing them separately makes `write_fraction` a constant
    per file - 1.0 in every window from a write trace, 0.0 in every window from
    a read trace - so the model can identify the source file from that column
    alone and learns nothing about behaviour. Merging on timestamp restores the
    mix a detector would actually observe, and turns write_fraction into a real
    signal: an encryptor writes far more than it reads, a browser does not.
    """
    frames = []

    if read_path.is_file():
        reads = pd.read_csv(read_path, header=None, names=RANSAP_READ_COLS)
        reads["is_write"] = 0.0
        reads["entropy"] = math.nan
        frames.append(reads[["timestamp", "size", "offset", "is_write", "entropy"]])

    if write_path.is_file():
        writes = pd.read_csv(write_path, header=None, names=RANSAP_WRITE_COLS)
        writes["is_write"] = 1.0
        writes["entropy"] = writes["entropy_1"]
        frames.append(writes[["timestamp", "size", "offset", "is_write", "entropy"]])

    if not frames:
        return None

    merged = pd.concat(frames, ignore_index=True)
    # kind="stable" keeps each source file's own order inside a shared second,
    # which matters because RanSAP's timestamps are whole seconds.
    return merged.sort_values("timestamp", kind="stable").reset_index(drop=True)


def _windows_from_stream(frame: pd.DataFrame) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []

    for start in range(0, len(frame) - WINDOW_OPERATIONS + 1, WINDOW_OPERATIONS):
        chunk = frame.iloc[start : start + WINDOW_OPERATIONS]
        entropy = chunk["entropy"].to_numpy()
        entropy = entropy[~np.isnan(entropy)]
        rows.append(
            window_features(
                timestamps=chunk["timestamp"].to_numpy(),
                sizes=chunk["size"].to_numpy(),
                offsets=chunk["offset"].to_numpy(),
                is_write=chunk["is_write"].to_numpy(),
                entropy=entropy if len(entropy) else None,
                access_patterns=None,
            )
        )
    return rows


def build_ransap_windows() -> tuple[list[dict], list[int], list[str]]:
    """One source per instrumented *run*, not per direction of I/O."""
    runs = [
        (
            "ransap_wannacry",
            1,
            DATA_DIR / "ransap_logs" / "ransomware" / "wannacry" / "wannacry_read.csv",
            DATA_DIR / "ransap_logs" / "ransomware" / "wannacry" / "wannacry_write.csv",
        ),
        (
            "ransap_firefox",
            0,
            DATA_DIR / "ransap_logs" / "benign" / "firefox_read.csv",
            DATA_DIR / "ransap_logs" / "benign" / "firefox_write.csv",
        ),
    ]

    rows: list[dict] = []
    labels: list[int] = []
    sources: list[str] = []

    for name, label, read_path, write_path in runs:
        merged = _merge_run(read_path, write_path)
        if merged is None:
            print(f"  [skip] {name}: no trace files found")
            continue
        windows = _windows_from_stream(merged)
        rows.extend(windows)
        labels.extend([label] * len(windows))
        sources.extend([name] * len(windows))
        write_share = merged["is_write"].mean()
        print(
            f"  {name:24s} {len(merged):>7,} ops "
            f"({write_share:.0%} writes) -> {len(windows):>4} windows (label {label})"
        )

    return rows, labels, sources


def build_clear_windows() -> tuple[list[dict], list[int], list[str]]:
    path = DATA_DIR / "clear_io" / "wannacry_io_sample.csv"
    if not path.is_file():
        print(f"  [skip] CLEAR: {path} not found")
        return [], [], []

    frame = pd.read_csv(path).rename(
        columns={"Timestamp": "timestamp", "Offset": "offset", "Size": "size"}
    )
    # CLEAR encodes reads and writes in OpCode. 1 is read, 2 is write - the
    # ransomware sample's operations are overwhelmingly OpCode 2, and its WAW
    # counter is the one that moves, which is only consistent with 2 = write.
    frame["is_write"] = (frame["OpCode"] == 2).astype(float)

    # CLEAR is only 1,000 operations, so a 256-operation window leaves too few
    # samples to hold any out. Windows are formed per process instead, which is
    # also the unit a real detector would score: one process's burst of I/O.
    clear_window = 64
    access_columns = ["WAR", "RAR", "RAW", "WAW"]

    rows: list[dict] = []
    labels: list[int] = []
    sources: list[str] = []

    for (process, label), group in frame.groupby(["Process Name", "Label"], sort=True):
        group = group.sort_values("timestamp")
        for start in range(0, len(group) - clear_window + 1, clear_window):
            chunk = group.iloc[start : start + clear_window]
            rows.append(
                window_features(
                    timestamps=chunk["timestamp"].to_numpy(),
                    sizes=chunk["size"].to_numpy(),
                    offsets=chunk["offset"].to_numpy(),
                    is_write=chunk["is_write"].to_numpy(),
                    entropy=None,
                    access_patterns={c: chunk[c].to_numpy() for c in access_columns},
                )
            )
            labels.append(int(label))
            sources.append(f"clear_{process}")

    for source, count in sorted(Counter(sources).items()):
        print(f"  {source:28s} -> {count:>4} windows")

    return rows, labels, sources


def to_matrix(rows: list[dict]) -> np.ndarray:
    return np.array([[row[name] for name in FEATURE_NAMES] for row in rows], dtype=np.float32)


def _metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray | None) -> dict:
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "samples": int(len(y_true)),
    }
    # A leave-one-source-out fold holds out a single process, so it contains one
    # class only and ROC-AUC is undefined there. Reporting None is correct;
    # reporting 0.0 or 1.0 would be a made-up number.
    if y_proba is not None and len(np.unique(y_true)) > 1:
        out["roc_auc"] = float(roc_auc_score(y_true, y_proba))
    else:
        out["roc_auc"] = None
    return out


def _make_model(scale_pos_weight: float | None = None) -> xgb.XGBClassifier:
    return xgb.XGBClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight if scale_pos_weight else 1.0,
        eval_metric="logloss",
        n_jobs=-1,
        random_state=42,
    )


def temporal_split(sources: list[str], fractions=(0.70, 0.15)) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """70/15/15 within each source, in time order. Never shuffled.

    Windows are emitted in trace order, so slicing each source's index range by
    position is a split in time. Shuffling instead would put windows from either
    side of a boundary in both train and test - the same few seconds of one run
    - and the score would measure memorisation.
    """
    sources_array = np.array(sources)
    train, val, test = [], [], []

    for source in np.unique(sources_array):
        index = np.flatnonzero(sources_array == source)
        cut_train = int(len(index) * fractions[0])
        cut_val = int(len(index) * (fractions[0] + fractions[1]))
        train.extend(index[:cut_train])
        val.extend(index[cut_train:cut_val])
        test.extend(index[cut_val:])

    return np.array(sorted(train)), np.array(sorted(val)), np.array(sorted(test))


def leave_one_source_out(X: np.ndarray, y: np.ndarray, sources: list[str], use_smote: bool) -> dict:
    """Train without one source, test on it. The honest generalisation number."""
    sources_array = np.array(sources)
    folds = {}
    all_true: list[int] = []
    all_pred: list[int] = []

    for source in sorted(np.unique(sources_array)):
        held_out = sources_array == source
        X_train, y_train = X[~held_out], y[~held_out]
        X_test, y_test = X[held_out], y[held_out]

        if len(np.unique(y_train)) < 2:
            continue

        X_fit, y_fit = _maybe_smote(X_train, y_train) if use_smote else (X_train, y_train)
        ratio = (y_fit == 0).sum() / max((y_fit == 1).sum(), 1)
        model = _make_model(scale_pos_weight=ratio)
        model.fit(X_fit, y_fit, verbose=False)

        y_pred = model.predict(X_test)
        folds[source] = {
            **_metrics(y_test, y_pred, None),
            "true_label": int(y_test[0]),
            "correct": int((y_pred == y_test).sum()),
        }
        all_true.extend(y_test.tolist())
        all_pred.extend(y_pred.tolist())

    aggregate = _metrics(np.array(all_true), np.array(all_pred), None) if all_true else {}
    return {"folds": folds, "aggregate": aggregate}


def _maybe_smote(X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """SMOTE the training half only. Returns the input unchanged if it cannot run.

    SMOTE interpolates between nearest neighbours, and it cannot interpolate
    through NaN - which every window has, because no source supplies both the
    entropy and the access-pattern features. The columns are median-imputed for
    the resampling and the synthetic rows therefore carry imputed values in
    those positions. That is a real cost of using SMOTE on this corpus and it is
    why the with/without comparison in reports/ is the thing that decides
    whether it is used, rather than the fact that the spec names it.
    """
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        print("  [smote] imbalanced-learn not installed; skipping")
        return X, y

    from sklearn.impute import SimpleImputer

    minority = min(Counter(y).values())
    if minority < 6:
        print(f"  [smote] minority class has {minority} samples; too few to interpolate")
        return X, y

    imputer = SimpleImputer(strategy="median")
    X_filled = imputer.fit_transform(X)
    X_resampled, y_resampled = SMOTE(random_state=42, k_neighbors=min(5, minority - 1)).fit_resample(
        X_filled, y
    )
    return X_resampled.astype(np.float32), y_resampled


def deployability_verdict(held_out: dict, loso: dict, source_count: int) -> dict:
    """Decide, from the two scores, whether this model belongs on the serving path.

    A held-out temporal score is not evidence that a detector works. It is
    evidence that the second half of a run looks like the first half, which is
    true of almost any recording. The question a deployed classifier has to
    answer is about a process it has never seen, and leave-one-run-out is the
    measurement of that.

    The rule below is deliberately blunt: if the model cannot beat calling
    everything the majority class when a run is held out, it does not ship.
    """
    loso_accuracy = loso.get("aggregate", {}).get("accuracy")
    if loso_accuracy is None:
        return {"deployable": False, "reason": "leave-one-source-out could not be computed"}

    deployable = loso_accuracy >= 0.70 and source_count >= 10
    if deployable:
        reason = (
            f"leave-one-source-out accuracy {loso_accuracy:.4f} over {source_count} "
            "independent runs"
        )
    else:
        reason = (
            f"leave-one-source-out accuracy is {loso_accuracy:.4f} over only "
            f"{source_count} independent runs, against a held-out temporal score of "
            f"{held_out['accuracy']:.4f}. The gap is the finding: with one substantial "
            "run per class, removing it removes the entire class from the feature "
            "space and the model confidently assigns the remaining label. That is "
            "memorisation of a recording, not learning of a behaviour, so this model "
            "is a research artefact and is NOT wired into the detection path."
        )
    return {
        "deployable": deployable,
        "reason": reason,
        "leave_one_source_out_accuracy": loso_accuracy,
        "held_out_temporal_accuracy": held_out["accuracy"],
        "independent_runs": source_count,
    }


def train_once(
    X: np.ndarray,
    y: np.ndarray,
    sources: list[str],
    indices: tuple[np.ndarray, np.ndarray, np.ndarray],
    use_smote: bool,
) -> tuple[xgb.XGBClassifier, dict]:
    train_index, val_index, test_index = indices
    X_train, y_train = X[train_index], y[train_index]
    X_val, y_val = X[val_index], y[val_index]
    X_test, y_test = X[test_index], y[test_index]

    X_fit, y_fit = _maybe_smote(X_train, y_train) if use_smote else (X_train, y_train)
    ratio = (y_fit == 0).sum() / max((y_fit == 1).sum(), 1)
    model = _make_model(scale_pos_weight=ratio)
    model.fit(X_fit, y_fit, eval_set=[(X_val, y_val)], verbose=False)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    result = _metrics(y_test, y_pred, y_proba)
    result["train_class_balance"] = {str(k): int(v) for k, v in Counter(y_fit.tolist()).items()}
    return model, result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smote", action="store_true", help="oversample the minority class")
    parser.add_argument(
        "--compare-smote",
        action="store_true",
        help="train both ways and write reports/smote_comparison.json (A3)",
    )
    args = parser.parse_args()

    MODEL_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)

    print("Building windows from RanSAP...")
    ransap_rows, ransap_labels, ransap_sources = build_ransap_windows()
    print("Building windows from CLEAR...")
    clear_rows, clear_labels, clear_sources = build_clear_windows()

    rows = ransap_rows + clear_rows
    labels = ransap_labels + clear_labels
    sources = ransap_sources + clear_sources

    if not rows:
        raise SystemExit("No I/O trace data found under data/. Nothing to train on.")

    X = to_matrix(rows)
    y = np.array(labels, dtype=int)

    counts = Counter(y.tolist())
    ratio = counts.get(0, 0) / max(counts.get(1, 0), 1)
    print(
        f"\n{len(X)} windows, {X.shape[1]} features "
        f"({counts.get(0, 0)} benign / {counts.get(1, 0)} ransomware, ratio {ratio:.3f})"
    )
    print(f"Sources: {len(set(sources))}")

    indices = temporal_split(sources)
    print(f"Temporal split: train {len(indices[0])}  val {len(indices[1])}  test {len(indices[2])}")

    if args.compare_smote:
        # A3: p.40 prescribes "SMOTE oversampling + class weights in XGBoost".
        # Whether that helps is a measurement, not a preference, so both arms
        # are trained on the identical split and both are written out.
        comparison = {}
        for label, flag in (("without_smote", False), ("with_smote", True)):
            print(f"\n--- {label} ---")
            _, result = train_once(X, y, sources, indices, use_smote=flag)
            loso_arm = leave_one_source_out(X, y, sources, use_smote=flag)
            result["leave_one_source_out_accuracy"] = loso_arm["aggregate"].get("accuracy")
            comparison[label] = result
            print(f"  accuracy {result['accuracy']:.4f}  recall {result['recall']:.4f}  "
                  f"f1 {result['f1_score']:.4f}  loso {result['leave_one_source_out_accuracy']}")

        comparison["corpus"] = {
            "windows": int(len(X)),
            "class_balance": {"benign_0": int(counts.get(0, 0)),
                              "ransomware_1": int(counts.get(1, 0))},
            "imbalance_ratio": round(float(ratio), 4),
        }
        comparison["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        (REPORTS_DIR / "smote_comparison.json").write_text(json.dumps(comparison, indent=2))
        print(f"\nWrote {REPORTS_DIR / 'smote_comparison.json'}")
        return 0

    model, held_out = train_once(X, y, sources, indices, use_smote=args.smote)
    if args.smote:
        print(f"  after SMOTE: {held_out['train_class_balance']}")

    y_test = y[indices[2]]
    y_pred = model.predict(X[indices[2]])

    print("\n=== HELD-OUT TEMPORAL SPLIT ===")
    for key, value in held_out.items():
        print(f"{key}: {value}")
    print("\n" + classification_report(y_test, y_pred, target_names=["benign", "ransomware"],
                                       zero_division=0))

    print("=== LEAVE-ONE-SOURCE-OUT ===")
    loso = leave_one_source_out(X, y, sources, use_smote=args.smote)
    for source, fold in loso["folds"].items():
        print(f"  {source:32s} label {fold['true_label']}  "
              f"{fold['correct']}/{fold['samples']} correct")
    print(f"  aggregate accuracy: {loso['aggregate'].get('accuracy')}")

    verdict = deployability_verdict(held_out, loso, len(set(sources)))
    print(f"\n=== DEPLOYABLE: {verdict['deployable']} ===")
    print(verdict["reason"])

    importance = dict(zip(FEATURE_NAMES, (float(v) for v in model.feature_importances_)))

    metrics = {
        **held_out,
        "deployability": verdict,
        "leave_one_source_out": loso,
        "feature_names": FEATURE_NAMES,
        "optional_features": sorted(OPTIONAL_FEATURES),
        "feature_importance": importance,
        "window_operations": WINDOW_OPERATIONS,
        "windows_total": int(len(X)),
        "class_balance": {"benign_0": int(counts.get(0, 0)), "ransomware_1": int(counts.get(1, 0))},
        "imbalance_ratio": round(float(ratio), 4),
        "smote": bool(args.smote),
        "sources": sorted(set(sources)),
        "datasets": ["CLEAR", "RanSAP"],
        "split": "70/15/15 per source, time-ordered, never shuffled",
        "trained_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    joblib.dump(model, MODEL_DIR / "io_behavior_model.pkl")
    payload = json.dumps(metrics, indent=2)
    (MODEL_DIR / "io_behavior_model_metrics.json").write_text(payload)
    (REPORTS_DIR / "io_behavior_model_metrics.json").write_text(payload)

    print(f"\nModel   -> {MODEL_DIR / 'io_behavior_model.pkl'}")
    print(f"Metrics -> {MODEL_DIR / 'io_behavior_model_metrics.json'} (+ reports/)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
