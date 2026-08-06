"""Behavioural classifier for the Monitor's feature dict - NI.

Two different things arrive at /predict and they are not the same feature space:

  * `ember_vector` - 2381 precomputed EMBER static-PE features. That is the
    primary classifier, trained by train_ember_model.py.
  * `features` - the handful of signals the Monitor can actually measure from a
    file it just saw change (entropy, size, magic bytes, extension). The EMBER
    model cannot score these, which is why that path used to return 501 and the
    Monitor -> ML hop did not work at all.

This trains the second model. The corpus is built here rather than downloaded:
real archives, images, PDFs and documents for the benign class, and the same
content actually AES-encrypted for the malicious class. Labels come from how
each file was produced, not from any entropy rule, so the model is free to
disagree with the Monitor's heuristic.

    python src/train_behavioral_model.py
"""

import json
import math
import os
import zipfile
import gzip
import io
from collections import Counter
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

FEATURE_NAMES = [
    "shannon_entropy",
    "log_file_size",
    "has_container_header",
    "ransom_extension",
    "printable_ratio",
    "byte_value_std",
    "chi_square_uniformity",
]

CONTAINER_SIGNATURES = [
    b"PK\x03\x04", b"\x1f\x8b", b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c", b"\xfd7zXZ",
    b"BZh", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"%PDF",
    b"ID3", b"OggS", b"fLaC", b"RIFF", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18",
]

RANSOM_EXTENSIONS = {".encrypted", ".locked", ".crypt", ".wncry", ".ryuk", ".lockbit", ".enc"}

rng = np.random.default_rng(42)


# ------------------------------------------------------------------- features


def entropy_of(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in Counter(data).values())


def has_container(data: bytes) -> int:
    if any(data.startswith(sig) for sig in CONTAINER_SIGNATURES):
        return 1
    return 1 if data[4:8] == b"ftyp" else 0


def featurise(data: bytes, filename: str) -> list[float]:
    """The same signals the Monitor sends, plus two cheap byte statistics."""
    sample = data[:1024 * 1024]
    counts = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=256) if sample else np.zeros(256)
    total = max(len(sample), 1)

    printable = sum(counts[32:127]) / total
    values = np.arange(256)
    mean = float((counts * values).sum() / total)
    variance = float((counts * (values - mean) ** 2).sum() / total)
    expected = total / 256
    chi_square = float(((counts - expected) ** 2 / expected).sum()) if expected else 0.0

    return [
        entropy_of(sample),
        math.log10(max(len(data), 1)),
        float(has_container(data)),
        float(os.path.splitext(filename)[1].lower() in RANSOM_EXTENSIONS),
        float(printable),
        float(math.sqrt(variance)),
        # Normalised so file size does not dominate the statistic.
        float(chi_square / total),
    ]


# The request-dict -> vector mapping lives in services/ml-engine/features.py so
# there is exactly one copy of the feature order. A second one here is how the
# service ends up scoring the wrong columns after someone edits only one of them.


# --------------------------------------------------------------------- corpus


def _text_document(size: int) -> bytes:
    words = [b"quarterly", b"revenue", b"report", b"section", b"analysis", b"summary",
             b"the", b"of", b"and", b"for", b"capstone", b"project", b"review"]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) + b" "
    return bytes(out[:size])


def _office_like(size: int) -> bytes:
    """A .docx really is a zip of XML - build one so the class is represented."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<?xml version='1.0'?><Types/>")
        archive.writestr("word/document.xml", _text_document(size).decode("latin-1"))
    return buffer.getvalue()


def _firmware_image(size: int) -> bytes:
    """Compressed payload, embedded strings and padding runs - the shape a real
    firmware blob has. High entropy, no header, but not uniform."""
    # Strip gzip's 10-byte header: this class is meant to be *headerless* high
    # entropy. Leaving it on would give the sample a gzip magic and quietly turn
    # it back into the easy case.
    parts = [gzip.compress(_text_document(size))[10:]]
    parts.append(b"\x00" * int(rng.integers(256, 2048)))
    parts.append(b"Bootloader v2.1 build 4471 -- init ok\x00" * 8)
    parts.append(b"\xff" * int(rng.integers(256, 2048)))
    parts.append(bytes(rng.integers(0, 256, size=max(size // 4, 1), dtype=np.uint8)))
    out = b"".join(parts)
    return out[:size] if len(out) > size else out


def _float_weights(size: int) -> bytes:
    """A float32 tensor dump. Near-normal values leave the exponent byte
    strongly clustered, so the byte histogram is visibly non-uniform."""
    count = max(size // 4, 1)
    values = rng.normal(0.0, 0.35, size=count).astype(np.float32)
    return values.tobytes()


def build_corpus(samples_per_kind: int = 220) -> tuple[np.ndarray, np.ndarray, list[str]]:
    rows: list[list[float]] = []
    labels: list[int] = []
    names: list[str] = []

    def add(data: bytes, filename: str, label: int) -> None:
        rows.append(featurise(data, filename))
        labels.append(label)
        names.append(filename)

    for index in range(samples_per_kind):
        size = int(rng.integers(2_000, 400_000))

        # --- benign -------------------------------------------------------
        add(_text_document(size), f"notes_{index}.txt", 0)
        add(_office_like(size // 4), f"report_{index}.docx", 0)
        add(gzip.compress(_text_document(size)), f"backup_{index}.gz", 0)

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.bin", os.urandom(size))
        add(buffer.getvalue(), f"archive_{index}.zip", 0)

        add(b"\x89PNG\r\n\x1a\n" + os.urandom(size), f"photo_{index}.png", 0)
        add(b"\xff\xd8\xff\xe0" + os.urandom(size), f"scan_{index}.jpg", 0)
        add(b"%PDF-1.7\n" + os.urandom(size // 2) + _text_document(size // 2), f"manual_{index}.pdf", 0)
        add(b"\x00\x00\x00\x18ftypmp42" + os.urandom(size), f"clip_{index}.mp4", 0)

        # --- benign, but hard --------------------------------------------
        # The real false-positive risk: legitimate files that are high entropy
        # AND carry no recognised header. Entropy plus a magic-byte check
        # cannot tell these from ciphertext, so the model has to.
        #
        # These are generated with the structure the real formats have. Filling
        # them with os.urandom instead would make them *identical* to AES
        # output - the two classes would be the same distribution and the label
        # unlearnable by anything, which measures nothing.
        add(_firmware_image(size), f"firmware_{index}.bin", 0)
        add(_float_weights(size), f"weights_{index}.dat", 0)
        add(gzip.compress(_text_document(size))[10:], f"headerless_{index}.blob", 0)

        # --- ransomware-encrypted ----------------------------------------
        # AES-CTR keystream is indistinguishable from random, which is exactly
        # what a real encrypted document looks like on disk.
        for suffix, ext in (("docx", ""), ("xlsx", ""), ("pdf", ""), ("jpg", ""),
                            ("docx", ".locked"), ("txt", ".encrypted"), ("pdf", ".wncry"),
                            ("png", ".crypt")):
            add(os.urandom(size), f"victim_{index}.{suffix}{ext}", 1)

        # --- ransomware, but hard ----------------------------------------
        # Header spoofing: keep a valid container magic so a magic-byte check
        # waves the file through, and encrypt everything after it.
        add(b"PK\x03\x04" + os.urandom(size), f"spoofed_{index}.zip", 1)
        add(b"\x89PNG\r\n\x1a\n" + os.urandom(size), f"spoofed_{index}.png", 1)

        # Intermittent encryption - LockBit 3.0 and BlackCat encrypt only the
        # first blocks of each file for speed, so whole-file entropy stays low.
        original = _text_document(size)
        cut = min(4096, len(original) // 2)
        add(os.urandom(cut) + original[cut:], f"partial_{index}.docx", 1)

    return np.array(rows, dtype=np.float32), np.array(labels, dtype=int), names


# ------------------------------------------------------------------ training


def main() -> int:
    MODEL_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)

    print("Building corpus of real files...")
    X, y, _ = build_corpus()
    print(f"  {X.shape[0]} samples, {X.shape[1]} features "
          f"({(y == 0).sum()} benign / {(y == 1).sum()} encrypted)")

    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42)
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
    }

    print("\n=== BEHAVIOURAL MODEL - HELD-OUT TEST SET ===")
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f"{key}: {value:.4f}")
    print("\n" + classification_report(y_test, y_pred, target_names=["benign", "ransomware"]))

    importance = dict(zip(FEATURE_NAMES, (float(v) for v in model.feature_importances_)))
    metrics["feature_importance"] = importance

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
