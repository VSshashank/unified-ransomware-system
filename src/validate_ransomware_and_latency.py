"""
Phase 3/6: Ransomware-Specific Validation + Latency Benchmark
Unified Ransomware Detection & Recovery System
NI - Machine Learning Engineer

Your doc's title and Chapter 6.4 ("Known Ransomware Simulation") promise
ransomware-specific detection, not just general malware detection. This
script:
  1. Filters the malicious EMBER samples down to known ransomware families
     (via avclass) and reports accuracy/recall on THAT subset specifically.
  2. Benchmarks per-sample inference latency against the <100ms target
     (Table 4.2, Week 13-16 deliverable).

Run from your project's src/ folder, AFTER train_ember_model.py:
    python validate_ransomware_and_latency.py
"""

import os
import json
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

script_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(script_dir, "..", "data", "ember_subset", "ember_50k.parquet")
model_path = os.path.join(script_dir, "..", "models", "xgboost_model.pkl")
reports_dir = os.path.join(script_dir, "..", "reports")
os.makedirs(reports_dir, exist_ok=True)

# Known ransomware family names as they commonly appear in avclass output.
# EDIT THIS LIST after checking what ransomware families actually show up
# in your avclass value_counts (wannacry is confirmed present; add others
# you see - e.g. locky, cerber, ryuk, cryptolocker, teslacrypt, petya, gandcrab).
RANSOMWARE_FAMILIES = ["wannacry", "locky", "cerber", "ryuk", "cryptolocker",
                       "teslacrypt", "petya", "gandcrab", "sodinokibi", "revil"]

print("Loading model and data...")
model = joblib.load(model_path)
df = pd.read_parquet(data_path)

# --- 1. Isolate ransomware-family samples ---
# NOTE: EMBER's 'label' column is stored as string dtype ("0"/"1"), not
# int - cast explicitly before filtering, or comparisons like
# df["label"] == 0 silently match nothing.
df["label_int"] = df["label"].astype(int)
df["avclass_lower"] = df["avclass"].astype(str).str.lower()
ransomware_mask = df["avclass_lower"].isin(RANSOMWARE_FAMILIES)
ransomware_df = df[ransomware_mask]
benign_df = df[df["label_int"] == 0]

print(f"\nFound {len(ransomware_df)} ransomware-family samples:")
print(ransomware_df["avclass_lower"].value_counts())

if len(ransomware_df) == 0:
    print("\nWARNING: No ransomware-family samples matched. Check the avclass")
    print("value_counts from check_ember_schema.py output and update the")
    print("RANSOMWARE_FAMILIES list above with the exact family names present.")
else:
    # Build a balanced-ish eval set: all ransomware samples + an equal
    # number of random benign samples (so recall isn't inflated by a
    # trivially easy majority class).
    n = len(ransomware_df)
    benign_sample = benign_df.sample(n=min(n, len(benign_df)), random_state=42)

    eval_df = pd.concat([ransomware_df, benign_sample])
    X_eval = np.stack(eval_df["x"].values).astype(np.float32)
    y_eval = eval_df["label_int"].values

    y_pred = model.predict(X_eval)

    print("\n=== RANSOMWARE-SPECIFIC EVALUATION ===")
    print(f"Ransomware samples: {n} | Benign comparison samples: {len(benign_sample)}")
    ransomware_metrics = {
        "accuracy": accuracy_score(y_eval, y_pred),
        "precision": precision_score(y_eval, y_pred),
        "recall": recall_score(y_eval, y_pred),
        "f1_score": f1_score(y_eval, y_pred),
    }
    for k, v in ransomware_metrics.items():
        print(f"{k}: {v:.4f}")

    # Recall on ransomware samples ONLY (the number that matters most -
    # "did we catch the ransomware", not "did we get the easy benign ones right")
    ransomware_only_mask = y_eval == 1
    ransomware_recall = recall_score(
        y_eval[ransomware_only_mask], y_pred[ransomware_only_mask],
        pos_label=1, zero_division=0
    ) if ransomware_only_mask.sum() > 0 else None
    ransomware_detect_rate = (y_pred[ransomware_only_mask] == 1).mean()
    print(f"\nRansomware detection rate (recall on ransomware-only rows): {ransomware_detect_rate:.4f}")

    with open(os.path.join(reports_dir, "ransomware_specific_metrics.json"), "w") as f:
        json.dump({**ransomware_metrics, "ransomware_detection_rate": float(ransomware_detect_rate)}, f, indent=2)
    print(f"\nSaved to: {reports_dir}/ransomware_specific_metrics.json")

# --- 2. Inference latency benchmark ---
print("\n=== INFERENCE LATENCY BENCHMARK ===")
sample_rows = df.sample(n=1000, random_state=42)
X_bench = np.stack(sample_rows["x"].values).astype(np.float32)

# Warm-up (first call is often slower due to lazy init)
_ = model.predict(X_bench[:10])

latencies = []
for i in range(len(X_bench)):
    row = X_bench[i:i+1]
    start = time.perf_counter()
    model.predict(row)
    latencies.append((time.perf_counter() - start) * 1000)  # ms

latencies = np.array(latencies)
print(f"Mean latency:   {latencies.mean():.2f} ms")
print(f"Median latency: {np.median(latencies):.2f} ms")
print(f"p95 latency:    {np.percentile(latencies, 95):.2f} ms")
print(f"p99 latency:    {np.percentile(latencies, 99):.2f} ms")
print(f"Max latency:    {latencies.max():.2f} ms")
print(f"\nTarget: <100ms per sample -> {'PASS' if np.percentile(latencies, 95) < 100 else 'FAIL'}")

with open(os.path.join(reports_dir, "latency_benchmark.json"), "w") as f:
    json.dump({
        "mean_ms": float(latencies.mean()),
        "median_ms": float(np.median(latencies)),
        "p95_ms": float(np.percentile(latencies, 95)),
        "p99_ms": float(np.percentile(latencies, 99)),
        "max_ms": float(latencies.max()),
    }, f, indent=2)
print(f"Saved to: {reports_dir}/latency_benchmark.json")
