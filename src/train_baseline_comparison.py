"""
Baseline Model Comparison: Random Forest vs XGBoost
Unified Ransomware Detection & Recovery System
NI - Machine Learning Engineer

Trains a Random Forest baseline on the same EMBER split used for the
XGBoost model, so Table 8.1 in your report has real comparison numbers
instead of placeholders.

Run from your project's src/ folder, AFTER train_ember_model.py:
    python train_baseline_comparison.py
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
)
import joblib

script_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(script_dir, "..", "data", "ember_subset", "ember_50k.parquet")
model_dir = os.path.join(script_dir, "..", "models")
reports_dir = os.path.join(script_dir, "..", "reports")

print("Loading EMBER dataset...")
df = pd.read_parquet(data_path)
X = np.stack(df["x"].values).astype(np.float32)
y = df["label"].astype(int).values

# Same split logic/seed as train_ember_model.py so the comparison is apples-to-apples
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.30, stratify=y, random_state=42
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
)

print("Training Random Forest baseline (this can take a few minutes on 2381 features)...")
rf_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced",
)
rf_model.fit(X_train, y_train)
print("Training complete.")

y_pred = rf_model.predict(X_test)
y_proba = rf_model.predict_proba(X_test)[:, 1]

rf_metrics = {
    "accuracy": accuracy_score(y_test, y_pred),
    "precision": precision_score(y_test, y_pred),
    "recall": recall_score(y_test, y_pred),
    "f1_score": f1_score(y_test, y_pred),
    "roc_auc": roc_auc_score(y_test, y_proba),
}

print("\n=== Random Forest Test Set Metrics ===")
for k, v in rf_metrics.items():
    print(f"{k}: {v:.4f}")

# Load the existing XGBoost metrics for a side-by-side table
xgb_metrics_path = os.path.join(reports_dir, "model_metrics.json")
if os.path.exists(xgb_metrics_path):
    with open(xgb_metrics_path) as f:
        xgb_metrics = json.load(f)

    print("\n=== Table 8.1: Model Performance Comparison ===")
    print(f"{'Model':<20}{'Accuracy':<12}{'Precision':<12}{'Recall':<12}{'F1-Score':<12}")
    print(f"{'Random Forest':<20}{rf_metrics['accuracy']:<12.4f}{rf_metrics['precision']:<12.4f}"
          f"{rf_metrics['recall']:<12.4f}{rf_metrics['f1_score']:<12.4f}")
    print(f"{'XGBoost (Ours)':<20}{xgb_metrics['accuracy']:<12.4f}{xgb_metrics['precision']:<12.4f}"
          f"{xgb_metrics['recall']:<12.4f}{xgb_metrics['f1_score']:<12.4f}")

# Save
joblib.dump(rf_model, os.path.join(model_dir, "random_forest_baseline.pkl"))
with open(os.path.join(reports_dir, "baseline_comparison.json"), "w") as f:
    json.dump({"random_forest": rf_metrics}, f, indent=2)
print(f"\nSaved model and metrics to models/ and reports/")
