"""
Phase 3 - Sprint 2: EMBER XGBoost Baseline Model
Unified Ransomware Detection & Recovery System
NI - Machine Learning Engineer

Trains the primary static-analysis classifier ("ML Engine" service, Section
3.4.2 of the project doc) on the EMBER feature vectors.

Run from your project's src/ folder:
    python train_ember_model.py
"""

import os
import json
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_score, recall_score, f1_score, accuracy_score
)
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# --- 1. Paths ---
script_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(script_dir, "..", "data", "ember_subset", "ember_50k.parquet")
model_dir = os.path.join(script_dir, "..", "models")
reports_dir = os.path.join(script_dir, "..", "reports")
os.makedirs(model_dir, exist_ok=True)
os.makedirs(reports_dir, exist_ok=True)

# --- 2. Load data ---
print("Loading EMBER dataset...")
df = pd.read_parquet(data_path)
print(f"Loaded {len(df)} rows.")

# The 'x' column holds a 2381-length numpy array per row (the standard EMBER
# static feature vector). Stack into a proper 2D matrix. float32 keeps
# memory reasonable (50000 x 2381 float32 ~= 450MB vs ~900MB in float64).
print("Stacking feature vectors (can take ~30-60s for 50k rows)...")
X = np.stack(df["x"].values).astype(np.float32)
y = df["label"].values.astype(int)
print(f"Feature matrix shape: {X.shape}")

# --- 3. Train/val/test split (70/15/15, matches your doc's target split) ---
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.30, stratify=y, random_state=42
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
)
print(f"Train: {X_train.shape[0]}  Val: {X_val.shape[0]}  Test: {X_test.shape[0]}")

# --- 4. Train baseline XGBoost ---
scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)

model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    eval_metric="logloss",
    n_jobs=-1,
    random_state=42,
)

print("Training XGBoost model...")
model.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    verbose=False,
)
print("Training complete.")

# --- 5. Evaluate on held-out test set ---
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

metrics = {
    "accuracy": accuracy_score(y_test, y_pred),
    "precision": precision_score(y_test, y_pred),
    "recall": recall_score(y_test, y_pred),
    "f1_score": f1_score(y_test, y_pred),
    "roc_auc": roc_auc_score(y_test, y_proba),
}

print("\n=== TEST SET METRICS ===")
for k, v in metrics.items():
    print(f"{k}: {v:.4f}")

print("\n" + classification_report(y_test, y_pred, target_names=["benign", "ransomware"]))

# --- 6. Confusion matrix plot (Figure 8.1 in your doc) ---
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["benign", "ransomware"],
            yticklabels=["benign", "ransomware"])
plt.title("Confusion Matrix - EMBER Test Set")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
cm_path = os.path.join(reports_dir, "confusion_matrix.png")
plt.savefig(cm_path)
print(f"\nConfusion matrix saved to: {cm_path}")

# --- 7. Save model + metrics ---
model_path = os.path.join(model_dir, "xgboost_model.pkl")
joblib.dump(model, model_path)
print(f"Model saved to: {model_path}")

metrics_path = os.path.join(reports_dir, "model_metrics.json")
with open(metrics_path, "w") as f:
    json.dump(metrics, f, indent=2)
print(f"Metrics saved to: {metrics_path}")

print("\nDone. Next: SHAP analysis, then wrap this model in the FastAPI /predict service.")
