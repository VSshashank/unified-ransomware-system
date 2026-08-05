"""
Phase 5 (pulled forward): SHAP Explainability Analysis
Unified Ransomware Detection & Recovery System
NI - Machine Learning Engineer

Loads the trained model and generates SHAP value explanations, matching
the "Explainable AI" key innovation (Section 1.4) and the
features_importance field in the /predict API response (Section 3.4.2).

Run from your project's src/ folder, AFTER train_ember_model.py:
    python shap_analysis.py
"""

import os
import json
import numpy as np
import pandas as pd
import joblib
import shap
import matplotlib.pyplot as plt

script_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(script_dir, "..", "data", "ember_subset", "ember_50k.parquet")
model_path = os.path.join(script_dir, "..", "models", "xgboost_model.pkl")
reports_dir = os.path.join(script_dir, "..", "reports")
os.makedirs(reports_dir, exist_ok=True)

# EMBER's 2381-dim vector is a concatenation of named feature groups, in
# this fixed order. Mapping an index to its group makes SHAP output
# interpretable instead of a bare "ember_637".
EMBER_FEATURE_GROUPS = [
    (0, 10, "general_file_info"),
    (10, 72, "header_info"),
    (72, 328, "byte_histogram"),
    (328, 584, "byte_entropy_histogram"),
    (584, 688, "string_info"),
    (688, 1968, "imported_functions"),
    (1968, 2096, "exported_functions"),
    (2096, 2351, "section_info"),
    (2351, 2381, "data_directories"),
]


def feature_group(idx: int) -> str:
    for start, end, name in EMBER_FEATURE_GROUPS:
        if start <= idx < end:
            return name
    return "unknown"

# --- 1. Load model + a sample of data for SHAP (SHAP is slow on full 50k rows) ---
print("Loading model...")
model = joblib.load(model_path)

print("Loading data sample for SHAP (500 rows)...")
df = pd.read_parquet(data_path)
sample = df.sample(n=500, random_state=42)
X_sample = np.stack(sample["x"].values).astype(np.float32)
feature_names = [f"ember_{i}" for i in range(X_sample.shape[1])]

# --- 2. Compute SHAP values ---
print("Computing SHAP values (this can take a few minutes)...")
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_sample)

# --- 3. Global feature importance (top 20) ---
mean_abs_shap = np.abs(shap_values).mean(axis=0)
top_idx = np.argsort(mean_abs_shap)[::-1][:20]

top_features = {
    feature_names[i]: {
        "importance": float(mean_abs_shap[i]),
        "group": feature_group(i),
    }
    for i in top_idx
}
print("\n=== Top 20 Most Important Features ===")
for name, info in top_features.items():
    print(f"{name} ({info['group']}): {info['importance']:.4f}")

# Also aggregate importance by group - useful for a summary chart in your report
group_totals = {}
for i, val in enumerate(mean_abs_shap):
    g = feature_group(i)
    group_totals[g] = group_totals.get(g, 0.0) + float(val)
print("\n=== Total Importance by Feature Group (top 20 features only) ===")
for g, total in sorted(group_totals.items(), key=lambda x: -x[1]):
    print(f"{g}: {total:.4f}")

importance_path = os.path.join(reports_dir, "shap_feature_importance.json")
with open(importance_path, "w") as f:
    json.dump({"top_features": top_features, "group_totals": group_totals}, f, indent=2)
print(f"\nSaved to: {importance_path}")

# --- 4. Summary plot ---
plt.figure()
shap.summary_plot(
    shap_values, X_sample, feature_names=feature_names,
    max_display=20, show=False
)
plt.tight_layout()
summary_plot_path = os.path.join(reports_dir, "shap_summary_plot.png")
plt.savefig(summary_plot_path, bbox_inches="tight")
print(f"Summary plot saved to: {summary_plot_path}")

print("\nDone. Use shap_feature_importance.json for the features_importance")
print("field format expected by the ML Engine API's /predict response.")
