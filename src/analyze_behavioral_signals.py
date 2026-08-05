"""
Phase 3: Behavioral / Entropy Analysis
Unified Ransomware Detection & Recovery System
NI - Machine Learning Engineer

Analyzes the RanSAP (I/O traces) and CLEAR (behavioral) datasets to:
 - characterize entropy differences between ransomware and benign I/O
 - calibrate the entropy detection threshold used by the Monitor Service
 - summarize behavioral (WAR/RAR/RAW/WAW) patterns from CLEAR

NOTE: These logs are continuous single-process traces (one WannaCry run,
one Firefox run) rather than per-sample rows like EMBER. They are NOT
merged into the EMBER feature matrix for training the XGBoost classifier -
they're used to calibrate thresholds and produce the demonstration evidence
required in Chapter 6 (Testing Scenarios) and Chapter 7 (Demonstration
Evidence) of your report.

Run from your project's src/ folder:
    python analyze_behavioral_signals.py
"""

import os
import pandas as pd
import matplotlib.pyplot as plt

script_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(script_dir, "..", "data")
reports_dir = os.path.join(script_dir, "..", "reports")
os.makedirs(reports_dir, exist_ok=True)

READ_COLS = ["timestamp", "interval_gap", "offset", "size"]
WRITE_COLS = ["timestamp", "interval_gap", "offset", "size", "entropy_1", "entropy_2"]


def load_ransap(path, cols):
    return pd.read_csv(path, header=None, names=cols)


# --- 1. Load RanSAP logs ---
ransomware_write = load_ransap(
    os.path.join(data_dir, "ransap_logs", "ransomware", "wannacry", "wannacry_write.csv"),
    WRITE_COLS,
)
benign_write = load_ransap(
    os.path.join(data_dir, "ransap_logs", "benign", "firefox_write.csv"),
    WRITE_COLS,
)
ransomware_read = load_ransap(
    os.path.join(data_dir, "ransap_logs", "ransomware", "wannacry", "wannacry_read.csv"),
    READ_COLS,
)
benign_read = load_ransap(
    os.path.join(data_dir, "ransap_logs", "benign", "firefox_read.csv"),
    READ_COLS,
)

print(f"WannaCry writes: {len(ransomware_write)} events")
print(f"Firefox writes:  {len(benign_write)} events")

# --- 2. Entropy comparison ---
print("\n=== Entropy Summary (entropy_1) ===")
print("WannaCry:\n", ransomware_write["entropy_1"].describe())
print("\nFirefox:\n", benign_write["entropy_1"].describe())

plt.figure(figsize=(8, 5))
plt.hist(ransomware_write["entropy_1"], bins=50, alpha=0.6, label="WannaCry (ransomware)")
plt.hist(benign_write["entropy_1"], bins=50, alpha=0.6, label="Firefox (benign)")
plt.xlabel("Write entropy")
plt.ylabel("Event count")
plt.title("Write Entropy Distribution: Ransomware vs Benign")
plt.legend()
plt.tight_layout()
entropy_plot_path = os.path.join(reports_dir, "entropy_distribution.png")
plt.savefig(entropy_plot_path)
print(f"\nEntropy distribution chart saved to: {entropy_plot_path}")

# --- 3. Suggest a detection threshold ---
# Midpoint between benign p95 and ransomware p5 - a simple, defensible way
# to pick a threshold that minimizes both false positives and false negatives.
benign_p95 = benign_write["entropy_1"].quantile(0.95)
ransom_p05 = ransomware_write["entropy_1"].quantile(0.05)
suggested_threshold = (benign_p95 + ransom_p05) / 2

print(f"\nBenign 95th percentile entropy: {benign_p95:.4f}")
print(f"Ransomware 5th percentile entropy: {ransom_p05:.4f}")
print(f"Suggested entropy threshold: {suggested_threshold:.4f}")

# --- 4. Write frequency (modification rate proxy) ---
ransomware_write["timestamp"] = pd.to_datetime(ransomware_write["timestamp"], unit="s")
benign_write["timestamp"] = pd.to_datetime(benign_write["timestamp"], unit="s")

ransom_duration = (ransomware_write["timestamp"].max() - ransomware_write["timestamp"].min()).total_seconds()
benign_duration = (benign_write["timestamp"].max() - benign_write["timestamp"].min()).total_seconds()

ransom_rate = len(ransomware_write) / max(ransom_duration, 1)
benign_rate = len(benign_write) / max(benign_duration, 1)

print(f"\nWannaCry write rate: {ransom_rate:.2f} writes/sec")
print(f"Firefox write rate:  {benign_rate:.2f} writes/sec")

# --- 5. CLEAR behavioral fingerprint (WAR/RAR/RAW/WAW) ---
clear_path = os.path.join(data_dir, "clear_io", "wannacry_io_sample.csv")
clear_df = pd.read_csv(clear_path)

behavioral_summary = clear_df.groupby("Label")[["WAR", "RAR", "RAW", "WAW"]].mean()
print("\n=== CLEAR Behavioral Fingerprint (mean counts by Label) ===")
print(behavioral_summary)

# --- 6. Save summary report (useful for Chapter 6/7 write-up) ---
summary_path = os.path.join(reports_dir, "behavioral_analysis_summary.txt")
with open(summary_path, "w") as f:
    f.write("Behavioral / Entropy Analysis Summary\n")
    f.write("=" * 40 + "\n")
    f.write(f"Suggested entropy threshold: {suggested_threshold:.4f}\n")
    f.write(f"WannaCry write rate: {ransom_rate:.2f} writes/sec\n")
    f.write(f"Firefox write rate: {benign_rate:.2f} writes/sec\n\n")
    f.write("CLEAR behavioral fingerprint (mean by label):\n")
    f.write(behavioral_summary.to_string())

print(f"\nSummary report saved to: {summary_path}")
