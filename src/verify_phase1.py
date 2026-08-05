import os
import pandas as pd

# Define paths relative to this script
base_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(base_dir, "..", "data")

# The Checklist of REQUIRED files for Phase 1
files = {
    "1. EMBER (Static Analysis)":      os.path.join(data_dir, "ember_subset", "ember_50k.parquet"),
    "2. RanSAP (Ransomware Logs)":     os.path.join(data_dir, "ransap_logs", "ransomware", "wannacry", "wannacry_write.csv"),
    "3. RanSAP (Benign Logs)":         os.path.join(data_dir, "ransap_logs", "benign", "firefox_write.csv"),
    "4. CLEAR (I/O Stream)":           os.path.join(data_dir, "clear_io", "wannacry_io_sample.csv")
}

print("="*50)
print("PHASE 1: FINAL COMPLETION CHECK")
print("="*50)

all_pass = True

for name, path in files.items():
    print(f"Checking {name}...", end=" ")
    if os.path.exists(path):
        size_mb = os.path.getsize(path) / (1024 * 1024)
        print(f"[✅ OK] - {size_mb:.2f} MB")
    else:
        print(f"[❌ MISSING]")
        print(f"   -> Expected at: {path}")
        all_pass = False

print("-" * 50)
if all_pass:
    print("🎉 CONGRATULATIONS! You have officially completed Weeks 1-4.")
    print("Next Step: Begin Week 5 (Feature Engineering).")
else:
    print("⚠️  INCOMPLETE: Please download the missing files listed above.")