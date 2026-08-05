import pandas as pd
import os

# 1. Setup Paths
base_dir = os.path.dirname(os.path.abspath(__file__))
ransap_dir = os.path.join(base_dir, "..", "data", "ransap_logs")

# Define the 4 files we need
files_to_check = {
    "WannaCry Read":  os.path.join(ransap_dir, "ransomware", "wannacry", "wannacry_read.csv"),
    "WannaCry Write": os.path.join(ransap_dir, "ransomware", "wannacry", "wannacry_write.csv"),
    "Benign Read":    os.path.join(ransap_dir, "benign", "firefox_read.csv"),
    "Benign Write":   os.path.join(ransap_dir, "benign", "firefox_write.csv")
}

print("--- Final RanSAP Verification ---")

all_good = True

for name, path in files_to_check.items():
    if os.path.exists(path):
        try:
            # Try to read just the first 3 rows
            df = pd.read_csv(path, header=None, nrows=3)
            print(f"[SUCCESS] {name} found and readable.")
        except Exception as e:
            print(f"[ERROR] {name} exists but cannot be read: {e}")
            all_good = False
    else:
        print(f"[MISSING] {name} NOT found at: {path}")
        all_good = False

print("-" * 30)
if all_good:
    print("PERFECT! You have all required RanSAP files.")
else:
    print("WARNING: Some files are missing. Please check the paths.")