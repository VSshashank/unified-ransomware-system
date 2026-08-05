import pandas as pd
import os
from datasets import load_dataset

# 1. Setup Paths
file_path = "../data/ember_subset/ember_50k.parquet"
os.makedirs(os.path.dirname(file_path), exist_ok=True)

print("Starting stream from HuggingFace (EMBER 2018)...")

# 2. Load the dataset (Streaming mode)
dataset = load_dataset("cw1521/ember2018-malware", split="train", streaming=True)

benign_samples = []
malicious_samples = []
target_count = 25000  # We want 25k of each

print(f"Goal: {target_count} Benign and {target_count} Malicious samples.")

# 3. Processing Loop
for i, sample in enumerate(dataset):
    
    # --- CRITICAL FIX: Convert String '0' to Integer 0 ---
    try:
        raw_label = sample['label']
        label = int(raw_label) # Forces '0' to become 0
    except (ValueError, TypeError):
        continue # Skip if label is garbage
    # -----------------------------------------------------

    # Skip Unlabeled (-1)
    if label == -1:
        continue

    # Collect Benign (0)
    if label == 0:
        if len(benign_samples) < target_count:
            benign_samples.append(sample)
    
    # Collect Malicious (1)
    elif label == 1:
        if len(malicious_samples) < target_count:
            malicious_samples.append(sample)
    
    # Progress Update (Shows us it is working!)
    total_found = len(benign_samples) + len(malicious_samples)
    if total_found % 1000 == 0 and total_found > 0:
        print(f"Progress: Benign {len(benign_samples)} | Malicious {len(malicious_samples)}")

    # STOP when we have enough of BOTH
    if len(benign_samples) >= target_count and len(malicious_samples) >= target_count:
        print("Target reached!")
        break

# 4. Save to Disk
print(f"Finished! Total collected: {len(benign_samples)} Benign, {len(malicious_samples)} Malicious.")

if len(benign_samples) > 0:
    df = pd.DataFrame(benign_samples + malicious_samples)
    df.to_parquet(file_path)
    print(f"SUCCESS: Data saved to {file_path}")
else:
    print("ERROR: No data collected. Something is still wrong.")