import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# --- 1. SETUP PATHS (Robust Way) ---
# This finds the file relative to where this script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, "..", "data", "ember_subset", "ember_50k.parquet")

print(f"Looking for data at: {file_path}")

if not os.path.exists(file_path):
    print("CRITICAL ERROR: File not found! Check your folders.")
    exit()

# --- 2. LOAD DATA ---
print("Loading data... (This might take a moment)")
df = pd.read_parquet(file_path)
print("Data loaded successfully!")

# --- 3. GENERATE STATISTICS FOR YOUR REPORT ---
print("\n" + "="*40)
print("     EDA REPORT DATA SUMMARY")
print("="*40)

# A. Basic Counts
total_samples = len(df)
print(f"1. Total Samples: {total_samples}")
print(f"2. Features (Columns): {len(df.columns)}")

# B. Class Balance (Benign vs Malicious)
# Note: Label 0 = Benign, 1 = Malicious
counts = df['label'].value_counts()
print("\n3. Class Distribution:")
print(counts)

if len(counts) == 2:
    print(f"   - Benign (0): {counts.get(0, 0)} ({(counts.get(0, 0)/total_samples)*100:.1f}%)")
    print(f"   - Malicious (1): {counts.get(1, 0)} ({(counts.get(1, 0)/total_samples)*100:.1f}%)")

# --- 4. VISUALIZATION (Save to file) ---
# We will create a simple bar chart showing the balance
plt.figure(figsize=(8, 5))
sns.countplot(x='label', data=df, palette='viridis')
plt.title('Dataset Balance: Benign (0) vs Ransomware (1)')
plt.xlabel('Label')
plt.ylabel('Count')

# Save the plot so you can put it in your report
plot_path = os.path.join(script_dir, "..", "class_balance_chart.png")
plt.savefig(plot_path)
print(f"\n[GRAPH SAVED] Chart saved to: {plot_path}")
print("="*40)