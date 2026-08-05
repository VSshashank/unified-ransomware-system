import pandas as pd
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, "..", "data", "ember_subset", "ember_50k.parquet")

df = pd.read_parquet(file_path)

# Inspect the vector columns
print("=== x column ===")
print(type(df['x'].iloc[0]))
first_x = df['x'].iloc[0]
try:
    print("length:", len(first_x))
except:
    print("value:", first_x)

print("\n=== input column ===")
print(type(df['input'].iloc[0]))
first_input = df['input'].iloc[0]
try:
    print("length:", len(first_input))
except:
    print("value:", first_input)

# Inspect the label / metadata columns
print("\n=== label ===")
print(df['label'].value_counts())

print("\n=== y ===")
print(df['y'].value_counts())

print("\n=== subset ===")
print(df['subset'].value_counts())

print("\n=== avclass (sample) ===")
print(df['avclass'].value_counts().head(10))

print("\n=== appeared (sample) ===")
print(df['appeared'].head(5))

print("\n=== sha256 (sample) ===")
print(df['sha256'].head(3))