"""
SUPERSEDED helper - drives the retired src/ml_api.py prototype, not the running
service. The live ML Engine is services/ml-engine/app.py and its tests are
services/ml-engine/tests/test_ml_api.py, which run under pytest with no server
to start by hand.

End-to-end test for the ML Engine API's /predict endpoint.
Unified Ransomware Detection & Recovery System
NI - Machine Learning Engineer

Sends real EMBER feature vectors (one confirmed-benign, one
confirmed-ransomware sample from your own test data) to the LIVE running
API and checks that the response matches the expected label.

Prereq: ml_api.py must already be running in another terminal:
    cd src
    uvicorn ml_api:app --reload --port 8002

Run this from a second terminal, from your project's src/ folder:
    python test_predict_endpoint.py
"""

import os
import requests
import numpy as np
import pandas as pd

script_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(script_dir, "..", "data", "ember_subset", "ember_50k.parquet")
API_URL = "http://localhost:8002"

print("Loading a benign sample and a ransomware sample from EMBER...")
df = pd.read_parquet(data_path)
df["label_int"] = df["label"].astype(int)
df["avclass_lower"] = df["avclass"].astype(str).str.lower()

benign_row = df[df["label_int"] == 0].iloc[0]
ransomware_row = df[df["avclass_lower"] == "wannacry"].iloc[0]

test_cases = [
    ("benign", benign_row),
    ("ransomware", ransomware_row),
]

for expected_label, row in test_cases:
    vector = row["x"].astype(float).tolist()
    payload = {"ember_vector": vector}

    print(f"\n--- Testing expected='{expected_label}' (avclass={row['avclass']}) ---")
    try:
        resp = requests.post(f"{API_URL}/predict", json=payload, timeout=10)
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not connect to the API. Is uvicorn running on port 8002?")
        break

    if resp.status_code != 200:
        print(f"FAILED - HTTP {resp.status_code}: {resp.text}")
        continue

    result = resp.json()
    print(f"Response: prediction={result['prediction']}, "
          f"confidence={result['confidence']:.4f}, "
          f"threat_level={result['threat_level']}")

    if result["prediction"] == expected_label:
        print("PASS - prediction matches expected label")
    else:
        print(f"MISMATCH - expected '{expected_label}' but got '{result['prediction']}'")

print("\n--- Testing /model/metrics ---")
resp = requests.get(f"{API_URL}/model/metrics", timeout=10)
print(f"HTTP {resp.status_code}")
print(resp.json() if resp.status_code == 200 else resp.text)
