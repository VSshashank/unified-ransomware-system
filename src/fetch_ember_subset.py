"""Fetch a balanced EMBER-2018 subset and build the training parquet - NI.

`download_ember.py` streams the whole dataset through the `datasets` library to
collect 25k of each class. That works, but it pulls far more than it keeps: the
shards are label-ordered, so the stream walks ~28GB of JSONL to fill both
buckets. This fetches only the shards that hold the classes we need.

    python src/fetch_ember_subset.py --per-class 10000

Writes data/ember_subset/ember_subset.parquet with the same {x, label} shape
train_ember_model.py expects.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

BASE = "https://huggingface.co/datasets/cw1521/ember2018-malware/resolve/main/data"
REPO_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = REPO_ROOT / "data" / "ember_raw"
OUT_DIR = REPO_ROOT / "data" / "ember_subset"

# Probed from the published shard order: label 0 lives in the low shards, label
# 1 around 200-300, and -1 (unlabeled, discarded) is scattered through the rest.
# Shards near 100 straddle the 0/1 boundary and yield under half a shard of
# label 1, so the denser ones are listed first.
BENIGN_SHARDS = [1, 2, 3, 4, 5, 6, 7, 8]
MALICIOUS_SHARDS = [200, 250, 300, 201, 251, 301, 202, 252, 302, 100, 203, 253]

RETRIES = 4


def fetch(shard: int) -> Path | None:
    """Download one shard, retrying dropped transfers.

    HuggingFace closed the connection part-way through more than once over a
    ~70MB body, so a single urlretrieve is not enough to get through a dozen
    shards. A shard that will not come down is skipped rather than fatal - the
    next one supplies the same class.
    """
    target = RAW_DIR / f"train_{shard}.jsonl"
    if target.exists() and target.stat().st_size > 1_000_000:
        print(f"  shard {shard}: cached", flush=True)
        return target

    url = f"{BASE}/ember2018_train_{shard}.jsonl"
    tmp = target.with_suffix(".part")

    # curl rather than urlretrieve: these transfers get cut off part-way
    # through often enough that resume (-C -) matters more than tidiness.
    for attempt in range(1, RETRIES + 1):
        print(f"  shard {shard}: downloading (attempt {attempt})", flush=True)
        result = subprocess.run(
            ["curl", "-sL", "-C", "-", "--retry", "5", "--retry-delay", "5",
             "--retry-all-errors", "--max-time", "1800", "-o", str(tmp), url],
            capture_output=True,
        )
        if result.returncode == 0 and tmp.exists() and tmp.stat().st_size > 1_000_000:
            tmp.rename(target)
            print(f"  shard {shard}: {target.stat().st_size / 1e6:.0f}MB", flush=True)
            return target
        print(f"  shard {shard}: attempt {attempt} failed (curl exit {result.returncode})", flush=True)
        time.sleep(5 * attempt)

    print(f"  shard {shard}: giving up, skipping", flush=True)
    tmp.unlink(missing_ok=True)
    return None


def collect(shards: list[int], want_label: int, per_class: int) -> list[dict]:
    rows: list[dict] = []
    for shard in shards:
        if len(rows) >= per_class:
            break
        path = fetch(shard)
        if path is None:
            continue
        with open(path) as handle:
            for line in handle:
                if len(rows) >= per_class:
                    break
                try:
                    record = json.loads(line)
                    label = int(record["label"])
                except (ValueError, TypeError, KeyError):
                    continue
                if label != want_label:
                    continue
                rows.append({"x": np.array(record["x"], dtype=np.float32), "label": label,
                             "sha256": record.get("sha256"), "avclass": record.get("avclass")})
        print(f"  -> {len(rows)}/{per_class} for label {want_label}", flush=True)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-class", type=int, default=10000)
    args = parser.parse_args()

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Collecting {args.per_class} benign...", flush=True)
    benign = collect(BENIGN_SHARDS, 0, args.per_class)
    print(f"Collecting {args.per_class} malicious...", flush=True)
    malicious = collect(MALICIOUS_SHARDS, 1, args.per_class)

    if not benign or not malicious:
        print("ERROR: could not fill both classes", file=sys.stderr)
        return 1

    frame = pd.DataFrame(benign + malicious)
    out = OUT_DIR / "ember_subset.parquet"
    frame.to_parquet(out)
    print(f"\nWrote {len(frame)} rows ({len(benign)} benign / {len(malicious)} malicious) to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
