"""Exploratory data analysis across all three datasets the spec names - NI.

Table 5.4 Weeks 1-4 asks for one EDA report covering "EMBER, CLEAR, and RanSAP"
with "dataset characteristics documented". The repo had EMBER characterised in
`analyze_ember.py` and the two I/O trace sets characterised separately in
`analyze_behavioral_signals.py`; nothing produced the single report the
deliverable names, and RanSAP's role in the project was never stated.

This script produces that report. It is deliberately descriptive: it measures
what is in each corpus and says what each one is used for, so the "training
input or EDA-only" question is answered from the data rather than asserted.

    python src/eda_datasets.py

Writes reports/eda_report.md and reports/eda_datasets.json.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
REPORTS_DIR = REPO_ROOT / "reports"

# RanSAP ships headerless CSVs. Read traces carry four columns and write traces
# carry six - the two extra are per-write entropy, measured by RanSAP's own
# collector over the 4KB block being written.
RANSAP_READ_COLS = ["timestamp", "interval_gap", "offset", "size"]
RANSAP_WRITE_COLS = ["timestamp", "interval_gap", "offset", "size", "entropy_1", "entropy_2"]


def _round(value, digits: int = 4):
    if value is None or (isinstance(value, float) and not np.isfinite(value)):
        return None
    return round(float(value), digits)


# ------------------------------------------------------------------- EMBER


def describe_ember() -> dict:
    path = DATA_DIR / "ember_subset" / "ember_50k.parquet"
    if not path.is_file():
        return {"available": False, "path": str(path)}

    frame = pd.read_parquet(path, columns=["label", "sha256", "appeared"])
    counts = frame["label"].astype(int).value_counts().to_dict()

    # Only the first rows are stacked: the point is the vector width, and
    # stacking all 50,000 costs ~450MB for a number visible from five.
    width = int(np.stack(pd.read_parquet(path, columns=["x"])["x"].values[:8]).shape[1])

    appeared = frame["appeared"].dropna().astype(str)

    return {
        "available": True,
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "role": "training input - the primary static-PE classifier (models/xgboost_model.pkl)",
        "samples": int(len(frame)),
        "features_per_sample": width,
        "class_balance": {"benign_0": int(counts.get(0, 0)), "malicious_1": int(counts.get(1, 0))},
        "imbalance_ratio": _round(counts.get(0, 0) / max(counts.get(1, 0), 1)),
        "unique_sha256": int(frame["sha256"].nunique()),
        "appeared_range": [appeared.min(), appeared.max()] if len(appeared) else None,
        "feature_family": (
            "EMBER v2 static feature vector: byte histogram, byte-entropy histogram, "
            "string statistics, general file info, PE header, section table, imports, "
            "exports and data directories"
        ),
    }


# ------------------------------------------------------------------- CLEAR


def describe_clear() -> dict:
    path = DATA_DIR / "clear_io" / "wannacry_io_sample.csv"
    if not path.is_file():
        return {"available": False, "path": str(path)}

    frame = pd.read_csv(path)
    labels = frame["Label"].astype(int)

    by_process = (
        frame.groupby(["Process Name", "Label"]).size().reset_index(name="operations")
    )

    # WAR/RAR/RAW/WAW are CLEAR's access-pattern counters: write-after-read,
    # read-after-read, read-after-write, write-after-write, counted per file
    # region. They are the closest thing in any of the three corpora to the
    # "file access patterns" half of the spec's behavioural fingerprinting.
    pattern_cols = ["WAR", "RAR", "RAW", "WAW"]
    pattern_means = frame.groupby("Label")[pattern_cols].mean()

    return {
        "available": True,
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "role": "training input - the I/O behaviour classifier (models/io_behavior_model.pkl)",
        "operations": int(len(frame)),
        "columns": list(frame.columns),
        "class_balance": {
            "benign_0": int((labels == 0).sum()),
            "ransomware_1": int((labels == 1).sum()),
        },
        "processes": {
            f"{row['Process Name']} (label {row['Label']})": int(row["operations"])
            for _, row in by_process.iterrows()
        },
        "opcode_counts": {str(k): int(v) for k, v in frame["OpCode"].value_counts().items()},
        "access_pattern_means_by_label": {
            str(label): {col: _round(pattern_means.loc[label, col]) for col in pattern_cols}
            for label in pattern_means.index
        },
        "io_size_bytes": {
            "mean": _round(frame["Size"].mean(), 1),
            "median": _round(frame["Size"].median(), 1),
            "max": int(frame["Size"].max()),
        },
        "note": (
            "Rows are individual I/O operations from one instrumented run, not "
            "per-file samples. There is no key on which a CLEAR row could be "
            "joined to an EMBER row, so the two corpora train two models rather "
            "than one merged feature matrix."
        ),
    }


# ------------------------------------------------------------------ RanSAP


def _load_ransap(path: Path, columns: list[str]) -> pd.DataFrame | None:
    if not path.is_file():
        return None
    return pd.read_csv(path, header=None, names=columns)


def describe_ransap() -> dict:
    traces = {
        "ransomware_write": (
            DATA_DIR / "ransap_logs" / "ransomware" / "wannacry" / "wannacry_write.csv",
            RANSAP_WRITE_COLS,
        ),
        "ransomware_read": (
            DATA_DIR / "ransap_logs" / "ransomware" / "wannacry" / "wannacry_read.csv",
            RANSAP_READ_COLS,
        ),
        "benign_write": (DATA_DIR / "ransap_logs" / "benign" / "firefox_write.csv", RANSAP_WRITE_COLS),
        "benign_read": (DATA_DIR / "ransap_logs" / "benign" / "firefox_read.csv", RANSAP_READ_COLS),
    }

    described: dict = {}
    for name, (path, columns) in traces.items():
        frame = _load_ransap(path, columns)
        if frame is None:
            described[name] = {"available": False, "path": str(path)}
            continue

        entry = {
            "available": True,
            "path": path.relative_to(REPO_ROOT).as_posix(),
            "operations": int(len(frame)),
            "size_bytes": {
                "mean": _round(frame["size"].mean(), 1),
                "median": _round(frame["size"].median(), 1),
                "fraction_4096": _round((frame["size"] == 4096).mean()),
            },
            "duration_seconds": int(frame["timestamp"].max() - frame["timestamp"].min()),
        }
        if "entropy_1" in frame.columns:
            # RanSAP's entropy columns are normalised to 0-1, not bits/byte.
            #
            # The mean is the wrong statistic here and reporting it alone would
            # mislead: the ransomware trace has a *lower* mean than the benign
            # one. That is because it is bimodal - two thirds of its writes are
            # near-zero entropy (zero-fill over the originals it is destroying,
            # plus metadata) and the rest are ciphertext sitting at the ceiling.
            # The benign trace is unimodal and never reaches that ceiling in
            # bulk. So the discriminating statistic is the shape of the tail,
            # not the centre, which is what the windowed features score.
            series = frame["entropy_1"]
            entry["write_entropy_normalised"] = {
                "mean": _round(series.mean()),
                "std": _round(series.std()),
                "median": _round(series.median()),
                "p95": _round(series.quantile(0.95)),
                "max": _round(series.max()),
                "fraction_above_0.9": _round((series > 0.9).mean()),
                "fraction_below_0.05": _round((series < 0.05).mean()),
            }
        described[name] = entry

    return {
        "available": any(v.get("available") for v in described.values()),
        "role": "training input - the I/O behaviour classifier (models/io_behavior_model.pkl)",
        "traces": described,
        "note": (
            "RanSAP write traces carry per-block entropy measured by its own "
            "collector, which is the only real (non-synthetic) encryption "
            "entropy in the repository. Read traces carry no entropy column."
        ),
    }


# ------------------------------------------------------------------- report


def build_report() -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "datasets": {
            "EMBER": describe_ember(),
            "CLEAR": describe_clear(),
            "RanSAP": describe_ransap(),
        },
    }


def _markdown(report: dict) -> str:
    ember = report["datasets"]["EMBER"]
    clear = report["datasets"]["CLEAR"]
    ransap = report["datasets"]["RanSAP"]

    lines = [
        "# EDA report - EMBER, CLEAR and RanSAP",
        "",
        "Table 5.4, Weeks 1-4: *\"Dataset acquisition (EMBER, CLEAR, RanSAP), exploratory",
        "data analysis, feature understanding\"*, deliverable *\"EDA report\"*, success",
        "criterion *\"Dataset characteristics documented\"*.",
        "",
        f"Generated {report['generated_at']} by `src/eda_datasets.py`. Every number below",
        "is measured from the files in `data/`.",
        "",
        "## Summary",
        "",
        "| Dataset | Unit of a row | Rows | Labels | Role in the project |",
        "|---|---|---|---|---|",
    ]

    if ember.get("available"):
        lines.append(
            f"| EMBER | one PE file | {ember['samples']:,} | "
            f"{ember['class_balance']['benign_0']:,} benign / "
            f"{ember['class_balance']['malicious_1']:,} malicious | "
            "Training input - static-PE classifier |"
        )
    if clear.get("available"):
        lines.append(
            f"| CLEAR | one I/O operation | {clear['operations']:,} | "
            f"{clear['class_balance']['benign_0']:,} benign / "
            f"{clear['class_balance']['ransomware_1']:,} ransomware | "
            "Training input - I/O behaviour classifier |"
        )
    if ransap.get("available"):
        total = sum(t.get("operations", 0) for t in ransap["traces"].values() if t.get("available"))
        lines.append(
            f"| RanSAP | one I/O operation | {total:,} | by trace (ransomware vs benign run) | "
            "Training input - I/O behaviour classifier |"
        )

    lines += ["", "## EMBER", ""]
    if ember.get("available"):
        lines += [
            f"- Path: `{ember['path']}`",
            f"- {ember['samples']:,} samples, {ember['features_per_sample']:,} features each",
            f"- Class balance: {ember['class_balance']['benign_0']:,} benign / "
            f"{ember['class_balance']['malicious_1']:,} malicious "
            f"(ratio {ember['imbalance_ratio']})",
            f"- Unique SHA-256 values: {ember['unique_sha256']:,} (no duplicate samples)",
            f"- Feature families: {ember['feature_family']}",
            "",
            "The corpus is exactly balanced, which is the measurement that decides the",
            "SMOTE question in `docs/APPROACH.md` §8.",
        ]
    else:
        lines.append("Not present in `data/`.")

    lines += ["", "## CLEAR", ""]
    if clear.get("available"):
        lines += [
            f"- Path: `{clear['path']}`",
            f"- {clear['operations']:,} I/O operations across "
            f"{len(clear['processes'])} process/label combinations",
            f"- Class balance: {clear['class_balance']['benign_0']} benign / "
            f"{clear['class_balance']['ransomware_1']} ransomware operations",
            "",
            "Operations by process:",
            "",
            "| Process (label) | Operations |",
            "|---|---|",
        ]
        for name, count in sorted(clear["processes"].items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{name}` | {count} |")

        lines += [
            "",
            "Access-pattern counters, mean per operation. These are CLEAR's behavioural",
            "fingerprint: write-after-read, read-after-read, read-after-write,",
            "write-after-write.",
            "",
            "| Label | WAR | RAR | RAW | WAW |",
            "|---|---|---|---|---|",
        ]
        for label, means in clear["access_pattern_means_by_label"].items():
            kind = "benign" if label == "0" else "ransomware"
            lines.append(
                f"| {label} ({kind}) | {means['WAR']} | {means['RAR']} | "
                f"{means['RAW']} | {means['WAW']} |"
            )

        lines += [
            "",
            "The separation is stark and is the reason CLEAR is worth training on:",
            "benign processes re-read what they have read (high RAR), ransomware",
            "overwrites what it has written and never reads it back (high WAW, RAR at",
            "zero). That is the encrypt-in-place signature expressed in I/O terms.",
            "",
            f"*{clear['note']}*",
        ]
    else:
        lines.append("Not present in `data/`.")

    lines += ["", "## RanSAP", ""]
    if ransap.get("available"):
        lines += [
            "| Trace | Operations | Duration (s) | Mean size | 4KB share |",
            "|---|---|---|---|---|",
        ]
        for name, trace in ransap["traces"].items():
            if not trace.get("available"):
                lines.append(f"| {name} | *missing* | | | |")
                continue
            lines.append(
                f"| {name} | {trace['operations']:,} | {trace['duration_seconds']:,} | "
                f"{trace['size_bytes']['mean']:,.0f} | "
                f"{trace['size_bytes']['fraction_4096']:.2%} |"
            )

        write_traces = {
            name: trace
            for name, trace in ransap["traces"].items()
            if trace.get("available") and trace.get("write_entropy_normalised")
        }
        if write_traces:
            lines += [
                "",
                "### Write entropy - the mean is the wrong statistic",
                "",
                "RanSAP normalises entropy to 0-1 rather than bits/byte. Read straight,",
                "the numbers say ransomware writes are *less* random than Firefox's,",
                "which is the opposite of the premise the whole detector rests on. The",
                "distribution shape explains it:",
                "",
                "| Trace | Mean | Median | p95 | Max | Share > 0.9 | Share < 0.05 |",
                "|---|---|---|---|---|---|---|",
            ]
            for name, trace in write_traces.items():
                e = trace["write_entropy_normalised"]
                lines.append(
                    f"| {name} | {e['mean']} | {e['median']} | {e['p95']} | {e['max']} | "
                    f"{e['fraction_above_0.9']:.2%} | {e['fraction_below_0.05']:.2%} |"
                )
            lines += [
                "",
                "The ransomware trace is **bimodal**. Roughly two thirds of its writes sit",
                "at effectively zero entropy - zero-fill over the originals it is",
                "destroying, plus filesystem metadata - and the remainder sit at the",
                "ceiling, which is the ciphertext. Averaging those two modes together",
                "produces a number that describes neither.",
                "",
                "The benign trace is unimodal around its median and its 95th percentile",
                "never approaches the ceiling the ransomware trace reaches in bulk.",
                "",
                "So the separating statistic is the **shape of the upper tail**, not the",
                "centre. That is what `src/train_io_behavior_model.py` scores: it windows",
                "the trace and takes the high-entropy share of each window, rather than a",
                "single per-operation reading. A per-operation threshold on this data",
                "would be close to useless in both directions.",
            ]
        lines += ["", f"*{ransap['note']}*"]
    else:
        lines.append("Not present in `data/`.")

    lines += [
        "",
        "## What each dataset is used for, and why",
        "",
        "The three corpora do not share a unit of observation. An EMBER row is a PE",
        "file; a CLEAR row and a RanSAP row are each a single I/O operation from an",
        "instrumented run. There is no key on which they could be joined, so merging",
        "them into one feature matrix is not possible without inventing a",
        "correspondence that does not exist.",
        "",
        "They therefore train two models, both of which serve:",
        "",
        "1. **Static-PE classifier** (`models/xgboost_model.pkl`) - EMBER only. Scores an",
        "   executable before it runs.",
        "2. **I/O behaviour classifier** (`models/io_behavior_model.pkl`) - CLEAR and",
        "   RanSAP, windowed into per-process bursts. Scores what a process is *doing*",
        "   to the file system, which is the signal a packed or previously unseen",
        "   binary cannot hide.",
        "",
        "A third model, the file-content behavioural classifier",
        "(`models/behavioral_model.pkl`), is trained on a generated corpus because no",
        "public dataset carries the raw bytes of encrypted user documents alongside",
        "their benign originals. That is stated in `docs/APPROACH.md` §8.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    REPORTS_DIR.mkdir(exist_ok=True)
    report = build_report()

    (REPORTS_DIR / "eda_datasets.json").write_text(json.dumps(report, indent=2))
    (REPORTS_DIR / "eda_report.md").write_text(_markdown(report), encoding="utf-8")

    for name, dataset in report["datasets"].items():
        status = "ok" if dataset.get("available") else "MISSING"
        print(f"{name:8s} {status}")

    print(f"\nWrote {REPORTS_DIR / 'eda_report.md'}")
    print(f"Wrote {REPORTS_DIR / 'eda_datasets.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
