"""Artefact hashes for the reproducibility appendix (P8.4).

The Week 32 exit gate asks that an independent reader reproduce every headline
figure from the repository and the appendix alone. A list of commands is not
enough for that: the reader also needs to know *what the output should be*, and
which parts of it are allowed to differ.

Every report in `reports/` carries `generated_at`, most carry `commit` and
`branch`, and several carry wall-clock timings. So **no artefact in this
repository reproduces byte-identically**, and a manifest that recorded only file
hashes would fail on its first line for reasons that have nothing to do with the
result. This script therefore records two digests per artefact:

- `sha256` over the committed bytes. This is an integrity check on the artefact
  as it sits in git: it detects an edited report, and it is what a reader quotes
  when citing a specific file.
- `stable_sha256` over the same JSON with the declared volatile paths removed,
  wall-clock durations and mkdtemp working directories normalised away, and the
  remainder canonicalised (sorted keys, no whitespace). **This is the digest a
  reproducer compares.** Two runs of the same script on the same commit agree on
  it, or the result changed.

The normalisation is deliberately narrow. It removes `generated_at`, `commit`,
`branch` and `host`; any key named in `TIMING_KEYS` at any depth; and the random
segment of a temporary directory, keeping the filename beneath it. A changed
count, verdict, capability level, bound or reason survives normalisation and
shows up as drift, which is the point.

Each artefact also declares the command that regenerates it, the seed it depends
on, and a reproduction class:

- `deterministic` - the stable digest is expected to match exactly.
- `timing-dependent` - the stable digest is *not* expected to match; the numbers
  are wall-clock measurements. What a reader checks instead is recorded in
  `tolerance`.
- `environment-dependent` - the stable digest is not expected to match because
  part of the artefact depends on something the repository does not carry, such
  as a gitignored trained model. `tolerance` names exactly which part, so the
  rest is still read as a result.

Usage:

    python scripts/artefact_manifest.py              # print, write nothing
    URDS_WRITE_REPORTS=1 python scripts/artefact_manifest.py
    python scripts/artefact_manifest.py --verify     # recompute, compare, exit 1 on drift

`--verify` is the appendix's own regression: it re-reads every artefact named in
`reports/artefact_manifest.json` and reports each one as `match`, `drift`
(stable digest changed - a real difference) or `missing`. A timing-dependent
artefact whose stable digest moved is reported as `expected-drift`, not a
failure, because that is what its class predicts.

Writes the manifest only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
MANIFEST = REPORTS / "artefact_manifest.json"

# Volatile paths are stripped before the stable digest. A dotted path descends
# through dicts only; a path that does not exist is not an error, because a
# report may legitimately omit a key.
COMMON_VOLATILE = ("generated_at", "commit", "branch")

# --------------------------------------------------------------------------
# The artefacts that back a headline figure. Anything not in this table is not
# cited by the thesis, the paper or the claim matrix, and is left out rather
# than hashed for completeness - a manifest nobody checks is not evidence.
# --------------------------------------------------------------------------

ARTEFACTS: list[dict] = [
    {
        "path": "reports/benign_corpus_manifest.json",
        "backs": "the 275-file stratified benign corpus and its per-file hashes",
        "command": "URDS_WRITE_REPORTS=1 python scripts/build_benign_corpus.py",
        "seed": "20260902 (scripts/build_benign_corpus.py DEFAULT_SEED)",
        "reproduction": "deterministic",
        "volatile": COMMON_VOLATILE,
        "verify_command": "python scripts/build_benign_corpus.py --verify",
        "tolerance": None,
    },
    {
        "path": "reports/capability_calibration.json",
        "backs": "10 capability levels on two ladders; the base64 finding",
        "command": "URDS_WRITE_REPORTS=1 python scripts/capability_calibration.py",
        "seed": "none - every strategy is built from fixed bytes",
        "reproduction": "environment-dependent",
        "volatile": COMMON_VOLATILE,
        "verify_command": None,
        "tolerance": "Nine of the ten strategies are built from fixed bytes and "
                     "reproduce exactly anywhere. The tenth, "
                     "Cforge(ml_confidence_gate), scores a feature vector "
                     "against models/behavioral_model.pkl, which is gitignored: "
                     "on a clean checkout that level is recorded unresolved "
                     "under D2 instead of measured, and four summary counters "
                     "move with it - levels_measured stays 10 while "
                     "with_empirical_source_trail and reproduced fall to 9 and "
                     "unresolved_under_d2 rises to 1. That is D2 behaving as "
                     "designed, not a failure. Every other level, both ladders, "
                     "the base64 finding and the disagreement list are "
                     "unaffected",
    },
    {
        "path": "reports/admission_recompute.json",
        "backs": "20 cells x 6 policies, 16 flips, D1 on both ladders",
        "command": "URDS_WRITE_REPORTS=1 python scripts/admission_recompute.py",
        "seed": "none - reads capability levels from capability_calibration.json",
        "reproduction": "deterministic",
        "volatile": COMMON_VOLATILE,
        "verify_command": None,
        "tolerance": None,
    },
    {
        "path": "reports/three_arm_experiment.json",
        "backs": "five arms, 34 attack cases, 275 benign files; D3 and D4",
        "command": "URDS_WRITE_REPORTS=1 python scripts/three_arm_experiment.py",
        "seed": "corpus seed 20260902; attack witnesses built from fixed bytes",
        "reproduction": "deterministic",
        # latency_ms is wall-clock and moves run to run. The counts do not.
        "volatile": COMMON_VOLATILE + ("latency_ms",),
        "verify_command": None,
        "tolerance": "latency_ms is excluded from the stable digest; it is a "
                     "measurement, and the arms are compared to each other "
                     "within one run rather than across runs",
    },
    {
        "path": "reports/benign_tradeoff.json",
        "backs": "Bound 1 at 25.323 pp against 2.00; D5 at 100.0 pp",
        "command": "URDS_WRITE_REPORTS=1 python scripts/benign_tradeoff.py",
        "seed": "none - reads three_arm_experiment.json",
        "reproduction": "deterministic",
        "volatile": COMMON_VOLATILE,
        "verify_command": None,
        "tolerance": None,
    },
    {
        "path": "reports/ledger_coverage.json",
        "backs": "100.0% coverage; 36/36 blocks on 5/5 required fields",
        "command": "URDS_WRITE_REPORTS=1 python scripts/ledger_coverage.py",
        "seed": "none",
        "reproduction": "deterministic",
        "volatile": COMMON_VOLATILE,
        "verify_command": None,
        "tolerance": None,
    },
    {
        "path": "reports/pipeline_governance.json",
        "backs": "one adjudication across Monitor to Recovery, asserted by equality",
        "command": "URDS_WRITE_REPORTS=1 python scripts/pipeline_governance.py",
        "seed": "none - payloads derive from a SHA-256 chain over a fixed tag",
        "reproduction": "deterministic",
        "volatile": COMMON_VOLATILE,
        "verify_command": None,
        "tolerance": None,
    },
    {
        "path": "reports/tamper_sweep.json",
        "backs": "20/20 in-place detected, 0/8 structural detected",
        "command": "URDS_WRITE_REPORTS=1 python scripts/tamper_sweep.py",
        "seed": "none - 40-block chains over fixed payloads",
        "reproduction": "deterministic",
        "volatile": COMMON_VOLATILE,
        "verify_command": None,
        "tolerance": None,
    },
    {
        "path": "reports/failure_injection.json",
        "backs": "five recovery injections, none reported as verified",
        "command": "URDS_WRITE_REPORTS=1 python scripts/failure_injection.py",
        "seed": "none",
        "reproduction": "deterministic",
        "volatile": COMMON_VOLATILE,
        "verify_command": None,
        "tolerance": None,
    },
    {
        "path": "reports/simulator_families.json",
        "backs": "13/13 simulator families detected and restored",
        "command": "URDS_WRITE_REPORTS=1 python scripts/simulator_sweep.py",
        "seed": "fixed per-family keystream seeds in scripts/ransomware_simulator.py",
        "reproduction": "deterministic",
        "volatile": ("generated_at",),
        "verify_command": None,
        "tolerance": "per-family detection latency is wall-clock; the 13/13 "
                     "detection and restore outcomes are not",
    },
    {
        "path": "reports/load_test.json",
        "backs": "p95 94.650 ms, p99 110.550 ms, 18.7:1 produce-to-drain",
        "command": "URDS_WRITE_REPORTS=1 python scripts/load_test.py",
        "seed": "none",
        "reproduction": "timing-dependent",
        "volatile": COMMON_VOLATILE + ("host",),
        "verify_command": None,
        "tolerance": "every number in this report is wall-clock on one host. A "
                     "reader reproduces the shape - p99 above the 100 ms budget "
                     "and a produce-to-drain ratio well above 1:1 - not the "
                     "digits. The host block records what it was measured on",
    },
    {
        "path": "reports/vss_status.json",
        "backs": "acceptance row 12: VSS supported, not elevated, both operations refuse",
        "command": "python scripts/verify_vss.py --status-only",
        "seed": "none",
        "reproduction": "timing-dependent",
        "volatile": COMMON_VOLATILE,
        "verify_command": None,
        "tolerance": "the result depends on the host and on whether the shell "
                     "is elevated. On an elevated Windows shell this report "
                     "should differ, and that difference is the point of "
                     "running it",
    },
]


# --------------------------------------------------------------------------
# Digests
# --------------------------------------------------------------------------

# Wall-clock durations, at any depth. A measurement script that reports how long
# its own verification took is reporting a fact about the host, not a result, and
# leaving these in the digest would make every deterministic artefact drift on
# every run - which is exactly what the first run of this script found.
TIMING_KEYS = frozenset({
    "verification_time_ms",
    "elapsed_ms",
    "duration_ms",
    "timestamp",
})

# A temporary working directory created by mkdtemp: the random segment differs
# every run and is not a result either. The filename beneath it is kept, because
# which file the script wrote to *is* part of what the report says.
_TMPDIR = re.compile(
    r"(?i)[a-z]:[\\/](?:[^\\/\s\"]+[\\/])*?temp[\\/][^\\/\s\"]+"
)


def normalise(value):
    """Strip wall-clock timings and mkdtemp paths, recursively.

    Everything else survives into the digest, so a changed count, verdict,
    level, bound or reason still shows up as drift.
    """
    if isinstance(value, dict):
        return {key: normalise(item) for key, item in value.items()
                if key not in TIMING_KEYS}
    if isinstance(value, list):
        return [normalise(item) for item in value]
    if isinstance(value, str):
        return _TMPDIR.sub("<tmpdir>", value)
    return value


def strip(value, paths: tuple[str, ...]):
    """Return a copy of `value` with the declared top-level paths removed."""
    if not isinstance(value, dict):
        return normalise(value)
    return normalise({key: item for key, item in value.items()
                      if key not in paths})


def stable_digest(path: Path, volatile: tuple[str, ...]) -> str | None:
    """SHA-256 over the JSON with volatile keys removed and keys sorted."""
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    canonical = json.dumps(strip(loaded, volatile), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def describe(entry: dict) -> dict:
    path = ROOT / entry["path"]
    present = path.is_file()
    return {
        "path": entry["path"],
        "backs": entry["backs"],
        "command": entry["command"],
        "verify_command": entry["verify_command"],
        "seed": entry["seed"],
        "reproduction": entry["reproduction"],
        "tolerance": entry["tolerance"],
        "volatile_excluded_from_stable_digest": list(entry["volatile"]),
        "present": present,
        "bytes": path.stat().st_size if present else None,
        "sha256": file_digest(path) if present else None,
        "stable_sha256": stable_digest(path, entry["volatile"]) if present else None,
    }


# --------------------------------------------------------------------------
# Source artefacts - the code whose behaviour the reports describe
# --------------------------------------------------------------------------

SOURCE_FILES = [
    "services/monitor/detection.py",
    "services/monitor/admissibility.py",
    "services/monitor/containers.py",
    "services/monitor/pipeline.py",
    "services/monitor/app.py",
    "services/ledger/hash_chain.py",
    "services/ledger/database.py",
    "scripts/capability_calibration.py",
    "scripts/admission_recompute.py",
    "scripts/three_arm_experiment.py",
    "scripts/benign_tradeoff.py",
    "scripts/build_benign_corpus.py",
]


def git(*args: str) -> str:
    try:
        done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                              text=True, encoding="utf-8", errors="replace")
        return done.stdout.strip()
    except OSError:
        return ""


def build() -> dict:
    return {
        "schema": "urds.artefact_manifest.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "what_the_two_digests_mean": {
            "sha256": "over the committed bytes; detects an edited artefact",
            "stable_sha256": "over the JSON with the listed volatile paths "
                             "removed and keys sorted; this is the digest a "
                             "reproducer compares",
        },
        "freeze_tags": {
            name: git("rev-list", "-n", "1", name)
            for name in ("corpus-frozen-week19", "cost-table-frozen-week20",
                         "corpus-frozen-week21", "repair-accepted-week24")
        },
        "artefacts": [describe(entry) for entry in ARTEFACTS],
        "source": [
            {"path": rel, "sha256": file_digest(ROOT / rel),
             "bytes": (ROOT / rel).stat().st_size if (ROOT / rel).is_file() else None}
            for rel in SOURCE_FILES
        ],
    }


def verify() -> int:
    """Recompute every digest and compare against the committed manifest."""
    if not MANIFEST.is_file():
        print(f"no manifest at {MANIFEST}; run without --verify first")
        return 1
    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    by_path = {entry["path"]: entry for entry in ARTEFACTS}

    drift = 0
    print(f"manifest recorded at commit {recorded.get('commit', '?')[:12]}")
    print(f"{'artefact':44s} {'class':18s} result")
    print("-" * 84)
    for row in recorded["artefacts"]:
        entry = by_path.get(row["path"])
        if entry is None:
            print(f"{row['path']:44s} {'-':18s} no longer declared")
            continue
        path = ROOT / row["path"]
        if not path.is_file():
            print(f"{row['path']:44s} {row['reproduction']:18s} MISSING")
            drift += 1
            continue
        now = stable_digest(path, entry["volatile"])
        if now == row["stable_sha256"]:
            result = "match"
        elif row["reproduction"] == "timing-dependent":
            result = "expected-drift (timing)"
        elif row["reproduction"] == "environment-dependent":
            result = "expected-drift (environment)"
        else:
            result = f"DRIFT {row['stable_sha256'][:12]} -> {now[:12]}"
            drift += 1
        print(f"{row['path']:44s} {row['reproduction']:18s} {result}")

    print("-" * 84)
    if drift:
        print(f"{drift} artefact(s) drifted or are missing. A deterministic "
              f"artefact whose stable digest moved means a result changed.")
    else:
        print("every deterministic artefact matches its recorded stable digest")
    return 1 if drift else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true",
                        help="recompute and compare against the committed manifest")
    args = parser.parse_args()

    if args.verify:
        return verify()

    manifest = build()

    print(f"{'artefact':44s} {'class':18s} {'bytes':>8s}  stable sha256")
    print("-" * 100)
    for row in manifest["artefacts"]:
        if not row["present"]:
            print(f"{row['path']:44s} {row['reproduction']:18s} {'-':>8s}  NOT PRESENT")
            continue
        print(f"{row['path']:44s} {row['reproduction']:18s} "
              f"{row['bytes']:8d}  {row['stable_sha256'][:32]}")
    print("-" * 100)
    present = sum(1 for row in manifest["artefacts"] if row["present"])
    print(f"{present} of {len(manifest['artefacts'])} artefacts present")
    print(f"{len(manifest['source'])} source files hashed")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: manifest not written")
        return 0

    REPORTS.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST, "w", encoding="utf-8", newline="") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    print(f"\nwrote {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
