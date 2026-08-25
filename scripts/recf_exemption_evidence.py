"""Reproduce and document URDS container-exemption governance behavior.

This is a deterministic, read-only characterization of the Monitor's decision
function. It creates high-entropy decoy bytes in a temporary directory, applies
each recognized magic prefix, evaluates the existing structural validator, and
calls ``detection.classify`` on a fresh path. It never starts a watcher, never
contacts downstream services, and writes a report only when
``URDS_WRITE_REPORTS=1``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MONITOR_DIR = REPO_ROOT / "services" / "monitor"
REPORTS_DIR = REPO_ROOT / "reports"
PAYLOAD_SIZE = 64 * 1024
SEED = b"recf-container-exemption-evidence-v1"

sys.path.insert(0, str(MONITOR_DIR))
import containers  # noqa: E402
import detection  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "recf_exemption_simulator", REPO_ROOT / "scripts" / "ransomware_simulator.py"
)
if spec is None or spec.loader is None:  # pragma: no cover
    raise RuntimeError("unable to load simulator primitives")
simulator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(simulator)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _signatures() -> list[tuple[bytes, str]]:
    # Use the detector's own table so the evidence cannot drift from production.
    return list(detection._CONTAINER_SIGNATURES)


def _payload(prefix: bytes, index: int) -> bytes:
    randomish = simulator.keystream(SEED + index.to_bytes(4, "big"), PAYLOAD_SIZE)
    return prefix + randomish[len(prefix) :]


def run() -> dict:
    records: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="urds_container_evidence_") as temp:
        root = Path(temp)
        for index, (prefix, format_name) in enumerate(_signatures()):
            payload = _payload(prefix, index)
            path = root / f"fresh_{index:02d}_{format_name}.bin"
            path.write_bytes(payload)
            head = payload[: detection.ENTROPY_SAMPLE_BYTES]
            tail = payload[-containers.CONTAINER_TAIL_BYTES :]
            container_name = detection.identify_container(prefix)
            status = containers.container_status(head, tail, container_name, len(payload))
            valid = containers.validate_container(head, tail, container_name, len(payload))
            entropy = detection.entropy_of(payload)
            verdict = detection.classify(
                str(path),
                entropy,
                prefix,
                container_valid=valid,
            )
            records.append(
                {
                    "format": format_name,
                    "magic_hex": prefix.hex(),
                    "payload_size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "entropy": round(entropy, 4),
                    "validated_by_registry": format_name in containers.VALIDATED_FORMATS,
                    "container_status": status,
                    "container_valid": valid,
                    "verdict": verdict["verdict"],
                    "suspicious": verdict["suspicious"],
                    "signal": verdict.get("signal"),
                    "reason": verdict["reason"],
                    "fresh_path": True,
                }
            )
    validated = [record for record in records if record["validated_by_registry"]]
    unvalidated = [record for record in records if not record["validated_by_registry"]]
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "experiment": "fresh-path high-entropy payload with recognized container prefix",
        "payload_size": PAYLOAD_SIZE,
        "seed_label": SEED.decode(),
        "recognized_signature_entries": len(records),
        "unique_formats": len({record["format"] for record in records}),
        "validated_formats": sorted({record["format"] for record in validated}),
        "unvalidated_formats": sorted({record["format"] for record in unvalidated}),
        "validated_entries_benign": sum(record["verdict"] == "benign_compressed" for record in validated),
        "validated_entries_suspicious": sum(record["suspicious"] for record in validated),
        "unvalidated_entries_benign": sum(record["verdict"] == "benign_compressed" for record in unvalidated),
        "unvalidated_entries_suspicious": sum(record["suspicious"] for record in unvalidated),
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-report", action="store_true", help="write reports/recf_exemption_evidence.json")
    args = parser.parse_args()
    payload = run()
    print(json.dumps(payload, indent=2))
    if args.write_report and os.getenv("URDS_WRITE_REPORTS") == "1":
        REPORTS_DIR.mkdir(exist_ok=True)
        path = REPORTS_DIR / "recf_exemption_evidence.json"
        path.write_text(json.dumps(payload, indent=2))
        print(f"wrote {path}")
    elif args.write_report:
        print("set URDS_WRITE_REPORTS=1 to write the report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
