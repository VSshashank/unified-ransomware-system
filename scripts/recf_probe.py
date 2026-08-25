"""Minimal RECF-DR detector-characterization probe for the URDS Monitor.

This is deliberately a characterization probe, not the full RECF-DR package. It
asks one question: what detector outcomes are analytically implied by an
expanded, detector-dependent behavior space, and which boundary cases need a
small executable witness?

The probe uses only safe, reversible transformations in disposable case
subdirectories. It never enables the production pipeline, never changes service
code, and writes a report only when ``URDS_WRITE_REPORTS=1``.

Examples::

    python scripts/recf_probe.py --dry-run
    python scripts/recf_probe.py --target-dir /tmp/urds-recf-probe --limit 48
    URDS_WRITE_REPORTS=1 python scripts/recf_probe.py --target-dir /tmp/urds-recf-probe
    python scripts/recf_probe.py --target-dir /tmp/urds-recf-probe --restore
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
import random
import shutil
import sys
import tempfile
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SIMULATOR_PATH = REPO_ROOT / "scripts" / "ransomware_simulator.py"
MONITOR_DIR = REPO_ROOT / "services" / "monitor"
REPORTS_DIR = REPO_ROOT / "reports"
MANIFEST_NAME = ".recf_probe_manifest.json"
ORIGINAL_NAME = ".recf_probe_original.bin"
CHECKSUM_BYTES = 32
MARKER = b"URDS-RECF-PROBE"
SCHEMA_VERSION = 1
DETECTION_DEADLINE_SECONDS = 2.0

PAYLOAD_MODES = ("keystream", "base64", "position_shuffle", "format_preserving")
FILE_SIZES = (4 * 1024, 12 * 1024, 64 * 1024, 1024 * 1024)
CHANGED_FRACTIONS = (0.05, 0.10, 0.25, 1.00)
BLOCK_PATTERNS = ("leading", "strided", "scattered")
STRUCTURAL_VALIDITY = ("broken", "magic_only", "valid")
HISTORY_MODES = ("fresh", "observed")

# A constrained first-pass witness set. These cases cross the detector's
# important boundaries without pretending that all Cartesian combinations are
# meaningful or deployable attacks. `--all` enumerates the full valid space.
WITNESS_VECTORS = (
    {"payload_mode": "keystream", "file_size": 4096, "changed_fraction": 1.0, "block_pattern": "leading", "structural_validity": "broken", "history_mode": "fresh"},
    {"payload_mode": "keystream", "file_size": 4096, "changed_fraction": 0.05, "block_pattern": "leading", "structural_validity": "broken", "history_mode": "fresh"},
    {"payload_mode": "keystream", "file_size": 12288, "changed_fraction": 0.05, "block_pattern": "strided", "structural_validity": "broken", "history_mode": "observed"},
    {"payload_mode": "keystream", "file_size": 65536, "changed_fraction": 0.10, "block_pattern": "scattered", "structural_validity": "broken", "history_mode": "observed"},
    {"payload_mode": "keystream", "file_size": 1048576, "changed_fraction": 0.25, "block_pattern": "strided", "structural_validity": "broken", "history_mode": "observed"},
    {"payload_mode": "base64", "file_size": 4096, "changed_fraction": 1.0, "block_pattern": "leading", "structural_validity": "broken", "history_mode": "fresh"},
    {"payload_mode": "base64", "file_size": 65536, "changed_fraction": 0.25, "block_pattern": "scattered", "structural_validity": "magic_only", "history_mode": "observed"},
    {"payload_mode": "position_shuffle", "file_size": 4096, "changed_fraction": 1.0, "block_pattern": "leading", "structural_validity": "broken", "history_mode": "fresh"},
    {"payload_mode": "position_shuffle", "file_size": 12288, "changed_fraction": 0.05, "block_pattern": "leading", "structural_validity": "broken", "history_mode": "observed"},
    {"payload_mode": "position_shuffle", "file_size": 65536, "changed_fraction": 0.25, "block_pattern": "strided", "structural_validity": "magic_only", "history_mode": "observed"},
    {"payload_mode": "position_shuffle", "file_size": 1048576, "changed_fraction": 0.10, "block_pattern": "scattered", "structural_validity": "broken", "history_mode": "observed"},
    {"payload_mode": "format_preserving", "file_size": 4096, "changed_fraction": 0.05, "block_pattern": "leading", "structural_validity": "valid", "history_mode": "observed"},
    {"payload_mode": "format_preserving", "file_size": 12288, "changed_fraction": 0.25, "block_pattern": "strided", "structural_validity": "valid", "history_mode": "observed"},
    {"payload_mode": "format_preserving", "file_size": 65536, "changed_fraction": 1.0, "block_pattern": "scattered", "structural_validity": "valid", "history_mode": "observed"},
    {"payload_mode": "format_preserving", "file_size": 1048576, "changed_fraction": 0.10, "block_pattern": "strided", "structural_validity": "valid", "history_mode": "fresh"},
    {"payload_mode": "keystream", "file_size": 4096, "changed_fraction": 0.25, "block_pattern": "scattered", "structural_validity": "magic_only", "history_mode": "observed"},
    {"payload_mode": "base64", "file_size": 12288, "changed_fraction": 0.10, "block_pattern": "leading", "structural_validity": "broken", "history_mode": "observed"},
    {"payload_mode": "position_shuffle", "file_size": 12288, "changed_fraction": 1.0, "block_pattern": "scattered", "structural_validity": "broken", "history_mode": "fresh"},
    {"payload_mode": "keystream", "file_size": 65536, "changed_fraction": 0.25, "block_pattern": "leading", "structural_validity": "magic_only", "history_mode": "fresh"},
    {"payload_mode": "format_preserving", "file_size": 65536, "changed_fraction": 0.05, "block_pattern": "leading", "structural_validity": "valid", "history_mode": "fresh"},
)

# The production pipeline is deliberately disabled: this probe attributes the
# result to the Monitor and does not send experiments to ML, Ledger, or Response.
os.environ["PIPELINE_ENABLED"] = "false"
sys.path.insert(0, str(MONITOR_DIR))

import app as monitor_app  # noqa: E402
import detection as monitor_detection  # noqa: E402
from watchdog.observers import Observer  # noqa: E402


# Load simulator primitives without importing the script as __main__.
spec = importlib.util.spec_from_file_location("recf_probe_simulator", SIMULATOR_PATH)
if spec is None or spec.loader is None:  # pragma: no cover - import guard
    raise RuntimeError(f"cannot load simulator from {SIMULATOR_PATH}")
simulator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(simulator)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _invalid_reason(vector: dict) -> str | None:
    # Structural validity is a construction property, not an independent label.
    # A genuine format-preserving container cannot simultaneously be broken or
    # magic-only; non-format-preserving payloads cannot honestly be called valid
    # containers without a format-aware encoder.
    if vector["payload_mode"] == "format_preserving" and vector["structural_validity"] != "valid":
        return "format_preserving requires structural_validity=valid"
    if vector["payload_mode"] != "format_preserving" and vector["structural_validity"] == "valid":
        return "structural_validity=valid requires format_preserving construction"
    return None


def _valid_vector(vector: dict) -> bool:
    return _invalid_reason(vector) is None


def _rejected_vectors():
    for vector in _all_vectors():
        reason = _invalid_reason(vector)
        if reason:
            yield {"behavior": vector, "reason": reason}


def valid_case_count() -> int:
    return sum(1 for vector in _all_vectors() if _valid_vector(vector))


def _all_vectors():
    for payload_mode in PAYLOAD_MODES:
        for file_size in FILE_SIZES:
            for changed_fraction in CHANGED_FRACTIONS:
                for block_pattern in BLOCK_PATTERNS:
                    for structural_validity in STRUCTURAL_VALIDITY:
                        for history_mode in HISTORY_MODES:
                            yield {
                                "payload_mode": payload_mode,
                                "file_size": file_size,
                                "changed_fraction": changed_fraction,
                                "block_pattern": block_pattern,
                                "structural_validity": structural_validity,
                                "history_mode": history_mode,
                            }


def iter_vectors(all_cases: bool = False):
    source = _all_vectors() if all_cases else WITNESS_VECTORS
    for vector in source:
        if _valid_vector(vector):
            yield vector


def _analytical_prediction(vector: dict) -> str:
    """Classify whether a result is threshold-derived or interaction-dependent."""
    mode = vector["payload_mode"]
    size = vector["file_size"]
    fraction = vector["changed_fraction"]
    if mode == "base64":
        return "guaranteed_below_entropy_threshold_unless_extension_signal"
    if mode == "position_shuffle":
        return "entropy_preserving_block_interaction"
    if mode == "format_preserving":
        return "valid_structure_entropy_rise_requires_history"
    if mode == "keystream" and fraction == 1.0 and size >= monitor_detection.MIN_ENTROPY_BLOCK_BYTES:
        return "static_entropy_expected"
    if size < monitor_detection.MIN_PROFILE_BLOCKS * monitor_detection.ENTROPY_BLOCK_BYTES:
        return "partial_profile_unavailable"
    if fraction < monitor_detection.PARTIAL_BLOCK_FRACTION:
        return "below_declared_changed_fraction_boundary"
    return "interaction_dependent"


def canonical_case_id(vector: dict, seed: str) -> str:
    payload = json.dumps(
        {"schema_version": SCHEMA_VERSION, "seed": seed, "behavior": vector},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()[:20]


def _reset_monitor_state() -> None:
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    monitor_app.TRAINING_MODE.reset()
    monitor_app.WHITELIST.replace([], [])


def _assert_safe_root(root: Path) -> None:
    resolved = root.resolve()
    forbidden = {Path("/"), Path.home().resolve(), REPO_ROOT.resolve()}
    if resolved in forbidden:
        raise ValueError(f"refusing unsafe probe target: {resolved}")
    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"probe target is not a directory: {resolved}")


def _prepare_root(root: Path) -> None:
    _assert_safe_root(root)
    root.mkdir(parents=True, exist_ok=True)
    entries = list(root.iterdir())
    if entries:
        names = ", ".join(entry.name for entry in entries[:5])
        raise ValueError(
            f"refusing to run: {root} is not empty; first entries: {names}. "
            "Use a fresh dedicated target or --restore."
        )


def _plain_bytes(size: int) -> bytes:
    if size < len(MARKER) + CHECKSUM_BYTES + 2:
        raise ValueError(f"file size too small for marker and checksum: {size}")
    seed_text = (
        b"This is a benign URDS probe document. It contains ordinary repeated text "
        b"so payload transformations can be measured against a low-entropy baseline.\n"
    )
    body_size = size - CHECKSUM_BYTES
    body = MARKER + b"\n"
    repeated = (seed_text * ((body_size - len(body)) // len(seed_text) + 1))
    body = (body + repeated)[:body_size]
    return body + hashlib.sha256(body).digest()


def _payload_bytes(data: bytes, mode: str, seed: bytes) -> bytes:
    if mode in {"keystream", "format_preserving"}:
        return simulator._xor(data, seed)
    if mode == "base64":
        encoded = base64.b64encode(simulator._xor(data, seed))
        return (encoded * ((len(data) // len(encoded)) + 1))[: len(data)]
    if mode == "position_shuffle":
        # A keyed permutation of positions preserves the exact byte histogram
        # while denying access to the original ordering. Unlike a fixed byte
        # substitution, it is an actual keyed rearrangement of the file.
        order = list(range(len(data)))
        rng = random.Random(int.from_bytes(seed[:8], "big"))
        rng.shuffle(order)
        output = bytearray(len(data))
        for destination, source in enumerate(order):
            output[destination] = data[source]
        return bytes(output)
    raise ValueError(f"unknown payload mode: {mode}")


def _selected_positions(length: int, fraction: float, pattern: str) -> list[int]:
    count = max(1, int(length * fraction))
    if count >= length:
        return list(range(length))
    if pattern == "leading":
        return list(range(count))
    if pattern == "strided":
        # Spread selected bytes through the file, approximating intermittent
        # encryption while keeping the amount of changed data controlled.
        positions = [int(index * length / count) for index in range(count)]
        return sorted(set(min(length - 1, position) for position in positions))
    if pattern == "scattered":
        # Deterministic pseudo-scatter; no unrecorded randomness is used.
        step = max(1, (length // count) | 1)
        position = (length // 7) % length
        positions: list[int] = []
        while len(positions) < count:
            if position not in positions:
                positions.append(position)
            position = (position + step) % length
        return sorted(positions)
    raise ValueError(f"unknown block pattern: {pattern}")


def _mutate_bytes(data: bytes, mode: str, fraction: float, pattern: str, seed: bytes) -> bytes:
    transformed = _payload_bytes(data, mode, seed)
    positions = _selected_positions(len(data), fraction, pattern)
    output = bytearray(data)
    for position in positions:
        output[position] = transformed[position]
    return bytes(output)


def _valid_zip(original: bytes, member: bytes) -> bytes:
    # The archive remains syntactically valid, but its application-level
    # manifest retains the original digest. This distinguishes format validity
    # from the attacker objective: the file opens as a ZIP but the protected
    # report content no longer passes its integrity check.
    output = io.BytesIO()
    manifest = json.dumps({"report_sha256": hashlib.sha256(original).hexdigest()}).encode()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", manifest)
        archive.writestr("report.bin", member)
    return output.getvalue()


def _materialize_payload(original: bytes, vector: dict, seed: bytes) -> bytes:
    mutated = _mutate_bytes(
        original,
        vector["payload_mode"],
        vector["changed_fraction"],
        vector["block_pattern"],
        seed,
    )
    structural = vector["structural_validity"]
    if structural == "broken":
        return mutated
    if structural == "magic_only":
        return simulator.ZIP_MAGIC + mutated
    if structural == "valid":
        # Rebuild a real ZIP, rather than pasting a four-byte header. The
        # detector's structural validator must see an actually valid container.
        return _valid_zip(original, mutated)
    raise ValueError(f"unknown structural validity: {structural}")


def _objective_intact(payload: bytes, vector: dict, original: bytes) -> bool:
    """Return whether the protected content remains usable after mutation.

    The probe's decoy has an application-level checksum. A valid ZIP additionally
    carries the original report digest in a manifest, so a syntactically valid
    container can still fail the content-integrity objective. This is deliberately
    stricter than merely checking that bytes changed.
    """
    try:
        if vector["structural_validity"] == "valid":
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                report = archive.read("report.bin")
            return manifest.get("report_sha256") == hashlib.sha256(report).hexdigest()
        candidate = payload[4:] if vector["structural_validity"] == "magic_only" else payload
        if len(candidate) < CHECKSUM_BYTES:
            return False
        return hashlib.sha256(candidate[:-CHECKSUM_BYTES]).digest() == candidate[-CHECKSUM_BYTES:]
    except (KeyError, OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError):
        return False


def _manifest_path(case_dir: Path) -> Path:
    return case_dir / MANIFEST_NAME


def _write_manifest(case_dir: Path, file_name: str, original: bytes, vector: dict, seed: str) -> None:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_at": utc_now(),
        "case_id": canonical_case_id(vector, seed),
        "seed": seed,
        "file_name": file_name,
        "original_file": ORIGINAL_NAME,
        "original_size": len(original),
        "original_sha256": hashlib.sha256(original).hexdigest(),
        "behavior": vector,
        "restored": False,
    }
    (case_dir / ORIGINAL_NAME).write_bytes(original)
    _manifest_path(case_dir).write_text(json.dumps(manifest, indent=2))


def _restore_case(case_dir: Path) -> bool:
    manifest_path = _manifest_path(case_dir)
    original_path = case_dir / ORIGINAL_NAME
    if not manifest_path.exists() or not original_path.exists():
        return False
    manifest = json.loads(manifest_path.read_text())
    target = case_dir / manifest["file_name"]
    original = original_path.read_bytes()
    if hashlib.sha256(original).hexdigest() != manifest["original_sha256"]:
        raise RuntimeError(f"original manifest hash mismatch in {case_dir}")
    target.write_bytes(original)
    verified = (
        target.read_bytes() == original
        and hashlib.sha256(target.read_bytes()).hexdigest() == manifest["original_sha256"]
    )
    manifest["restored"] = verified
    manifest["restored_at"] = utc_now()
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return verified


def restore_root(root: Path) -> int:
    _assert_safe_root(root)
    if not root.exists():
        print(f"no probe target at {root}; nothing to restore")
        return 0
    restored = 0
    failures = 0
    for case_dir in sorted(root.glob("case_*")):
        if not case_dir.is_dir():
            continue
        try:
            if _restore_case(case_dir):
                restored += 1
            else:
                failures += 1
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"restore failed for {case_dir}: {exc}")
            failures += 1
    print(f"restored {restored} case(s); failures {failures}")
    return 0 if failures == 0 else 1


def _first_flag_time(target: Path, deadline: float) -> float | None:
    while time.monotonic() < deadline:
        with monitor_app._LOCK:
            events = list(monitor_app.EVENTS)
        if any(event.get("file_path") == str(target) and event.get("suspicious") for event in events):
            return time.monotonic()
        time.sleep(0.002)
    return None


def _latest_target_event(target: Path) -> dict | None:
    with monitor_app._LOCK:
        events = list(monitor_app.EVENTS)
    matching = [event for event in events if event.get("file_path") == str(target)]
    return matching[-1] if matching else None


def run_case(vector: dict, root: Path, seed_text: str, settle: float, deadline: float, keep: bool) -> dict:
    case_id = canonical_case_id(vector, seed_text)
    case_dir = root / f"case_{case_id}"
    case_dir.mkdir(parents=True, exist_ok=False)
    original = _plain_bytes(vector["file_size"])
    file_name = "probe_sample.docx"
    target = case_dir / file_name
    _write_manifest(case_dir, file_name, original, vector, seed_text)
    seed = hashlib.sha256(f"{seed_text}:{case_id}".encode()).digest()
    payload = _materialize_payload(original, vector, seed)
    objective_intact = _objective_intact(payload, vector, original)

    observer: Observer | None = None
    restored = False
    try:
        _reset_monitor_state()
        if vector["history_mode"] == "fresh":
            # The path exists before observation begins, so there is no detector
            # history even though the probe owns the file.
            target.write_bytes(original)

        observer = Observer()
        observer.schedule(monitor_app.MonitorHandler(), str(case_dir), recursive=True)
        observer.start()

        if vector["history_mode"] == "observed":
            # Use the repository's established decoy creator. The observer sees
            # the benign creation and obtains a baseline before mutation.
            decoy = simulator.build_decoys(case_dir, 1)[0]
            if decoy.name != file_name:
                decoy.rename(target)
            target.write_bytes(original)
            time.sleep(0.12)

        started = time.monotonic()
        target.write_bytes(payload)
        flagged_at = _first_flag_time(target, started + deadline)
        time.sleep(settle)

        observer.stop()
        observer.join(timeout=10)
        observer = None
        event = _latest_target_event(target) or {}
        restored = _restore_case(case_dir)
        actual_hash = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
        detection_seconds = round(flagged_at - started, 4) if flagged_at else None
        result = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "case_id": case_id,
            "seed": seed_text,
            "behavior": vector,
            "analytical_prediction": _analytical_prediction(vector),
            "detected": bool(event.get("suspicious")),
            "flag_seen": flagged_at is not None,
            "signal": event.get("signal"),
            "verdict": event.get("verdict"),
            "reason": event.get("reason"),
            "entropy": event.get("entropy"),
            "entropy_delta": event.get("entropy_delta"),
            "container_format": event.get("container_format"),
            "container_valid": event.get("container_valid"),
            "detection_seconds": detection_seconds,
            "within_2s": detection_seconds is not None and detection_seconds <= deadline,
            "restore_verified": restored,
            "restored_sha256": actual_hash,
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "event_type": event.get("event_type"),
            "attacker_objective_met": not objective_intact,
            "attacker_objective_reason": "application_integrity_failed" if not objective_intact else "content_remains_intact",
        }
        if not keep:
            shutil.rmtree(case_dir, ignore_errors=True)
        return result
    except KeyboardInterrupt:
        if observer is not None:
            observer.stop()
            observer.join(timeout=10)
        print(f"interrupted; case preserved for recovery: {case_dir}", flush=True)
        raise
    except Exception:
        if observer is not None:
            observer.stop()
            observer.join(timeout=10)
        # Preserve a failed case so --restore can prove whether recovery works.
        raise


def _summary(results: list[dict], all_cases: bool = False) -> dict:
    detected = [result for result in results if result["detected"]]
    misses = [result for result in results if not result["detected"]]
    latencies = [result["detection_seconds"] for result in detected if result["detection_seconds"] is not None]
    by_payload: dict[str, dict[str, int]] = defaultdict(lambda: {"cases": 0, "detected": 0, "missed": 0})
    by_signal: Counter[str] = Counter()
    by_prediction: Counter[str] = Counter()
    by_size: dict[str, dict[str, int]] = defaultdict(lambda: {"cases": 0, "detected": 0, "missed": 0})
    for result in results:
        payload = result["behavior"]["payload_mode"]
        size = str(result["behavior"]["file_size"])
        by_payload[payload]["cases"] += 1
        by_payload[payload]["detected"] += int(result["detected"])
        by_payload[payload]["missed"] += int(not result["detected"])
        by_size[size]["cases"] += 1
        by_size[size]["detected"] += int(result["detected"])
        by_size[size]["missed"] += int(not result["detected"])
        if result.get("signal"):
            by_signal[result["signal"]] += 1
        by_prediction[result["analytical_prediction"]] += 1
    attacker_valid = [result for result in results if result["attacker_objective_met"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "probe": "recf_probe",
        "pipeline_enabled": False,
        "cases_run": len(results),
        "case_set": "full_valid_space" if all_cases else "witness_set",
        "cases_expected": valid_case_count() if all_cases else len(WITNESS_VECTORS),
        "cases_detected": len(detected),
        "cases_missed": len(misses),
        "case_miss_rate": round(len(misses) / len(results), 6) if results else None,
        "all_restore_verified": all(result["restore_verified"] for result in results),
        "attacker_objective_met": len(attacker_valid),
        "attacker_objective_not_met": len(results) - len(attacker_valid),
        "all_executed_cases_met_attacker_objective": len(attacker_valid) == len(results),
        "within_2s": sum(result["within_2s"] for result in results),
        "fastest_detection_seconds": min(latencies) if latencies else None,
        "slowest_detection_seconds": max(latencies) if latencies else None,
        "signals": dict(sorted(by_signal.items())),
        "analytical_predictions": dict(sorted(by_prediction.items())),
        "by_payload_mode": dict(sorted(by_payload.items())),
        "by_file_size": dict(sorted(by_size.items(), key=lambda item: int(item[0]))),
        "rejected_combinations": list(_rejected_vectors()),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target-dir", type=Path, help="fresh dedicated directory for probe cases")
    parser.add_argument("--seed", default="recf-probe-2026", help="recorded campaign seed")
    parser.add_argument("--settle", type=float, default=0.10, help="seconds to let events land after detection polling")
    parser.add_argument("--deadline", type=float, default=DETECTION_DEADLINE_SECONDS, help="detection deadline per case")
    parser.add_argument("--limit", type=int, default=0, help="run only the first N deterministic witness cases; 0 means all witnesses")
    parser.add_argument("--all", action="store_true", help="enumerate the full valid constrained space instead of the 20-case witness set")
    parser.add_argument("--keep-workdirs", action="store_true", help="keep successfully restored case directories")
    parser.add_argument("--dry-run", action="store_true", help="print the exact case count without executing anything")
    parser.add_argument("--restore", action="store_true", help="restore preserved case directories and exit")
    args = parser.parse_args()

    if args.dry_run:
        print("purpose=detector_characterization; no adaptive_search_or_pareto")
        print(f"witness_case_count={len(WITNESS_VECTORS)}")
        print(f"valid_full_case_count={valid_case_count()}")
        print(f"invalid_structural_combinations={len(list(_rejected_vectors()))}")
        print(f"payload_modes={','.join(PAYLOAD_MODES)}")
        print(f"file_sizes={','.join(map(str, FILE_SIZES))}")
        print(f"changed_fractions={','.join(map(str, CHANGED_FRACTIONS))}")
        print(f"block_patterns={','.join(BLOCK_PATTERNS)}")
        print(f"structural_validity={','.join(STRUCTURAL_VALIDITY)}")
        print(f"history_modes={','.join(HISTORY_MODES)}")
        return 0

    if args.target_dir is None:
        parser.error("--target-dir is required unless --dry-run is used")
    root = args.target_dir.resolve()
    if args.restore:
        return restore_root(root)

    try:
        _prepare_root(root)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    vectors = iter_vectors(all_cases=args.all)
    if args.limit < 0:
        parser.error("--limit must be non-negative")
    if args.limit:
        vectors = (vector for index, vector in enumerate(vectors) if index < args.limit)

    results: list[dict] = []
    try:
        for index, vector in enumerate(vectors, start=1):
            print(
                f"[{index}] {vector['payload_mode']} size={vector['file_size']} "
                f"fraction={vector['changed_fraction']} pattern={vector['block_pattern']} "
                f"structure={vector['structural_validity']} history={vector['history_mode']}",
                flush=True,
            )
            result = run_case(vector, root, args.seed, args.settle, args.deadline, args.keep_workdirs)
            results.append(result)
            print(
                f"    {'DETECTED' if result['detected'] else 'MISSED'} "
                f"signal={result.get('signal')} entropy={result.get('entropy')} "
                f"latency={result.get('detection_seconds')}s "
                f"restore={'ok' if result['restore_verified'] else 'FAILED'}",
                flush=True,
            )
    except KeyboardInterrupt:
        print("probe interrupted; run with --restore against the same target before reuse", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"probe failed; preserved target for --restore: {exc}", file=sys.stderr)
        return 1

    summary = _summary(results, all_cases=args.all)
    print("=" * 72)
    print(
        f"detected {summary['cases_detected']}/{summary['cases_run']} cases; "
        f"missed {summary['cases_missed']}; "
        f"all restore verified={summary['all_restore_verified']}"
    )
    if summary["cases_missed"]:
        print("boundary misses exist in the executed characterization space")
    else:
        print("no boundary misses in the executed characterization space")

    if os.getenv("URDS_WRITE_REPORTS") == "1":
        REPORTS_DIR.mkdir(exist_ok=True)
        path = REPORTS_DIR / "recf_probe_findings.json"
        path.write_text(json.dumps(summary, indent=2))
        print(f"wrote {path}")
    else:
        print("set URDS_WRITE_REPORTS=1 to record this to reports/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
