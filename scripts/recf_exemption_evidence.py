"""What the container exemption actually admits, entry by entry - AS.

Item P5.2, Chapter 9 §9.4.1 and the artefact register §9.8. Writes
reports/recf_exemption_evidence.json.

§9.3 finding 1 says the Monitor recognises 20 signature entries across 16 unique
formats, that 11 of those formats have no structural validator, that
`validate_container()` returns None for them, and that `detection.classify()`
tests `container_valid is not False` - so "I could not check" is treated exactly
like "I checked and it passed". It records a run in which 13 unvalidated entries
returned `benign_compressed` and none returned suspicious.

This harness is the reproduction of that claim, and the thing that decides it if
the code has moved. Four witness families:

(a) **Every signature entry.** All 20 rows of `detection._CONTAINER_SIGNATURES`,
    plus the ISO-BMFF entry that lives at offset 4 rather than 0, each given a
    fresh high-entropy payload behind its own magic bytes. This is the cheapest
    attack in the system: write the header, keep the ciphertext.

(b) **The standard-library valid container.** `gzip.compress(ciphertext)` and a
    `ZIP_STORED` member holding ciphertext. These are not forgeries. They are
    genuine, structurally perfect containers whose *content* is the attacker's
    payload, produced by two calls into the Python standard library. §9.3
    finding 2 prices this at Level 1 against a cost table that assumed MODERATE.
    D4 turns on whether a repair closes it, so the witness has to exist before
    any repair is designed.

(c) **The INCOMPLETE witness.** A file that is genuinely the format it claims
    and is genuinely unfinished - a PNG with a correct IHDR and no IEND, a ZIP
    with a local header and no central directory. `container_status` calls these
    INCOMPLETE, and `validate_container` projects INCOMPLETE to the same `None`
    it uses for "no validator". Two different reasons, one indistinguishable
    outcome.

(d) **Fresh versus observed.** The same bytes classified twice: once as a path
    the Monitor has never seen, once as a path it measured at low entropy first.
    Differential entropy is the one signal that survives a valid container, so
    the pair shows exactly how much of the detector the exemption is cancelling
    and how much it never touched.

Per entry the report carries: the format, whether a validator exists for it,
`container_status()` by name, `validate_container()`'s tri-state, and
`classify()`'s verdict, `suspicious`, `signal` and reason. Nothing is asserted -
the harness reports what the code did, and §9.3 is confirmed or restated against
it.

    .venv\\Scripts\\python.exe scripts/recf_exemption_evidence.py

Writes the report only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"

sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

import containers  # noqa: E402
import detection  # noqa: E402

# The threshold the Monitor actually runs with, taken the way app.py takes it,
# so the harness scores against the deployed value rather than the library
# default.
ENTROPY_THRESHOLD = float(
    os.getenv("ENTROPY_THRESHOLD", detection.DEFAULT_ENTROPY_THRESHOLD)
)

PAYLOAD_BYTES = 120_000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


# ------------------------------------------------------------------ scoring


def score(path: Path, entropy_delta: float | None = None) -> dict:
    """Run one file down the detection path exactly as `handle_event` does.

    Reconstructed from `app.handle_event` rather than imported, because the
    Monitor's handler also buffers, hashes and fans out - none of which this
    harness wants - and because reimplementing the *reading* would risk
    measuring a different detector from the one that runs.
    """
    size = path.stat().st_size
    head, tail = detection.sample_file(str(path), size)
    entropy, statistics = detection.measure(head)
    magic = detection.read_magic(str(path))
    container = detection.identify_container(magic)
    status = containers.container_status(head, tail, container, size)
    tri_state = containers.validate_container(head, tail, container, size)

    verdict = detection.classify(
        str(path),
        entropy,
        magic,
        ENTROPY_THRESHOLD,
        readable=True,
        entropy_delta=entropy_delta,
        container_valid=tri_state,
        statistics=statistics,
    )

    return {
        "file_size": size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "entropy": verdict["entropy"],
        "container_format": container,
        "validator_present": container in containers.VALIDATED_FORMATS,
        "container_status": status,
        "validate_container": tri_state,
        "verdict": verdict["verdict"],
        "suspicious": verdict["suspicious"],
        "signal": verdict["signal"],
        "reason": verdict["reason"],
    }


# ------------------------------------------- (a) every signature entry


def signature_entries(workdir: Path) -> list[dict]:
    """All 20 rows of the registry, plus the offset-4 ISO-BMFF entry.

    Each is the same attack: the entry's own magic bytes, then ciphertext. The
    payload is `os.urandom`, which is what a stream cipher's output is
    indistinguishable from, so this is the honest shape of the thing.
    """
    rows = []
    entries = [
        (signature, name, 0) for signature, name in detection._CONTAINER_SIGNATURES
    ]
    # ISO base media declares its brand at offset 4. It is a recognised format
    # with a validator, and leaving it out would understate the registry.
    entries.append((b"ftyp", "iso-bmff", detection._FTYP_OFFSET))

    for index, (signature, name, offset) in enumerate(entries):
        payload = os.urandom(PAYLOAD_BYTES)
        blob = payload[:offset] + signature + payload[offset + len(signature):]
        path = workdir / f"entry_{index:02d}_{name}.bin"
        path.write_bytes(blob)
        row = score(path)
        row.update(
            {
                "entry_index": index,
                "signature_hex": signature.hex(),
                "signature_offset": offset,
                "declared_format": name,
            }
        )
        rows.append(row)
    return rows


# --------------------------------- (b) the standard-library valid container


def standard_library_witnesses(workdir: Path) -> list[dict]:
    """Two genuine containers whose content is the attacker's payload.

    Neither is a forgery. `gzip.compress` emits a real deflate stream with a
    real CRC-32; `ZIP_STORED` emits a real local header, a real central
    directory and a real end-of-central-directory record. Both pass structural
    validation because both *are* the format. The cost to an attacker is one
    standard-library call.
    """
    rows = []
    ciphertext = os.urandom(PAYLOAD_BYTES)

    path = workdir / "witness_gzip_compress.gz"
    path.write_bytes(gzip.compress(ciphertext))
    row = score(path)
    row.update(
        {
            "witness": "gzip.compress(ciphertext)",
            "construction": "one call: gzip.compress()",
            "attacker_cost_note": "standard library, no encoder shipped",
        }
    )
    rows.append(row)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", ciphertext)
    path = workdir / "witness_zip_stored.zip"
    path.write_bytes(buffer.getvalue())
    row = score(path)
    row.update(
        {
            "witness": "zipfile ZIP_STORED member",
            "construction": "one call: ZipFile.writestr() with ZIP_STORED",
            "attacker_cost_note": "standard library, no compression, payload verbatim",
        }
    )
    rows.append(row)

    return rows


# ------------------------------------------------ (c) the INCOMPLETE witness


def incomplete_witnesses(workdir: Path) -> list[dict]:
    """Files that really are the format and really are unfinished.

    A PNG with a correct IHDR CRC and no IEND, and a ZIP with a well-formed
    local header and no central directory. `container_status` answers
    INCOMPLETE for both. `validate_container` projects that to None - the same
    None it returns for a format it has no validator for - and `classify` reads
    `container_valid is not False`.

    The deferral is deliberate and its reasoning (containers.py:23-46) is sound:
    a large archive mid-write has no central directory yet, and calling that
    forged would fire on every legitimate big write. What is measured here is
    not whether the deferral is right but whether the *outcome* is
    distinguishable from a completed check - which TC-16 requires it to be.
    """
    rows = []

    ihdr = (
        b"\x00\x00\x00\x0dIHDR"
        + (400).to_bytes(4, "big")
        + (300).to_bytes(4, "big")
        + bytes([8, 6, 0, 0, 0])
    )
    ihdr += zlib.crc32(ihdr[4:]).to_bytes(4, "big")
    idat_body = zlib.compress(os.urandom(PAYLOAD_BYTES))
    idat = len(idat_body).to_bytes(4, "big") + b"IDAT" + idat_body
    idat += zlib.crc32(idat[4:]).to_bytes(4, "big")

    path = workdir / "witness_png_no_iend.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + ihdr + idat)  # no IEND
    row = score(path)
    row.update(
        {
            "witness": "PNG with a valid IHDR CRC and no IEND",
            "construction": "genuine format, terminal structure absent",
        }
    )
    rows.append(row)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", os.urandom(PAYLOAD_BYTES))
    complete = buffer.getvalue()
    # Everything up to the central directory: a local header and its data, which
    # is exactly what an archiver has written when it is halfway through.
    truncated = complete[: complete.rfind(b"PK\x01\x02")]

    path = workdir / "witness_zip_no_central_directory.zip"
    path.write_bytes(truncated)
    row = score(path)
    row.update(
        {
            "witness": "ZIP with a local header and no central directory",
            "construction": "genuine format, terminal structure absent",
        }
    )
    rows.append(row)

    return rows


# ------------------------------------------------- (d) fresh versus observed


def fresh_versus_observed(workdir: Path) -> list[dict]:
    """The same bytes, judged with and without a history for the path.

    `entropy_delta` is what `EntropyHistory.observe` returns for a path it has
    measured before. A file that arrives once, on a path nothing has seen, has
    no delta and no `entropy_rise` signal available. The same file written over
    a document the Monitor measured at ~4.6 bits/byte does.

    Both readings are taken for the two witnesses that matter - the
    standard-library gzip, and an unvalidated-format entry - because
    differential entropy is the only signal in the system that survives a
    structurally valid container, and the size of that gap is the honest measure
    of what the exemption costs.
    """
    rows = []
    ciphertext = os.urandom(PAYLOAD_BYTES)

    cases = [
        ("gzip.compress witness", "fvo_gzip.gz", gzip.compress(ciphertext)),
        ("unvalidated 7z entry", "fvo_7z.7z", b"7z\xbc\xaf\x27\x1c" + ciphertext),
        ("unvalidated rar entry", "fvo_rar.rar", b"Rar!\x1a\x07" + ciphertext),
    ]
    # A plain-text document reads around 4.5-4.7 bits/byte; the rise from there
    # to ciphertext is what the observed reading models.
    observed_delta = 3.35

    for label, name, blob in cases:
        path = workdir / name
        path.write_bytes(blob)
        fresh = score(path)
        observed = score(path, entropy_delta=observed_delta)
        rows.append(
            {
                "case": label,
                "declared_format": fresh["container_format"],
                "validator_present": fresh["validator_present"],
                "fresh_path": {
                    "entropy_delta": None,
                    "verdict": fresh["verdict"],
                    "suspicious": fresh["suspicious"],
                    "signal": fresh["signal"],
                },
                "observed_path": {
                    "entropy_delta": observed_delta,
                    "verdict": observed["verdict"],
                    "suspicious": observed["suspicious"],
                    "signal": observed["signal"],
                },
                "exemption_survived_by_history": (
                    not fresh["suspicious"] and observed["suspicious"]
                ),
            }
        )
    return rows


# ------------------------------------------------------------------ summary


def registry_shape() -> dict:
    """The counts §9.3 asserts, taken from the registry itself."""
    names = [name for _, name in detection._CONTAINER_SIGNATURES]
    unique = sorted(set(names))
    validated = sorted(n for n in unique if n in containers.VALIDATED_FORMATS)
    unvalidated = sorted(n for n in unique if n not in containers.VALIDATED_FORMATS)
    return {
        "signature_entries": len(detection._CONTAINER_SIGNATURES),
        "unique_formats_in_signature_table": len(unique),
        "validators_defined": sorted(containers.VALIDATED_FORMATS),
        "validated_formats_in_signature_table": validated,
        "unvalidated_formats_in_signature_table": unvalidated,
        "unvalidated_format_count": len(unvalidated),
        "unvalidated_signature_entry_count": sum(
            1 for name in names if name not in containers.VALIDATED_FORMATS
        ),
        "note": (
            "iso-bmff has a validator and is reached through the ftyp branch at "
            "detection.identify_container, not through the signature table, so it "
            "is in validators_defined and not in the signature-table lists."
        ),
    }


def finding_1_verdict(entries: list[dict], shape: dict) -> dict:
    """Confirm or restate §9.3 finding 1 against what the run produced."""
    unvalidated = [row for row in entries if not row["validator_present"]]
    benign_compressed = [r for r in unvalidated if r["verdict"] == "benign_compressed"]
    suspicious = [r for r in unvalidated if r["suspicious"]]
    none_tri_state = [r for r in unvalidated if r["validate_container"] is None]

    claimed = {
        "unique_formats": 16,
        "formats_without_validator": 11,
        "unvalidated_entries_returning_benign_compressed": 13,
        "unvalidated_entries_returning_suspicious": 0,
    }
    observed = {
        "unique_formats": shape["unique_formats_in_signature_table"],
        "formats_without_validator": shape["unvalidated_format_count"],
        "unvalidated_entries_returning_benign_compressed": len(benign_compressed),
        "unvalidated_entries_returning_suspicious": len(suspicious),
    }
    return {
        "claim": (
            "§9.3 finding 1: 20 signature entries over 16 formats, 11 without a "
            "structural validator; validate_container() returns None for those and "
            "classify() tests `container_valid is not False`, so 13 unvalidated "
            "entries return benign_compressed and none return suspicious."
        ),
        "claimed": claimed,
        "observed": observed,
        "status": "confirmed" if claimed == observed else "restated",
        "validate_container_returned_none_for_all_unvalidated": len(none_tri_state)
        == len(unvalidated),
        "unvalidated_entries_that_returned_suspicious": [
            {"format": r["declared_format"], "verdict": r["verdict"], "signal": r["signal"]}
            for r in suspicious
        ],
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="recf_evidence_") as tmp:
        workdir = Path(tmp)
        entries = signature_entries(workdir)
        stdlib = standard_library_witnesses(workdir)
        incomplete = incomplete_witnesses(workdir)
        history = fresh_versus_observed(workdir)

    shape = registry_shape()
    report = {
        "schema": "urds.recf_exemption_evidence/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "payload_bytes": PAYLOAD_BYTES,
        "entropy_threshold": ENTROPY_THRESHOLD,
        "registry": shape,
        "finding_1": finding_1_verdict(entries, shape),
        "a_signature_entries": entries,
        "b_standard_library_witnesses": stdlib,
        "c_incomplete_witnesses": incomplete,
        "d_fresh_versus_observed": history,
    }

    finding = report["finding_1"]
    print(f"registry: {shape['signature_entries']} entries, "
          f"{shape['unique_formats_in_signature_table']} formats, "
          f"{shape['unvalidated_format_count']} without a validator")
    print(f"finding 1: {finding['status']}")
    print(f"  claimed  {finding['claimed']}")
    print(f"  observed {finding['observed']}")
    print("\nstandard-library witnesses:")
    for row in stdlib:
        print(f"  {row['witness']:<34} status={row['container_status']:<11} "
              f"verdict={row['verdict']:<19} suspicious={row['suspicious']}")
    print("\nINCOMPLETE witnesses:")
    for row in incomplete:
        print(f"  {row['witness']:<48} status={row['container_status']:<11} "
              f"verdict={row['verdict']:<19} suspicious={row['suspicious']}")
    print("\nfresh versus observed:")
    for row in history:
        print(f"  {row['case']:<24} fresh={row['fresh_path']['verdict']:<19} "
              f"observed={row['observed_path']['verdict']:<19} "
              f"signal={row['observed_path']['signal']}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "recf_exemption_evidence.json").write_text(json.dumps(report, indent=2))
    print(f"\nwrote {REPORTS / 'recf_exemption_evidence.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
