"""Arm A, Arm B and Arm C over the same locked cases - AS.

Item P6.2, Chapter 9 §9.4.2 and the artefact register §9.8. Writes
reports/three_arm_experiment.json.

Three arms, and one more that exists to attribute the difference:

    A   `legacy`                   what shipped through Phase 5
    B   `off`                      the exemption removed entirely - the null
                                   control. Not a shipping candidate; it prices
                                   what the exemption is buying.
    C1  `strict-unvalidated`       the core repair alone: a validator has to
                                   have run and passed. Reported so that D4's
                                   verdict is attributable to a clause rather
                                   than to "the repair".
    C   `strict-unvalidated+ratio` the selected repair
    D   `strict-unvalidated+ratio+inner`
                                   a refinement added **after** Arm C's benign
                                   cost was measured, and reported as the
                                   post-hoc arm it is. It is not the arm the
                                   predeclared bounds were written for, and no
                                   predeclared criterion is claimed for it.

All four score the *same* files. The attack cases are built here from a fixed
seed and hashed into the report; the benign cases are the frozen corpus at
`corpus-frozen-week21`, scored from disk. Nothing is scored twice under
different bytes, because a paired comparison is the whole point.

**Two decision rules are evaluated by this harness and neither is allowed to
come out quietly:**

D3 - if Arm B's false-positive cost is acceptable, then the exemption is not
worth governing and the governance layer is not required for this mitigation.
That is a finding against the project's own contribution, and §9.7 says to
report it plainly.

D4 - if Arm C still returns `benign_compressed` for the standard-library valid
container, the repair is insufficient. Arm C must **not** be certified on the
unvalidated-format witness alone: family A1 passing is not evidence about
family A2, and this harness reports them separately so the distinction cannot
be averaged away.

    .venv\\Scripts\\python.exe scripts/three_arm_experiment.py

Writes the report only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import random
import statistics
import subprocess
import sys
import time
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"
CASE_ROOT = REPO_ROOT / "corpus" / "attack_cases"

sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

import containers  # noqa: E402
import detection  # noqa: E402

# The threshold the Monitor runs with, taken the way app.py takes it.
ENTROPY_THRESHOLD = float(
    os.getenv("ENTROPY_THRESHOLD", detection.DEFAULT_ENTROPY_THRESHOLD)
)

# The seed for every attack case. Fixed, so the case set is a thing that can be
# rebuilt and disagreed with rather than a thing that happened once.
ATTACK_SEED = 20260903
PAYLOAD_BYTES = 120_000

ARMS = [
    ("A", detection.CONTAINER_POLICY_LEGACY, "current behaviour"),
    ("B", detection.CONTAINER_POLICY_OFF, "exemption removed entirely (null control)"),
    ("C1", detection.CONTAINER_POLICY_STRICT, "core repair alone"),
    ("C", detection.CONTAINER_POLICY_RATIO, "the selected repair"),
    (
        "D",
        detection.CONTAINER_POLICY_INNER,
        "post-hoc refinement: ratio with an inner-content appeal",
    ),
]

LATENCY_REPETITIONS = 20


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


# --------------------------------------------------------------------- scoring


def read_inputs(path: Path) -> dict:
    """Everything `handle_event` reads before it classifies, read once.

    The four arms differ only in `policy`, so the file is sampled, measured and
    validated a single time and the four verdicts are taken from the same
    readings. Re-reading per arm would let a re-encode or a filesystem quirk
    show up as an arm difference.
    """
    size = path.stat().st_size
    head, tail = detection.sample_file(str(path), size)
    entropy, stats = detection.measure(head)
    magic = detection.read_magic(str(path))
    fmt = detection.identify_container(magic)
    return {
        "size": size,
        "entropy": entropy,
        "statistics": stats,
        "magic": magic,
        "container_format": fmt,
        "container_valid": containers.validate_container(head, tail, fmt, size),
        "container_status": containers.container_status(head, tail, fmt, size),
        "compression": containers.compression_evidence(head, tail, fmt, size),
        "inner_content": containers.inner_content_evidence(head, tail, fmt, size),
        "validator_present": fmt in containers.VALIDATED_FORMATS,
    }


def score(path: Path, inputs: dict, policy: str, entropy_delta: float | None = None) -> dict:
    verdict = detection.classify(
        str(path),
        inputs["entropy"],
        inputs["magic"],
        ENTROPY_THRESHOLD,
        readable=True,
        entropy_delta=entropy_delta,
        container_valid=inputs["container_valid"],
        statistics=inputs["statistics"],
        compression=inputs["compression"],
        inner_content=inputs["inner_content"],
        policy=policy,
        container_status=inputs["container_status"],
    )
    return {
        "verdict": verdict["verdict"],
        "suspicious": verdict["suspicious"],
        "signal": verdict["signal"],
        "reason": verdict["reason"],
    }


# -------------------------------------------------------------- attack cases


def noise(rng: random.Random, size: int) -> bytes:
    """Deterministic high-entropy bytes. What a stream cipher's output looks like."""
    return rng.randbytes(size)


def prose(rng: random.Random, size: int) -> bytes:
    words = (
        "quarterly revenue variance headcount forecast reconciliation invoice "
        "supplier ledger settlement amortisation depreciation covenant"
    ).split()
    out = bytearray()
    while len(out) < size:
        out += (" ".join(rng.choice(words) for _ in range(12)) + ".\n").encode()
    return bytes(out[:size])


def _zip_of(payload: bytes, name: str, method: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = method
        archive.writestr(info, payload)
    return buffer.getvalue()


def _real_jpeg(rng: random.Random) -> bytes:
    """A genuine JPEG, encoded by Pillow. Used to build A7's inner forgeries."""
    from PIL import Image

    image = Image.new("RGB", (320, 240))
    image.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(320 * 240)
        ]
    )
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", quality=88)
    return buffer.getvalue()


def build_attack_cases() -> list[dict]:
    """Every attack case, from one seed, written to disk and hashed.

    Six families. They are kept separate in the report because D4 turns on the
    difference between two of them: an arm that catches A1 and misses A2 has
    closed the cheap forgery and left the cheaper one open.
    """
    rng = random.Random(ATTACK_SEED)
    CASE_ROOT.mkdir(parents=True, exist_ok=True)
    cases: list[dict] = []

    def emit(family: str, name: str, blob: bytes, note: str, must_flag: bool = True) -> None:
        path = CASE_ROOT / name
        path.write_bytes(blob)
        cases.append(
            {
                "family": family,
                "file": name,
                "path": path,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
                "construction": note,
                "attacker_wins_if_not_flagged": must_flag,
            }
        )

    # A1 - a header over ciphertext, one per registry entry. The cheapest attack
    # in the system: write the magic bytes, keep the payload.
    entries = [(sig, name, 0) for sig, name in detection._CONTAINER_SIGNATURES]
    entries.append((b"ftyp", "iso-bmff", detection._FTYP_OFFSET))
    for index, (signature, fmt, offset) in enumerate(entries):
        payload = noise(rng, PAYLOAD_BYTES)
        blob = payload[:offset] + signature + payload[offset + len(signature):]
        emit(
            "A1_header_over_ciphertext",
            f"a1_{index:02d}_{fmt}.bin",
            blob,
            f"{fmt} magic bytes at offset {offset}, ciphertext behind them",
        )

    # A2 - genuine containers whose content is the payload. Not forgeries: two
    # standard-library calls. This is the family D4 is about.
    payload = noise(rng, PAYLOAD_BYTES)
    emit(
        "A2_standard_library_container",
        "a2_gzip_compress.gz",
        gzip.compress(payload),
        "gzip.compress(ciphertext) - a real deflate stream with a real CRC-32",
    )
    emit(
        "A2_standard_library_container",
        "a2_zip_stored.zip",
        _zip_of(noise(rng, PAYLOAD_BYTES), "payload.bin", zipfile.ZIP_STORED),
        "ZIP_STORED member of ciphertext - a real archive, real central directory",
    )
    emit(
        "A2_standard_library_container",
        "a2_zip_deflated.zip",
        _zip_of(noise(rng, PAYLOAD_BYTES), "payload.bin", zipfile.ZIP_DEFLATED),
        "ZIP_DEFLATED member of ciphertext - deflate ran and achieved nothing",
    )

    # A3 - the INCOMPLETE witness. Genuinely the format, genuinely unfinished.
    # `validate_container` projects INCOMPLETE to the same None it uses for
    # "no validator", so an attacker who stops short gets the same exemption.
    png_head = (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0dIHDR"
        + b"\x00\x00\x01\x00\x00\x00\x01\x00\x08\x02\x00\x00\x00"
        + b"\x00\x00\x00\x00"
    )
    idat = noise(rng, PAYLOAD_BYTES)
    emit(
        "A3_incomplete_container",
        "a3_png_no_iend.png",
        png_head + b"\x00\x01\xe8HIDAT" + idat,
        "a real IHDR with ciphertext where the IDAT data goes, and no IEND",
    )
    truncated = _zip_of(noise(rng, PAYLOAD_BYTES), "payload.bin", zipfile.ZIP_STORED)
    emit(
        "A3_incomplete_container",
        "a3_zip_no_central_dir.zip",
        truncated[: PAYLOAD_BYTES // 2],
        "a real local file header, ciphertext, and no central directory",
    )

    # A4 - intermittent encryption inside a valid container. P5.4 measured this
    # composite at 6.84 bits/byte and the system returned plain `benign`.
    for fraction in (0.25, 0.5, 0.75):
        blocks = []
        filler = prose(rng, 4096)
        count = 40
        encrypted = int(count * fraction)
        for i in range(count):
            blocks.append(noise(rng, 4096) if i < encrypted else filler)
        emit(
            "A4_intermittent_in_valid_container",
            f"a4_composite_{int(fraction * 100):02d}.zip",
            _zip_of(b"".join(blocks), "report.dat", zipfile.ZIP_STORED),
            f"ZIP_STORED archive, {int(fraction * 100)}% of 40 4KB blocks are ciphertext",
        )

    # A7 - the attack that answers Arm D. The inner-content appeal asks whether
    # what the archive carries identifies as a container and survives a
    # head-level check. Three levels of attacker effort against exactly that:
    #
    #   naive     four JPEG magic bytes in front of the ciphertext. The marker
    #             chain does not parse, so the inner check calls it FORGED.
    #   real head a genuine JPEG through its SOS marker, ciphertext after it.
    #             Every marker is real. Nothing in the leading sample says the
    #             scan data is not scan data.
    #   real tail the same, with a genuine EOI appended, so the head-level check
    #             has a complete-looking JPEG in front of it.
    #
    # If Arm D misses these, that is the price of the refinement, and it is
    # measured here rather than left for a reader to discover.
    jpeg = _real_jpeg(rng)
    sos = jpeg.find(b"\xff\xda")
    head_only = jpeg[: sos + 12] if sos > 0 else jpeg[:2048]
    emit(
        "A7_forged_inner_content",
        "a7_gzip_naive_magic.gz",
        gzip.compress(b"\xff\xd8\xff\xe0" + noise(rng, PAYLOAD_BYTES)),
        "gzip of four JPEG magic bytes and ciphertext - no real marker chain",
    )
    emit(
        "A7_forged_inner_content",
        "a7_gzip_real_jpeg_head.gz",
        gzip.compress(head_only + noise(rng, PAYLOAD_BYTES)),
        "gzip of a genuine JPEG through SOS, ciphertext where the scan data goes",
    )
    emit(
        "A7_forged_inner_content",
        "a7_zip_real_jpeg_head.zip",
        _zip_of(
            head_only + noise(rng, PAYLOAD_BYTES) + b"\xff\xd9",
            "photo.jpg",
            zipfile.ZIP_DEFLATED,
        ),
        "ZIP_DEFLATED of a genuine JPEG head, ciphertext, and a genuine EOI",
    )

    # A5 / A6 - controls. Every arm must catch these; an arm that does not has a
    # defect, not a policy.
    emit(
        "A5_control_naked_ciphertext",
        "a5_naked.bin",
        noise(rng, PAYLOAD_BYTES),
        "ciphertext with no header at all",
    )
    emit(
        "A6_control_forged_header",
        "a6_forged_zip.zip",
        b"PK\x03\x04" + noise(rng, PAYLOAD_BYTES),
        "a ZIP local-header signature with no ZIP structure behind it",
    )

    return cases


# ------------------------------------------------------------------- benign


def load_benign_manifest() -> dict:
    path = REPORTS / "benign_corpus_manifest.json"
    if not path.exists():
        raise SystemExit(
            f"no benign corpus manifest at {path} - run scripts/build_benign_corpus.py first"
        )
    return json.loads(path.read_text())


# ------------------------------------------------------------------- latency


def _one_pass(path: Path, policy: str) -> float:
    """One file down the whole detection path under one policy, in milliseconds."""
    start = time.perf_counter()
    size = path.stat().st_size
    head, tail = detection.sample_file(str(path), size)
    entropy, stats = detection.measure(head)
    magic = detection.read_magic(str(path))
    fmt = detection.identify_container(magic)
    detection.classify(
        str(path),
        entropy,
        magic,
        ENTROPY_THRESHOLD,
        readable=True,
        container_valid=containers.validate_container(head, tail, fmt, size),
        statistics=stats,
        compression=containers.compression_evidence(head, tail, fmt, size),
        inner_content=containers.inner_content_evidence(head, tail, fmt, size),
        policy=policy,
        container_status=containers.container_status(head, tail, fmt, size),
    )
    return (time.perf_counter() - start) * 1000.0


def measure_latency(paths: list[Path], arms: list[tuple]) -> dict:
    """The whole detection path, per file, per arm - not `classify` alone.

    Table 9.8 asks for the latency *after repair*, and the repair's cost is in
    the reading it added (`compression_evidence`), not in the branch it changed.
    Timing `classify` on its own would report the repair as free.

    The arms are **interleaved within each repetition**, and their order rotates
    between repetitions. Measuring one arm to completion and then the next
    hands the whole warm page cache to whichever ran last: the first version of
    this measurement did that and reported the arm doing the most work as the
    fastest, which is not a result, it is an ordering artefact.
    """
    samples: dict[str, list[float]] = {arm: [] for arm, _, _ in arms}
    for repetition in range(LATENCY_REPETITIONS):
        rotated = arms[repetition % len(arms):] + arms[: repetition % len(arms)]
        for path in paths:
            for arm, policy, _ in rotated:
                samples[arm].append(_one_pass(path, policy))

    out = {}
    for arm, values in samples.items():
        values.sort()
        quartile = len(values) // 4
        out[arm] = {
            "repetitions": LATENCY_REPETITIONS,
            "files_per_repetition": len(paths),
            "samples": len(values),
            "median_ms": round(statistics.median(values), 3),
            "q1_ms": round(values[quartile], 3),
            "q3_ms": round(values[-quartile - 1], 3),
            "iqr_ms": round(values[-quartile - 1] - values[quartile], 3),
            "p95_ms": round(values[int(len(values) * 0.95)], 3),
            "max_ms": round(values[-1], 3),
            "order": "interleaved with the other arms, rotating per repetition",
        }
    return out


# -------------------------------------------------------------------- report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-cases", action="store_true", help="leave the attack cases on disk"
    )
    args = parser.parse_args()

    manifest = load_benign_manifest()
    corpus_root = REPO_ROOT / manifest["corpus_root"]

    print("building attack cases ...")
    cases = build_attack_cases()
    print(f"  {len(cases)} cases in {len({c['family'] for c in cases})} families")

    # ---------------------------------------------------------- attack arms
    attack_rows = []
    for case in cases:
        inputs = read_inputs(case["path"])
        row = {
            key: case[key]
            for key in ("family", "file", "sha256", "size", "construction")
        }
        row.update(
            {
                "entropy": inputs["entropy"],
                "detected_format": inputs["container_format"],
                "validator_present": inputs["validator_present"],
                "container_status": inputs["container_status"],
                "container_valid": inputs["container_valid"],
                "compression": inputs["compression"],
                "inner_content": inputs["inner_content"],
                "arms": {
                    arm: score(case["path"], inputs, policy)
                    for arm, policy, _ in ARMS
                },
            }
        )
        attack_rows.append(row)

    # ---------------------------------------------------------- benign arms
    print("scoring the frozen benign corpus ...")
    benign_rows = []
    for record in manifest["files"]:
        path = corpus_root / record["file"]
        if not path.exists():
            raise SystemExit(
                f"{path} is missing - rebuild the corpus with "
                f"scripts/build_benign_corpus.py --per-cell {manifest['per_cell']}"
            )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != record["sha256"]:
            raise SystemExit(
                f"{record['file']} does not match the frozen manifest "
                f"({digest[:12]} != {record['sha256'][:12]}) - the corpus on disk is "
                "not the corpus that was frozen"
            )
        inputs = read_inputs(path)
        benign_rows.append(
            {
                "file": record["file"],
                "sha256": record["sha256"],
                "stratum": record["stratum"],
                "detected_format": inputs["container_format"],
                "entropy": inputs["entropy"],
                "arms": {arm: score(path, inputs, policy) for arm, policy, _ in ARMS},
            }
        )

    # -------------------------------------------------------------- summarise
    families = sorted({row["family"] for row in attack_rows})
    strata = sorted({row["stratum"] for row in benign_rows})

    per_arm = {}
    for arm, policy, label in ARMS:
        by_family = {}
        for family in families:
            rows = [r for r in attack_rows if r["family"] == family]
            caught = [r for r in rows if r["arms"][arm]["suspicious"]]
            by_family[family] = {
                "cases": len(rows),
                "flagged": len(caught),
                "rate": round(len(caught) / len(rows), 4),
                "missed": [r["file"] for r in rows if not r["arms"][arm]["suspicious"]],
            }
        by_stratum = {}
        for stratum in strata:
            rows = [r for r in benign_rows if r["stratum"] == stratum]
            flagged = [r for r in rows if r["arms"][arm]["suspicious"]]
            by_stratum[stratum] = {
                "files": len(rows),
                "false_positives": len(flagged),
                "rate": round(len(flagged) / len(rows), 4) if rows else None,
                "offenders": [r["file"] for r in flagged][:20],
            }
        attack_total = len(attack_rows)
        attack_caught = sum(1 for r in attack_rows if r["arms"][arm]["suspicious"])
        benign_total = len(benign_rows)
        benign_flagged = sum(1 for r in benign_rows if r["arms"][arm]["suspicious"])
        per_arm[arm] = {
            "policy": policy,
            "label": label,
            "attack": {
                "cases": attack_total,
                "flagged": attack_caught,
                "rate": round(attack_caught / attack_total, 4),
                "by_family": by_family,
            },
            "benign": {
                "files": benign_total,
                "false_positives": benign_flagged,
                "rate": round(benign_flagged / benign_total, 4),
                "by_stratum": by_stratum,
            },
        }

    # ------------------------------------------------------------------- D3
    arm_b = per_arm["B"]["benign"]
    arm_a = per_arm["A"]["benign"]
    d3 = {
        "question": (
            "Is Arm B's false-positive cost acceptable? If it is, the exemption "
            "is not worth governing and the governance layer is not required for "
            "this mitigation."
        ),
        "criterion": (
            "Table 5.9's corpus-wide false-positive budget, < 5%. It is the "
            "number an operator was already promised, and it is not superseded "
            "by Phase 6."
        ),
        "arm_a_false_positive_rate": arm_a["rate"],
        "arm_b_false_positive_rate": arm_b["rate"],
        "budget": 0.05,
        "arm_b_within_budget": arm_b["rate"] < 0.05,
        "arm_b_by_stratum": {k: v["rate"] for k, v in arm_b["by_stratum"].items()},
    }
    d3["finding"] = (
        "Arm B's false-positive cost is within the budget the project already "
        "set, so the exemption is not buying enough to be worth governing and "
        "the governance layer is not required for this mitigation. Reported as "
        "a primary finding against the project's own contribution, per D3."
        if d3["arm_b_within_budget"]
        else
        "Arm B's false-positive cost exceeds Table 5.9's budget, so removing the "
        "exemption is not an option and something has to decide when it applies. "
        "D3's branch does not fire: the governance layer is doing work that "
        "deleting the exemption cannot do."
    )

    # ------------------------------------------------------------------- D4
    a2_rows = [r for r in attack_rows if r["family"] == "A2_standard_library_container"]
    a1_rows = [r for r in attack_rows if r["family"] == "A1_header_over_ciphertext"]
    d4 = {
        "question": (
            "Does Arm C still return benign_compressed for the standard-library "
            "valid container? If it does, the repair is insufficient."
        ),
        "guard": (
            "Arm C must not be certified on the unvalidated-format witness "
            "alone. A1 and A2 are reported separately for exactly that reason."
        ),
        "by_arm": {},
    }
    for arm, _policy, _label in ARMS:
        still_benign = [
            r["file"] for r in a2_rows if r["arms"][arm]["verdict"] == "benign_compressed"
        ]
        d4["by_arm"][arm] = {
            "A1_flagged": sum(1 for r in a1_rows if r["arms"][arm]["suspicious"]),
            "A1_cases": len(a1_rows),
            "A2_flagged": sum(1 for r in a2_rows if r["arms"][arm]["suspicious"]),
            "A2_cases": len(a2_rows),
            "A2_still_benign_compressed": still_benign,
        }
    a7_rows = [r for r in attack_rows if r["family"] == "A7_forged_inner_content"]
    d4["a7_by_arm"] = {
        arm: {
            "flagged": sum(1 for r in a7_rows if r["arms"][arm]["suspicious"]),
            "cases": len(a7_rows),
            "missed": [r["file"] for r in a7_rows if not r["arms"][arm]["suspicious"]],
        }
        for arm, _p, _l in ARMS
    }
    d4["a7_note"] = (
        "A7 is the attack against Arm D's inner-content appeal. Arm D is a "
        "post-hoc refinement and A7 exists to price it: whatever A7 costs Arm D "
        "is the limit of the refinement, recorded here rather than left to be "
        "found later."
    )
    c_residual = d4["by_arm"]["C"]["A2_still_benign_compressed"]
    d4["arm_c_sufficient"] = not c_residual
    d4["finding"] = (
        "Arm C flags every standard-library valid container. The repair is not "
        "certified on A1 alone: A2 is measured separately and passes on its own. "
        "The clause that does it is the compression-yield check - C1, which is "
        "the core repair without it, leaves every A2 case benign_compressed."
        if d4["arm_c_sufficient"]
        else
        "Arm C still returns benign_compressed for "
        + ", ".join(c_residual)
        + ". Under D4 the repair is insufficient as it stands and is recorded as "
        "an accepted residual limitation with the attack documented."
    )

    # -------------------------------------------------------------- latency
    print("measuring the detection path per arm ...")
    # One case from each family, so the timing spans the work the policies
    # actually differ on rather than 10 copies of the cheapest branch.
    latency_paths = [
        next(c["path"] for c in cases if c["family"] == family) for family in families
    ]
    latency = measure_latency(latency_paths, ARMS)

    report = {
        "schema": "urds.three_arm_experiment/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "entropy_threshold": ENTROPY_THRESHOLD,
        "arms": {arm: {"policy": policy, "label": label} for arm, policy, label in ARMS},
        "attack_cases": {
            "seed": ATTACK_SEED,
            "count": len(cases),
            "families": {
                family: sum(1 for c in cases if c["family"] == family)
                for family in families
            },
            "root": str(CASE_ROOT.relative_to(REPO_ROOT)).replace("\\", "/"),
        },
        "benign_corpus": {
            "manifest": "reports/benign_corpus_manifest.json",
            "tag": "corpus-frozen-week21",
            "files": len(benign_rows),
            "seed": manifest["seed"],
            "per_cell": manifest["per_cell"],
            "every_file_hash_verified_against_the_manifest": True,
        },
        "per_arm": per_arm,
        "d3": d3,
        "d4": d4,
        "latency_ms": latency,
        "attacks": attack_rows,
        "benign": benign_rows,
    }

    # ------------------------------------------------------------------ print
    print()
    header = f"{'family':38}" + "".join(f"{arm:>8}" for arm, _, _ in ARMS)
    print(header)
    print("-" * len(header))
    for family in families:
        cells = "".join(
            f"{per_arm[arm]['attack']['by_family'][family]['flagged']:>4}"
            f"/{per_arm[arm]['attack']['by_family'][family]['cases']:<3}"
            for arm, _, _ in ARMS
        )
        print(f"{family:38}{cells}")
    print()
    print(f"{'benign stratum':38}" + "".join(f"{arm:>8}" for arm, _, _ in ARMS))
    print("-" * len(header))
    for stratum in strata:
        cells = "".join(
            f"{per_arm[arm]['benign']['by_stratum'][stratum]['false_positives']:>4}"
            f"/{per_arm[arm]['benign']['by_stratum'][stratum]['files']:<3}"
            for arm, _, _ in ARMS
        )
        print(f"{stratum:38}{cells}")
    print()
    print(f"{'ALL benign':38}" + "".join(
        f"{per_arm[arm]['benign']['false_positives']:>4}"
        f"/{per_arm[arm]['benign']['files']:<3}" for arm, _, _ in ARMS
    ))
    print()
    print("D3:", d3["finding"])
    print()
    print("D4:", d4["finding"])
    print()
    for arm, _, _ in ARMS:
        print(f"latency {arm:3} median {latency[arm]['median_ms']:7.3f} ms  "
              f"IQR {latency[arm]['iqr_ms']:7.3f} ms  p95 {latency[arm]['p95_ms']:7.3f} ms")

    if not args.keep_cases:
        for case in cases:
            case["path"].unlink(missing_ok=True)

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    for row in report["attacks"]:
        row.pop("path", None)
    path = REPORTS / "three_arm_experiment.json"
    path.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
