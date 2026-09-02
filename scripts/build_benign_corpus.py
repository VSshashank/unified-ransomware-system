"""A stratified benign corpus, built by real encoders and frozen - NI.

Item P5.3, Chapter 9 §9.4.1, artefact register §9.8 →
reports/benign_corpus_manifest.json, tagged at Week 19.

Phase 6 measures what a repair costs on files nobody should ever be alerted
about. That measurement is only worth having if the corpus is stratified the way
the failure is expected to fall, so the strata are the two axes that decide it:

    {validated, unvalidated}  x  {compressible, incompressible}

**validated / unvalidated** is a property of the *format*: does
`containers._VALIDATORS` hold a structural validator for it? This is a fact
about the code, read from `containers.VALIDATED_FORMATS`, not a judgement.

**compressible / incompressible** is a property of the *file*, and it is
measured, not declared. Each file is scored with `detection.measure`, and the
stratum is `incompressible` when its Shannon entropy is at or above the
detector's own threshold. Declaring it would let a mislabelled file hide in the
stratum that matters most; measuring it means the corpus says what it is.

`unvalidated x incompressible` is the stratum D5 turns on: a format with no
structural validator, holding content that legitimately looks like ciphertext. A
repair that stops trusting unvalidated headers has to alert on something, and
this is what it will alert on.

What "genuine" means here, exactly
----------------------------------
Every file is produced by a real encoder for its format - Pillow for PNG, JPEG
and GIF, the standard library's `zipfile`, `gzip`, `bz2`, `lzma` and `wave`,
fpdf for PDF. None is a magic number in front of noise. They pass structural
validation because they are structurally real.

The *content* is synthetic: generated images, generated prose, generated audio.
These are not files taken off a user's disk, and the manifest does not claim
they are. To put some genuinely-not-synthesised files in the corpus, artefacts
this project produced during Phases 1-4 - the matplotlib PNGs in reports/, the
PDF in docs/ - are included under a second provenance class. Those cannot be
rebuilt from a seed and are marked `rebuildable: false`.

Format coverage, stated rather than implied
-------------------------------------------
§9.9's risk row anticipates this: *"Report exact counts and treat undersized
formats descriptively. Five or six deployment-relevant formats only; no claim of
16-format coverage."*

Real encoders are available in this environment for nine of the sixteen formats
in the registry:

    validated   - zip, gzip, png, jpeg, pdf          (5 of 6)
    unvalidated - bzip2, xz, gif, riff/wav           (4 of 11)

There is no encoder here for rar, 7z, lz4, zstd, mp3, ogg, flac or iso-bmff, and
a hand-assembled byte string for one of those would be exactly the forgery this
corpus exists to be the opposite of. They are absent, they are listed as absent
in the manifest, and **no claim of 16-format coverage is made or implied.**

Reproducibility
---------------
Every generated file derives from `random.Random(seed)`, never `os.urandom`, and
every encoder is pinned to a fixed timestamp. `--verify` rebuilds the corpus and
compares each hash against the manifest, so "rebuilds byte-identically" is a
test rather than an assurance.

    .venv\\Scripts\\python.exe scripts/build_benign_corpus.py
    .venv\\Scripts\\python.exe scripts/build_benign_corpus.py --verify

Writes the manifest only when URDS_WRITE_REPORTS=1. The corpus itself lands in
data/, which is gitignored - the manifest is the artefact, the bytes are
rebuildable from it.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import random
import struct
import subprocess
import sys
import wave
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"
CORPUS_ROOT = REPO_ROOT / "data" / "benign_corpus"

sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))

import containers  # noqa: E402
import detection  # noqa: E402

DEFAULT_SEED = 20260902

# ZIP and GZIP both embed a modification time. Pinning it is what makes a
# rebuild byte-identical rather than merely equivalent.
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_EPOCH = 0

# Files per (format, construction) cell. 8 keeps every stratum populated enough
# for a paired comparison without making the build take longer than the thing it
# feeds.
PER_CELL = 8

WORDS = (
    "quarterly", "revenue", "deployment", "incident", "baseline", "container",
    "entropy", "recovery", "ledger", "threshold", "operator", "signature",
    "mitigation", "verdict", "archive", "document", "analysis", "report",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


# --------------------------------------------------------------- content


def prose(rng: random.Random, size: int) -> bytes:
    """Low-entropy text. A real document's byte distribution, near enough."""
    out = []
    total = 0
    while total < size:
        line = " ".join(rng.choice(WORDS) for _ in range(rng.randint(6, 14))) + ".\n"
        out.append(line)
        total += len(line)
    return "".join(out).encode()[:size]


def noise(rng: random.Random, size: int) -> bytes:
    """High-entropy bytes from a seeded generator, so a rebuild reproduces them.

    `os.urandom` would be a better model of ciphertext and would make the corpus
    impossible to rebuild, which is the property §9.4.1 asks for. Mersenne
    Twister output is not cryptographic and does not need to be: what is being
    measured is a byte distribution, and this one is flat.
    """
    return rng.randbytes(size)


def gradient_image(rng: random.Random, width: int, height: int):
    """A smooth image. Compresses well - this is the compressible half."""
    from PIL import Image

    base = rng.randint(0, 120)
    image = Image.new("RGB", (width, height))
    pixels = image.load()
    for y in range(height):
        for x in range(width):
            pixels[x, y] = (
                (base + x * 255 // max(width - 1, 1)) % 256,
                (base + y * 255 // max(height - 1, 1)) % 256,
                base,
            )
    return image


def photographic_image(rng: random.Random, width: int, height: int):
    """A noisy image. What a photograph looks like to an entropy meter."""
    from PIL import Image

    data = bytes(rng.randrange(256) for _ in range(width * height * 3))
    return Image.frombytes("RGB", (width, height), data)


def tone_audio(rng: random.Random, frames: int) -> bytes:
    """A pure tone. Low entropy, and a real WAV."""
    import math

    period = rng.randint(40, 90)
    return b"".join(
        struct.pack("<h", int(20000 * math.sin(2 * math.pi * i / period)))
        for i in range(frames)
    )


def noise_audio(rng: random.Random, frames: int) -> bytes:
    """White noise. A real WAV whose bytes are indistinguishable from ciphertext."""
    return b"".join(struct.pack("<h", rng.randint(-30000, 30000)) for i in range(frames))


# --------------------------------------------------------------- encoders


def _zip_of(payload: bytes, name: str, compression: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        info = zipfile.ZipInfo(name, date_time=FIXED_TIMESTAMP)
        info.compress_type = compression
        info.create_system = 0
        archive.writestr(info, payload)
    return buffer.getvalue()


def _gzip_of(payload: bytes, name: str) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(filename=name, mode="wb", fileobj=buffer, mtime=FIXED_EPOCH) as handle:
        handle.write(payload)
    return buffer.getvalue()


def _pillow_of(image, fmt: str, **options) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format=fmt, **options)
    return buffer.getvalue()


def _pdf_of(text: str) -> bytes:
    from fpdf import FPDF

    pdf = FPDF()
    # fpdf stamps a creation date by default; a rebuild has to produce the same
    # bytes, so it is pinned rather than left to the clock.
    pdf.set_creation_date(datetime(1980, 1, 1, tzinfo=timezone.utc))
    pdf.add_page()
    pdf.set_font("helvetica", size=11)
    for line in text.splitlines():
        pdf.cell(0, 6, line[:90], new_x="LMARGIN", new_y="NEXT")
    out = pdf.output()
    return bytes(out)


def _wav_of(frames: bytes) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(22050)
        handle.writeframes(frames)
    return buffer.getvalue()


# ----------------------------------------------------------------- recipes

# (filename stem, extension, declared format, construction note, builder)
# The builder takes a seeded Random and returns the file's bytes.
RECIPES = [
    # ---------------------------------------------------------- validated
    (
        "zip_stored_text", ".zip", "zip",
        "ZIP_STORED archive of prose - a real archive, low-entropy content",
        lambda rng: _zip_of(prose(rng, 90_000), "notes.txt", zipfile.ZIP_STORED),
    ),
    (
        "zip_deflated_text", ".zip", "zip",
        "ZIP_DEFLATED archive of prose - real deflate over compressible input",
        lambda rng: _zip_of(prose(rng, 300_000), "report.txt", zipfile.ZIP_DEFLATED),
    ),
    (
        "zip_deflated_photo", ".zip", "zip",
        "ZIP_DEFLATED archive of a JPEG - a backup of an already-compressed file",
        lambda rng: _zip_of(
            _pillow_of(photographic_image(rng, 200, 150), "JPEG", quality=88),
            "photo.jpg",
            zipfile.ZIP_DEFLATED,
        ),
    ),
    (
        "gzip_text", ".gz", "gzip",
        "gzip of prose - a real deflate stream over compressible input",
        lambda rng: _gzip_of(prose(rng, 300_000), "log.txt"),
    ),
    (
        "gzip_photo", ".gz", "gzip",
        "gzip of a JPEG - the shape a nightly backup of a photo directory has",
        lambda rng: _gzip_of(
            _pillow_of(photographic_image(rng, 220, 165), "JPEG", quality=88), "photo.jpg"
        ),
    ),
    (
        "png_gradient", ".png", "png",
        "PNG of a smooth gradient - a real IHDR, IDAT and IEND",
        lambda rng: _pillow_of(gradient_image(rng, 320, 240), "PNG", optimize=False),
    ),
    (
        "png_photo", ".png", "png",
        "PNG of photographic content - lossless over noise, so high entropy",
        lambda rng: _pillow_of(photographic_image(rng, 260, 200), "PNG", optimize=False),
    ),
    (
        "jpeg_photo", ".jpg", "jpeg",
        "JPEG of photographic content - a real marker chain to SOS and EOI",
        lambda rng: _pillow_of(photographic_image(rng, 320, 240), "JPEG", quality=90),
    ),
    (
        "jpeg_gradient", ".jpg", "jpeg",
        "JPEG of a smooth gradient - a real JPEG that compresses hard",
        lambda rng: _pillow_of(gradient_image(rng, 400, 300), "JPEG", quality=70),
    ),
    (
        "pdf_text", ".pdf", "pdf",
        "PDF of prose - real indirect objects, a real xref and %%EOF",
        lambda rng: _pdf_of(prose(rng, 4_000).decode()),
    ),
    # -------------------------------------------------------- unvalidated
    (
        "bzip2_text", ".bz2", "bzip2",
        "bzip2 of prose - a real bzip2 stream over compressible input",
        lambda rng: bz2.compress(prose(rng, 300_000)),
    ),
    (
        "bzip2_photo", ".bz2", "bzip2",
        "bzip2 of a JPEG - already-compressed input, so the output is flat",
        lambda rng: bz2.compress(
            _pillow_of(photographic_image(rng, 220, 165), "JPEG", quality=88)
        ),
    ),
    (
        "xz_text", ".xz", "xz",
        "xz of prose - a real LZMA2 stream over compressible input",
        lambda rng: lzma.compress(prose(rng, 300_000)),
    ),
    (
        "xz_photo", ".xz", "xz",
        "xz of a JPEG - already-compressed input",
        lambda rng: lzma.compress(
            _pillow_of(photographic_image(rng, 220, 165), "JPEG", quality=88)
        ),
    ),
    (
        "gif_flat", ".gif", "gif",
        "GIF of a flat-colour image - a real GIF89a with an LZW-coded image block",
        lambda rng: _pillow_of(gradient_image(rng, 240, 180).convert("P"), "GIF"),
    ),
    (
        "gif_dithered", ".gif", "gif",
        "GIF of photographic content - dithered to 256 colours, high entropy",
        lambda rng: _pillow_of(
            photographic_image(rng, 220, 165).convert("P", dither=1), "GIF"
        ),
    ),
    (
        "wav_tone", ".wav", "riff",
        "WAV of a pure tone - a real RIFF/WAVE header and PCM frames",
        lambda rng: _wav_of(tone_audio(rng, 60_000)),
    ),
    (
        "wav_noise", ".wav", "riff",
        "WAV of white noise - a real RIFF whose samples look like ciphertext",
        lambda rng: _wav_of(noise_audio(rng, 60_000)),
    ),
]

# Formats in the registry this environment has no real encoder for. Listed so
# the manifest states the gap instead of leaving it to be inferred.
NO_ENCODER_AVAILABLE = {
    "iso-bmff": "no ffmpeg or MP4 muxer in this environment",
    "rar": "RAR is a proprietary format with no free encoder",
    "7z": "py7zr not installed",
    "lz4": "lz4 not installed",
    "zstd": "zstandard not installed",
    "mp3": "no LAME or MP3 encoder available",
    "ogg": "no Vorbis encoder available",
    "flac": "no FLAC encoder available",
}

# Real files this project produced during Phases 1-4. Not synthesised, not
# rebuildable from a seed, and included so the corpus is not entirely generated.
REPOSITORY_ARTEFACTS = (
    "reports/confusion_matrix.png",
    "reports/entropy_distribution.png",
    "reports/shap_summary_plot.png",
    "class_balance_chart.png",
    "docs/Phase1-4_Team_Explainer.pdf",
)


# ------------------------------------------------------------------ strata


def measure_file(path: Path) -> dict:
    """Score one corpus file the way the detector reads it.

    The current verdict is recorded alongside the measurement, because a benign
    corpus the deployed detector already alerts on is not a benign corpus - it
    is a bad recipe, and catching that here is cheaper than discovering it as a
    false-positive figure in Phase 6. It is also Arm A's baseline on this
    corpus, measured at the moment the corpus is frozen.
    """
    size = path.stat().st_size
    head, tail = detection.sample_file(str(path), size)
    entropy, statistics = detection.measure(head)
    magic = detection.read_magic(str(path))
    container = detection.identify_container(magic)
    tri_state = containers.validate_container(head, tail, container, size)
    verdict = detection.classify(
        str(path),
        entropy,
        magic,
        detection.DEFAULT_ENTROPY_THRESHOLD,
        readable=True,
        entropy_delta=None,
        container_valid=tri_state,
        statistics=statistics,
    )
    return {
        "entropy": entropy,
        "detected_format": container,
        "validator_present": container in containers.VALIDATED_FORMATS,
        "container_status": containers.container_status(head, tail, container, size),
        "arm_a_verdict": verdict["verdict"],
        "arm_a_suspicious": verdict["suspicious"],
        "arm_a_signal": verdict["signal"],
    }


def stratum_of(validator_present: bool, entropy: float, threshold: float) -> str:
    axis_one = "validated" if validator_present else "unvalidated"
    axis_two = "incompressible" if entropy >= threshold else "compressible"
    return f"{axis_one}_x_{axis_two}"


# ------------------------------------------------------------------- build


def build(seed: int, per_cell: int, root: Path, write_files: bool) -> list[dict]:
    """Generate the corpus and measure every file. Returns the manifest rows."""
    threshold = detection.DEFAULT_ENTROPY_THRESHOLD
    rows: list[dict] = []

    # Always created, even for a verification pass: `measure_file` reads through
    # `detection.sample_file`, which takes a path, so every file has to exist on
    # disk long enough to be scored the way the detector would score it.
    # `write_files=False` controls whether it survives that, not whether it lands.
    root.mkdir(parents=True, exist_ok=True)

    for stem, extension, declared, note, builder in RECIPES:
        for index in range(per_cell):
            # One generator per file, derived from the corpus seed and the
            # file's identity. A per-file stream means adding a recipe later
            # does not shift the bytes of every file after it.
            rng = random.Random(f"{seed}:{stem}:{index}")
            blob = builder(rng)
            name = f"{stem}_{index:02d}{extension}"
            path = root / name
            path.write_bytes(blob)

            measured = measure_file(path)
            rows.append(
                {
                    "file": name,
                    "sha256": sha256_bytes(blob),
                    "size": len(blob),
                    "declared_format": declared,
                    "source": "generated",
                    "construction": note,
                    "seed_key": f"{seed}:{stem}:{index}",
                    "rebuildable": True,
                    "stratum": stratum_of(
                        measured["validator_present"], measured["entropy"], threshold
                    ),
                    **measured,
                }
            )

            if not write_files:
                path.unlink(missing_ok=True)

    for relative in REPOSITORY_ARTEFACTS:
        source = REPO_ROOT / relative
        if not source.exists():
            continue
        blob = source.read_bytes()
        name = f"repo_{Path(relative).name}"
        path = root / name
        path.write_bytes(blob)
        measured = measure_file(path)
        rows.append(
            {
                "file": name,
                "sha256": sha256_bytes(blob),
                "size": len(blob),
                "declared_format": measured["detected_format"],
                "source": f"repository artefact: {relative}",
                "construction": "produced by this project during Phases 1-4; not synthesised",
                "seed_key": None,
                "rebuildable": False,
                "stratum": stratum_of(
                    measured["validator_present"], measured["entropy"], threshold
                ),
                **measured,
            }
        )
        if not write_files:
            path.unlink(missing_ok=True)

    return rows


def summarise(rows: list[dict]) -> dict:
    strata: dict[str, int] = {}
    formats: dict[str, int] = {}
    for row in rows:
        strata[row["stratum"]] = strata.get(row["stratum"], 0) + 1
        key = row["detected_format"] or "<no container header>"
        formats[key] = formats.get(key, 0) + 1

    validated = sorted({r["detected_format"] for r in rows if r["validator_present"] and r["detected_format"]})
    unvalidated = sorted({r["detected_format"] for r in rows if not r["validator_present"] and r["detected_format"]})

    # A benign corpus the deployed detector already alerts on is not a benign
    # corpus. This is both the recipe check and Arm A's false-positive baseline
    # on this corpus, per stratum, taken at freeze time.
    flagged = [r for r in rows if r["arm_a_suspicious"]]
    per_stratum_flagged: dict[str, int] = {}
    for row in flagged:
        per_stratum_flagged[row["stratum"]] = per_stratum_flagged.get(row["stratum"], 0) + 1

    return {
        "files": len(rows),
        "by_stratum": dict(sorted(strata.items())),
        "arm_a_baseline": {
            "flagged": len(flagged),
            "rate": round(len(flagged) / len(rows), 4) if rows else 0.0,
            "by_stratum": dict(sorted(per_stratum_flagged.items())),
            "offenders": [
                {"file": r["file"], "verdict": r["arm_a_verdict"], "signal": r["arm_a_signal"]}
                for r in flagged
            ],
        },
        "by_detected_format": dict(sorted(formats.items())),
        "validated_formats_present": validated,
        "unvalidated_formats_present": unvalidated,
        "formats_in_registry_with_no_encoder_here": NO_ENCODER_AVAILABLE,
        "rebuildable_files": sum(1 for r in rows if r["rebuildable"]),
        "non_rebuildable_files": sum(1 for r in rows if not r["rebuildable"]),
    }


def verify(manifest: dict, per_cell: int, root: Path) -> dict:
    """Rebuild from the recorded seed and compare every generated file's hash."""
    rebuilt = build(manifest["seed"], per_cell, root, write_files=False)
    recorded = {r["file"]: r["sha256"] for r in manifest["files"] if r["rebuildable"]}
    fresh = {r["file"]: r["sha256"] for r in rebuilt if r["rebuildable"]}

    missing = sorted(set(recorded) - set(fresh))
    added = sorted(set(fresh) - set(recorded))
    mismatched = sorted(name for name in set(recorded) & set(fresh) if recorded[name] != fresh[name])

    return {
        "checked": len(recorded),
        "identical": len(recorded) - len(mismatched) - len(missing),
        "mismatched": mismatched,
        "missing_from_rebuild": missing,
        "unexpected_in_rebuild": added,
        "byte_identical": not (mismatched or missing or added),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--per-cell", type=int, default=PER_CELL)
    parser.add_argument("--verify", action="store_true", help="rebuild and compare against the manifest")
    args = parser.parse_args()

    manifest_path = REPORTS / "benign_corpus_manifest.json"

    if args.verify:
        if not manifest_path.exists():
            print(f"no manifest at {manifest_path}; build it first")
            return 1
        manifest = json.loads(manifest_path.read_text())
        result = verify(manifest, manifest.get("per_cell", args.per_cell), CORPUS_ROOT / "_verify")
        print(json.dumps(result, indent=2))
        return 0 if result["byte_identical"] else 1

    rows = build(args.seed, args.per_cell, CORPUS_ROOT, write_files=True)
    summary = summarise(rows)

    # Rebuild immediately and compare, so the manifest can state the property
    # rather than assert it.
    reproduction = verify(
        {"seed": args.seed, "files": rows, "per_cell": args.per_cell},
        args.per_cell,
        CORPUS_ROOT / "_verify",
    )

    manifest = {
        "schema": "urds.benign_corpus_manifest/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "seed": args.seed,
        "per_cell": args.per_cell,
        "corpus_root": str(CORPUS_ROOT.relative_to(REPO_ROOT)).replace("\\", "/"),
        "entropy_threshold": detection.DEFAULT_ENTROPY_THRESHOLD,
        "stratum_definition": {
            "axis_1": "validated | unvalidated - whether containers._VALIDATORS holds a "
                      "structural validator for the detected format",
            "axis_2": "compressible | incompressible - measured, not declared: "
                      "incompressible when detection.measure reports entropy >= the "
                      "detector's own threshold",
        },
        "coverage_statement": (
            "Nine of the sixteen registry formats are represented, because real "
            "encoders for the other seven are not available in this environment. "
            "No claim of 16-format coverage is made. See "
            "formats_in_registry_with_no_encoder_here."
        ),
        "provenance_statement": (
            "Every generated file is produced by a real encoder for its format and is "
            "structurally genuine. Its content is synthetic - generated images, prose "
            "and audio - and the manifest does not claim these are files taken from a "
            "user's disk. Five files carry repository provenance instead and are marked "
            "rebuildable: false."
        ),
        "summary": summary,
        "reproduction": reproduction,
        "files": rows,
    }

    print(json.dumps(summary, indent=2))
    print(f"\nreproduction: byte_identical={reproduction['byte_identical']} "
          f"({reproduction['identical']}/{reproduction['checked']} generated files)")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: manifest not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\nwrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
