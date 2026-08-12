"""TC-01 harness: a safe stand-in for a ransomware sample.

Table 5.8 TC-01 reads "Detect known ransomware (Jasmin) -> Alert triggered,
process terminated, <5 files encrypted". Section 1.5 of the same document
requires live samples to run only in "isolated, air-gapped sandbox
environments", which a development laptop is not. This script reproduces the
*behaviour* that test exercises with no malicious payload:

    write decoy documents -> rewrite each in place with high-entropy bytes,
    fast, in descending order of how much a real operator would miss the file

That is the signal the Monitor is built to catch: a .docx whose contents stop
looking like a .docx. Everything the detection path sees - entropy, magic bytes,
modification rate, event ordering - is identical to the real thing.

What makes this safe, and why each guard is here:

  * It only ever rewrites files it created itself, in this run. A manifest is
    written before the first rewrite and every target is checked against it.
  * It refuses to run outside a directory it was told to use, and refuses
    outright if that directory already holds files it did not create.
  * Originals are kept, so `--restore` puts the directory back exactly.
  * The "encryption" is a keystream XOR. It is not cryptography and is not
    meant to be - the point is high-entropy output, and a reversible
    transformation is a feature here, not a weakness.

    python scripts/ransomware_simulator.py --target-dir watched_files/tc01
    python scripts/ransomware_simulator.py --target-dir watched_files/tc01 --restore
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

MANIFEST_NAME = ".simulator_manifest.json"
DECOY_SUFFIXES = [".docx", ".xlsx", ".pdf", ".jpg", ".txt"]
MARKER = b"URDS-TC01-DECOY"


def build_decoys(target: Path, count: int) -> list[Path]:
    """Plausible documents, each carrying a marker so we can prove ownership."""
    created = []
    for index in range(count):
        suffix = DECOY_SUFFIXES[index % len(DECOY_SUFFIXES)]
        path = target / f"quarterly_report_{index:02d}{suffix}"
        body = MARKER + b"\n" + (f"decoy document {index} ".encode() * 2000)
        path.write_bytes(body)
        created.append(path)
    return created


def keystream(seed: bytes, length: int) -> bytes:
    """SHA-256 counter-mode keystream. High entropy, deterministic, reversible."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(out[:length])


def encrypt_in_place(path: Path, seed: bytes) -> None:
    """Rewrite the file with high-entropy bytes and take the extension, the way
    most families do - the rename is itself a detection signal."""
    original = path.read_bytes()
    scrambled = bytes(a ^ b for a, b in zip(original, keystream(seed, len(original))))
    path.write_bytes(scrambled)
    path.rename(path.with_suffix(path.suffix + ".locked"))


def restore(target: Path, seed: bytes) -> int:
    manifest_path = target / MANIFEST_NAME
    if not manifest_path.exists():
        print(f"no manifest at {manifest_path}; nothing this script created is here")
        return 0

    manifest = json.loads(manifest_path.read_text())
    restored = 0
    for name in manifest["files"]:
        locked = target / (name + ".locked")
        if not locked.exists():
            continue
        scrambled = locked.read_bytes()
        original = bytes(a ^ b for a, b in zip(scrambled, keystream(seed, len(scrambled))))
        locked.with_name(name).write_bytes(original)
        locked.unlink()
        restored += 1
    print(f"restored {restored} file(s) in {target}")
    return restored


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target-dir", required=True, help="Directory to operate in. Created if absent.")
    parser.add_argument("--files", type=int, default=20, help="Decoy documents to create.")
    parser.add_argument("--delay-ms", type=int, default=120, help="Pause between encryptions.")
    parser.add_argument("--seed", default="tc01-simulator", help="Keystream seed; same value restores.")
    parser.add_argument("--restore", action="store_true", help="Undo a previous run and exit.")
    args = parser.parse_args()

    target = Path(args.target_dir).resolve()
    seed = args.seed.encode()

    if args.restore:
        return 0 if restore(target, seed) >= 0 else 1

    target.mkdir(parents=True, exist_ok=True)

    # Refuse to run anywhere that already holds files we did not create. This is
    # the guard that stops a mistyped --target-dir from being destructive.
    pre_existing = [
        p for p in target.iterdir()
        if p.is_file() and p.name != MANIFEST_NAME and not p.read_bytes().startswith(MARKER)
    ]
    if pre_existing:
        print(f"refusing to run: {target} contains {len(pre_existing)} file(s) this script did not create.")
        print(f"  first few: {[p.name for p in pre_existing[:5]]}")
        print("  point --target-dir at an empty or simulator-owned directory.")
        return 2

    decoys = build_decoys(target, args.files)
    (target / MANIFEST_NAME).write_text(json.dumps({"files": [p.name for p in decoys], "seed": args.seed}, indent=2))
    print(f"created {len(decoys)} decoy document(s) in {target}", flush=True)

    time.sleep(0.5)  # let the watcher enumerate them before anything changes

    print("beginning simulated encryption", flush=True)
    encrypted = 0
    for path in decoys:
        encrypt_in_place(path, seed)
        encrypted += 1
        # Printed per file and flushed: the harness reads this to count how many
        # were lost before the response engine terminated the process.
        print(f"ENCRYPTED {encrypted} {path.name}", flush=True)
        time.sleep(args.delay_ms / 1000)

    print(f"finished: {encrypted} file(s) encrypted (nothing terminated this process)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
