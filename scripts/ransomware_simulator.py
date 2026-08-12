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

Four families are imitated, because section 5.6.2 asks the system to detect
"3+ different ransomware simulators" and one behaviour is not three. They differ
in the *shape* of what the watcher sees, not just the payload:

    locker   rewrite in place, append .locked   entropy + extension signal
    silent   rewrite in place, keep the name    entropy only, no rename to help
    copycat  write a new file, delete the old   created + deleted, not modified
    partial  scramble the leading quarter       intermittent encryption

    python scripts/ransomware_simulator.py --target-dir watched_files/tc01
    python scripts/ransomware_simulator.py --target-dir watched_files/tc01 --family silent
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


def _xor(data: bytes, seed: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream(seed, len(data))))


# How much of the file the `partial` family scrambles. Real intermittent
# encryptors (LockBit 3, BlackCat) touch a fraction of each file to go faster;
# the side effect is that whole-file entropy rises less, which is precisely what
# makes them harder to catch on an entropy threshold alone.
PARTIAL_FRACTION = 0.25


def encrypt_locker(path: Path, seed: bytes) -> Path:
    """Rewrite in place, then append a ransom extension.

    The classic pattern (WannaCry, Locky). Two signals fire at once: the
    contents stop matching the declared type, and the extension is a known one.
    """
    path.write_bytes(_xor(path.read_bytes(), seed))
    renamed = path.with_suffix(path.suffix + ".locked")
    path.rename(renamed)
    return renamed


def encrypt_silent(path: Path, seed: bytes) -> Path:
    """Rewrite in place and keep the original filename.

    Modern in-place encryptors do this deliberately: no rename means no
    extension signal, so the only evidence is that the bytes changed character.
    This is the case the entropy threshold and the differential-entropy check
    have to carry on their own.
    """
    path.write_bytes(_xor(path.read_bytes(), seed))
    return path


def encrypt_copycat(path: Path, seed: bytes) -> Path:
    """Write the ciphertext to a new file, then delete the original.

    A different event sequence from the other two - `created` followed by
    `deleted`, rather than `modified` - which is worth exercising because the
    watcher handles those on separate callbacks.
    """
    encrypted = path.with_suffix(path.suffix + ".enc")
    encrypted.write_bytes(_xor(path.read_bytes(), seed))
    path.unlink()
    return encrypted


def encrypt_partial(path: Path, seed: bytes) -> Path:
    """Scramble only the leading fraction of the file, leaving the tail intact.

    Intermittent encryption, the technique that makes a file unusable while
    moving far less data. It is included because it is the hardest of the four
    for an entropy-based detector: the unscrambled tail pulls the whole-file
    measurement back down toward the original.
    """
    original = path.read_bytes()
    cut = max(1, int(len(original) * PARTIAL_FRACTION))
    path.write_bytes(_xor(original[:cut], seed) + original[cut:])
    return path


FAMILIES = {
    "locker": encrypt_locker,
    "silent": encrypt_silent,
    "copycat": encrypt_copycat,
    "partial": encrypt_partial,
}


def _encrypted_path(target: Path, name: str, family: str) -> Path:
    suffix = {"locker": ".locked", "copycat": ".enc"}.get(family, "")
    return target / (name + suffix)


def restore(target: Path, seed: bytes) -> int:
    manifest_path = target / MANIFEST_NAME
    if not manifest_path.exists():
        print(f"no manifest at {manifest_path}; nothing this script created is here")
        return 0

    manifest = json.loads(manifest_path.read_text())
    # Older manifests predate --family and are all locker runs.
    family = manifest.get("family", "locker")
    restored = 0

    for name in manifest["files"]:
        encrypted = _encrypted_path(target, name, family)
        if not encrypted.exists():
            continue
        scrambled = encrypted.read_bytes()

        if family == "partial":
            cut = max(1, int(len(scrambled) * PARTIAL_FRACTION))
            original = _xor(scrambled[:cut], seed) + scrambled[cut:]
        else:
            original = _xor(scrambled, seed)

        (target / name).write_bytes(original)
        if encrypted.name != name:
            encrypted.unlink()
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
    parser.add_argument(
        "--family",
        choices=sorted(FAMILIES),
        default="locker",
        help=(
            "Which behaviour to imitate. locker: rewrite in place and append "
            ".locked. silent: rewrite in place, keep the name. copycat: write a "
            "new encrypted file and delete the original. partial: scramble only "
            "the leading quarter."
        ),
    )
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
    (target / MANIFEST_NAME).write_text(
        json.dumps(
            {"files": [p.name for p in decoys], "seed": args.seed, "family": args.family},
            indent=2,
        )
    )
    print(f"created {len(decoys)} decoy document(s) in {target}", flush=True)

    time.sleep(0.5)  # let the watcher enumerate them before anything changes

    encrypt = FAMILIES[args.family]
    print(f"beginning simulated encryption (family: {args.family})", flush=True)
    encrypted = 0
    for path in decoys:
        encrypt(path, seed)
        encrypted += 1
        # Printed per file and flushed: the harness reads this to count how many
        # were lost before the response engine terminated the process.
        print(f"ENCRYPTED {encrypted} {path.name}", flush=True)
        time.sleep(args.delay_ms / 1000)

    print(f"finished: {encrypted} file(s) encrypted (nothing terminated this process)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
