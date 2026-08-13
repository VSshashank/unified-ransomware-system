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

Ten families are imitated. Section 5.6.2 asks the system to detect "3+ different
ransomware simulators" and section 6.4.1 describes a run of "10 different
ransomware simulators", so ten is the number the document's own methodology
chapter uses. They differ in the *shape of what the watcher sees* - which is
what a detector either handles or does not - rather than in the payload, which
is the same reversible keystream XOR in every one:

    locker       rewrite in place, append .locked    entropy + extension signal
    silent       rewrite in place, keep the name     entropy alone, no rename
    copycat      write a new file, delete the old    created + deleted
    partial      scramble the leading quarter        intermittent encryption
    headerspoof  in place, ZIP magic over ciphertext magic-byte evasion, has a
                                                     baseline to rise from
    renamer      in place, then rename to random hex no extension, no known type
    notedrop     in place, plus a ransom note        encryption mixed with
                                                     benign low-entropy writes
    slowburn     in place, one file every 800ms      low event rate
    staged       two passes, half the file each      entropy walked up in steps
    spoofer      new .zip file with ZIP magic over   magic-byte evasion with no
                 ciphertext, delete the original     baseline to rise from

Every family round-trips through --restore; a family that cannot be undone is
not safe to ship in a defensive project.

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


# Windows opens files without FILE_SHARE_DELETE by default, so *any* process
# holding the file open for reading blocks a rename with WinError 32 - and the
# Monitor opens exactly this file, at exactly this moment, to classify the write
# that just happened. Measured against a live watcher, the unretried rename in
# `locker` and `renamer` failed on the very first file every time.
#
# Retrying is what the real thing does, so imitating it is the accurate
# behaviour, not a workaround: a family that gave up the moment a scanner held a
# handle would encrypt nothing. The budget is short because the handle is held
# for the length of one read.
RENAME_RETRY_BUDGET_SECONDS = 2.0
RENAME_RETRY_BACKOFF_SECONDS = 0.005


def _retrying(action):
    deadline = time.monotonic() + RENAME_RETRY_BUDGET_SECONDS
    delay = RENAME_RETRY_BACKOFF_SECONDS
    while True:
        try:
            return action()
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.1)


def _rename(path: Path, target: Path) -> Path:
    _retrying(lambda: path.rename(target))
    return target


def _unlink(path: Path) -> None:
    """Deleting the original hits the same held-handle problem a rename does."""
    _retrying(path.unlink)


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
    return _rename(path, path.with_suffix(path.suffix + ".locked"))


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
    _unlink(path)
    return encrypted


def encrypt_partial(path: Path, seed: bytes) -> Path:
    """Scramble only the leading fraction of the file, leaving the tail intact.

    Intermittent encryption, the technique that makes a file unusable while
    moving far less data. It is the hardest of the ten for an entropy-based
    detector: the unscrambled tail pulls the whole-file measurement back down
    toward the original.
    """
    original = path.read_bytes()
    cut = max(1, int(len(original) * PARTIAL_FRACTION))
    path.write_bytes(_xor(original[:cut], seed) + original[cut:])
    return path


# A valid ZIP local-file header. Families that write this over ciphertext are
# imitating the magic-byte evasion the detector's container exemption exists to
# handle - and testing whether the exemption can be turned against it.
ZIP_MAGIC = b"PK\x03\x04"


def encrypt_headerspoof(path: Path, seed: bytes) -> Path:
    """Rewrite in place with a ZIP header pasted over the ciphertext.

    A magic-byte check alone waves this through: the file declares itself an
    archive, and archives are high entropy by design. What it cannot fake is
    history - this path was measured before, at document entropy, so the rise is
    still visible. This is the case differential entropy analysis exists for, and
    the reason `classify` checks the rise *before* the container exemption.
    """
    path.write_bytes(ZIP_MAGIC + _xor(path.read_bytes(), seed))
    return path


def decrypt_headerspoof(data: bytes, seed: bytes) -> bytes:
    return _xor(data[len(ZIP_MAGIC):], seed)


def encrypt_renamer(path: Path, seed: bytes) -> Path:
    """Rewrite in place, then rename to random hex with no extension.

    GandCrab and several others discard the original name entirely. There is no
    ransom extension to key on and no declared file type at all, so entropy has
    to carry the decision by itself - and the rename means the new path has no
    measurement history behind it.
    """
    path.write_bytes(_xor(path.read_bytes(), seed))
    return _rename(path, path.with_name(hashlib.sha256(path.name.encode() + seed).hexdigest()[:16]))


RANSOM_NOTE_NAME = "README_RESTORE_FILES.txt"
RANSOM_NOTE_BODY = (
    b"Your files have been encrypted.\n"
    b"This is a simulation. Run the simulator with --restore to undo it.\n"
)


def encrypt_notedrop(path: Path, seed: bytes) -> Path:
    """Rewrite in place and drop a plaintext ransom note beside it.

    Real families leave a note in every directory they touch. It matters to the
    detector because it interleaves *low*-entropy creates with high-entropy
    rewrites: a detector that alerted on the note as well would be generating a
    false positive on every directory, and one that treated the burst as a
    single event could let the note mask the rewrite.
    """
    path.write_bytes(_xor(path.read_bytes(), seed))
    (path.parent / RANSOM_NOTE_NAME).write_bytes(RANSOM_NOTE_BODY)
    return path


def encrypt_slowburn(path: Path, seed: bytes) -> Path:
    """Identical bytes to `silent`; the difference is the pace, set by --delay-ms.

    Rate-limiting is a real evasion against detectors that trigger on a burst of
    modifications rather than on the content of any one of them. Included to
    prove this detector's decision is per-file, so slowing down buys nothing.
    """
    path.write_bytes(_xor(path.read_bytes(), seed))
    return path


def encrypt_staged(path: Path, seed: bytes) -> Path:
    """Two passes, half the file each, as two separate write events.

    This is the case that defeats a naive differential-entropy check. Comparing
    each reading against the previous one, neither pass is a large enough rise to
    flag; comparing against the lowest reading in the window, the second pass is.
    `EntropyHistory` takes the minimum for exactly this reason, and this family
    is what tests that choice.
    """
    original = path.read_bytes()
    half = max(1, len(original) // 2)
    path.write_bytes(_xor(original[:half], seed) + original[half:])
    time.sleep(0.05)
    partial = path.read_bytes()
    path.write_bytes(partial[:half] + _xor(partial[half:], seed))
    return path


def decrypt_staged(data: bytes, seed: bytes) -> bytes:
    half = max(1, len(data) // 2)
    return _xor(data[:half], seed) + _xor(data[half:], seed)


def encrypt_spoofer(path: Path, seed: bytes) -> Path:
    """Write a new .zip carrying a ZIP header over ciphertext, delete the original.

    The same evasion as `headerspoof` but with the one thing that makes it work:
    a path the detector has never measured. With no baseline there is no rise to
    catch, and the container exemption has nothing to override it. This is the
    honest hard case, and it is included precisely so the sweep reports it.
    """
    encrypted = path.with_suffix(path.suffix + ".zip")
    encrypted.write_bytes(ZIP_MAGIC + _xor(path.read_bytes(), seed))
    _unlink(path)
    return encrypted


def _decrypt_full(data: bytes, seed: bytes) -> bytes:
    return _xor(data, seed)


def _decrypt_partial(data: bytes, seed: bytes) -> bytes:
    cut = max(1, int(len(data) * PARTIAL_FRACTION))
    return _xor(data[:cut], seed) + data[cut:]


def _strip_zip_magic(data: bytes, seed: bytes) -> bytes:
    return _xor(data[len(ZIP_MAGIC):], seed)


# name -> (encrypt, decrypt, extra files it leaves behind)
FAMILIES = {
    "locker": (encrypt_locker, _decrypt_full, ()),
    "silent": (encrypt_silent, _decrypt_full, ()),
    "copycat": (encrypt_copycat, _decrypt_full, ()),
    "partial": (encrypt_partial, _decrypt_partial, ()),
    "headerspoof": (encrypt_headerspoof, decrypt_headerspoof, ()),
    "renamer": (encrypt_renamer, _decrypt_full, ()),
    "notedrop": (encrypt_notedrop, _decrypt_full, (RANSOM_NOTE_NAME,)),
    "slowburn": (encrypt_slowburn, _decrypt_full, ()),
    "staged": (encrypt_staged, decrypt_staged, ()),
    "spoofer": (encrypt_spoofer, _strip_zip_magic, ()),
}

# Families whose default pace differs from --delay-ms's default, because the
# pace is the behaviour being imitated.
FAMILY_DEFAULT_DELAY_MS = {"slowburn": 800}


def _legacy_encrypted_name(name: str, family: str) -> str:
    """Where a pre-manifest-v2 run left the encrypted file.

    Manifests written before the ten-family rewrite record only the original
    names, so the encrypted name has to be reconstructed. Only the four families
    that existed then are reachable this way.
    """
    return name + {"locker": ".locked", "copycat": ".enc"}.get(family, "")


def restore(target: Path, seed: bytes) -> int:
    manifest_path = target / MANIFEST_NAME
    if not manifest_path.exists():
        print(f"no manifest at {manifest_path}; nothing this script created is here")
        return 0

    manifest = json.loads(manifest_path.read_text())
    # Older manifests predate --family and are all locker runs.
    family = manifest.get("family", "locker")
    if family not in FAMILIES:
        print(f"manifest names an unknown family {family!r}; refusing to guess")
        return 0

    _, decrypt, _ = FAMILIES[family]

    # Manifest v2 records the encrypted name each original became, because
    # `renamer` chooses names that cannot be derived from the original alone.
    entries = manifest.get("entries")
    if entries is None:
        entries = [
            {"original": name, "encrypted": _legacy_encrypted_name(name, family)}
            for name in manifest.get("files", [])
        ]

    restored = 0
    for entry in entries:
        encrypted = target / entry["encrypted"]
        if not encrypted.exists():
            continue
        (target / entry["original"]).write_bytes(decrypt(encrypted.read_bytes(), seed))
        if encrypted.name != entry["original"]:
            encrypted.unlink()
        restored += 1

    for extra in manifest.get("extra", []):
        leftover = target / extra
        if leftover.exists():
            leftover.unlink()

    print(f"restored {restored} file(s) in {target}")
    return restored


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target-dir", required=True, help="Directory to operate in. Created if absent.")
    parser.add_argument("--files", type=int, default=20, help="Decoy documents to create.")
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=None,
        help="Pause between encryptions. Defaults to 120, or the family's own pace.",
    )
    parser.add_argument("--seed", default="tc01-simulator", help="Keystream seed; same value restores.")
    parser.add_argument("--restore", action="store_true", help="Undo a previous run and exit.")
    parser.add_argument(
        "--family",
        choices=sorted(FAMILIES),
        default="locker",
        help="Which behaviour to imitate; see the module docstring for all ten.",
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

    encrypt, _, extra = FAMILIES[args.family]
    delay_ms = (
        args.delay_ms
        if args.delay_ms is not None
        else FAMILY_DEFAULT_DELAY_MS.get(args.family, 120)
    )

    decoys = build_decoys(target, args.files)
    manifest_path = target / MANIFEST_NAME

    # The manifest is written before the first rewrite, and rewritten after each
    # one with the name that file actually became. Deriving the encrypted name
    # afterwards is not possible for `renamer`, which picks names the original
    # does not determine - and a run interrupted halfway must still be
    # restorable, which is the whole reason the manifest exists.
    entries: list[dict] = []
    manifest = {"family": args.family, "entries": entries, "extra": list(extra)}
    manifest_path.write_text(json.dumps(manifest))

    print(f"created {len(decoys)} decoy document(s) in {target}", flush=True)
    time.sleep(0.5)  # let the watcher enumerate them before anything changes

    print(f"beginning simulated encryption (family: {args.family})", flush=True)
    encrypted = 0
    for decoy in decoys:
        original_name = decoy.name
        result = encrypt(decoy, seed)
        entries.append({"original": original_name, "encrypted": result.name})
        manifest_path.write_text(json.dumps(manifest))
        encrypted += 1
        # Printed per file and flushed: the harness reads this to count how many
        # were lost before the response engine terminated the process. The name
        # reported is the one now on disk, not the original - `renamer` and
        # `spoofer` choose names the original does not determine, and a harness
        # that reconstructed the name by appending ".locked" would only ever work
        # for one of the ten families.
        print(f"ENCRYPTED {encrypted} {result.name}", flush=True)
        if delay_ms:
            time.sleep(delay_ms / 1000)

    print(f"finished: {encrypted} file(s) encrypted (nothing terminated this process)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
