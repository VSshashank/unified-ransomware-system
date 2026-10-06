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
  * Before any file is rewritten, a copy of every original is saved OUTSIDE the
    target directory (see "Saved originals" below), and each file is journalled
    as in flight before it is touched. `--restore` puts every file back from
    those copies - including the one that was half-rewritten when the process
    was killed, which no decryption can undo - and then removes the copies.
  * The "encryption" is a keystream XOR. It is not cryptography and is not
    meant to be - the point is high-entropy output, and a reversible
    transformation is a feature here, not a weakness.

Thirteen families are imitated. Section 5.6.2 asks the system to detect "3+
different ransomware simulators" and section 6.4.1 describes a run of "10
different ransomware simulators", so ten was the number the document's own
methodology chapter uses; the last three were added afterwards, each written
against a specific hole that reading the detector's own source turned up. They
differ in the *shape of what the watcher sees* - which is what a detector either
handles or does not - rather than in the payload, which is the same reversible
keystream XOR in every one:

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

    strider      encrypt 4KB, skip 8KB, repeat       true strided intermittent
                                                     encryption - `partial` only
                                                     touches the front, which a
                                                     leading-block check would
                                                     catch by accident
    grinder      five sub-floor warm-up writes, then flushes the differential-
                 ciphertext behind a ZIP header      entropy window, then
                                                     collects the container
                                                     exemption. Both of Table
                                                     5.7's built mitigations in
                                                     six writes.
    poisoner     write a high-entropy file of each   raises a training-mode
                 extension, then encrypt in place    ceiling and encrypts
                                                     underneath it

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
import tempfile
import time
import uuid
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


_KEYSTREAM_BLOCK = 32  # one SHA-256 digest


def _keystream_at(seed: bytes, offset: int, length: int) -> bytes:
    """The slice of the same keystream that covers `offset`.

    `strider` encrypts disjoint regions of a file and has to XOR each one with
    the keystream bytes belonging to *its* offset, not with the keystream from
    the beginning. Restarting the keystream per region would give two regions of
    identical plaintext identical ciphertext, which is both wrong for imitating
    a real stream cipher and quietly lowers the entropy the detector measures -
    the number this family exists to test.
    """
    first = offset // _KEYSTREAM_BLOCK
    last = (offset + length + _KEYSTREAM_BLOCK - 1) // _KEYSTREAM_BLOCK
    out = bytearray()
    for counter in range(first, last):
        out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
    skip = offset - first * _KEYSTREAM_BLOCK
    return bytes(out[skip : skip + length])


def _xor_at(data: bytes, seed: bytes, offset: int) -> bytes:
    return bytes(a ^ b for a, b in zip(data, _keystream_at(seed, offset, len(data))))


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


def _renamer_name(name: str, seed: bytes) -> str:
    return hashlib.sha256(name.encode() + seed).hexdigest()[:16]


def encrypt_renamer(path: Path, seed: bytes) -> Path:
    """Rewrite in place, then rename to random hex with no extension.

    GandCrab and several others discard the original name entirely. There is no
    ransom extension to key on and no declared file type at all, so entropy has
    to carry the decision by itself - and the rename means the new path has no
    measurement history behind it.
    """
    path.write_bytes(_xor(path.read_bytes(), seed))
    return _rename(path, path.with_name(_renamer_name(path.name, seed)))


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


# ------------------------------------------------------------------- strider
#
# LockBit 3.0 and BlackCat encrypt a fraction of each file in a repeating
# stride, not a single leading run. `partial` only scrambles the front, which a
# detector could catch by looking at the first block alone and never notice it
# had solved a narrower problem. This is the general shape: encrypt
# STRIDE_ENCRYPT_BYTES, skip STRIDE_SKIP_BYTES, to the end of the file.
#
# One in three, at 4KB granularity, is chosen so a ~34KB decoy alternates
# several times rather than being one encrypted chunk and one plaintext chunk.
# The whole-file entropy that results sits well under the static threshold,
# which is the point: only a per-block view sees it.
STRIDE_ENCRYPT_BYTES = 4096
STRIDE_SKIP_BYTES = 8192


def _stride_regions(length: int):
    offset = 0
    while offset < length:
        yield offset, min(STRIDE_ENCRYPT_BYTES, length - offset)
        offset += STRIDE_ENCRYPT_BYTES + STRIDE_SKIP_BYTES


def _stride(data: bytes, seed: bytes) -> bytes:
    out = bytearray(data)
    for offset, size in _stride_regions(len(data)):
        out[offset : offset + size] = _xor_at(bytes(out[offset : offset + size]), seed, offset)
    return bytes(out)


def encrypt_strider(path: Path, seed: bytes) -> Path:
    """Strided intermittent encryption, in place, keeping the name.

    The file is unusable and most of its bytes were never touched. Whole-file
    entropy lands around 6 bits/byte - below the static threshold, above the
    plaintext, and the rise is under the 2.0 the differential check needs. What
    gives it away is that a third of its 4KB blocks are at ciphertext entropy
    and the rest are at document entropy, which no ordinary file does.
    """
    path.write_bytes(_stride(path.read_bytes(), seed))
    return path


# ------------------------------------------------------------------- grinder
#
# The differential-entropy window keeps ENTROPY_HISTORY_WINDOW readings and
# takes the lowest as the baseline. Five is that window's size in
# services/monitor/detection.py, so five writes are enough to push the original
# document's reading out of it - and any reading below ENTROPY_RISE_FLOOR does
# not alert on its own. Warm up with five, then write the ciphertext: measured
# against the warm-up writes the rise is too small to flag, and a ZIP header
# over the top collects the container exemption as well.
#
# Hardcoded rather than imported: the simulator is a black box to the detector
# and must not read its constants, or a test would pass by construction.
GRINDER_WARMUP_WRITES = 5
GRINDER_WARMUP_ALPHABET = 96  # log2(96) = 6.58 bits/byte, under the 7.0 floor
GRINDER_WARMUP_DELAY_SECONDS = 0.06


def encrypt_grinder(path: Path, seed: bytes) -> Path:
    """Flush the entropy window with sub-floor writes, then encrypt behind a header.

    Each warm-up write is drawn from a 96-symbol alphabet, which caps it at 6.58
    bits/byte - high enough to lift the window's minimum above 5.99, low enough
    that ENTROPY_RISE_FLOOR (7.0) means none of them alerts by itself.
    """
    original = path.read_bytes()
    for index in range(GRINDER_WARMUP_WRITES):
        filler = keystream(seed + b"warmup" + bytes([index]), len(original))
        path.write_bytes(bytes(byte % GRINDER_WARMUP_ALPHABET + 32 for byte in filler))
        # The watcher has to see these as separate events, or the window is
        # never flushed and the family is testing nothing.
        time.sleep(GRINDER_WARMUP_DELAY_SECONDS)

    path.write_bytes(ZIP_MAGIC + _xor(original, seed))
    return path


# ------------------------------------------------------------------ poisoner
#
# Training mode learns the highest entropy each extension reached and then stops
# alerting at or below it. Anything that can write into the watched tree while
# that window is open can therefore choose the ceiling. These files are what
# does the choosing: one per extension in use, at the top of the range, carrying
# the decoy marker so the script still only ever touches files it created.
POISON_PREFIX = "cache_bundle"
POISON_SIZE = 256 * 1024
POISON_SETTLE_SECONDS = 1.0


def _poison_files(target: Path, seed: bytes) -> list[Path]:
    written = []
    for index, suffix in enumerate(DECOY_SUFFIXES):
        path = target / f"{POISON_PREFIX}_{index:02d}{suffix}"
        path.write_bytes(MARKER + keystream(seed + b"poison" + bytes([index]), POISON_SIZE))
        written.append(path)
    return written


def poison_names() -> list[str]:
    """The extra files a `poisoner` run leaves behind, for the manifest."""
    return [f"{POISON_PREFIX}_{index:02d}{suffix}" for index, suffix in enumerate(DECOY_SUFFIXES)]


def encrypt_poisoner(path: Path, seed: bytes) -> Path:
    """Encrypt in place, underneath a ceiling the poison files already raised.

    Byte for byte this is `silent`. What makes it a different family is the
    setup, which happens once before the loop: a high-entropy file of every
    extension the decoys use, written while training mode is learning. If the
    baseline accepts them, every one of these encryptions then sits at or below
    a ceiling the attacker chose.
    """
    path.write_bytes(_xor(path.read_bytes(), seed))
    return path


def _decrypt_full(data: bytes, seed: bytes) -> bytes:
    return _xor(data, seed)


def _decrypt_stride(data: bytes, seed: bytes) -> bytes:
    return _stride(data, seed)


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
    "strider": (encrypt_strider, _decrypt_stride, ()),
    "grinder": (encrypt_grinder, decrypt_headerspoof, ()),
    "poisoner": (encrypt_poisoner, _decrypt_full, tuple(poison_names())),
}

# Families whose default pace differs from --delay-ms's default, because the
# pace is the behaviour being imitated.
FAMILY_DEFAULT_DELAY_MS = {"slowburn": 800}

# Families that write something before the encryption loop starts. The setup is
# part of the behaviour, not scaffolding: `poisoner` is only a distinct family
# because of what it writes first.
FAMILY_SETUP = {"poisoner": _poison_files}


# What each family can leave on disk besides the original name, derived from the
# original's name alone. `--restore` removes these when it puts a file back, which
# is what makes a run killed *between* the rewrite and the manifest update (or in
# the middle of writing the new file) restorable: the manifest never heard about
# that file, but every possible output is a name this script would have made.
FAMILY_OUTPUTS = {
    "locker": lambda name, seed: [name + ".locked"],
    "copycat": lambda name, seed: [name + ".enc"],
    "spoofer": lambda name, seed: [name + ".zip"],
    "renamer": lambda name, seed: [_renamer_name(name, seed)],
}


def possible_outputs(family: str, name: str, seed: bytes) -> list[str]:
    produce = FAMILY_OUTPUTS.get(family)
    return [out for out in (produce(name, seed) if produce else []) if out != name]


# ------------------------------------------------------------- saved originals
#
# `--restore` used to undo a run by decrypting what the manifest listed, and the
# manifest listed a file only after its encryption finished. A process killed in
# the middle of a rewrite therefore left a partial file that nothing described and
# nothing could decrypt (the 2026-10-05 VM run restored `grinder` 9 of 10). The
# only way to return the in-flight file exactly is to have its bytes from before.
#
# They are saved outside the target because the target is the directory the
# Monitor watches: a copy inside it would add events to every measurement this
# script exists to produce. The default is a directory under the system temp
# directory, not under any watched root; `--save-dir` or URDS_SIMULATOR_SAVE_ROOT
# chooses another. The target's manifest records where, and the journal beside
# the copies records each file as `pending`, `in_flight` or `done`.
SAVE_ROOT_ENV = "URDS_SIMULATOR_SAVE_ROOT"
SAVE_DIR_PREFIX = "urds-sim-"
JOURNAL_NAME = "journal.json"


def _same_path(a: Path, b: Path) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _is_inside(path: Path, parent: Path) -> bool:
    path = os.path.normcase(os.path.abspath(path))
    parent = os.path.normcase(os.path.abspath(parent))
    return path == parent or path.startswith(parent.rstrip("\\/") + os.sep)


def _bare_name(name: object) -> bool:
    """A journal or manifest is data from disk: only plain file names are acted on."""
    return (
        isinstance(name, str)
        and name not in ("", ".", "..", MANIFEST_NAME)
        and Path(name).name == name
        and "/" not in name
        and "\\" not in name
    )


class SavedOriginals:
    """Copies of the decoys, kept outside the target, plus the in-flight journal."""

    def __init__(self, directory: Path, target: Path, family: str):
        self.directory = directory
        self.target = target
        self.family = family
        self.originals: dict[str, dict] = {}

    @property
    def journal_path(self) -> Path:
        return self.directory / JOURNAL_NAME

    def _write_journal(self) -> None:
        document = {
            "version": 1,
            "target": str(self.target),
            "family": self.family,
            "originals": self.originals,
        }
        temporary = self.directory / (JOURNAL_NAME + ".tmp")
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        # Replaced atomically: a kill during the write leaves the previous journal.
        _retrying(lambda: os.replace(temporary, self.journal_path))

    def save_all(self, decoys: list[Path]) -> None:
        self.directory.mkdir(parents=True, exist_ok=False)
        for index, decoy in enumerate(decoys):
            data = decoy.read_bytes()
            saved = f"{index:03d}.bin"
            with open(self.directory / saved, "wb") as handle:
                handle.write(data)
            self.originals[decoy.name] = {
                "saved": saved,
                "sha256": hashlib.sha256(data).hexdigest(),
                "state": "pending",
            }
        # The journal exists only once every copy is complete: a kill while
        # saving leaves no journal, and nothing has been rewritten yet.
        self._write_journal()

    def begin(self, name: str) -> None:
        """Mark `name` in flight, and whatever was in flight before it done."""
        for other in self.originals.values():
            if other["state"] == "in_flight":
                other["state"] = "done"
        self.originals[name]["state"] = "in_flight"
        self._write_journal()

    def finish(self) -> None:
        for other in self.originals.values():
            if other["state"] == "in_flight":
                other["state"] = "done"
        self._write_journal()


def _save_root(arg: str | None) -> Path:
    chosen = arg or os.environ.get(SAVE_ROOT_ENV)
    return Path(chosen) if chosen else Path(tempfile.gettempdir()) / "urds-simulator-originals"


def _load_journal(saved_dir: Path, target: Path) -> dict | None:
    """The journal, only if it is ours: right name, right shape, and for this target."""
    if not saved_dir.name.startswith(SAVE_DIR_PREFIX):
        return None
    try:
        journal = json.loads((saved_dir / JOURNAL_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(journal, dict) or not isinstance(journal.get("originals"), dict):
        return None
    if not _same_path(Path(str(journal.get("target", ""))), target):
        return None
    return journal


def _discard_saved(saved_dir: Path, journal: dict) -> None:
    """Remove exactly the files the journal names, then the directory if it is empty."""
    for info in journal["originals"].values():
        saved = info.get("saved") if isinstance(info, dict) else None
        if _bare_name(saved):
            (saved_dir / saved).unlink(missing_ok=True)
    for leftover in (JOURNAL_NAME, JOURNAL_NAME + ".tmp"):
        (saved_dir / leftover).unlink(missing_ok=True)
    try:
        saved_dir.rmdir()
    except OSError:
        pass


def prune_orphans(save_root: Path) -> int:
    """Discard saved originals whose run can no longer be restored.

    A run that is killed and then simply deleted (a test's temp directory, a
    sweep's work dir) would otherwise leave its copies in the save root forever.
    A saved directory is an orphan when its journal names a target that is gone,
    or whose manifest no longer points at it. A run in progress is never one: its
    manifest is written before its saved directory exists. Only directories named
    like ours that hold a journal for a target are touched.
    """
    removed = 0
    try:
        candidates = [p for p in save_root.iterdir() if p.is_dir() and p.name.startswith(SAVE_DIR_PREFIX)]
    except OSError:
        return 0
    for saved_dir in candidates:
        try:
            journal = json.loads((saved_dir / JOURNAL_NAME).read_text(encoding="utf-8"))
            target = Path(str(journal["target"]))
            if not isinstance(journal.get("originals"), dict):
                continue
            try:
                manifest = json.loads((target / MANIFEST_NAME).read_text(encoding="utf-8"))
                live = _same_path(Path(str(manifest.get("saved_dir", ""))), saved_dir)
            except (OSError, ValueError):
                live = False
            if not live:
                _discard_saved(saved_dir, journal)
                removed += 1
        except (OSError, ValueError, KeyError):
            continue
    return removed


def _restore_from_saved(
    target: Path, seed: bytes, family: str, saved_dir: Path, journal: dict, produced: dict[str, str]
) -> set[str]:
    """Put back every file the journal says was started, from its saved copy.

    `produced` maps an original's name to the encrypted name the manifest
    recorded for it, if any. Returns the originals that were restored; one whose
    saved copy is missing or fails its checksum is left for the decrypt path.
    """
    restored: set[str] = set()
    for name, info in journal["originals"].items():
        if not _bare_name(name) or not isinstance(info, dict) or info.get("state") not in ("in_flight", "done"):
            continue  # `pending` was never touched; anything else is not ours to act on
        saved = info.get("saved")
        if not _bare_name(saved):
            continue
        try:
            data = (saved_dir / saved).read_bytes()
        except OSError:
            print(f"saved copy of {name} is missing; falling back to decrypting it")
            continue
        if hashlib.sha256(data).hexdigest() != info.get("sha256"):
            print(f"saved copy of {name} fails its checksum; falling back to decrypting it")
            continue
        (target / name).write_bytes(data)
        # Every name this file could have become: the one the manifest recorded,
        # and each one the family could have been midway to making.
        for output in [produced.get(name), *possible_outputs(family, name, seed)]:
            if output and output != name and _bare_name(output):
                (target / output).unlink(missing_ok=True)
        restored.add(name)
    return restored


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

    # A run made since the originals were saved: put every file it started back
    # from its saved copy. That is the only way to return the file that was in
    # flight when the process died. Runs without one (the legacy and v2
    # manifests) fall through to the decrypt path below, unchanged.
    handled: set[str] = set()
    saved_dir = journal = None
    if manifest.get("saved_dir"):
        saved_dir = Path(manifest["saved_dir"])
        journal = _load_journal(saved_dir, target)
        if journal is None:
            print(f"no saved originals at {saved_dir}; restoring finished files by decrypting them")
        else:
            produced = {e["original"]: e["encrypted"] for e in entries if "original" in e and "encrypted" in e}
            handled = _restore_from_saved(target, seed, family, saved_dir, journal, produced)

    restored = len(handled)
    for entry in entries:
        if entry["original"] in handled:
            continue
        encrypted = target / entry["encrypted"]
        if not encrypted.exists():
            continue
        (target / entry["original"]).write_bytes(decrypt(encrypted.read_bytes(), seed))
        if encrypted.name != entry["original"]:
            encrypted.unlink()
        restored += 1

    for extra in manifest.get("extra", []):
        leftover = target / extra
        if _bare_name(extra) and leftover.exists():
            leftover.unlink()

    if journal is not None:
        _discard_saved(saved_dir, journal)

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
        help="Which behaviour to imitate; see the module docstring for all thirteen.",
    )
    parser.add_argument(
        "--save-dir",
        default=None,
        help="Where the originals are saved before they are rewritten. Must be outside "
        f"--target-dir. Defaults to ${SAVE_ROOT_ENV}, else a folder under the system temp directory.",
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

    save_root = _save_root(args.save_dir)
    if _is_inside(save_root, target) or _is_inside(target, save_root):
        print(f"refusing to run: the saved originals ({save_root}) and the target ({target}) must not contain one another.")
        return 2
    prune_orphans(save_root)
    saved_dir = save_root / f"{SAVE_DIR_PREFIX}{uuid.uuid4().hex[:12]}"

    decoys = build_decoys(target, args.files)
    manifest_path = target / MANIFEST_NAME

    # The manifest is written before the first rewrite, and rewritten after each
    # one with the name that file actually became. Deriving the encrypted name
    # afterwards is not possible for `renamer`, which picks names the original
    # does not determine - and a run interrupted halfway must still be
    # restorable, which is the whole reason the manifest exists.
    entries: list[dict] = []
    manifest = {
        "family": args.family,
        "entries": entries,
        "extra": list(extra),
        "saved_dir": str(saved_dir),
    }
    manifest_path.write_text(json.dumps(manifest))

    # Every original is saved, outside the target, before the first rewrite. The
    # manifest already names the directory, so a kill at any point from here on
    # leaves a run `--restore` can find. Done up front rather than file by file so
    # the loop below (and its pace) does nothing it did not do before except one
    # journal write per file, also outside the target.
    saved = SavedOriginals(saved_dir, target, args.family)
    saved.save_all(decoys)

    print(f"created {len(decoys)} decoy document(s) in {target}", flush=True)
    time.sleep(0.5)  # let the watcher enumerate them before anything changes

    setup = FAMILY_SETUP.get(args.family)
    if setup:
        written = setup(target, seed)
        # Announced on stdout and then paused on, because a harness driving this
        # against a live monitor has to do something between the setup and the
        # attack - scripts/simulator_sweep.py closes the training window here,
        # which is exactly when a real attacker would want it closed.
        print(f"SETUP {len(written)} {args.family}", flush=True)
        time.sleep(POISON_SETTLE_SECONDS)

    print(f"beginning simulated encryption (family: {args.family})", flush=True)
    encrypted = 0
    for decoy in decoys:
        original_name = decoy.name
        saved.begin(original_name)  # in flight from here until the next file begins
        result = encrypt(decoy, seed)
        entries.append({"original": original_name, "encrypted": result.name})
        manifest_path.write_text(json.dumps(manifest))
        encrypted += 1
        # Printed per file and flushed: the harness reads this to count how many
        # were lost before the response engine terminated the process. The name
        # reported is the one now on disk, not the original - `renamer` and
        # `spoofer` choose names the original does not determine, and a harness
        # that reconstructed the name by appending ".locked" would only ever work
        # for one of the thirteen families.
        print(f"ENCRYPTED {encrypted} {result.name}", flush=True)
        if delay_ms:
            time.sleep(delay_ms / 1000)

    saved.finish()
    print(f"finished: {encrypted} file(s) encrypted (nothing terminated this process)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
