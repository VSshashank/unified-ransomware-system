r"""Runs a third-party encryptor over a directory. Measures nothing.

Separate from `scripts/adversary_corpus.py` for the reason §2 rule 1 gives: an
attack written by the same file that measures the response is not evidence. The
split is the same one `selftest.py` / `selftest_writer.py` uses, and it is worth
restating because the temptation is to collapse it - this file knows nothing
about the agent, reads no ledger, and has no opinion about whether anything was
detected. It encrypts files and exits.

**No encryption is implemented here.** Every arm is a command line handed to a
binary this project did not write and does not ship:

    openssl.exe   OpenSSL (Git for Windows)   T1486: "Encrypt files using openssl"
    gpg.exe       GnuPG                       T1486: "Encrypt files using gpg"
    7z.exe        7-Zip                       T1486: "Encrypt files using 7z"
    quickbuck.exe NextronSystems'             ransomware-simulator 1.0.3
                  ransomware-simulator
    powershell    Red Canary's Atomic Red   T1486-8: "Data Encrypted with
                  Team, running T1486-8     GPG4Win" - the technique run as
                                            published, not reimplemented

The arms differ in the shape of the *process*, which is what decides whether a
response can reach it at all:

  openssl-loop      one short-lived openssl per file, original unlinked
  gpg-loop          one short-lived gpg per file, original unlinked
  sevenzip-archive  one long-lived 7z, everything into one encrypted archive,
                    originals unlinked by 7z itself (-sdel)
  openssl-inplace   one short-lived openssl per file whose **stdout is the file
                    it is reading**, opened r+b so nothing is truncated. This is
                    the "open existing, write over" case, and the bytes are
                    written by openssl - this file only inherits it the handle.
  nextron-quickbuck one long-lived process that stages 10,001 documents,
                    encrypts every one of them, drops a ransom note and runs a
                    shadow-copy deletion. See the function for what it does not
                    do.
  atomic-t1486      one long-lived PowerShell host running Red Canary's
                    published atomic once per file, with a short-lived
                    `gpg.exe` under it per invocation. The only arm where the
                    process that *writes* and the process that is *reachable*
                    are different processes, which is why the answer key has
                    to hold the whole tree.

GROUND TRUTH, AND WHY IT IS RECORDED HERE

`--writers` names a JSONL file, and this process appends one line for every
process it starts, with the PID the OS returned for it. That file is the answer
key the measuring script grades attribution against, and it is written by the
side that *launched* the writers rather than by the side that has to identify
them - grading the agent against the agent's own record would prove nothing.

`Popen.pid` is used for the children and is correct for these tools because
they are native binaries: `CreateProcess` returns the PID of the process that
runs them. It is *not* used for this process. `.venv\Scripts\python.exe` is a
launcher that starts the real interpreter as its own child, so the parent's
idea of this PID is the launcher's; the first line of the writers file, and the
announcement on stdout, are both `os.getpid()` reported by the process that
will do the launching - and the unlinks.

Exit codes: 0 the arm ran to completion; 1 a tool invocation failed; 2 the arm
could not start (tool missing, corpus empty). Being suspended mid-run is not an
error here - the measuring script decides what a suspension means.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil

#: Not a secret and deliberately so: this is a demonstration corpus and the
#: passphrase is published with it, so anything encrypted during a run can be
#: recovered by hand without the agent, the snapshot, or this project.
PASSPHRASE = "urds-phase5-corpus-passphrase"


class Writers:
    """The answer key: every process this one started, as it starts it."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.recorded: set[int] = set()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")

    def record(self, pid: int, image: str, target: str, role: str) -> None:
        # Deduplication applies to the *sweep*, never to a launch.
        #
        # The descendant sweep sees the process this script started as a child
        # of this script, which it is; letting that second line through would
        # rewrite an `encryptor` into a `descendant` and lose the distinction
        # between what the arm chose to start and what that started in turn.
        #
        # A launch is different and must always be written. Windows recycles
        # PIDs fast enough that a 200-file loop of 65 ms processes reuses
        # numbers - one measured run of `gpg-loop` produced 180 distinct PIDs
        # from 200 launches - and dropping the repeats would silently shorten
        # the answer key by twenty files. The key is a record of launches, and
        # the reader of it decides what to do about a number appearing twice.
        if role == "descendant" and pid in self.recorded:
            return
        self.recorded.add(int(pid))
        if self.path is None:
            return
        line = json.dumps({"pid": int(pid), "image": image, "target": target,
                           "role": role, "at": time.time()})
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())


class DescendantWatch(threading.Thread):
    """Adds every descendant of a recorded process to the answer key.

    `Popen.pid` is the process this script started, and for `openssl.exe` or
    `gpg.exe` that is also the process that writes. It is not for every arm:
    the Atomic Red Team arm starts **powershell.exe**, which starts `cmd.exe`,
    which starts `gpg.exe`, and gpg is the one whose handle the bytes go
    through. An answer key holding only the PowerShell host would grade the
    agent as *mis-attributing* every write it named correctly - and
    "mis-attribution must be 0" is the claim this whole branch exists to
    defend, so a key that manufactures one is worse than no key at all.

    So the key is the process *tree*, walked while the arm runs. Roles stay
    distinct: `encryptor` is what this script launched, `descendant` is what
    that launched. Both belong to the attack; only the first is something this
    script chose.
    """

    def __init__(self, writers: "Writers", roots: set[int],
                 interval_s: float = 0.05) -> None:
        super().__init__(daemon=True)
        self.writers = writers
        self.roots = roots
        self.interval_s = interval_s
        self._seen: set[int] = set()
        self._stop = threading.Event()

    def sweep(self) -> None:
        for root in list(self.roots):
            try:
                parent = psutil.Process(root)
                children = parent.children(recursive=True)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            for child in children:
                if child.pid in self._seen or child.pid in self.roots:
                    continue
                self._seen.add(child.pid)
                if child.pid in self.writers.recorded:
                    continue
                try:
                    image = child.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        OSError):
                    image = child.name() if child.is_running() else "?"
                self.writers.record(child.pid, image, "", "descendant")

    def run(self) -> None:
        while not self._stop.is_set():
            self.sweep()
            time.sleep(self.interval_s)

    def stop(self) -> None:
        # One last sweep: a descendant that appeared between the final poll and
        # the arm finishing is still the attack's, and leaving it out of the
        # key turns a correct attribution into a mis-attribution.
        self.sweep()
        self._stop.set()


#: Originals the arm meant to delete and could not. Counted rather than
#: swallowed: one measured run of `openssl-loop` left 44 of 200 originals in
#: place with their hashes unchanged, and the measuring script could only
#: report them as "untouched" - which reads as an encryptor that stopped early
#: rather than as unlinks the operating system refused. Windows will not unlink
#: a file another process has open, and the detector opens every file it judges
#: to read its entropy, so the refusals are a fact about the interaction and
#: belong in the record.
UNLINK_FAILURES: list[dict] = []


def _unlink(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except OSError as exc:
        UNLINK_FAILURES.append({"path": str(path), "errno": exc.errno,
                                "error": str(exc)})
        return False


def announce(**fields: object) -> None:
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()


def targets(corpus: Path) -> list[Path]:
    return sorted(p for p in corpus.rglob("*") if p.is_file())


def _launch(argv: list[str], writers: Writers, target: str,
            stdin=None, stdout=None) -> int:
    """Start one third-party process, record its PID, wait for it."""
    child = subprocess.Popen(argv, stdin=stdin, stdout=stdout,
                             stderr=subprocess.PIPE)
    writers.record(child.pid, argv[0], target, "encryptor")
    _, err = child.communicate()
    if child.returncode not in (0,):
        sys.stderr.write((err or b"").decode("utf-8", "replace")[:400])
    return child.returncode


# --------------------------------------------------------------- the arms


def openssl_loop(tool: str, corpus: Path, writers: Writers, inplace: bool) -> int:
    """`openssl enc -aes-256-cbc` per file.

    Two shapes from one function because they differ in exactly one thing -
    where openssl's ciphertext lands - and writing them twice would let them
    drift apart while claiming to be the same encryptor.
    """
    failures = 0
    for path in targets(corpus):
        if inplace:
            # r+b: no truncation, offset zero, so openssl overwrites the
            # plaintext where it lies and reads it back through stdin. Corpus
            # files are small enough that the read completes before the first
            # write lands, which is why the measuring script caps their size
            # rather than leaving it to taste.
            try:
                with path.open("rb") as src, path.open("r+b") as dst:
                    code = _launch(
                        [tool, "enc", "-aes-256-cbc", "-pbkdf2",
                         "-pass", "pass:" + PASSPHRASE],
                        writers, str(path), stdin=src, stdout=dst)
            except OSError as exc:
                sys.stderr.write(f"{path}: {exc}\n")
                failures += 1
                continue
            if code != 0:
                failures += 1
            continue

        out = path.with_suffix(path.suffix + ".enc")
        code = _launch(
            [tool, "enc", "-aes-256-cbc", "-pbkdf2",
             "-in", str(path), "-out", str(out),
             "-pass", "pass:" + PASSPHRASE],
            writers, str(path))
        if code != 0:
            failures += 1
            continue
        # The original goes, which is what makes this ransomware rather than
        # backup. The unlink is done by *this* process, so it is recorded as a
        # writer too - an unlink inside a protected path is an audited,
        # attributable operation and the agent treats a deletion as evidence.
        _unlink(path)
    return 1 if failures else 0


def gpg_loop(tool: str, corpus: Path, writers: Writers, inplace: bool) -> int:
    """`gpg --symmetric --cipher-algo AES256` per file."""
    if inplace:
        sys.stderr.write("gpg has no in-place mode; use openssl-inplace\n")
        return 2
    failures = 0
    for path in targets(corpus):
        out = path.with_suffix(path.suffix + ".gpg")
        code = _launch(
            [tool, "--batch", "--yes", "--quiet", "--symmetric",
             "--cipher-algo", "AES256", "--passphrase", PASSPHRASE,
             "--output", str(out), str(path)],
            writers, str(path))
        if code != 0:
            failures += 1
            continue
        _unlink(path)
    return 1 if failures else 0


def sevenzip_archive(tool: str, corpus: Path, writers: Writers,
                     inplace: bool) -> int:
    """`7z a -p -mhe=on -sdel`: one process, one archive, originals unlinked.

    The only arm whose writer outlives the write. Everything else here is a new
    short-lived process per file, and docs/LIMITATIONS.md §4 is about what that
    costs the response; this arm is what a response can actually reach.
    """
    archive = corpus.parent / (corpus.name + "_locked.7z")
    code = _launch(
        [tool, "a", "-p" + PASSPHRASE, "-mhe=on", "-sdel", "-bso0", "-bsp0",
         str(archive), str(corpus / "*")],
        writers, str(corpus))
    # 7-Zip's 1 is "warning" - a file it could not open, which is what a
    # suspension mid-run looks like from the outside.
    return 0 if code in (0, 1) else 1


def nextron_quickbuck(tool: str, corpus: Path, writers: Writers,
                      inplace: bool) -> int:
    """NextronSystems' `quickbuck.exe`: one process, ten thousand files.

    The only member of this corpus whose writer stays alive long enough to be
    reachable. It stages 10,001 documents in `--dir`, encrypts each to a `.enc`
    with AES-256-CTR and deletes the original, drops a ransom note, and runs a
    shadow-copy deletion - all from one process that lives for as long as that
    takes. Every other arm here is a new process per file, which is why none of
    them can be suspended.

    Two things it deliberately does **not** do, both confirmed in its source
    before it was ever run here:

    * It does not touch pre-existing files. The documents it encrypts are ones
      it wrote itself, which is why the measuring script counts damage over
      what appears in `--dir` rather than over a seeded corpus, and reports no
      restore for this arm rather than a restore of nothing.
    * Its shadow-copy deletion is `vssadmin delete shadows /for=norealvolume
      /all /quiet` - a volume that does not exist, so nothing can be deleted.
      That is why the step is left enabled here: it is the exact command line
      `agent/procmon.py` watches for, and it can be tested without destroying
      the machine's restore points.

    The macro simulation is disabled. It spawns winword.exe, which is not
    installed on every host and is a process-chain question rather than a file
    one.
    """
    note = corpus / "HOW-TO-RECOVER-YOUR-FILES.txt"
    return _launch(
        [tool, "run", "--dir", str(corpus), "--note-location", str(note),
         "--disable-macro-simulation"],
        writers, str(corpus))


#: Where `Install-AtomicRedTeam` puts things. Not searched for on PATH: the
#: module is not on it, and a corpus member that silently resolves to
#: something else is not the corpus member.
ATOMIC_MODULE = r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
ATOMIC_YAML = r"C:\AtomicRedTeam\atomics\T1486\T1486.yaml"


def atomic_t1486(tool: str, corpus: Path, writers: Writers,
                 inplace: bool) -> int:
    r"""Red Canary's published T1486-8, `Data Encrypted with GPG4Win`.

    The technique the build plan names by number, run as its authors shipped
    it rather than reimplemented from its description. `Invoke-AtomicTest`
    reads the YAML, substitutes `File_to_Encrypt_Location`, and runs the
    executor - two lines of PowerShell that overwrite the target with a fixed
    string and then hand it to GPG4Win's `gpg.exe -c`. Both of those are
    damage and both are somebody else's code.

    Three things about it are worth knowing before reading its numbers.

    * **Its executor ignores `GPG_Exe_Location`.** The input argument exists
      and is documented, and the command line hardcodes
      ``C:\Program Files (x86)\GnuPG\bin\gpg.exe`` anyway. That is a defect in
      the atomic, not in this harness, and it is why the prerequisite has to be
      satisfied at that exact path instead of pointed at the GnuPG that Git for
      Windows already ships.
    * **It encrypts one file per invocation.** The atomic is a single-file
      demonstration, so a corpus means invoking it once per file. That is done
      from *one* PowerShell host rather than one per file, which is both far
      faster and the more honest shape: real tooling loops inside a process.
    * **That host is the first writer in this corpus that outlives its own
      audit record.** Everything else here is a new process per file, gone in
      milliseconds (docs/LIMITATIONS.md §4). The PowerShell host lives for the
      whole arm, and `gpg.exe` underneath it does not - so whichever of the two
      the agent names, only one of them can still be suspended.

    The atomic's own `-Cleanup` is deliberately not run. It deletes the target,
    and the target is the operator's file: what happens to it afterwards is the
    restore path's question, not the attacker's.
    """
    if not Path(ATOMIC_MODULE).is_file():
        sys.stderr.write(
            f"Invoke-AtomicRedTeam is not installed at {ATOMIC_MODULE}\n")
        return 2

    files = targets(corpus)
    listing = Path(os.getenv("TEMP", ".")) / f"urds_atomic_{os.getpid()}.txt"
    listing.write_text("\n".join(str(f) for f in files),
                       encoding="utf-8")

    script = (
        # 6>$null on the call below, and not just `| Out-Null`:
        # `Invoke-AtomicTest` announces each test with `Write-Host`, which
        # bypasses the pipeline and goes to the information stream. Two hundred
        # invocations put about 33 KB down this process's stdout, and the
        # measuring script holds that pipe - close enough to the 64 KB buffer
        # that a slightly chattier atomic would deadlock the arm and report the
        # timeout as a result.
        f"$ErrorActionPreference='Continue';"
        f"Import-Module '{ATOMIC_MODULE}' -Force;"
        f"foreach ($f in Get-Content -LiteralPath '{listing}') {{"
        f"  Invoke-AtomicTest T1486 -TestNumbers 8"
        f"    -InputArgs @{{ File_to_Encrypt_Location = $f }}"
        f"    -TimeoutSeconds 30 6>$null | Out-Null "
        f"}}")
    try:
        code = _launch(
            [tool, "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            writers, str(corpus))
    finally:
        try:
            listing.unlink()
        except OSError:
            pass
    return 0 if code == 0 else 1


ARMS = {
    "openssl-loop": (openssl_loop, False),
    "openssl-inplace": (openssl_loop, True),
    "gpg-loop": (gpg_loop, False),
    "sevenzip-archive": (sevenzip_archive, False),
    "nextron-quickbuck": (nextron_quickbuck, False),
    "atomic-t1486": (atomic_t1486, False),
    # Same command, pointed by the caller at the protected root rather than at
    # a directory inside it, so it meets the decoys. Nothing here knows the
    # difference, which is the point: the arm is the tool's own behaviour and
    # the scope is the measuring script's decision.
    "sevenzip-root": (sevenzip_archive, False),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", required=True, choices=sorted(ARMS))
    parser.add_argument("--tool", required=True,
                        help="full path to the third-party binary")
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--writers", type=Path,
                        help="JSONL answer key: every process this one starts")
    args = parser.parse_args(argv)

    if not Path(args.tool).is_file():
        announce(pid=os.getpid(), arm=args.arm, tool=args.tool,
                 error="tool not found")
        return 2
    if not args.corpus.is_dir() or not targets(args.corpus):
        announce(pid=os.getpid(), arm=args.arm, tool=args.tool,
                 error="corpus is empty")
        return 2

    writers = Writers(args.writers)
    # This process unlinks originals and owns the handles the in-place arm
    # writes through, so it belongs in the answer key before anything starts.
    writers.record(os.getpid(), sys.executable, str(args.corpus), "launcher")

    announce(pid=os.getpid(), arm=args.arm, tool=args.tool,
             files=len(targets(args.corpus)), started_at=time.time())

    handler, inplace = ARMS[args.arm]
    # The tree, not just the child. See DescendantWatch for why an incomplete
    # answer key reads as mis-attribution rather than as a missing row.
    watch = DescendantWatch(writers, {os.getpid()})
    watch.start()
    try:
        return handler(args.tool, args.corpus, writers, inplace)
    finally:
        watch.stop()
        if UNLINK_FAILURES:
            sys.stderr.write(
                f"unlink refused for {len(UNLINK_FAILURES)} originals; "
                f"first: {UNLINK_FAILURES[0]['error'][:160]}\n")


if __name__ == "__main__":
    raise SystemExit(main())
