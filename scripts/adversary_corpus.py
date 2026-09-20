r"""Phase 5: what the agent does against encryptors nobody here wrote.

    .venv\Scripts\python.exe scripts/adversary_corpus.py --files 200
    .venv\Scripts\python.exe scripts/adversary_corpus.py --arm sevenzip-archive

Elevated, on a host where `install.ps1` has run and `URDSAgent` is running.
This script attacks nothing. It seeds a corpus, asks `scripts/adversary_runner.py`
to run a third-party encryptor over it, and then measures - from the agent's own
hash-chained ledger and from the operating system - what happened.

THE FIVE NUMBERS, AND WHERE EACH ONE COMES FROM

  FEBR      files whose bytes changed before the first suspension. Measured by
            hashing every corpus file before the run and comparing afterwards,
            then counting the changed ones whose mtime precedes the suspension.
            Not read from the ledger: a file the agent never saw must still
            count against it, and a metric sourced from the detector cannot
            report the detector missing something.
  TTS       first observed change to a corpus file -> first observed suspension.
            Both ends are observed by this process. The first end is a stat
            loop over the corpus, not a watchdog event and not an audit record,
            so it is independent of every mechanism under test.
  FP        not measured here. `scripts/benign_soak.py` runs the benign corpus.
  attribution accuracy
            every CERTAIN attribution the agent recorded on a corpus path,
            graded against the answer key `adversary_runner.py` writes as it
            launches each process. Correct, mis-attributed, unresolved.
            **Mis-attribution must be 0.**
  RPO/MTTR  RPO is the pre-attack snapshot -> first malicious write, which is
            the work a restore gives back. MTTR is suspension -> the last file
            verified byte-for-byte against its pre-attack hash.

WHY THE CORPUS IS SEEDED AND THEN LEFT ALONE FOR A WHILE

This process writes the corpus, so for the next `WINDOW_MS` it is an audited
writer of every path in it. An attack launched inside that window is judged
against evidence that still names *this* process, and the agent will suspend
this process - correctly, on the evidence it has. That happened in Phase 4 and
it is block 16095 of this host's ledger. `selftest.py` waits it out for one
file; the same wait is here for the same reason. Phase 5 also fixed the
underlying defect (`WriteLog.lookup` now refuses a record that predates the
event), which makes the wait belt-and-braces rather than load-bearing - but a
harness that relies on a fix it is also measuring is not measuring it.

ARMS AND WHY THEY DIFFER

Three of the five arms start a new short-lived process per file. That is not an
implementation detail, it is the finding: docs/LIMITATIONS.md §4 says a process
that finishes inside a second is named correctly and named too late, and these
arms are what that costs in files. The two 7-Zip arms are the ones whose writer
outlives its writes. Reporting only those would be choosing the arms that
flatter the response.

`sevenzip-archive` and `sevenzip-root` run the identical 7-Zip command line and
differ only in where it is pointed. The first is aimed at a directory this
script created, which contains nothing but the corpus; the second is aimed at
the protected root, where `install.ps1` seeded the decoys. The pair exists
because the first one, run alone, answers a question nobody asked: it measures
what the system does when the encryptor is kept away from the mechanism built
to catch it.

Exit codes: 0 every arm that ran passed its bounds; 1 an arm failed a bound or
a tool was missing (a skipped check is a failed check); 2 could not run at all.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
RESPONSE_DIR = ROOT / "services" / "response"
if str(RESPONSE_DIR) not in sys.path:
    sys.path.insert(0, str(RESPONSE_DIR))
LEDGER_DIR = ROOT / "services" / "ledger"
if str(LEDGER_DIR) not in sys.path:
    sys.path.insert(0, str(LEDGER_DIR))

import psutil  # noqa: E402

RUNNER = ROOT / "scripts" / "adversary_runner.py"
REPORT = ROOT / "reports" / "phase5_attack_corpus.json"

#: The two bounds §5 of the build prompt sets for this phase.
FEBR_BOUND = 20
TTS_BOUND_S = 2.0

#: Every corpus directory this run created, for the emergency cleanup in
#: `main`. A harness that leaves an encrypted archive inside a protected folder
#: when it crashes has made the machine worse than it found it.
_CREATED: list[tuple[Path, Path, Path]] = []

#: Corpus file size. Small enough that openssl's read of a file completes
#: before its first write to the same file lands, which is what makes the
#: in-place arm deterministic rather than a race; large enough to carry a
#: believable document.
FILE_BYTES = (8 * 1024, 24 * 1024)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def git(*args: str) -> str:
    """The commit these numbers were produced at.

    `claim_matrix.py` refuses an evidence artefact whose commit is not an
    ancestor of HEAD, which is how a figure that quietly moved to a different
    file gets caught (docs/CORRECTIONS.md correction 5). An artefact with no
    commit at all fails the same gate, so it is stamped here rather than by
    hand afterwards.
    """
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, check=False).stdout.strip()


def parse_utc(stamp: str) -> float | None:
    """A ledger block's timestamp as epoch seconds, or None if it is not one.

    The services stamp blocks with `isoformat()` and a `Z` suffix, which
    `fromisoformat` did not accept before Python 3.11 and does now. Returning
    None rather than raising is deliberate: a block whose timestamp cannot be
    read is a block this script declines to draw a number from, and the caller
    reports the moment as unmeasured rather than guessing at it.
    """
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def attribution_window_ms() -> float:
    """From the agent's own module, never typed in here."""
    try:
        from agent import imports  # noqa: PLC0415

        return float(imports.load("attribution").WINDOW_MS)
    except Exception:  # noqa: BLE001
        return float(os.getenv("ATTRIBUTION_WINDOW_MS", "3000"))


# ------------------------------------------------------------- the tools

@dataclass
class Tool:
    """A binary this project did not write, and where to find it."""

    key: str
    atomic: str
    candidates: tuple[str, ...]
    #: Files that make this arm somebody else's work, where the launched
    #: binary does not. Hashed into the report beside the binary; an arm whose
    #: provenance is missing cannot run, because what would run is not the
    #: corpus member it claims to be.
    provenance: tuple[str, ...] = ()
    path: str | None = None

    def missing_provenance(self) -> list[str]:
        return [f for f in self.provenance if not Path(f).is_file()]

    def locate(self) -> str | None:
        for candidate in self.candidates:
            if candidate and Path(candidate).is_file():
                self.path = candidate
                return candidate
        found = shutil.which(self.key)
        if found:
            self.path = found
        return self.path


def known_tools() -> dict[str, Tool]:
    git = os.getenv("ProgramFiles", r"C:\Program Files") + r"\Git"
    return {
        "openssl": Tool(
            "openssl", "T1486: Encrypt files using openssl",
            (git + r"\usr\bin\openssl.exe", git + r"\mingw64\bin\openssl.exe")),
        "gpg": Tool(
            "gpg", "T1486: Encrypt files using gpg",
            (git + r"\usr\bin\gpg.exe",
             r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
             r"C:\Program Files\GnuPG\bin\gpg.exe")),
        "7z": Tool(
            "7z", "T1486: Encrypt files using 7z",
            (r"C:\Program Files\7-Zip\7z.exe",
             r"C:\Program Files (x86)\7-Zip\7z.exe")),
        # Not on PATH and not installed by anything: fetched deliberately, to
        # a fixed location, with its hash recorded in the report.
        "nextron": Tool(
            "quickbuck", "NextronSystems ransomware-simulator 1.0.3",
            (str(Path(os.getenv("LOCALAPPDATA", "")) / "URDS" / "tools"
                 / "quickbuck.exe"),)),
        # The binary launched is PowerShell, and hashing PowerShell would
        # record the provenance of Windows rather than of the attack. What
        # makes this arm third-party is the atomic: Red Canary's YAML and the
        # module that executes it, so those are what `provenance` names and
        # what the report hashes. The arm cannot run without all three.
        "atomic": Tool(
            "powershell",
            "T1486-8: Data Encrypted with GPG4Win (Atomic Red Team)",
            (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",),
            provenance=(
                r"C:\AtomicRedTeam\atomics\T1486\T1486.yaml",
                r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1",
                r"C:\Program Files (x86)\GnuPG\bin\gpg.exe")),
    }


#: arm -> (tool key, what shape of process it is)
ARMS = {
    "openssl-loop": ("openssl", "one short-lived process per file"),
    "openssl-inplace": ("openssl", "one short-lived process per file, "
                                   "writing over the file it is reading"),
    "gpg-loop": ("gpg", "one short-lived process per file"),
    "sevenzip-archive": ("7z", "one long-lived process for the whole corpus"),
    "sevenzip-root": ("7z", "one long-lived process over the whole protected "
                            "root, decoys included"),
    "nextron-quickbuck": ("nextron", "one long-lived process, 10,001 files, "
                                     "a ransom note and a shadow-copy deletion"),
    "atomic-t1486": ("atomic", "one long-lived PowerShell host, one "
                               "short-lived gpg.exe per file beneath it"),
}

#: Arms whose encryptor writes its *own* files rather than existing ones.
#:
#: `quickbuck.exe` stages 10,001 documents and then encrypts those - it takes
#: no action against pre-existing files, and says so in its README and in its
#: source. So damage for this arm is counted over what appears in the corpus
#: directory, not over a seeded corpus that it will never touch, and there is
#: no restore to report: nothing of the operator's was lost, so returning
#: "restored 0 of 0" would read as a recovery that happened.
#:
#: What the arm is *for* is the only thing the others cannot supply: a writer
#: that is still alive when its audit record arrives. Every other tool in this
#: corpus is a new process per file, gone in milliseconds, named correctly and
#: named too late (docs/LIMITATIONS.md §4). FEBR and TTS mean something here
#: and nowhere else.
STAGES_ITS_OWN_FILES = frozenset({"nextron-quickbuck"})

#: Arms that walk the protected root itself rather than a corpus directory
#: inside it.
#:
#: `sevenzip-archive` points 7-Zip at a directory this script created, and it
#: found that an archive-and-delete attack on ordinary files produces no
#: detection at all: the output is a structurally valid encrypted 7z container,
#: which the detector deliberately does not treat as encryption, and deleted
#: files carry no content to measure. That is a real result and it is also only
#: half the question, because it never meets a decoy - `install.ps1` seeds those
#: at the top of each protected root, not in subdirectories anybody creates
#: later, and the decoy field is the system's designed answer to exactly this
#: attack. An arm that keeps the encryptor away from the one mechanism built to
#: catch it is an arm that has chosen its own answer.
#:
#: So this arm goes where the installer put the decoys. Everything under the
#: root is hashed first and restored afterwards, and the decoy manifest is
#: checked at the end, because walking the root means the blast radius is the
#: whole protected folder.
ROOT_SCOPE_ARMS = frozenset({"sevenzip-root"})


# --------------------------------------------------------- the observers

class FirstChange(threading.Thread):
    """When did the corpus first change? Asked of the filesystem, not the agent.

    A stat loop rather than a watchdog observer or an audit record, because
    both of those are mechanisms under test. If TTS were measured from a
    watchdog event, a watcher that fell behind would shorten TTS.

    `watch_dir` is for the arm whose encryptor writes its own files: there is
    no list to stat, so the directory is scanned for the first file to appear,
    and separately for the first *ciphertext* to appear. Both are recorded,
    because "the attacker started writing" and "the attacker started
    encrypting" are different moments and only one of them is what TTS is
    usually taken to mean.
    """

    def __init__(self, files: list[Path], interval_s: float = 0.002,
                 watch_dir: Path | None = None,
                 ciphertext_suffix: str | None = None) -> None:
        super().__init__(daemon=True)
        self.files = files
        self.interval_s = interval_s
        self.watch_dir = watch_dir
        self.ciphertext_suffix = ciphertext_suffix
        self.baseline: dict[Path, tuple[int, int]] = {}
        self.at: float | None = None
        self.path: Path | None = None
        self.ciphertext_at: float | None = None
        self._stop = threading.Event()

    def snapshot(self) -> None:
        for path in self.files:
            try:
                stat = path.stat()
                self.baseline[path] = (stat.st_size, stat.st_mtime_ns)
            except OSError:
                self.baseline[path] = (-1, -1)

    def run(self) -> None:
        if self.watch_dir is not None:
            self._watch_directory()
            return
        while not self._stop.is_set():
            for path, before in self.baseline.items():
                try:
                    stat = path.stat()
                    now = (stat.st_size, stat.st_mtime_ns)
                except OSError:
                    now = (-1, -1)
                if now != before:
                    self.at = time.monotonic()
                    self.path = path
                    return
            time.sleep(self.interval_s)

    def _watch_directory(self) -> None:
        while not self._stop.is_set():
            try:
                entries = os.listdir(self.watch_dir)
            except OSError:
                entries = []
            if entries and self.at is None:
                self.at = time.monotonic()
                self.path = Path(entries[0])
            if self.ciphertext_suffix and self.ciphertext_at is None:
                if any(name.endswith(self.ciphertext_suffix) for name in entries):
                    self.ciphertext_at = time.monotonic()
            if self.at is not None and (
                    not self.ciphertext_suffix or self.ciphertext_at is not None):
                return
            time.sleep(self.interval_s)

    def stop(self) -> None:
        self._stop.set()


class SuspendWatch(threading.Thread):
    """The first moment any process from the answer key is observed STOPPED.

    psutil reports STATUS_STOPPED on Windows when every thread of a process is
    suspended, which is what `Responder` does before it decides anything. This
    is corroboration of the ledger, measured independently; where the freeze is
    shorter than the polling interval it reports *not observed* rather than
    inferring one from the ledger it is supposed to be checking.
    """

    def __init__(self, writers_file: Path, interval_s: float = 0.01) -> None:
        super().__init__(daemon=True)
        self.writers_file = writers_file
        self.interval_s = interval_s
        self.at: float | None = None
        self.pid: int | None = None
        self.seen: dict[int, str] = {}
        #: Candidates that looked suspended and were not the right process.
        #: Reported rather than dropped: a run with hundreds of these is a run
        #: whose PIDs were recycled under it, which the reader should know.
        self.rejected: list[dict] = []
        self._stop = threading.Event()

    #: How far a process's real creation time may sit from the moment the
    #: runner recorded launching it and still be the same process. Popen
    #: returns and the line is written within milliseconds of the process
    #: existing; five seconds is generous in the direction of accepting.
    SAME_PROCESS_TOLERANCE_S = 5.0

    def _known(self) -> list[tuple[int, float]]:
        try:
            lines = self.writers_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        found = []
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            pid = int(record.get("pid", 0))
            if pid:
                found.append((pid, float(record.get("at", 0.0))))
                self.seen.setdefault(pid, str(record.get("image", "")))
        return found

    def run(self) -> None:
        while not self._stop.is_set():
            for pid, launched_at in self._known():
                try:
                    process = psutil.Process(pid)
                    if process.status() != psutil.STATUS_STOPPED:
                        continue
                    # Is this still the process the runner started?
                    #
                    # Measured, and the reason this check exists: the
                    # `openssl-loop` arm starts 200 processes that each live
                    # about 65 ms, and Windows recycles their PIDs almost
                    # immediately. A run of this harness reported a
                    # time-to-suspend of 12.307 s from pid 6372 while the
                    # agent's own ledger held no escalation at all - the PID
                    # had been reused by unrelated software that happened to
                    # be suspended. A harness that reports a suspension the
                    # chain does not have is not measuring the system.
                    created = process.create_time()
                    if abs(created - launched_at) > self.SAME_PROCESS_TOLERANCE_S:
                        self.rejected.append(
                            {"pid": pid, "launched_at": launched_at,
                             "create_time": created,
                             "why": "PID was recycled; this is not the process "
                                    "the runner started"})
                        continue
                    self.at = time.monotonic()
                    self.pid = pid
                    return
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(self.interval_s)

    def stop(self) -> None:
        self._stop.set()


# ------------------------------------------------------------ the ledger
#
# Read, never written, and not reimplemented. `selftest.py` already opens the
# service's ledger read-only - it is deliberately not in WAL mode, so a second
# writer would contend with the thing under test - and already walks the chain
# using the ledger service's own `compute_hash` rather than a second copy of
# it. Both of those are decisions with a reason behind them, and importing them
# is how the reason stays attached. A local copy of `verify_chain` written here
# got the hash function's signature wrong on the first run and certified
# nothing; a second implementation of a block hash is exactly the thing that
# could certify a chain the service would reject.

sys.path.insert(0, str(ROOT / "scripts"))
from selftest import (  # noqa: E402
    blocks_since,
    read_only_connection,  # noqa: F401 - re-exported for the tests
    tip_id,
    verify_chain,
)


# --------------------------------------------------------------- one arm

@dataclass
class ArmResult:
    arm: str
    tool: str
    tool_path: str | None
    atomic: str
    shape: str
    ran: bool = False
    reason: str = ""
    metrics: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        if not self.ran:
            return False
        return bool(self.metrics.get("within_bounds"))

    def as_dict(self) -> dict:
        return {"arm": self.arm, "tool": self.tool, "tool_path": self.tool_path,
                "atomic": self.atomic, "process_shape": self.shape,
                "ran": self.ran, "reason": self.reason, "passed": self.passed,
                "metrics": self.metrics, "evidence": self.evidence}


def seed_corpus(directory: Path, count: int, rng: random.Random) -> list[Path]:
    """Believable low-entropy documents. Nothing here should look suspicious."""
    directory.mkdir(parents=True, exist_ok=True)
    words = ("quarterly", "revenue", "forecast", "region", "customer",
             "invoice", "margin", "headcount", "renewal", "pipeline",
             "variance", "actual", "budget", "north", "south", "east", "west")
    made = []
    for index in range(count):
        path = directory / f"document_{index:04d}.csv"
        target = rng.randint(*FILE_BYTES)
        lines = ["row,label,region,amount,note"]
        size = len(lines[0])
        row = 0
        while size < target:
            line = "{0},{1},{2},{3:.2f},{4}".format(
                row, rng.choice(words), rng.choice(words),
                rng.uniform(0, 10_000), " ".join(rng.choices(words, k=6)))
            lines.append(line)
            size += len(line) + 1
            row += 1
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        made.append(path)
    return made


#: A restore of one corpus file is a copy and a hash of at most 24 KiB. Above
#: this, the gap is not the work.
FREEZE_FLOOR_S = 0.5


def restore_interval_s(args: argparse.Namespace) -> float:
    """Seconds per file, from the agent's own velocity configuration.

    Not a number chosen here. `velocity_path_threshold` distinct paths inside
    `velocity_window_s` is what the agent treats as a signal, so staying one
    path under that is staying under the rule as configured - and if the
    configuration changes, this follows it rather than going stale.
    """
    if args.restore_rate is not None:
        return 0.0 if args.restore_rate <= 0 else 1.0 / args.restore_rate
    try:
        from agent import config as agent_config  # noqa: PLC0415

        config = agent_config.load()
        paths = max(1, int(config.velocity_path_threshold) - 1)
        return float(config.velocity_window_s) / paths
    except Exception:  # noqa: BLE001
        return 1.0


def check_canaries() -> dict:
    """Do the decoys still hash to what the agent's manifest says?

    Read from the manifest the agent itself wrote, not from a list this script
    keeps. A decoy that comes back from a snapshot with different bytes is not
    a cosmetic problem: `CanaryField.touched` compares against the manifest, so
    it would read as a tripwire being hit by whoever next opens the file.
    """
    try:
        from agent import config as agent_config  # noqa: PLC0415
        from agent.canary import CanaryField  # noqa: PLC0415

        field_ = CanaryField(agent_config.load())
        field_.load()
        paths = field_.paths()
    except Exception as exc:  # noqa: BLE001
        return {"total": 0, "matching": 0, "missing": 0,
                "error": f"{type(exc).__name__}: {exc}"}

    matching, changed, missing = 0, [], []
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            missing.append(path.name)
            continue
        expected = field_._paths.get(str(path).lower())  # noqa: SLF001
        if expected is None or sha256_of(path) == expected:
            matching += 1
        else:
            changed.append(path.name)
    return {"total": len(paths), "matching": matching,
            "missing": len(missing), "changed": len(changed),
            "missing_names": missing[:10], "changed_names": changed[:10]}


def run_arm(arm: str, tool: Tool, protected: Path, ledger_db: Path,
            args: argparse.Namespace) -> ArmResult:
    shape = ARMS[arm][1]
    result = ArmResult(arm=arm, tool=tool.key, tool_path=tool.path,
                       atomic=tool.atomic, shape=shape)
    if not tool.path:
        result.reason = (
            f"{tool.key} is not installed on this host, so this arm did not "
            f"run. A skipped check is a failed check: this counts against the "
            f"run rather than being dropped from it.")
        return result

    absent = tool.missing_provenance()
    if absent:
        # Same rule, one level further in. `atomic-t1486` launches PowerShell,
        # which is on every Windows host, so `tool.path` alone would let the
        # arm start and then quietly run nothing - a green arm whose attack
        # never existed. What is missing is named, because "the atomic did not
        # run" and "the atomics library is not installed" are different
        # findings and only one of them is about this system.
        result.reason = (
            f"this arm is {tool.atomic}, and it cannot be that without "
            + ", ".join(absent) + ". A skipped check is a failed check.")
        return result

    tag = uuid.uuid4().hex[:8]
    corpus = protected / f"phase5_{arm}_{tag}"
    workdir = Path(os.getenv("TEMP", ".")) / f"urds_phase5_{tag}"
    workdir.mkdir(parents=True, exist_ok=True)
    writers_file = workdir / "writers.jsonl"
    # Registered before anything is written, so that a crash anywhere below
    # still leaves `main` able to take the corpus back out of the protected
    # path. The first crash of this script left twelve files and an encrypted
    # archive sitting in a watched folder.
    root_scope = arm in ROOT_SCOPE_ARMS
    target = protected if root_scope else corpus
    _CREATED.append((corpus, workdir,
                     target.parent / (target.name + "_locked.7z")))

    print(f"\n{'=' * 74}\n{arm}  ({shape})\n  tool: {tool.path}\n{'=' * 74}")

    stages_own = arm in STAGES_ITS_OWN_FILES
    rng = random.Random(0xA11CE ^ hash(arm) & 0xFFFF)
    if stages_own:
        # Nothing is seeded: this encryptor brings its own files and will
        # refuse to start if the directory already has any. Seeding a corpus
        # for it would put documents in front of an attacker that never looks
        # at them, and then report them as undamaged.
        corpus.mkdir(parents=True, exist_ok=True)
        files = []
    else:
        files = seed_corpus(corpus, args.files, rng)
    seeded_at = time.monotonic()
    # A root-scope arm will reach everything under the protected root, decoys
    # and demonstration files included, so everything under it is hashed here
    # and restored at the end. Hashing only what this script seeded would leave
    # the rest damaged and unmeasured.
    if root_scope:
        before = {p: sha256_of(p) for p in sorted(protected.rglob("*"))
                  if p.is_file()}
        print(f"  seeded {len(files)} files into {corpus}")
        print(f"  root scope: {len(before)} files under {protected} are in "
              f"scope, including the decoys")
    elif stages_own:
        before = {}
        print(f"  nothing seeded: {tool.key} brings its own 10,001 documents "
              f"and encrypts those")
    else:
        before = {path: sha256_of(path) for path in files}
        print(f"  seeded {len(files)} files into {corpus}")

    # ---- a snapshot that predates the damage ----------------------------
    snapshot_id = None
    snapshot_at = None
    try:
        from recovery.vss_manager import VSSManager  # noqa: PLC0415

        class _NoLedger:
            def try_log_event(self, *a, **k):  # noqa: ANN002, ANN003, ARG002
                return None

        vss = VSSManager(ledger_client=_NoLedger())
        started = time.perf_counter()
        snapshot_id = vss.create_snapshot(str(protected.anchor or "C:\\"))
        snapshot_at = time.monotonic()
        print(f"  pre-attack snapshot {snapshot_id} in "
              f"{time.perf_counter() - started:.2f}s")
    except Exception as exc:  # noqa: BLE001
        print(f"  no pre-attack snapshot: {type(exc).__name__}: {exc}")

    # ---- let this process's own writes age out --------------------------
    settle_s = (attribution_window_ms() / 1000.0) + 1.5
    waited = time.monotonic() - seeded_at
    if waited < settle_s:
        print(f"  waiting {settle_s - waited:.1f}s for the seeding writes to "
              f"leave the {attribution_window_ms():.0f}ms attribution window")
        time.sleep(settle_s - waited)

    # ---- observers up before the attacker -------------------------------
    if stages_own:
        # No list to stat: the attacker's files do not exist yet. The directory
        # is watched instead, for the first file to appear and separately for
        # the first `.enc` - "it started writing" and "it started encrypting"
        # are different moments, and only one of them is what TTS usually
        # means.
        first_change = FirstChange([], watch_dir=corpus, ciphertext_suffix=".enc")
    else:
        first_change = FirstChange(list(before))
        first_change.snapshot()
    first_change.start()
    writers_file.write_text("", encoding="utf-8")
    suspend_watch = SuspendWatch(writers_file)
    suspend_watch.start()

    before_attack = tip_id(ledger_db)
    wall_at_monotonic_zero = time.time() - time.monotonic()

    # ---- the third-party encryptor --------------------------------------
    child = subprocess.Popen(
        [sys.executable, str(RUNNER), "--arm", arm, "--tool", str(tool.path),
         "--corpus", str(target), "--writers", str(writers_file)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    launched_at = time.monotonic()

    announced: dict = {}

    def read_announcement() -> None:
        """First line is the announcement; the rest is drained and dropped.

        Draining matters. This process holds the child's stdout pipe, and a
        pipe nobody reads fills at 64 KB and blocks the writer - the arm would
        then sit until `--timeout` and report whatever half-finished state it
        was in as a measurement. The Atomic Red Team arm is the one close to
        it: `Invoke-AtomicTest` announces every invocation on the information
        stream, and two hundred of those is tens of kilobytes.
        """
        if child.stdout is None:
            return
        line = child.stdout.readline()
        if line.strip():
            try:
                announced.update(json.loads(line))
            except ValueError:
                pass
        for _ in child.stdout:
            pass

    reader = threading.Thread(target=read_announcement, daemon=True)
    reader.start()
    reader.join(timeout=30.0)

    # Wait for the encryptor to finish. A suspension does not end the wait: the
    # responder escalates and, on a near miss, resumes - so a run cut short at
    # the first freeze would report FEBR as of the suspension and never find
    # out what the process went on to do after being let go.
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline and child.poll() is None:
        time.sleep(0.02)
    finished_at = time.monotonic()

    # Give the agent time to finish writing what it decided. The response is
    # taken on the detection path, but the ledger append is a hop behind it,
    # and an event parked waiting for an audit record can be responded to up to
    # a full attribution window after the write.
    settle = (attribution_window_ms() / 1000.0) + 3.0
    time.sleep(min(settle, max(1.0, deadline - time.monotonic() + settle)))
    after_attack = tip_id(ledger_db)
    first_change.stop()
    suspend_watch.stop()

    # stderr only. stdout belongs to the draining reader thread above, and
    # `communicate` would be a second reader on the same pipe.
    stderr_tail = ""
    try:
        if child.stderr is not None:
            stderr_tail = child.stderr.read()
        child.wait(timeout=10)
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass

    # ---- what the operating system says ---------------------------------
    # Two views of the same file, because they answer different questions.
    # `answer_key` maps a PID to who it was, for grading an attribution.
    # `launches` keeps every line, for counting how far the attack got: Windows
    # recycles PIDs inside a 200-file loop - one measured run produced 180
    # distinct numbers from 200 launches - so the dict is twenty launches short
    # of the truth and the list is not.
    answer_key = {}
    launches: list[dict] = []
    for line in writers_file.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        launches.append(record)
        answer_key[int(record["pid"])] = record
    runner_pid = announced.get("pid")
    if runner_pid:
        answer_key.setdefault(int(runner_pid), {"pid": int(runner_pid),
                                                "image": sys.executable,
                                                "role": "launcher"})

    changed, gone, unchanged = [], [], []
    for path, digest in before.items():
        if not path.exists():
            gone.append(path)
        elif sha256_of(path) != digest:
            changed.append(path)
        else:
            unchanged.append(path)

    # The arm that brings its own files leaves its damage as ciphertext in the
    # corpus directory: one `.enc` per document it got through. Counted from
    # the filesystem like everything else here - the encryptor's own log is not
    # evidence any more than the detector's is.
    ciphertext: list[Path] = []
    if stages_own:
        ciphertext = sorted(corpus.rglob("*.enc"))
        changed = ciphertext

    suspend_at = suspend_watch.at
    first_at = first_change.at
    tts_s = (suspend_at - first_at) if (suspend_at and first_at) else None
    tts_from_ciphertext_s = (
        (suspend_at - first_change.ciphertext_at)
        if (suspend_at and first_change.ciphertext_at) else None)

    # FEBR: files damaged before the suspension landed. Measured against the
    # filesystem, so a file the agent never saw still counts.
    #
    # Where nothing was suspended, FEBR is every file the encryptor got - not
    # `null`. "Files encrypted before the response fired" has an answer when
    # the response never fires, and it is the whole corpus. Reporting it as
    # unmeasured would let the arm the response could not reach look like the
    # arm with no damage.
    damaged = len(changed) + len(gone)

    def files_before(suspend_wall: float) -> int:
        count = 0
        for path in changed:
            try:
                if path.stat().st_mtime <= suspend_wall:
                    count += 1
            except OSError:
                count += 1
        # A file the encryptor unlinked is damage too, and its mtime is gone
        # with it, so it is counted whole rather than dropped for being
        # unmeasurable.
        return count + len(gone)

    if suspend_at is None:
        febr = damaged
    else:
        febr = files_before(wall_at_monotonic_zero + suspend_at)

    # ---- what the agent says --------------------------------------------
    #
    # Not yet. First make sure it has finished saying it: see
    # `wait_for_the_agent_to_catch_up` for the run this cost.
    drain = wait_for_the_agent_to_catch_up(protected, ledger_db, after_attack,
                                           timeout_s=args.drain_timeout)
    if drain["waited_s"] > 5.0:
        print(f"  waited {drain['waited_s']:.1f}s for the agent's queue to "
              f"drain past this arm")
    if not drain["drained"]:
        print(f"  {drain['why']}")

    blocks = blocks_since(ledger_db, before_attack)
    # Everything the arm touches, not only the directory it was pointed at.
    # `sevenzip-archive` writes its ciphertext to a *sibling* of the corpus, so
    # a filter anchored on the corpus directory alone would have discarded the
    # only file that arm creates and then reported the agent as silent about
    # an attack it may well have seen.
    archive_path = target.parent / (target.name + "_locked.7z")
    attack_prefixes = tuple(str(p).lower() for p in (target, archive_path))

    if root_scope:
        # `target` is the protected root itself, so a prefix match sweeps in
        # everything that lives there - including another workload's backlog.
        # Measured: this arm reported five mis-attributions, and all five were
        # the agent correctly naming `makecab.exe` and `git.exe` for files the
        # *benign soak* had written an hour earlier, still queued. Grading a
        # correct answer as wrong because the answer key belongs to a different
        # run is the harness manufacturing the one number this branch exists to
        # keep at zero.
        #
        # Scope is therefore the file set this arm actually had: the snapshot
        # taken before it started, plus what it is allowed to create.
        scoped = {str(path).lower() for path in before}
        created_prefixes = tuple(
            str(path).lower() for path in (corpus, archive_path))

        def on_corpus(block: dict) -> bool:
            path = str(block["data"].get("file_path", "")).lower()
            return path in scoped or path.startswith(created_prefixes)
    else:
        def on_corpus(block: dict) -> bool:
            path = str(block["data"].get("file_path", "")).lower()
            return path.startswith(attack_prefixes)

    file_events = [b for b in blocks
                   if b["event_type"] == "file_event" and on_corpus(b)]
    escalations = [b for b in blocks if b["event_type"] == "response_escalation"]

    correct, misattributed, unresolved = [], [], []
    for block in file_events:
        confidence = block["data"].get("attribution_confidence")
        pid = block["data"].get("process_id")
        if confidence != "certain" or pid is None:
            unresolved.append({"block": block["id"],
                               "file": block["data"].get("file_path"),
                               "confidence": confidence,
                               "reason": block["data"].get("attribution_reason")})
        elif int(pid) in answer_key:
            correct.append({"block": block["id"], "pid": int(pid),
                            "role": answer_key[int(pid)].get("role")})
        else:
            misattributed.append({
                "block": block["id"], "pid": int(pid),
                "image": block["data"].get("process_image"),
                "file": block["data"].get("file_path"),
                "reason": block["data"].get("attribution_reason")})

    suspended_pids = sorted({
        int(b["data"]["process_id"]) for b in escalations
        if b["data"].get("process_id") is not None})
    suspended_in_key = [p for p in suspended_pids if p in answer_key]
    suspended_outside_key = [p for p in suspended_pids if p not in answer_key]

    # ---- a suspension the chain holds and the watcher did not see --------
    #
    # `SuspendWatch` reports only a freeze it saw itself, checked against the
    # creation time the runner wrote down, and that is the right default: it
    # is corroboration of the ledger, and corroboration that reads the ledger
    # corroborates nothing. It has a blind spot. A process suspended and
    # resumed inside one 10 ms poll, or one already on its way out, leaves the
    # watcher empty while the agent's chain holds a `response_escalation`
    # naming a PID the runner started. Measured: the `gpg-loop` arm reported
    # `suspended [16476]` with no time to go with it, so FEBR fell back to all
    # 200 files and TTS to null - a suspension that did happen, reported as
    # though the response had never fired.
    #
    # So the *moment* may come from the block, and the report always says
    # which source it came from. The *identity* may not: a PID is accepted
    # here only if the launcher's answer key already holds it, so the agent
    # cannot nominate its own success. And the block is stamped when it is
    # written, which is after the suspend call returned, so a moment taken
    # this way is late - the TTS it produces is an upper bound, and the FEBR
    # it produces counts at least as many files as really got through.
    ledger_suspend_wall: float | None = None
    if suspend_at is None and suspended_in_key:
        stamps = []
        for block in escalations:
            pid = block["data"].get("process_id")
            if pid is None or int(pid) not in answer_key:
                continue
            when = parse_utc(str(block.get("timestamp") or ""))
            if when is not None:
                stamps.append(when)
        if stamps:
            ledger_suspend_wall = min(stamps)
            febr = files_before(ledger_suspend_wall)

    # ---- FEBR for an encryptor that unlinks what it encrypts --------------
    #
    # `files_before` counts a deleted file whole, because its mtime went with
    # it and a file that cannot be timed must not be assumed to have survived.
    # That is right in general and it is very wrong for the arms that unlink
    # every original: `gpg-loop` deletes all 200, so FEBR is 200 no matter when
    # the response landed, and a suspension that saved 96 files reads as one
    # that saved none.
    #
    # There is a third source for those arms and it is the best one available:
    # the launcher's own answer key. Where the runner started exactly one
    # writer per seeded file - which the key proves rather than the arm's
    # description asserting - the number of writers it had started by the
    # suspension is the number of files the attack had reached. It comes from
    # the process that launched them, so it is not the agent's word, and it
    # does not depend on an artefact the attacker destroyed.
    #
    # Published beside FEBR and never in place of it: the two count different
    # things, and an arm where they disagree is telling the reader something.
    febr_from_launcher = None
    writers_launched = sorted(
        float(record.get("at", 0.0))
        for record in launches
        if record.get("role") == "encryptor" and record.get("at"))
    one_writer_per_file = len(writers_launched) == len(files)
    suspend_wall_effective = (
        (wall_at_monotonic_zero + suspend_at) if suspend_at is not None
        else ledger_suspend_wall)
    if one_writer_per_file and suspend_wall_effective is not None:
        febr_from_launcher = sum(1 for at in writers_launched
                                 if at <= suspend_wall_effective)

    tts_from_ledger_s = None
    if ledger_suspend_wall is not None and first_at is not None:
        tts_from_ledger_s = (ledger_suspend_wall
                             - (wall_at_monotonic_zero + first_at))
    suspend_moment_source = (
        "observed" if suspend_at is not None
        else "ledger" if ledger_suspend_wall is not None
        else None)
    #: The number the §5 bound is read against, whichever source it came from.
    effective_tts_s = tts_s if tts_s is not None else tts_from_ledger_s

    # ---- restore, and verify against the pre-attack hashes ---------------
    #
    # Throttled, and the throttle is a finding rather than a convenience.
    #
    # Measured on this host: an unthrottled restore of 55 files into the
    # protected root - twenty of them decoys - was suspended and then
    # **killed** by the agent 1.4 s in, "2 independent signals agreed (canary,
    # path_velocity), including canary", ledger block 16297. It was right about
    # the evidence: a process rewriting decoys and dozens of files a second is
    # the signature, and nothing in the file contents distinguishes restoring a
    # document from encrypting it.
    #
    # So recovery here runs below the rate the agent itself considers
    # suspicious, and the rate is read from the agent's own configuration
    # rather than typed in. That makes MTTR below a real number for this system
    # rather than an artificial one: you cannot restore faster than the
    # protection will tolerate without being stopped by it. What the throttle
    # does not prevent is a decoy restore reading as a decoy hit - one signal,
    # a near miss - so this process can still be suspended and resumed while it
    # works, and it counts those rather than pretending they did not happen.
    restored_ok, restore_failures = 0, []
    self_suspensions, frozen_s = 0, 0.0
    per_file_s = restore_interval_s(args)
    restore_started = time.monotonic()
    if stages_own:
        # Nothing of the operator's was lost - this encryptor only destroys
        # documents it wrote itself minutes earlier. "Restored 0 of 0" would
        # read as a recovery that happened, so recovery is reported as not
        # applicable to this arm and the numbers come from the other five.
        pass
    elif snapshot_id and (changed or gone):
        try:
            from recovery.recovery import RecoveryManager  # noqa: PLC0415

            manager = RecoveryManager()
            snapshot_root = manager.resolve_snapshot_root(snapshot_id)
            for path in changed + gone:
                loop_started = time.monotonic()
                try:
                    digest = manager.restore_file(snapshot_root, str(path))
                    if digest == before[path]:
                        restored_ok += 1
                    else:
                        restore_failures.append(
                            {"file": path.name, "restored": digest[:16],
                             "expected": before[path][:16]})
                except Exception as exc:  # noqa: BLE001
                    restore_failures.append({"file": path.name,
                                             "error": f"{type(exc).__name__}: {exc}"})
                # A copy of a file this size is milliseconds. A gap far larger
                # than that, with nothing here that blocks, is this process
                # having been frozen by the agent and let go again - the one
                # way it can observe its own suspension, since while suspended
                # it cannot observe anything.
                took = time.monotonic() - loop_started
                if took > FREEZE_FLOOR_S:
                    self_suspensions += 1
                    frozen_s += took
                    print(f"    this process was frozen for {took:.1f}s while "
                          f"restoring {path.name}")
                if per_file_s > 0:
                    time.sleep(max(0.0, per_file_s - took))
        except Exception as exc:  # noqa: BLE001
            restore_failures.append({"error": f"{type(exc).__name__}: {exc}"})
    restore_finished = time.monotonic()

    # Walking the root means the decoys were in the blast radius. Whether they
    # came back byte-for-byte is not a detail of cleanup: the agent holds a
    # manifest of their hashes and compares against it, so a decoy restored to
    # different bytes would leave every future run reporting a tripwire nobody
    # tripped.
    canaries_intact = None
    if root_scope:
        canaries_intact = check_canaries()
        print(f"  decoys after restore: {canaries_intact['matching']}/"
              f"{canaries_intact['total']} match the agent's manifest")

    rpo_s = (first_at - snapshot_at) if (first_at and snapshot_at) else None
    # MTTR as the plan defines it - suspension to verified restore - exists
    # only where there was a suspension. Where there was not, recovery still
    # took a measurable time and it is the number an operator actually
    # experiences, so it is reported separately rather than left as a null
    # beside a null.
    if suspend_at is not None:
        mttr_s = restore_finished - suspend_at
    elif ledger_suspend_wall is not None:
        mttr_s = (wall_at_monotonic_zero + restore_finished) - ledger_suspend_wall
    else:
        mttr_s = None
    recovery_s = ((restore_finished - first_at)
                  if (first_at and (changed or gone) and not stages_own)
                  else None)

    chain = verify_chain_since(ledger_db, before_attack)

    # Did the agent say anything at all about this attack? A file_event whose
    # verdict is not the benign one, or an escalation naming a process the
    # runner started. Asked separately from every other verdict below, because
    # a bound that only applies once something was suspended is a bound that
    # passes by default on an attack nobody noticed - and "the response never
    # fired, therefore its bounds were not exceeded" is exactly the shape of a
    # gate weakened to make it pass.
    flagged = [b for b in file_events
               if b["data"].get("verdict") not in (None, "benign", "normal")]
    detected = bool(flagged) or bool(suspended_in_key)

    # The two bounds §5 sets apply only where a suspension happened at all, and
    # whether one *could* happen is a property of the arm: a process that exits
    # in milliseconds is named correctly and named too late
    # (docs/LIMITATIONS.md §4). So this is reported, never silently excused.
    reachable = bool(suspended_in_key)
    febr_ok = None if not reachable else (febr is None or febr <= FEBR_BOUND)
    tts_ok = None if not reachable else (effective_tts_s is not None
                                         and effective_tts_s <= TTS_BOUND_S)

    within_bounds = (
        drain["drained"]                      # else the chain was read early
        and detected
        and misattributed == []
        and suspended_outside_key == []
        and chain["valid"]
        and damaged > 0                       # the arm actually did something
        and (stages_own or not (changed or gone) or restore_failures == [])
        and febr_ok is not False
        and tts_ok is not False
        and (canaries_intact is None
             or (canaries_intact["matching"] == canaries_intact["total"]
                 and canaries_intact["total"] > 0))
    )

    result.ran = True
    result.metrics = {
        "febr_files_before_suspend": febr,
        "febr_bound": FEBR_BOUND,
        "tts_s": round(tts_s, 3) if tts_s is not None else None,
        "tts_from_first_ciphertext_s": (round(tts_from_ciphertext_s, 3)
                                        if tts_from_ciphertext_s is not None
                                        else None),
        "febr_from_launcher_writer_count": febr_from_launcher,
        "febr_one_writer_per_file": one_writer_per_file,
        "tts_from_ledger_s": (round(tts_from_ledger_s, 3)
                              if tts_from_ledger_s is not None else None),
        "suspend_moment_source": suspend_moment_source,
        "tts_bound_s": TTS_BOUND_S,
        "files_seeded": len(files),
        "files_damaged": damaged,
        "files_overwritten": len(changed),
        "files_unlinked": len(gone),
        "files_untouched": len(unchanged),
        "attribution_correct": len(correct),
        "attribution_misattributed": len(misattributed),
        "attribution_unresolved": len(unresolved),
        "suspended_pids": suspended_pids,
        "suspended_pids_in_answer_key": suspended_in_key,
        "suspended_pids_outside_answer_key": suspended_outside_key,
        "detected": detected,
        "flagged_file_events": len(flagged),
        "response_reached_the_writer": reachable,
        "febr_within_bound": febr_ok,
        "tts_within_bound": tts_ok,
        "attacker_staged_its_own_files": stages_own,
        "ciphertext_files_left": len(ciphertext) if stages_own else None,
        "restore_applicable": not stages_own,
        "restored_and_verified": restored_ok,
        "restore_failures": len(restore_failures),
        "restore_files_per_second_cap": (round(1.0 / per_file_s, 3)
                                         if per_file_s > 0 else None),
        "restore_self_suspensions": self_suspensions,
        "restore_seconds_frozen": round(frozen_s, 3),
        "rpo_s": round(rpo_s, 3) if rpo_s is not None else None,
        "mttr_s": round(mttr_s, 3) if mttr_s is not None else None,
        "recovery_s_first_write_to_last_verified": (
            round(recovery_s, 3) if recovery_s is not None else None),
        # Recovery decomposed, because the whole-arm figure hid a seventeen-fold
        # difference between two arms doing the same amount of work: the
        # `openssl-loop` arm reported 3,527 s where `openssl-inplace` reported
        # 194 s, with the same 200 files, the same restore cap and no freeze on
        # either. With one number there is no way to tell whether the time went
        # into the attack, the wait for the ledger, or the restore - so all
        # three are published and the next run answers it instead of inviting a
        # guess.
        "attack_s_launch_to_exit": round(finished_at - launched_at, 3),
        "restore_s": round(restore_finished - restore_started, 3),
        "agent_queue_drained": drain["drained"],
        "agent_drain_wait_s": drain["waited_s"],
        "chain_valid": chain["valid"],
        "root_scope": root_scope,
        "decoys_intact_after_restore": canaries_intact,
        "within_bounds": within_bounds,
    }
    result.evidence = {
        "corpus": str(corpus),
        "answer_key_pids": sorted(answer_key),
        "answer_key_size": len(answer_key),
        "runner_announced_pid": runner_pid,
        "first_change_file": first_change.path.name if first_change.path else None,
        "observed_stopped_pid": suspend_watch.pid,
        "recycled_pids_rejected": len(suspend_watch.rejected),
        "recycled_pids_sample": suspend_watch.rejected[:5],
        "snapshot_id": snapshot_id,
        # After the drain, not before it: the whole point of waiting is
        # that blocks were still arriving.
        "ledger_blocks": len(blocks),
        "file_event_blocks_on_corpus": len(file_events),
        "misattributed": misattributed[:10],
        "unresolved_sample": unresolved[:5],
        "restore_failures_sample": restore_failures[:5],
        # What the detector concluded, counted. An arm that was not detected is
        # a finding and needs the verdicts that were reached instead, not just
        # a False.
        "verdicts": {
            verdict: sum(1 for b in file_events
                         if b["data"].get("verdict") == verdict)
            for verdict in sorted({str(b["data"].get("verdict"))
                                   for b in file_events})
        },
        "container_formats": {
            fmt: sum(1 for b in file_events
                     if b["data"].get("container_format") == fmt)
            for fmt in sorted({str(b["data"].get("container_format"))
                               for b in file_events})
        },
        "runner_exit": child.returncode,
        "runner_stderr_tail": (stderr_tail or "")[-400:],
        "chain": chain,
    }

    print(f"  damaged {damaged}/{len(before)}  detected={detected} "
          f"({len(flagged)} flagged of {len(file_events)} events)")
    print(f"  FEBR {febr}  TTS {result.metrics['tts_s']}s  "
          f"attribution {len(correct)} correct / {len(misattributed)} wrong / "
          f"{len(unresolved)} unresolved")
    print(f"  suspended {suspended_pids or 'nothing'}  "
          f"restored {restored_ok}/{damaged}  "
          f"RPO {result.metrics['rpo_s']}s  MTTR {result.metrics['mttr_s']}s  "
          f"-> {'within bounds' if within_bounds else 'OUT OF BOUNDS'}")

    cleanup_arm(corpus, answer_key, workdir, args, archive_path)
    return result


def emergency_cleanup(args: argparse.Namespace) -> None:
    """Anything `cleanup_arm` did not reach, because the harness raised."""
    if args.keep:
        return
    for corpus, workdir, archive in _CREATED:
        for target in (corpus, archive, workdir):
            if not target.exists():
                continue
            print(f"  cleaning up after a failed arm: {target}")
            try:
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink()
            except OSError as exc:
                print(f"    could not remove it: {exc}")


def cleanup_arm(corpus: Path, answer_key: dict, workdir: Path,
                args: argparse.Namespace, archive: Path) -> None:
    """Resume anything left frozen, then take the corpus away.

    Resume first and unconditionally. A suspended process that this script
    leaves behind is a process nobody will ever resume, and the rule is suspend
    before you kill precisely because a suspension is meant to be reversible.
    Nothing is killed here: every process in the answer key was started by the
    runner and exits on its own.
    """
    for pid in answer_key:
        try:
            process = psutil.Process(pid)
            if process.status() == psutil.STATUS_STOPPED:
                process.resume()
                print(f"  resumed pid {pid}, which was left suspended")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if args.keep:
        print(f"  keeping {corpus}")
        return
    for target in (corpus, archive, workdir):
        try:
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            elif target.exists():
                target.unlink()
        except OSError:
            pass


def wait_for_the_agent_to_catch_up(protected: Path, ledger_db: Path,
                                   after_id: int,
                                   timeout_s: float = 600.0) -> dict:
    """Write one file into the protected path and wait for its block.

    The reason this exists, measured on 20 September 2026: an hour of benign
    work left the agent minutes behind its own event queue, and the attack
    corpus read the chain the moment each arm finished. Five of six arms were
    published as `detected=False` with zero events - while the agent went on to
    write 398, 351 and 459 `suspected_encryption` blocks for three of them
    after the harness had already looked and moved on. The agent had not missed
    the attack. The harness had asked too early, and then reported the silence
    as a property of the system.

    A sentinel answers it properly. The agent processes its queue in order, so
    a file written *after* the attack whose block has arrived means every event
    before it has been dealt with. Two seconds on an idle agent; as long as the
    backlog takes otherwise.

    Returns the probe's block id, how long it took, and whether it arrived at
    all. It not arriving is a failed arm, never a quiet one: a chain read
    before the writer finished is not evidence about the writer.
    """
    tag = uuid.uuid4().hex[:8]
    probe = protected / f"drain_probe_{tag}.txt"
    started = time.monotonic()
    try:
        probe.write_text(
            "urds phase 5 drain probe; written after the arm, removed once "
            "its block arrives\n"
            * 40, encoding="utf-8")
    except OSError as exc:
        return {"drained": False, "waited_s": 0.0, "block": None,
                "why": f"could not write the probe: {exc}"}
    _CREATED.append((probe, probe, probe))

    seen = None
    while time.monotonic() - started < timeout_s:
        for block in blocks_since(ledger_db, after_id):
            if tag in json.dumps(block.get("data", {})):
                seen = block["id"]
                break
        if seen is not None:
            break
        time.sleep(0.5)

    waited = time.monotonic() - started
    try:
        probe.unlink()
    except OSError:
        pass
    return {"drained": seen is not None, "waited_s": round(waited, 2),
            "block": seen,
            "why": "" if seen is not None else
                   f"no block naming the probe arrived within {timeout_s:.0f}s; "
                   f"the agent is still behind and this arm measured nothing"}


def verify_chain_since(db: Path, anchor_id: int) -> dict:
    """Recompute the hashes of the blocks one arm produced, and no others.

    `selftest.verify_chain` walks the whole chain, which is the right check to
    run once and the wrong one to run six times. At 285,632 blocks in a 180 MB
    file it is a full table scan with `fetchall`, holding a SHARED lock the
    whole time - and this ledger is deliberately not in WAL mode, so the
    agent's own appends block behind every one of them. Measured on
    20 September 2026: during a six-arm run the agent fell minutes behind its
    queue and five arms were published as having detected nothing, while the
    blocks proving otherwise were written after the harness had looked.

    The anchor is the last block before the arm started. Its `current_hash` is
    what the arm's first block must chain to, so a rewrite anywhere inside the
    window is still caught; everything before the anchor belongs to the
    run-level check, which still walks the whole chain once.

    The hash function is the ledger service's own, imported rather than
    rewritten, for the reason `selftest.verify_chain` gives.
    """
    from hash_chain import GENESIS_HASH, HashChainLedger  # noqa: PLC0415

    conn = read_only_connection(db)
    try:
        anchor = conn.execute(
            "SELECT current_hash FROM blocks WHERE id = ?",
            (anchor_id,)).fetchone()
        rows = conn.execute(
            "SELECT id, timestamp, event_type, event_data, previous_hash,"
            " current_hash FROM blocks WHERE id > ? ORDER BY id ASC",
            (anchor_id,)).fetchall()
    finally:
        conn.close()

    expected_previous = anchor["current_hash"] if anchor else GENESIS_HASH
    for row in rows:
        recomputed = HashChainLedger.compute_hash(
            row["timestamp"], row["event_type"], row["event_data"],
            row["previous_hash"])
        if (recomputed != row["current_hash"]
                or row["previous_hash"] != expected_previous):
            return {"valid": False, "blocks_checked": len(rows),
                    "invalid_block_id": int(row["id"]),
                    "scope": f"blocks after {anchor_id}"}
        expected_previous = row["current_hash"]
    return {"valid": True, "blocks_checked": len(rows),
            "invalid_block_id": None, "scope": f"blocks after {anchor_id}"}


# ------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", action="append", choices=sorted(ARMS),
                        help="repeatable; default is every arm")
    parser.add_argument("--files", type=int, default=200,
                        help="corpus size per arm (default 200)")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--drain-timeout", type=float, default=600.0,
                        help="seconds to wait for the agent's queue to reach "
                             "past this arm before calling the arm unmeasured")
    parser.add_argument("--keep", action="store_true",
                        help="leave the corpus in place for inspection")
    parser.add_argument("--restore-rate", type=float, default=None,
                        help="files per second during recovery; 0 for "
                             "unthrottled, which this agent kills. The default "
                             "is derived from the agent's own velocity "
                             "configuration - see restore_interval_s")
    parser.add_argument("--write-report", action="store_true",
                        help="write reports/phase5_attack_corpus.json")
    args = parser.parse_args(argv)

    if platform.system() != "Windows":
        print("This needs Windows: attribution is a Security-channel "
              "subscription and the agent is a Windows Service.", file=sys.stderr)
        return 2
    if not is_elevated():
        print("Run this from an Administrator console.", file=sys.stderr)
        return 2

    try:
        from agent import config as agent_config  # noqa: PLC0415

        config = agent_config.load()
    except Exception as exc:  # noqa: BLE001
        print(f"cannot load the agent configuration: {exc}", file=sys.stderr)
        return 2

    protected = Path(config.protected_paths[0])
    ledger_db = Path(config.ledger_db)
    if not ledger_db.is_file() or not protected.is_dir():
        print(f"expected a ledger at {ledger_db} and a directory at "
              f"{protected}", file=sys.stderr)
        return 2

    state = subprocess.run(["sc.exe", "query", "URDSAgent"],
                           capture_output=True, text=True, check=False)
    if "RUNNING" not in state.stdout:
        print("URDSAgent is not RUNNING. This measures what the agent does; "
              "with the agent down it would measure nothing and say so at "
              "length.", file=sys.stderr)
        return 2

    tools = known_tools()
    for tool in tools.values():
        tool.locate()

    chosen = args.arm or sorted(ARMS)
    print("\nURDS Phase 5 - third-party attack corpus")
    print("=" * 74)
    print(f"protected path : {protected}")
    print(f"ledger         : {ledger_db}")
    print(f"corpus size    : {args.files} files per arm")
    for key, tool in sorted(tools.items()):
        print(f"  {key:<8} {tool.path or '-- not installed --'}")

    results = []
    try:
        for arm in chosen:
            try:
                results.append(
                    run_arm(arm, tools[ARMS[arm][0]], protected, ledger_db, args))
            except Exception as exc:  # noqa: BLE001
                # One arm that raises must not take the measurements of the
                # arms that ran with it, and must not be mistaken for an arm
                # that passed.
                import traceback  # noqa: PLC0415

                traceback.print_exc()
                broken = ArmResult(
                    arm=arm, tool=ARMS[arm][0],
                    tool_path=tools[ARMS[arm][0]].path,
                    atomic=tools[ARMS[arm][0]].atomic, shape=ARMS[arm][1])
                broken.reason = f"the harness raised: {type(exc).__name__}: {exc}"
                results.append(broken)
    finally:
        emergency_cleanup(args)

    whole_chain = verify_chain(ledger_db)
    if not whole_chain["valid"]:
        print(f"  THE CHAIN DOES NOT VERIFY: block "
              f"{whole_chain['invalid_block_id']}")

    report = {
        "_what_this_is": (
            "Phase 5's attack corpus: four arms, each an encryptor this "
            "project did not write, run against a seeded corpus inside the "
            "agent's protected path. Every number is measured from the "
            "filesystem or from the agent's own hash-chained ledger, and "
            "attribution is graded against an answer key written by the "
            "process that launched the encryptors."),
        "_what_this_does_not_show": (
            "False-positive rate. That is scripts/benign_soak.py, which runs "
            "the benign corpus for an hour and counts suspensions. Of the "
            "four T1486 atomics Red Canary publishes for Windows, only "
            "T1486-8 is run here: T1486-5 writes a ransom note to the "
            "Desktop and T1486-10 writes to the root of C:, both outside "
            "every configured protected path, and T1486-9 encrypts a whole "
            "volume with DiskCryptor, which is not reversible from a "
            "file-level snapshot. Those three are excluded by decision and "
            "not by accident, and the decision is the blast-radius rule "
            "rather than a judgement about how good the atomics are."),
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "host": platform.platform(),
        "attribution_window_ms": attribution_window_ms(),
        "corpus_files_per_arm": args.files,
        "bounds": {"febr_files": FEBR_BOUND, "tts_s": TTS_BOUND_S},
        # The binaries themselves, hashed. An attack corpus whose provenance
        # is "openssl, presumably" is not a corpus anybody can re-run: these
        # are the exact files that produced the numbers below.
        "tools": {k: {"path": t.path, "atomic": t.atomic,
                      "sha256": (sha256_of(Path(t.path)) if t.path else None),
                      "provenance": {f: (sha256_of(Path(f))
                                         if Path(f).is_file() else None)
                                     for f in t.provenance}}
                  for k, t in sorted(tools.items())},
        "arms": [r.as_dict() for r in results],
        "summary": {
            "arms_run": sum(1 for r in results if r.ran),
            "arms_requested": len(results),
            "arms_within_bounds": sum(1 for r in results if r.passed),
            "total_misattributions": sum(
                r.metrics.get("attribution_misattributed", 0) for r in results),
            "arms_where_the_response_reached_the_writer": sum(
                1 for r in results if r.metrics.get("response_reached_the_writer")),
            "arms_detected": sum(1 for r in results if r.metrics.get("detected")),
            "total_files_restored_and_verified": sum(
                r.metrics.get("restored_and_verified", 0) for r in results),
            "total_restore_failures": sum(
                r.metrics.get("restore_failures", 0) for r in results),
            # The whole chain, once. Each arm verifies only its own window
            # (see `verify_chain_since` for what walking all of it six times
            # did to the agent underneath); this is the check that the blocks
            # before the run are still what they were.
            "whole_chain": whole_chain,
        },
    }

    print("\n" + "=" * 74)
    for result in results:
        mark = "ok  " if result.passed else "FAIL"
        note = result.reason if not result.ran else (
            f"detected={result.metrics.get('detected')}, "
            f"suspended={result.metrics.get('response_reached_the_writer')}, "
            f"FEBR {result.metrics.get('febr_files_before_suspend')}, "
            f"TTS {result.metrics.get('tts_s')}s, "
            f"{result.metrics.get('attribution_misattributed')} mis-attributed, "
            f"restored {result.metrics.get('restored_and_verified')}/"
            f"{result.metrics.get('files_damaged')}")
        print(f"  {mark} {result.arm:<18} {note}")
    # §5 of the build prompt asks for a third-party encryptor suspended within
    # 20 files and 2 s. That is a claim about the system, not about every arm:
    # an encryptor whose process exits in milliseconds cannot be suspended by
    # anything that learns its PID from an audit record delivered later, and
    # docs/LIMITATIONS.md §4 says so. So it is asked once, across the run, and
    # a run where nothing was ever suspended fails whatever the arms say.
    suspended_within_bounds = [
        r.arm for r in results
        if r.metrics.get("response_reached_the_writer")
        and r.metrics.get("febr_within_bound")
        and r.metrics.get("tts_within_bound")]
    report["summary"]["arms_suspended_within_bounds"] = suspended_within_bounds
    report["summary"]["a_third_party_encryptor_was_suspended_within_bounds"] = (
        bool(suspended_within_bounds))

    print(f"\n  mis-attributions across every arm: "
          f"{report['summary']['total_misattributions']} (must be 0)")
    print(f"  suspended within {FEBR_BOUND} files and {TTS_BOUND_S}s: "
          f"{', '.join(suspended_within_bounds) or 'no arm'}")

    if args.write_report or os.getenv("URDS_WRITE_REPORTS"):
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"  wrote {REPORT}")
    else:
        print("  report not written (pass --write-report)")

    return 0 if (all(r.passed for r in results) and suspended_within_bounds) else 1


if __name__ == "__main__":
    raise SystemExit(main())
