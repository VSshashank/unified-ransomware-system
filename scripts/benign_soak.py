r"""Phase 5: how often the agent stops something that was not an attack.

    .venv\Scripts\python.exe scripts/benign_soak.py --minutes 60 --write-report

Elevated, on a host where `install.ps1` has run and `URDSAgent` is running.
The one number this produces is the false-positive rate: **suspensions per hour
across a corpus of ordinary work**, run inside the protected path, by tools
this project did not write.

WHY IT HAS TO RUN INSIDE THE PROTECTED PATH

A benign corpus run somewhere the agent is not watching measures nothing. These
workloads write, compress, archive, delete and rewrite files under the same
root the attack corpus attacks, which is the only place the question "would
this have been suspended?" has an answer.

WHAT COUNTS AS A FALSE POSITIVE

A suspension - or a kill - of a process this script started. Not a flagged
file, not an alert: `docs/LIMITATIONS.md` is clear that an alert is cheap and a
suspension is not, and the build plan asks for "suspends per hour". Flagged
events are reported beside it, because a corpus that raises a thousand alerts
and suspends nothing is a different system from one that does neither, and the
difference matters to whoever has to read the alerts.

The answer key is the same shape as the attack corpus's: every process this
script starts is recorded with the PID the OS returned, as it starts. An
escalation naming a PID in that key is a false positive. An escalation naming a
PID outside it is somebody else's software and is reported separately rather
than being quietly counted as a pass.

THE CORPUS, AND WHAT IS MISSING FROM IT

The build plan names: ffmpeg transcode, 7-Zip archive, VeraCrypt container,
`git clone` of a large repo, Windows Update, a Visual Studio build, browser
cache churn, OneDrive sync. What runs here is whatever of that is installed,
and **every absent member is reported as absent and counts against the run**.
A false-positive rate measured over half a corpus is not the rate; it is a
lower bound, and it is labelled as one.

Exit codes: 0 no suspension of anything this script started, and at least one
workload ran; 1 a false positive, or no workload could run; 2 could not run at
all.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
LEDGER_DIR = ROOT / "services" / "ledger"
if str(LEDGER_DIR) not in sys.path:
    sys.path.insert(0, str(LEDGER_DIR))
sys.path.insert(0, str(ROOT / "scripts"))

from selftest import blocks_since, tip_id, verify_chain  # noqa: E402

REPORT = ROOT / "reports" / "phase5_benign_soak.json"

#: Bytes of real, compressible content each seeding pass lays down. Small
#: enough that a pass finishes in seconds, large enough that compressing it is
#: real work rather than a syscall.
SEED_FILES = 40


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


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------------ the corpus

@dataclass
class Workload:
    """One kind of ordinary work, and the third-party tool that does it."""

    key: str
    what: str
    build: object          # (workdir, tools) -> list[list[str]] | None
    needs: tuple[str, ...] = ()
    network: bool = False
    runs: int = 0
    failures: int = 0
    seconds: float = 0.0
    reason: str = ""

    def available(self, tools: dict[str, str | None]) -> bool:
        return all(tools.get(name) for name in self.needs)


def _seed(workdir: Path, count: int = SEED_FILES) -> Path:
    """Ordinary documents for the tools to work on.

    Written by this process, which is why its PID is in the answer key: it is a
    writer inside the protected path like everything else here, and a
    suspension of it would be a false positive like any other.
    """
    import random  # noqa: PLC0415

    source = workdir / "documents"
    source.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20260918)
    words = ("invoice", "customer", "region", "renewal", "forecast", "margin",
             "quarter", "supplier", "contract", "delivery", "warehouse")
    for index in range(count):
        path = source / f"note_{index:03d}.txt"
        lines = [" ".join(rng.choices(words, k=12)) for _ in range(rng.randint(200, 600))]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return source


def _sevenzip(workdir: Path, tools: dict) -> list[list[str]]:
    _prune(workdir, "archive_")
    source = _seed(workdir)
    archive = workdir / f"archive_{uuid.uuid4().hex[:6]}.7z"
    return [[tools["7z"], "a", "-bso0", "-bsp0", str(archive), str(source / "*")]]


def _tar_gzip(workdir: Path, tools: dict) -> list[list[str]]:
    _prune(workdir, "backup_")
    source = _seed(workdir)
    tarball = workdir / f"backup_{uuid.uuid4().hex[:6]}.tar.gz"
    return [[tools["tar"], "-czf", str(tarball), "-C", str(source), "."]]


def _makecab(workdir: Path, tools: dict) -> list[list[str]]:
    """Windows' own compressor. Stands in for nothing; it is simply here."""
    _prune(workdir, "bundle_")
    source = _seed(workdir, count=8)
    cab = workdir / f"bundle_{uuid.uuid4().hex[:6]}.cab"
    return [[tools["makecab"], str(next(source.glob("*.txt"))), str(cab)]]


def _force_rmtree(target: Path) -> bool:
    """Remove a tree that contains read-only files, and say whether it went.

    `shutil.rmtree(..., ignore_errors=True)` ignores the errors and the caller
    then prints that it removed something it did not. Measured: a one-hour soak
    left a 139 MB `git clone` inside the protected path and reported "removed",
    because git marks every object in `.git/objects` read-only and Windows
    refuses to unlink a read-only file. The next thing to run in that path was
    the attack corpus, whose `sevenzip-root` arm archives the protected root -
    it would have archived the leftover and counted its files as damage.

    So: clear the read-only bit and retry, and return the truth either way.
    """
    def on_error(func, path, _exc):
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except OSError:
            pass

    shutil.rmtree(target, onerror=on_error)
    return not target.exists()


def _prune(workdir: Path, prefix: str, keep: int = 0) -> None:
    """Take the previous round's output away before making another.

    Every workload here writes a uniquely named directory so that two rounds
    never collide, which without this would grow without bound: a full clone of
    this repository is 331 MB, and an hour of cycles would put gigabytes into
    the protected path for no measurement gain. Removing it is not tidying
    between measurements - deletions are file events too, and an operator
    clearing out a build directory is exactly the kind of ordinary work this
    corpus is supposed to contain.
    """
    existing = sorted(workdir.glob(prefix + "*"))
    for path in existing[:max(0, len(existing) - keep)]:
        shutil.rmtree(path, ignore_errors=True) if path.is_dir() else path.unlink(
            missing_ok=True)


def _git_clone(workdir: Path, tools: dict) -> list[list[str]] | None:
    """A real clone of a real repository - once.

    The build plan asks for a large repo, and this checkout is one: 331 MB of
    objects, thousands of small files written fast by git.exe, which is the
    shape that matters. It is cloned from the local path rather than from the
    network because re-cloning somebody else's repository every few minutes for
    an hour is rude, and it is cloned **once** because the clone is 331 MB and
    the ongoing churn comes from `git-gc` repacking it afterwards.
    """
    if list(workdir.glob("clone_*")):
        return None
    target = workdir / f"clone_{uuid.uuid4().hex[:6]}"
    return [[tools["git"], "clone", "--quiet", "--no-hardlinks",
             str(ROOT), str(target)]]


def _git_churn(workdir: Path, tools: dict) -> list[list[str]] | None:
    """Checkout churn inside an existing clone: git rewriting the tree."""
    clones = sorted(workdir.glob("clone_*"))
    if not clones:
        return None
    clone = clones[-1]
    return [[tools["git"], "-C", str(clone), "gc", "--quiet", "--aggressive"]]


def _venv_build(workdir: Path, tools: dict) -> list[list[str]]:
    """The nearest thing on this host to a Visual Studio build.

    Thousands of files written by an interpreter in a few seconds, which is the
    shape of a build that matters here - not the compiler it came from.
    """
    _prune(workdir, "build_")
    target = workdir / f"build_{uuid.uuid4().hex[:6]}"
    return [[sys.executable, "-m", "venv", str(target)]]


def _npm_install(workdir: Path, tools: dict) -> list[list[str]] | None:
    """A JavaScript build's file churn, if node is installed."""
    _prune(workdir, "node_")
    target = workdir / f"node_{uuid.uuid4().hex[:6]}"
    target.mkdir(parents=True, exist_ok=True)
    (target / "package.json").write_text(
        json.dumps({"name": "urds-benign", "version": "1.0.0",
                    "dependencies": {"left-pad": "1.3.0"}}), encoding="utf-8")
    return [[tools["npm"], "install", "--prefix", str(target),
             "--no-audit", "--no-fund", "--loglevel", "error"]]


def _binary_copy(workdir: Path, tools: dict) -> list[list[str]]:
    """Copying real binaries in: high-entropy content that is not an attack.

    `shell32.dll` is 8 MB of compiled code and sits near the top of the entropy
    range without being ciphertext. Copied by `robocopy`, which is Windows'
    own, so the writer is a Microsoft binary rather than this script.
    """
    _prune(workdir, "binaries_")
    target = workdir / f"binaries_{uuid.uuid4().hex[:6]}"
    system32 = Path(os.getenv("SystemRoot", r"C:\Windows")) / "System32"
    return [[tools["robocopy"], str(system32), str(target),
             "shell32.dll", "kernel32.dll", "advapi32.dll", "ntdll.dll",
             "/NJH", "/NJS", "/NP", "/NFL", "/NDL"]]


def _base64_churn(workdir: Path, tools: dict) -> list[list[str]]:
    """`certutil -encode`: base64, written by a Windows binary.

    Included deliberately. base64 output sits at 6.0 bits/byte, under every
    entropy threshold in this system, so this is the benign case that looks
    least like an attack to the detector and most like one to a human reading
    the file. If it were ever to produce a suspension, that would be worth
    knowing.
    """
    _prune(workdir, "encoded_")
    source = _seed(workdir, count=4)
    first = next(source.glob("*.txt"))
    return [[tools["certutil"], "-encode", str(first),
             str(workdir / f"encoded_{uuid.uuid4().hex[:6]}.b64")]]


CORPUS = [
    Workload("sevenzip-archive", "7-Zip archives a folder of documents",
             _sevenzip, needs=("7z",)),
    Workload("tar-gzip", "tar + gzip a folder of documents", _tar_gzip,
             needs=("tar",)),
    Workload("makecab", "Windows' own compressor", _makecab, needs=("makecab",)),
    Workload("git-clone", "git clones a repository", _git_clone, needs=("git",)),
    Workload("git-gc", "git repacks a clone", _git_churn, needs=("git",)),
    Workload("venv-build", "a build writing thousands of files", _venv_build),
    Workload("npm-install", "npm installs a dependency", _npm_install,
             needs=("npm",), network=True),
    Workload("binary-copy", "robocopy copies system binaries in", _binary_copy,
             needs=("robocopy",)),
    Workload("base64", "certutil base64-encodes a document", _base64_churn,
             needs=("certutil",)),
]

#: Named in the build plan and not installed on this host. Listed by name so
#: the gap is in the artefact rather than in somebody's memory.
NOT_INSTALLED = {
    "ffmpeg-transcode": "ffmpeg is not installed on this host",
    "veracrypt-container": "VeraCrypt is not installed on this host",
    "visual-studio-build": "no Visual Studio or MSBuild on this host; "
                           "`venv-build` and `npm-install` stand in for the "
                           "file-churn shape, not for the compiler",
    "windows-update": "cannot be scheduled from a measurement script, and "
                      "forcing one on somebody's machine is not this script's "
                      "decision",
    "browser-cache-churn": "not driven here: it would mean automating the "
                           "user's browser, and the cache lives outside the "
                           "protected path anyway",
    "onedrive-sync": "OneDrive syncs its own folders, not the protected path; "
                     "pointing it at one would be a configuration change to "
                     "the machine",
}


def find_tools() -> dict[str, str | None]:
    system32 = Path(os.getenv("SystemRoot", r"C:\Windows")) / "System32"
    fixed = {
        "7z": [r"C:\Program Files\7-Zip\7z.exe",
               r"C:\Program Files (x86)\7-Zip\7z.exe"],
        "makecab": [str(system32 / "makecab.exe")],
        "robocopy": [str(system32 / "robocopy.exe")],
        "certutil": [str(system32 / "certutil.exe")],
    }
    found: dict[str, str | None] = {}
    for key, candidates in fixed.items():
        found[key] = next((c for c in candidates if Path(c).is_file()), None)
    for key in ("git", "tar", "npm"):
        located = shutil.which(key)
        if located is None and key == "npm":
            located = shutil.which("npm.cmd")
        found[key] = located
    return found


# --------------------------------------------------------------- the soak

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minutes", type=float, default=60.0,
                        help="how long to keep working (default 60)")
    parser.add_argument("--keep", action="store_true",
                        help="leave the working directory in place")
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args(argv)

    if platform.system() != "Windows":
        print("This needs Windows.", file=sys.stderr)
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
    state = subprocess.run(["sc.exe", "query", "URDSAgent"],
                           capture_output=True, text=True, check=False)
    if "RUNNING" not in state.stdout:
        print("URDSAgent is not RUNNING. A false-positive rate measured with "
              "the agent down is zero for the wrong reason.", file=sys.stderr)
        return 2

    tools = find_tools()
    workdir = protected / f"benign_soak_{uuid.uuid4().hex[:8]}"
    workdir.mkdir(parents=True, exist_ok=True)

    print("\nURDS Phase 5 - benign corpus")
    print("=" * 74)
    print(f"protected path : {protected}")
    print(f"working under  : {workdir}")
    print(f"duration       : {args.minutes:.0f} minutes")
    for key, path in sorted(tools.items()):
        print(f"  {key:<10} {path or '-- not installed --'}")

    runnable = [w for w in CORPUS if w.available(tools)]
    for workload in CORPUS:
        if workload not in runnable:
            workload.reason = (
                "needs " + ", ".join(n for n in workload.needs
                                     if not tools.get(n)) + ", not installed")
    print(f"\n{len(runnable)} of {len(CORPUS)} workloads can run here; "
          f"{len(NOT_INSTALLED)} named in the plan are absent entirely")

    # The answer key: every process this run starts, and this process, which
    # seeds the documents the tools work on.
    answer_key: dict[int, str] = {os.getpid(): sys.executable}

    before_tip = tip_id(ledger_db)
    started = time.monotonic()
    deadline = started + args.minutes * 60.0
    cycle = 0

    while time.monotonic() < deadline and runnable:
        cycle += 1
        for workload in runnable:
            if time.monotonic() >= deadline:
                break
            began = time.monotonic()
            try:
                commands = workload.build(workdir, tools)
            except Exception as exc:  # noqa: BLE001
                workload.failures += 1
                workload.reason = f"could not be prepared: {exc}"
                continue
            if not commands:
                continue
            for argv_ in commands:
                try:
                    child = subprocess.Popen(argv_, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.PIPE)
                except OSError as exc:
                    workload.failures += 1
                    workload.reason = f"could not start: {exc}"
                    continue
                answer_key[child.pid] = argv_[0]
                try:
                    _, err = child.communicate(timeout=300)
                except subprocess.TimeoutExpired:
                    child.kill()
                    workload.failures += 1
                    workload.reason = "took longer than 300s and was stopped"
                    continue
                # robocopy's success codes are 0-7; git gc warns on 1.
                ok = child.returncode == 0 or (
                    workload.key == "binary-copy" and child.returncode < 8)
                if ok:
                    workload.runs += 1
                else:
                    workload.failures += 1
                    workload.reason = (err or b"").decode("utf-8", "replace")[-200:]
            workload.seconds += time.monotonic() - began
        elapsed = (time.monotonic() - started) / 60.0
        print(f"  cycle {cycle:>3}  {elapsed:5.1f} min  "
              f"{sum(w.runs for w in runnable)} workloads completed")

    # Let anything the agent parked come to a decision before the tally.
    time.sleep(10.0)
    ran_for_s = time.monotonic() - started
    after_tip = tip_id(ledger_db)
    blocks = blocks_since(ledger_db, before_tip)

    ours = str(workdir).lower()
    flagged = [b for b in blocks
               if b["event_type"] == "file_event"
               and str(b["data"].get("file_path", "")).lower().startswith(ours)
               and b["data"].get("verdict") not in (None, "benign", "deleted")]
    escalations = [b for b in blocks if b["event_type"] == "response_escalation"]
    ours_suspended, others_suspended = [], []
    for block in escalations:
        pid = block["data"].get("process_id")
        entry = {"block": block["id"], "pid": pid,
                 "image": block["data"].get("process_image"),
                 "decision": block["data"].get("decision")}
        (ours_suspended if pid in answer_key else others_suspended).append(entry)

    hours = ran_for_s / 3600.0
    chain = verify_chain(ledger_db)
    report = {
        "_what_this_is": (
            "The false-positive rate: suspensions per hour of ordinary work "
            "done by third-party tools inside the agent's protected path."),
        "_what_this_does_not_show": (
            "A rate over the whole corpus the build plan names. Six of its "
            "members are not installable or not drivable on this host and are "
            "listed under `not_installed`; this is a lower bound on the rate, "
            "measured over what could actually be run."),
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "host": platform.platform(),
        "protected_path": str(protected),
        "ran_for_seconds": round(ran_for_s, 1),
        "ran_for_hours": round(hours, 4),
        "cycles": cycle,
        "tools": tools,
        "workloads": [
            {"key": w.key, "what": w.what, "available": w.available(tools),
             "runs": w.runs, "failures": w.failures,
             "seconds": round(w.seconds, 1), "note": w.reason}
            for w in CORPUS],
        "not_installed": NOT_INSTALLED,
        "answer_key_size": len(answer_key),
        "metrics": {
            "workload_runs": sum(w.runs for w in CORPUS),
            "workload_failures": sum(w.failures for w in CORPUS),
            "false_positive_suspensions": len(ours_suspended),
            "false_positives_per_hour": (round(len(ours_suspended) / hours, 3)
                                         if hours > 0 else None),
            "flagged_file_events": len(flagged),
            "flagged_events_per_hour": (round(len(flagged) / hours, 3)
                                        if hours > 0 else None),
            "suspensions_of_other_software": len(others_suspended),
            "ledger_blocks": after_tip - before_tip,
            "chain_valid": chain["valid"],
        },
        "false_positives": ours_suspended[:20],
        "suspensions_of_other_software": others_suspended[:20],
        "flagged_sample": [
            {"block": b["id"], "file": b["data"].get("file_path"),
             "verdict": b["data"].get("verdict"),
             "reason": b["data"].get("reason")}
            for b in flagged[:10]],
    }

    print("\n" + "=" * 74)
    for workload in CORPUS:
        mark = "ok  " if workload.available(tools) else "----"
        print(f"  {mark} {workload.key:<18} {workload.runs:>4} runs, "
              f"{workload.failures} failures  {workload.reason[:40]}")
    print(f"\n  ran for {ran_for_s / 60.0:.1f} minutes")
    print(f"  suspensions of this run's own processes : "
          f"{len(ours_suspended)}  "
          f"({report['metrics']['false_positives_per_hour']}/hour)")
    print(f"  flagged file events                     : {len(flagged)}")
    print(f"  suspensions of other software           : {len(others_suspended)}")

    if not args.keep:
        if _force_rmtree(workdir):
            print(f"  removed {workdir}")
        else:
            print(f"  COULD NOT REMOVE {workdir} - it is still inside the "
                  f"protected path and the next run will see it")

    if args.write_report or os.getenv("URDS_WRITE_REPORTS"):
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"  wrote {REPORT}")
    else:
        print("  report not written (pass --write-report)")

    if not any(w.runs for w in CORPUS):
        print("\n  no workload ran: this measured nothing.", file=sys.stderr)
        return 1
    return 0 if not ours_suspended else 1


if __name__ == "__main__":
    raise SystemExit(main())
