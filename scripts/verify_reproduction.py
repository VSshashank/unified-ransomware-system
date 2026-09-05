"""The Week 32 exit gate, run rather than inspected (P8.4).

> "An independent reader can reproduce every headline figure from the repository
> and the appendix alone. Verify this by actually re-running the appendix
> commands from a clean checkout, not by inspection."

So this script *is* the verification. It clones the repository into a scratch
directory, builds a fresh virtual environment, installs each service's declared
requirements, and then runs the commands `docs/REPRODUCIBILITY_APPENDIX.md`
gives a reader - in the order the appendix gives them - checking each result
against the committed artefact manifest.

What it checks, in five stages:

1. **Clean checkout.** `git clone` of the working repository at `HEAD`. Only
   committed content survives, so anything the appendix depends on that is not
   committed fails here rather than on the reader's machine.
2. **Dependencies.** A fresh venv and `pip install -r` for each service. A
   dependency a service forgot to declare fails here.
3. **The corpus.** Rebuilt from its recorded seed and verified file by file
   against the committed manifest. The benign figures mean nothing if the corpus
   is not the corpus.
4. **The artefacts.** Every deterministic generator is re-run and its stable
   digest compared against `reports/artefact_manifest.json`. A digest that moved
   means a result moved.
5. **The suite.** All five service suites, from the clean checkout.

Anything that cannot be reproduced is recorded as not reproduced. The script
does not fail quietly and does not skip a stage to keep a later one green.

Usage:

    python scripts/verify_reproduction.py                 # full run
    python scripts/verify_reproduction.py --skip-install  # reuse an existing venv
    python scripts/verify_reproduction.py --keep          # leave the clone behind

Writes reports/reproduction_check.json only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
OUT = REPORTS / "reproduction_check.json"

# The dashboard is not in the CI matrix and no appendix command touches it, so
# its streamlit/pandas stack is not installed. Stated rather than silently
# omitted.
SERVICES = ("gateway", "ledger", "monitor", "ml-engine", "response")

# The generators the appendix asks a reader to run, in order. Each must finish
# before the next: benign_tradeoff reads three_arm_experiment's report, and
# admission_recompute reads capability_calibration's.
GENERATORS = (
    ("scripts/capability_calibration.py", []),
    ("scripts/admission_recompute.py", []),
    ("scripts/three_arm_experiment.py", []),
    ("scripts/benign_tradeoff.py", []),
    ("scripts/ledger_coverage.py", []),
    ("scripts/pipeline_governance.py", []),
    ("scripts/tamper_sweep.py", []),
    ("scripts/failure_injection.py", []),
    ("scripts/simulator_sweep.py", []),
)


def scratch_root() -> Path:
    base = os.getenv("URDS_SCRATCH") or os.getenv("TEMP") or "/tmp"
    return Path(base) / "urds_reproduction"


def run(command: list[str], cwd: Path, env: dict | None = None,
        timeout: int = 1800) -> dict:
    started = time.perf_counter()
    try:
        done = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout, env=env)
        stdout, stderr, code = done.stdout, done.stderr, done.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, code = "", f"timed out after {timeout}s", 124
    except OSError as exc:
        stdout, stderr, code = "", str(exc), 127
    tail = [line for line in (stdout or "").strip().splitlines() if line.strip()]
    return {
        "command": " ".join(command),
        "returncode": code,
        "ok": code == 0,
        "seconds": round(time.perf_counter() - started, 2),
        "last_line": tail[-1] if tail else "",
        "stderr_tail": (stderr or "").strip().splitlines()[-4:],
    }


# --------------------------------------------------------------------------

def stage_clone(target: Path) -> dict:
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    result = run(["git", "clone", "--quiet", str(ROOT), str(target)],
                 cwd=ROOT, timeout=600)
    result["stage"] = "clean checkout"
    if result["ok"]:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target,
                              capture_output=True, text=True).stdout.strip()
        result["cloned_commit"] = head
        result["tracked_files"] = len(subprocess.run(
            ["git", "ls-files"], cwd=target, capture_output=True,
            text=True).stdout.split())
    return result


def stage_venv(target: Path, skip: bool) -> tuple[Path, list[dict]]:
    venv = target / ".venv"
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    steps: list[dict] = []

    if skip and python.is_file():
        steps.append({"stage": "dependencies", "command": "(reused existing venv)",
                      "ok": True, "returncode": 0, "seconds": 0.0,
                      "last_line": str(python), "stderr_tail": []})
        return python, steps

    step = run([sys.executable, "-m", "venv", str(venv)], cwd=target, timeout=600)
    step["stage"] = "dependencies"
    steps.append(step)
    if not step["ok"]:
        return python, steps

    for service in SERVICES:
        req = target / "services" / service / "requirements.txt"
        step = run([str(python), "-m", "pip", "install", "--quiet",
                    "--disable-pip-version-check", "-r", str(req)],
                   cwd=target, timeout=1800)
        step["stage"] = f"dependencies: {service}"
        steps.append(step)

    # The measurement scripts' own dependencies. This file exists because the
    # first run of this script failed here: Pillow was installed on the author's
    # machine and declared nowhere, so the corpus rebuild - and every benign
    # figure downstream of it - could not be reproduced by anyone else.
    step = run([str(python), "-m", "pip", "install", "--quiet",
                "--disable-pip-version-check",
                "-r", str(target / "scripts" / "requirements.txt")],
               cwd=target, timeout=900)
    step["stage"] = "dependencies: measurement scripts"
    steps.append(step)

    # Test-only, declared by no service's requirements.txt because no service
    # imports them at runtime. The CI matrix installs the same three.
    step = run([str(python), "-m", "pip", "install", "--quiet",
                "--disable-pip-version-check",
                "pytest", "pytest-asyncio", "httpx", "psutil"],
               cwd=target, timeout=900)
    step["stage"] = "dependencies: test-only"
    steps.append(step)
    return python, steps


def stage_corpus(target: Path, python: Path, env: dict) -> list[dict]:
    steps = []
    step = run([str(python), "scripts/build_benign_corpus.py"], cwd=target, env=env)
    step["stage"] = "corpus: rebuild from seed"
    steps.append(step)
    step = run([str(python), "scripts/build_benign_corpus.py", "--verify"],
               cwd=target, env=env)
    step["stage"] = "corpus: verify every file hash"
    steps.append(step)
    return steps


def stage_artefacts(target: Path, python: Path, env: dict) -> list[dict]:
    steps = []
    for script, extra in GENERATORS:
        step = run([str(python), script, *extra], cwd=target, env=env)
        step["stage"] = f"regenerate: {Path(script).name}"
        steps.append(step)
    step = run([str(python), "scripts/artefact_manifest.py", "--verify"],
               cwd=target, env=env)
    step["stage"] = "compare every stable digest"
    steps.append(step)
    step = run([str(python), "scripts/claim_matrix.py"], cwd=target, env=env)
    step["stage"] = "re-check every claim"
    steps.append(step)
    return steps


def stage_suite(target: Path, python: Path, env: dict) -> list[dict]:
    steps = []
    for service in SERVICES:
        step = run([str(python), "-m", "pytest", "-q", "--no-header"],
                   cwd=target / "services" / service, env=env, timeout=1800)
        step["stage"] = f"suite: {service}"
        steps.append(step)
    return steps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-install", action="store_true",
                        help="reuse the clone's venv if it already exists")
    parser.add_argument("--keep", action="store_true",
                        help="leave the clone in place for inspection")
    parser.add_argument("--stage", choices=("clone", "deps", "corpus",
                                            "artefacts", "suite"),
                        help="run up to this stage and stop")
    args = parser.parse_args()

    target = scratch_root() / "clone"
    stages: list[dict] = []
    order = ("clone", "deps", "corpus", "artefacts", "suite")
    stop_at = order.index(args.stage) if args.stage else len(order) - 1

    print(f"clean checkout -> {target}")
    clone = stage_clone(target)
    stages.append(clone)
    print(f"  {'ok' if clone['ok'] else 'FAILED':6s} clone "
          f"({clone.get('tracked_files', '?')} tracked files, {clone['seconds']}s)")
    if not clone["ok"] or stop_at < 1:
        return report(stages, target, args.keep)

    python, dep_steps = stage_venv(target, args.skip_install)
    stages.extend(dep_steps)
    for step in dep_steps:
        print(f"  {'ok' if step['ok'] else 'FAILED':6s} {step['stage']} "
              f"({step['seconds']}s)")
    if not all(step["ok"] for step in dep_steps) or stop_at < 2:
        return report(stages, target, args.keep)

    env = dict(os.environ, URDS_WRITE_REPORTS="1", PYTHONIOENCODING="utf-8")

    for index, stage_fn in ((2, stage_corpus), (3, stage_artefacts), (4, stage_suite)):
        if stop_at < index:
            break
        steps = stage_fn(target, python, env)
        stages.extend(steps)
        for step in steps:
            print(f"  {'ok' if step['ok'] else 'FAILED':6s} {step['stage']:44s} "
                  f"{step['last_line'][:44]}")

    return report(stages, target, args.keep)


def report(stages: list[dict], target: Path, keep: bool) -> int:
    failed = [s for s in stages if not s["ok"]]
    payload = {
        "schema": "urds.reproduction_check.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
            text=True).stdout.strip(),
        "clone_path": str(target),
        "gate": ("NOVELTY_PROOF_PLAN.md §9, Week 32: an independent reader can "
                 "reproduce every headline figure from the repository and the "
                 "appendix alone, verified by re-running the appendix commands "
                 "from a clean checkout"),
        "services_installed": list(SERVICES),
        "services_not_installed": ["dashboard"],
        "why_dashboard_is_excluded": (
            "It is not in the CI matrix and no appendix command touches it. Its "
            "streamlit and pandas stack would be installed for nothing."),
        "stages": stages,
        "summary": {
            "stages_run": len(stages),
            "failed": len(failed),
            "failed_stages": [s["stage"] for s in failed],
            "total_seconds": round(sum(s["seconds"] for s in stages), 1),
        },
    }

    print("-" * 96)
    print(f"{len(stages)} stages, {len(failed)} failed, "
          f"{payload['summary']['total_seconds']}s total")
    if failed:
        for step in failed:
            print(f"  FAILED {step['stage']}: {step['last_line'] or step['stderr_tail']}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() in {"1", "true", "yes"}:
        REPORTS.mkdir(parents=True, exist_ok=True)
        with open(OUT, "w", encoding="utf-8", newline="") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        print(f"wrote {OUT}")
    else:
        print("URDS_WRITE_REPORTS is not set: report not written")

    if not keep:
        print(f"(clone left at {target}; pass --keep to keep it after a rerun)")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
