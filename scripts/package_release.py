"""The packaged deployment, and the checks that make it one (P8.3).

A "packaged deployment" that is a zip of the working directory is a backup, not
a package. What makes it a package is that it is complete, that it carries no
secret, and that something checked both rather than asserting them.

So this script does three things, in order:

1. **Audits the deployment** against `docker-compose.yml`. Every build context
   must exist and contain a Dockerfile; every service must declare its
   requirements; every `${VAR}` the compose file interpolates must either carry
   an inline default or appear in `.env.example`, so an operator cannot start
   the stack with a variable nobody told them about. Every published port is
   listed with its bind address, because the difference between `127.0.0.1:8003`
   and `0.0.0.0:8003` is the difference between a loopback service and an
   unauthenticated audit-log endpoint on the LAN.
2. **Refuses to package a secret.** `.env` is excluded by name and the packager
   fails if it is ever tracked by git. A committed `JWT_SECRET` is a forged
   token for anyone holding the archive.
3. **Writes the archive and a manifest.** Every file in the package is hashed,
   so a reader can tell whether the archive they received is the archive that
   was built.

The audit runs whether or not an archive is written, so it is usable as a
pre-flight check on its own:

    python scripts/package_release.py --audit-only
    URDS_WRITE_REPORTS=1 python scripts/package_release.py

Exit status is 1 if the audit fails. Writes `dist/urds-<commit>.zip` and
`reports/release_package.json` only when URDS_WRITE_REPORTS=1.

**What this does not do.** It does not build the images and it does not start
the stack: that needs a Docker daemon, and no recorded run had one. The package
is verified to be *complete and consistent*, not verified to *run*. That
distinction is the whole reason this file says so out loud - see
`docs/PHASE8_COMPLETION_REPORT.md` for what remains unverified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
DIST = ROOT / "dist"
OUT = REPORTS / "release_package.json"

SERVICES = ("monitor", "ml-engine", "ledger", "response", "gateway", "dashboard")

# What a deployment needs. Reports and docs are included because the package is
# also the thesis's evidence bundle; the corpus is not, because it rebuilds from
# a seed and shipping 275 generated files would be shipping the seed twice.
INCLUDE = (
    "docker-compose.yml",
    ".env.example",
    "README.md",
    "PROJECT_IMPLEMENTATION_RECORD.md",
    "services/",
    "scripts/",
    "docs/",
    "reports/",
)

# Never packaged, whatever a glob says.
EXCLUDE_NAMES = frozenset({".env"})
EXCLUDE_PARTS = (
    "__pycache__", ".pytest_cache", ".venv", "node_modules", ".git",
    "corpus", "models", "data", "logs", "watched_files", "dist",
)
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".log", ".db", ".pkl")

VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:-[^}]*)?\}")
PORT = re.compile(r'^\s*-\s*"?([0-9.]+:)?(\d+):(\d+)"?\s*$')


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

def audit() -> dict:
    findings: list[dict] = []
    compose_path = ROOT / "docker-compose.yml"

    def fail(check: str, detail: str) -> None:
        findings.append({"check": check, "status": "FAIL", "detail": detail})

    def ok(check: str, detail: str) -> None:
        findings.append({"check": check, "status": "ok", "detail": detail})

    if not compose_path.is_file():
        fail("compose file present", "docker-compose.yml is missing")
        return {"findings": findings, "failed": 1, "services": {}, "ports": [],
                "variables": {}}
    compose = compose_path.read_text(encoding="utf-8")
    ok("compose file present", f"{len(compose.splitlines())} lines")

    # --- every service has a build context, a Dockerfile and requirements
    services: dict[str, dict] = {}
    for service in SERVICES:
        directory = ROOT / "services" / service
        dockerfile = directory / "Dockerfile"
        requirements = directory / "requirements.txt"
        row = {
            "directory": directory.is_dir(),
            "dockerfile": dockerfile.is_file(),
            "requirements": requirements.is_file(),
            "referenced_by_compose": f"./services/{service}" in compose,
        }
        services[service] = row
        missing = [name for name, present in row.items() if not present]
        if missing:
            fail(f"service {service}", f"missing: {', '.join(missing)}")
        else:
            ok(f"service {service}", "context, Dockerfile, requirements, compose entry")

    # --- every interpolated variable is either defaulted or documented
    example = (ROOT / ".env.example")
    documented = set()
    if example.is_file():
        for line in example.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                documented.add(line.split("=", 1)[0].strip())
        ok(".env.example present", f"{len(documented)} variables documented")
    else:
        fail(".env.example present", "an operator has nothing to copy")

    variables: dict[str, dict] = {}
    undocumented = []
    for match in VAR.finditer(compose):
        name, default = match.group(1), match.group(2)
        entry = variables.setdefault(name, {"has_inline_default": False,
                                            "in_env_example": name in documented})
        if default is not None:
            entry["has_inline_default"] = True
            entry["default"] = default[2:]
    for name, entry in sorted(variables.items()):
        if not entry["has_inline_default"] and not entry["in_env_example"]:
            undocumented.append(name)
    if undocumented:
        fail("every compose variable is defaulted or documented",
             f"neither: {', '.join(undocumented)}")
    else:
        ok("every compose variable is defaulted or documented",
           f"{len(variables)} variables, all covered")

    # --- no secret in the package
    tracked_env = [p for p in git("ls-files").split("\n") if p.strip() == ".env"]
    if tracked_env:
        fail("no secret is packaged",
             ".env is tracked by git - a committed JWT_SECRET forges tokens")
    else:
        ok("no secret is packaged", ".env untracked and excluded by name")

    # --- port exposure, reported rather than judged
    ports = []
    for line in compose.splitlines():
        match = PORT.match(line)
        if match:
            bind = (match.group(1) or "0.0.0.0:").rstrip(":")
            ports.append({"bind": bind, "host": int(match.group(2)),
                          "container": int(match.group(3)),
                          "loopback_only": bind.startswith("127.")})
    public = [p for p in ports if not p["loopback_only"]]
    ok("published ports",
       f"{len(ports)} published, {len(public)} reachable off-host "
       f"({', '.join(str(p['host']) for p in public) or 'none'})")

    return {
        "findings": findings,
        "failed": sum(1 for f in findings if f["status"] == "FAIL"),
        "services": services,
        "ports": ports,
        "variables": variables,
    }


# --------------------------------------------------------------------------
# Packaging
# --------------------------------------------------------------------------

def wanted(path: Path) -> bool:
    if path.name in EXCLUDE_NAMES:
        return False
    if path.suffix in EXCLUDE_SUFFIXES:
        return False
    parts = set(path.relative_to(ROOT).parts)
    return not (parts & set(EXCLUDE_PARTS))


def collect() -> list[Path]:
    files: list[Path] = []
    for entry in INCLUDE:
        target = ROOT / entry.rstrip("/")
        if target.is_file():
            if wanted(target):
                files.append(target)
        elif target.is_dir():
            for candidate in sorted(target.rglob("*")):
                if candidate.is_file() and wanted(candidate):
                    files.append(candidate)
    return files


def build_archive(files: list[Path], commit: str) -> tuple[Path, list[dict]]:
    DIST.mkdir(parents=True, exist_ok=True)
    archive = DIST / f"urds-{commit[:12]}.zip"
    manifest: list[dict] = []
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in files:
            rel = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            bundle.writestr(rel, data)
            manifest.append({"path": rel, "bytes": len(data),
                             "sha256": hashlib.sha256(data).hexdigest()})
    return archive, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-only", action="store_true",
                        help="run the deployment audit and write no archive")
    args = parser.parse_args()

    result = audit()
    print(f"{'status':7s} check")
    print("-" * 84)
    for finding in result["findings"]:
        print(f"{finding['status']:7s} {finding['check']:44s} {finding['detail'][:32]}")
    print("-" * 84)
    print(f"{len(result['findings'])} checks, {result['failed']} failed")

    if result["failed"]:
        print("\nthe deployment audit failed: not packaging")
        return 1

    if args.audit_only:
        return 0

    commit = git("rev-parse", "HEAD").strip() or "unknown"
    files = collect()
    total = sum(p.stat().st_size for p in files)
    print(f"\n{len(files)} files, {total / 1_048_576:.1f} MiB before compression")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("URDS_WRITE_REPORTS is not set: no archive and no report written")
        return 0

    archive, manifest = build_archive(files, commit)
    print(f"wrote {archive} ({archive.stat().st_size / 1_048_576:.1f} MiB)")

    payload = {
        "schema": "urds.release_package.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "branch": git("rev-parse", "--abbrev-ref", "HEAD").strip(),
        "archive": archive.name,
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "file_count": len(manifest),
        "audit": result,
        "excluded": {
            "names": sorted(EXCLUDE_NAMES),
            "directories": sorted(EXCLUDE_PARTS),
            "suffixes": sorted(EXCLUDE_SUFFIXES),
            "why": {
                ".env": "carries JWT_SECRET; a committed secret forges tokens",
                "corpus": "rebuilds byte-identically from seed 20260902",
                "models": "trained artefacts derived from EMBER, not "
                          "redistributable through this repository",
                "data/logs/watched_files": "runtime state, not deployment input",
            },
        },
        "what_this_does_not_show": [
            "The images were not built and the stack was not started: that "
            "needs a Docker daemon and no recorded run had one. The package is "
            "verified complete and internally consistent, not verified to run.",
            "The audit reads docker-compose.yml as text. It checks that every "
            "interpolated variable is defaulted or documented and that every "
            "build context exists; it does not validate the compose schema.",
            "Published ports are reported, not judged. Two are reachable "
            "off-host by design - the gateway, which authenticates, and the "
            "dashboard.",
        ],
        "files": manifest,
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
