"""Process termination and network isolation - AS's slice of the Response service.

Two things happen here, and they have very different risk profiles.

**Termination** is real and unconditional: a ransomware process that is still
running is still encrypting, so `/response/terminate` sends SIGTERM, waits, then
SIGKILLs. The guards below exist because a wrong PID here is destructive - PID 1,
this service's own process tree, and core OS processes are refused outright.

**Isolation** is real but opt-in. Writing firewall rules is a foot-gun: applied
to the wrong host it locks an operator out of the machine they are defending.
So the rules are built and reported always, and only applied when
`RESPONSE_ISOLATION_ENABLED` is explicitly set. The response says which of the
two happened rather than claiming a block that never landed - the same posture
VSSManager takes on a host that cannot do shadow copies.
"""

import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter

import psutil

logger = logging.getLogger(__name__)

# SIGTERM first, then SIGKILL. The whole budget has to fit the <2s target.
TERM_GRACE_SECONDS = float(os.getenv("TERMINATE_GRACE_SECONDS", "1.0"))
KILL_GRACE_SECONDS = float(os.getenv("KILL_GRACE_SECONDS", "0.5"))

ISOLATION_ENABLED = os.getenv("RESPONSE_ISOLATION_ENABLED", "false").lower() in {"true", "1", "yes"}

# Killing any of these takes the host or the container down with it.
PROTECTED_NAMES = frozenset(
    {
        "init", "systemd", "launchd", "kernel_task", "kthreadd",
        "dockerd", "containerd", "docker", "sshd", "logind", "systemd-journald",
        "windowserver", "loginwindow", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "smss.exe", "winlogon.exe",
    }
)

#: Directories whose contents are never terminated, whatever the process is
#: called. See `_guard_image_path`: a name denylist covers only what someone
#: remembered to list, and attribution can hand this service any PID on the
#: host. `%SystemRoot%` is read from the environment because it is not always
#: `C:\Windows`, and the literal is kept alongside it for the case where the
#: variable is unset or the lookup happens inside a container.
PROTECTED_IMAGE_ROOTS = tuple(
    p
    for p in (
        os.environ.get("SystemRoot"),
        r"C:\Windows",
        "/usr/sbin",
        "/sbin",
        "/usr/lib/systemd",
    )
    if p
)


class TerminationError(RuntimeError):
    """The process could not be terminated, with a reason worth reporting."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ------------------------------------------------------------------ termination


def _self_and_ancestors() -> set[int]:
    """This process and everything it descends from.

    Killing any of these kills the responder mid-response. Descendants are
    deliberately *not* protected: a process this service happens to sit above
    in the tree can still be the one encrypting files, and refusing those would
    block legitimate kills.
    """
    pids = {os.getpid(), os.getppid()}
    try:
        pids.update(parent.pid for parent in psutil.Process().parents())
    except psutil.Error:
        pass
    return pids


def guard(pid: int) -> None:
    """Refuse the PIDs that must never be killed. Raises TerminationError."""
    if pid <= 1:
        raise TerminationError(f"PID {pid} is reserved (0 = kernel, 1 = init); refusing to terminate")

    if pid in _self_and_ancestors():
        raise TerminationError(
            f"PID {pid} is the response service itself or one of its ancestors; refusing to terminate"
        )

    try:
        process = psutil.Process(pid)
        name = process.name().lower()
    except psutil.NoSuchProcess as exc:
        raise TerminationError(f"PID {pid} does not exist") from exc
    except psutil.AccessDenied as exc:
        raise TerminationError(f"PID {pid} is not inspectable by this user") from exc

    if name in PROTECTED_NAMES:
        raise TerminationError(f"PID {pid} is a protected system process ({name}); refusing to terminate")

    _guard_image_path(pid, process, name)


def _guard_image_path(pid: int, process, name: str) -> None:
    """Refuse anything running out of a system directory.

    `PROTECTED_NAMES` is a denylist of the processes whose death takes the host
    with it, and a denylist only covers what someone thought to add. Once a PID
    can arrive from attribution rather than from an operator typing it, the
    blast radius of one wrong answer is any process on the machine - so the
    location of the executable is checked as well as its name.

    A process whose image path cannot be read is *not* refused on that basis:
    on Windows that is the normal result for a process owned by another user,
    and refusing it would make this guard reject most of what it exists to
    allow. The name check above still applies to those.
    """
    try:
        image = process.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return
    if not image:
        return

    resolved = os.path.normcase(os.path.abspath(image))
    for protected in PROTECTED_IMAGE_ROOTS:
        root = os.path.normcase(os.path.abspath(protected))
        if resolved == root or resolved.startswith(root + os.sep):
            raise TerminationError(
                f"PID {pid} ({name}) runs from a protected system location ({image}); "
                "refusing to terminate"
            )


def terminate_process(pid: int, force: bool = True) -> dict:
    """SIGTERM, wait, then SIGKILL if `force`. Target: under 2 seconds."""
    started = perf_counter()
    guard(pid)

    process = psutil.Process(pid)
    name = process.name()
    method = "sigterm"

    try:
        process.terminate()
        try:
            exit_code = process.wait(timeout=TERM_GRACE_SECONDS)
        except psutil.TimeoutExpired:
            if not force:
                raise TerminationError(
                    f"PID {pid} ({name}) ignored SIGTERM after {TERM_GRACE_SECONDS}s and force was not set"
                )
            process.kill()
            method = "sigkill"
            try:
                exit_code = process.wait(timeout=KILL_GRACE_SECONDS)
            except psutil.TimeoutExpired as exc:
                raise TerminationError(f"PID {pid} ({name}) survived SIGKILL") from exc
    except psutil.NoSuchProcess:
        # Died between the guard and the signal. The goal was "not running".
        exit_code = 0
        method = "already_exited"
    except psutil.AccessDenied as exc:
        raise TerminationError(f"Not permitted to terminate PID {pid} ({name})") from exc

    elapsed_ms = round((perf_counter() - started) * 1000, 2)
    logger.info("terminated pid=%s name=%s via=%s in %sms", pid, name, method, elapsed_ms)

    return {
        "status": "terminated",
        "process_id": pid,
        "process_name": name,
        "method": method,
        "exit_code": exit_code if exit_code is not None else 0,
        "termination_time_ms": elapsed_ms,
        "timestamp": utc_now(),
    }


# -------------------------------------------------------------------- isolation


@dataclass
class IsolationPlan:
    backend: str
    supported: bool
    reason: str
    commands: list[list[str]] = field(default_factory=list)


def _linux_plan(level: str, allow_localhost: bool) -> IsolationPlan:
    if not shutil.which("iptables"):
        return IsolationPlan("iptables", False, "iptables is not installed in this image")

    commands: list[list[str]] = []
    if allow_localhost:
        commands.append(["iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"])
        commands.append(["iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"])
    if level == "full":
        commands.append(["iptables", "-A", "OUTPUT", "-j", "DROP"])
        commands.append(["iptables", "-A", "INPUT", "-j", "DROP"])
    else:  # partial: cut egress, leave management access in
        commands.append(["iptables", "-A", "OUTPUT", "-j", "DROP"])
    return IsolationPlan("iptables", True, "iptables available", commands)


def _macos_plan(level: str, allow_localhost: bool) -> IsolationPlan:
    if not shutil.which("pfctl"):
        return IsolationPlan("pfctl", False, "pfctl is not available on this host")
    rules = "block drop out all\n" + ("block drop in all\n" if level == "full" else "")
    if allow_localhost:
        rules = "pass on lo0 all\n" + rules
    return IsolationPlan("pfctl", True, "pfctl available", [["pfctl", "-f", "-"], ["#rules", rules]])


def _windows_plan(level: str, allow_localhost: bool) -> IsolationPlan:
    if not shutil.which("netsh"):
        return IsolationPlan("netsh", False, "netsh is not available on this host")
    commands = [["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockoutbound,blockinbound"]]
    if level != "full":
        commands = [["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "allowinbound,blockoutbound"]]
    return IsolationPlan("netsh", True, "netsh available", commands)


def build_plan(level: str = "full", allow_localhost: bool = True) -> IsolationPlan:
    system = platform.system()
    if system == "Linux":
        return _linux_plan(level, allow_localhost)
    if system == "Darwin":
        return _macos_plan(level, allow_localhost)
    if system == "Windows":
        return _windows_plan(level, allow_localhost)
    return IsolationPlan("none", False, f"No isolation backend for platform '{system}'")


def isolate_host(level: str = "full", duration_seconds: int = 300, allow_localhost: bool = True) -> dict:
    """Apply (or plan) network isolation.

    Returns `enforced: False` with the exact rule set when isolation is not
    switched on, rather than reporting a block that did not happen.
    """
    started = perf_counter()
    plan = build_plan(level, allow_localhost)
    rendered = [" ".join(c) for c in plan.commands]

    if not ISOLATION_ENABLED:
        return {
            "status": "simulated",
            "enforced": False,
            "isolation_level": level,
            "duration_seconds": duration_seconds,
            "backend": plan.backend,
            "backend_supported": plan.supported,
            "reason": "RESPONSE_ISOLATION_ENABLED is not set; rules were planned but not applied",
            "planned_rules": rendered,
            "isolation_time_ms": round((perf_counter() - started) * 1000, 2),
            "timestamp": utc_now(),
        }

    if not plan.supported:
        return {
            "status": "unsupported",
            "enforced": False,
            "isolation_level": level,
            "duration_seconds": duration_seconds,
            "backend": plan.backend,
            "backend_supported": False,
            "reason": plan.reason,
            "planned_rules": rendered,
            "isolation_time_ms": round((perf_counter() - started) * 1000, 2),
            "timestamp": utc_now(),
        }

    applied: list[str] = []
    for command in plan.commands:
        if command[0] == "#rules":
            continue
        try:
            subprocess.run(command, check=True, capture_output=True, timeout=5)
            applied.append(" ".join(command))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            logger.error("isolation rule failed: %s (%s)", command, exc)
            return {
                "status": "failed",
                "enforced": False,
                "isolation_level": level,
                "duration_seconds": duration_seconds,
                "backend": plan.backend,
                "backend_supported": True,
                "reason": f"rule '{' '.join(command)}' failed: {exc}",
                "planned_rules": rendered,
                "applied_rules": applied,
                "isolation_time_ms": round((perf_counter() - started) * 1000, 2),
                "timestamp": utc_now(),
            }

    return {
        "status": "isolated",
        "enforced": True,
        "isolation_level": level,
        "duration_seconds": duration_seconds,
        "backend": plan.backend,
        "backend_supported": True,
        "reason": f"{len(applied)} rule(s) applied via {plan.backend}",
        "planned_rules": rendered,
        "applied_rules": applied,
        "isolation_time_ms": round((perf_counter() - started) * 1000, 2),
        "timestamp": utc_now(),
    }
