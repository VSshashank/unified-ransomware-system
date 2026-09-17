"""What the agent is allowed to watch, and what it is allowed to do about it.

Rule: the agent never acts outside the configured protected paths. That makes
this file the blast radius, which is why it validates rather than merely parses.
A protected root that is a drive root, or that contains the Windows directory,
is refused here and not later - "later" means after a suspend.

Resolution order:

1. ``$URDS_AGENT_CONFIG``, if set, which is what the Windows Service passes.
2. ``%ProgramData%\\URDS\\agent.json`` - where ``install.ps1`` writes it.
3. ``agent/agent.default.json`` in the checkout, for development.

Nothing is silently defaulted: if no file is found, loading raises and says
which three places it looked.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "agent" / "agent.default.json"


class ConfigError(ValueError):
    """The configuration is missing, malformed, or would be unsafe to act on."""


def _program_data() -> Path:
    return Path(os.getenv("ProgramData", r"C:\ProgramData")) / "URDS"


#: Directories no protected root may be, or contain. Watching any of these
#: would point the responder at the operating system.
def _forbidden_roots() -> list[Path]:
    candidates = [
        os.getenv("SystemRoot", r"C:\Windows"),
        os.getenv("ProgramFiles", r"C:\Program Files"),
        os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        "/usr", "/bin", "/sbin", "/etc", "/boot", "/lib",
    ]
    out = []
    for raw in candidates:
        if not raw:
            continue
        try:
            out.append(Path(raw).resolve())
        except OSError:
            continue
    return out


def _anchor(raw: str) -> Path:
    """Expand a configured path, anchoring a relative one to the checkout.

    A Windows Service has no meaningful working directory - it starts in
    ``%SystemRoot%\\system32`` - so a relative path in the configuration must
    not resolve against the CWD. It resolves against the repository, which is
    the only stable referent a checked-in development config can have.
    """
    expanded = Path(os.path.expandvars(raw)).expanduser()
    return expanded if expanded.is_absolute() else (ROOT / expanded)


@dataclass(frozen=True)
class Config:
    """The agent's whole surface area, in one object."""

    protected_paths: tuple[Path, ...]
    data_dir: Path

    #: Process images that may write to a canary without being suspended.
    #: Explicit and empty by default: an allowlist that ships with entries is
    #: an allowlist nobody has read.
    allowlist_images: tuple[str, ...] = ()

    #: Sliding window for the velocity signals, in seconds.
    velocity_window_s: float = 10.0
    #: Distinct paths written by one PID inside the window before it counts as
    #: a velocity signal.
    velocity_path_threshold: int = 12
    #: Directories touched by one PID inside the window before fan-out counts.
    velocity_fanout_threshold: int = 3

    #: Canary decoys seeded per protected root.
    canaries_per_root: int = 20

    #: How long to wait for attribution to name a writer, in milliseconds.
    attribution_timeout_ms: float = 750.0

    source: Path | None = None

    @property
    def ledger_db(self) -> Path:
        return self.data_dir / "ledger.db"

    @property
    def snapshot_root(self) -> Path:
        return self.data_dir / "snapshots"

    def protects(self, path: str | Path) -> bool:
        """Is this path inside a protected root? The only gate on any action."""
        try:
            candidate = Path(path).resolve()
        except (OSError, ValueError):
            return False
        for root in self.protected_paths:
            try:
                candidate.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def as_dict(self) -> dict:
        return {
            "protected_paths": [str(p) for p in self.protected_paths],
            "data_dir": str(self.data_dir),
            "ledger_db": str(self.ledger_db),
            "snapshot_root": str(self.snapshot_root),
            "allowlist_images": list(self.allowlist_images),
            "velocity_window_s": self.velocity_window_s,
            "velocity_path_threshold": self.velocity_path_threshold,
            "velocity_fanout_threshold": self.velocity_fanout_threshold,
            "canaries_per_root": self.canaries_per_root,
            "attribution_timeout_ms": self.attribution_timeout_ms,
            "source": str(self.source) if self.source else None,
        }


def candidate_paths() -> list[Path]:
    explicit = os.getenv("URDS_AGENT_CONFIG")
    found = [Path(explicit)] if explicit else []
    found.append(_program_data() / "agent.json")
    found.append(DEFAULT_CONFIG)
    return found


def load(path: Path | None = None) -> Config:
    """Read, validate, and refuse anything whose blast radius is wrong."""
    if path is not None:
        sources = [Path(path)]
    else:
        sources = candidate_paths()

    chosen = next((p for p in sources if p.is_file()), None)
    if chosen is None:
        raise ConfigError(
            "no agent configuration found. Looked at: "
            + ", ".join(str(p) for p in sources)
        )

    try:
        raw = json.loads(chosen.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{chosen} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{chosen}: top level must be an object")

    return from_mapping(raw, source=chosen)


def from_mapping(raw: dict, source: Path | None = None) -> Config:
    """Build and validate a Config from an already-parsed mapping."""
    declared = raw.get("protected_paths")
    if not isinstance(declared, list) or not declared:
        raise ConfigError(
            "protected_paths must be a non-empty list. An agent with no "
            "protected roots watches nothing; it does not watch everything."
        )

    forbidden = _forbidden_roots()
    resolved: list[Path] = []
    for entry in declared:
        if not isinstance(entry, str) or not entry.strip():
            raise ConfigError(f"protected_paths entry is not a path: {entry!r}")
        candidate = _anchor(entry)
        try:
            candidate = candidate.resolve()
        except OSError as exc:
            raise ConfigError(f"cannot resolve protected path {entry!r}: {exc}") from exc

        if candidate.parent == candidate:
            raise ConfigError(
                f"refusing to protect {candidate}: it is a filesystem root. "
                f"Every write on the volume would be in scope, including the "
                f"operating system's."
            )
        for bad in forbidden:
            if candidate == bad or bad.is_relative_to(candidate) or candidate.is_relative_to(bad):
                raise ConfigError(
                    f"refusing to protect {candidate}: it overlaps {bad}. "
                    f"The responder suspends processes that write inside a "
                    f"protected root, and that must never be able to mean a "
                    f"system directory."
                )
        resolved.append(candidate)

    data_dir_raw = raw.get("data_dir")
    if not isinstance(data_dir_raw, str) or not data_dir_raw.strip():
        raise ConfigError("data_dir must be a path")
    data_dir = _anchor(data_dir_raw)

    allowlist = tuple(raw.get("allowlist_images") or ())
    if not all(isinstance(item, str) for item in allowlist):
        raise ConfigError("allowlist_images must be a list of strings")

    def number(key: str, default: float) -> float:
        value = raw.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{key} must be a number, got {value!r}")
        if value <= 0:
            raise ConfigError(f"{key} must be positive, got {value!r}")
        return value

    return Config(
        protected_paths=tuple(resolved),
        data_dir=data_dir,
        allowlist_images=allowlist,
        velocity_window_s=float(number("velocity_window_s", 10.0)),
        velocity_path_threshold=int(number("velocity_path_threshold", 12)),
        velocity_fanout_threshold=int(number("velocity_fanout_threshold", 3)),
        canaries_per_root=int(number("canaries_per_root", 20)),
        attribution_timeout_ms=float(number("attribution_timeout_ms", 750.0)),
        source=source,
    )
