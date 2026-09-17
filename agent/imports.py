"""Load the services' modules without copying them, and prove which file loaded.

The five services use flat module names that match their container layout, so
`services/gateway`, `services/ledger`, `services/ml-engine`, `services/monitor`
and `services/response` each have an `app.py`, two have a `main.py`, and two
have a `models.py`. Putting several service directories on `sys.path` and
importing by bare name is therefore ambiguous in general: whichever directory
reached the path first wins, silently. That exact collision is why CI runs one
pytest process per service rather than one over `services/`.

It is *not* ambiguous for the modules this agent needs. `detection`,
`containers`, `attribution`, `actions`, `recovery`, `hash_chain` and `database`
each exist in exactly one service. The agent never imports `app`, `main` or
`models`.

"Each exists in exactly one service" is a fact about the tree today, and a fact
about the tree today is the kind of thing that stops being true without anyone
noticing. So every load here is checked against the file it was supposed to
come from, and a mismatch raises. The cost is one `assert`-shaped check per
module; the alternative is an agent that one day suspends a process because it
imported a different service's module of the same name.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROOT / "services"

#: module name -> the service directory it must come from.
_OWNERS = {
    "containers": "monitor",
    "detection": "monitor",
    "attribution": "monitor",
    # `app` is the collision this module warns about - five services define
    # one - and it is imported anyway, because `app.handle_event` *is* the
    # measured detection path: entropy history, container validation,
    # admissibility, suppression and attribution, in the order and with the
    # latency accounting the thesis reports. Reimplementing that in the agent
    # would be a second detector to keep in step with the first. The origin
    # check below is what makes importing it safe rather than lucky.
    "app": "monitor",
    "pipeline": "monitor",
    "actions": "response",
    "recovery": "response",
    "recovery.ledger_client": "response",
    "recovery.recovery": "response",
    "recovery.vss_manager": "response",
    "database": "ledger",
    "hash_chain": "ledger",
}

_PREPARED = False


class ServiceImportError(ImportError):
    """A service module did not load, or loaded from the wrong service."""


def prepare_path() -> list[str]:
    """Put the three service directories the agent draws on onto `sys.path`.

    Idempotent, and it prepends rather than appends: a stale install of one of
    these names in site-packages must not win over the tree being run.
    """
    global _PREPARED
    wanted = [str(SERVICES / name) for name in ("monitor", "response", "ledger")]
    for entry in reversed(wanted):
        if not Path(entry).is_dir():
            raise ServiceImportError(
                f"{entry} does not exist. The agent imports the services rather "
                f"than duplicating them, so it has to be run from a checkout "
                f"that still contains them."
            )
        if entry in sys.path:
            sys.path.remove(entry)
        sys.path.insert(0, entry)
    _PREPARED = True
    return wanted


def load(name: str) -> ModuleType:
    """Import one service module by bare name, and verify where it came from."""
    if not _PREPARED:
        prepare_path()

    owner = _OWNERS.get(name)
    if owner is None:
        raise ServiceImportError(
            f"{name!r} is not a module this agent is allowed to import. Add it "
            f"to _OWNERS with the service that owns it, so the check below can "
            f"mean something."
        )

    try:
        module = importlib.import_module(name)
    except ImportError as exc:
        raise ServiceImportError(f"could not import {name} from {owner}: {exc}") from exc

    origin = getattr(module, "__file__", None)
    if origin is None:
        raise ServiceImportError(f"{name} has no __file__; cannot prove its origin")

    expected_dir = (SERVICES / owner).resolve()
    actual = Path(origin).resolve()
    try:
        actual.relative_to(expected_dir)
    except ValueError:
        raise ServiceImportError(
            f"{name} loaded from {actual}, which is not under {expected_dir}. "
            f"Another service, or an installed package, now provides a module "
            f"of this name. Resolve the collision rather than reordering "
            f"sys.path: the agent suspends processes on what these modules say."
        ) from None

    return module


def load_all() -> dict[str, ModuleType]:
    """Every module the agent needs, loaded and origin-checked in one call."""
    prepare_path()
    return {name: load(name) for name in _OWNERS}
