"""Command line for urds-agent.

    python -m agent run          run in the foreground, Ctrl-C to stop
    python -m agent status       what the agent would see from here
    python -m agent config       the resolved configuration and where it came from
    python -m agent canary       list, seed or remove the decoy field

    python -m agent install      register the Windows Service, auto-start
    python -m agent start        ask the SCM to start it
    python -m agent stop
    python -m agent remove

`run` exists so the whole path can be exercised from an Administrator console
without going through the SCM, which is what the acceptance checks do: the same
code, the same configuration, and a traceback you can read.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading

SERVICE_VERBS = ("install", "start", "stop", "restart", "remove", "update", "debug")


def _print(payload: dict) -> None:
    print(json.dumps(payload, indent=2, default=str))


def cmd_run(args: argparse.Namespace) -> int:
    from agent.agent import Agent
    from agent.service import configure_logging

    configure_logging(logging.DEBUG if args.verbose else logging.INFO)
    agent = Agent()
    started = agent.start()
    _print(started)

    if not started["elevated"]:
        print(
            "\nNOT ELEVATED. The agent is running and detecting, and it will "
            "suspend nothing:\nwithout the Security-channel subscription no "
            "attribution reaches CERTAIN, and\nthe agent does not guess a PID. "
            "Run from an Administrator console for the\nfull path.\n",
            file=sys.stderr,
        )

    done = threading.Event()

    def handle(signum, frame):  # noqa: ARG001
        done.set()

    signal.signal(signal.SIGINT, handle)
    try:
        signal.signal(signal.SIGTERM, handle)
    except (AttributeError, ValueError):
        pass

    try:
        done.wait()
    finally:
        _print(agent.stop())
    return 0


def cmd_status(args: argparse.Namespace) -> int:  # noqa: ARG001
    from agent.agent import Agent

    agent = Agent()
    status = agent.status()
    status["note"] = (
        "this is a fresh process inspecting the same configuration, not the "
        "running service; events_seen and responses are this process's"
    )
    _print(status)
    agent.ledger.close()
    return 0


def cmd_config(args: argparse.Namespace) -> int:  # noqa: ARG001
    from agent import config as agent_config

    resolved = agent_config.load()
    _print({
        "looked_at": [str(p) for p in agent_config.candidate_paths()],
        **resolved.as_dict(),
    })
    return 0


def cmd_canary(args: argparse.Namespace) -> int:
    """List, seed or remove the decoy field without starting the agent.

    `install.ps1` has no need for this - the agent seeds on start, which is the
    only moment that can guarantee the decoys exist before the observers do -
    but `uninstall.ps1` does: removing twenty files it has no list of would
    mean matching them by name, and a name is not what makes a file a canary.
    The manifest is, and this is the only thing that reads it.

    `agent/canary.py` has named this command in its own docstring since it was
    written; until now it did not exist.
    """
    from agent.canary import CanaryField
    from agent import config as agent_config

    config = agent_config.load()
    field = CanaryField(config)
    field.load()

    if args.seed:
        result = field.seed()
        _print({"action": "seed", "created": len(result["created"]),
                "already_present": len(result["existing"]),
                "total": result["total"],
                "manifest": str(field.manifest_path)})
        return 0
    if args.remove:
        result = field.remove()
        _print({"action": "remove", **result,
                "manifest": str(field.manifest_path)})
        # A decoy that could not be deleted is still on disk after an
        # uninstall that reported success. Say so in the exit code.
        return 1 if result["failed"] else 0

    paths = field.paths()
    _print({"action": "list", "total": len(paths),
            "manifest": str(field.manifest_path),
            "protected_paths": [str(p) for p in config.protected_paths],
            "paths": paths})
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # The service verbs are pywin32's, and it wants the whole command line.
    if argv and argv[0] in SERVICE_VERBS:
        from agent import service

        return service.main(argv=["agent", *argv])

    parser = argparse.ArgumentParser(prog="python -m agent", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run in the foreground")
    run.set_defaults(func=cmd_run)

    status = sub.add_parser("status", help="what the agent sees from here")
    status.set_defaults(func=cmd_status)

    conf = sub.add_parser("config", help="the resolved configuration")
    conf.set_defaults(func=cmd_config)

    canary = sub.add_parser("canary", help="list, seed or remove the decoys")
    canary_what = canary.add_mutually_exclusive_group()
    canary_what.add_argument("--seed", action="store_true",
                             help="create any decoy that is missing")
    canary_what.add_argument("--remove", action="store_true",
                             help="delete every decoy in the manifest (uninstall)")
    canary.set_defaults(func=cmd_canary)

    for verb in SERVICE_VERBS:
        sub.add_parser(verb, help=f"Windows Service: {verb}")

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
