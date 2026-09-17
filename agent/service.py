"""urds-agent as a Windows Service, so that protection survives a reboot.

A service and not a scheduled task, and not a tray app, for three reasons that
are all the same reason: it starts before anybody logs in, it runs as SYSTEM,
and the SCM restarts it when it dies. Ransomware does not wait for a console
session, and a protection path that is only running when someone is signed in
is a protection path with a documented hole in it.

Running as SYSTEM is what makes the rest work. Subscribing to the Security
channel for Event ID 4663 needs it, creating a Volume Shadow Copy needs it, and
`psutil.Process(pid).suspend()` against a process owned by another account needs
it. Without elevation the agent still runs, still detects, and suspends nothing
- attribution never reaches CERTAIN, so nothing is authorised, which is the
honest degradation rather than a silent one.

    python -m agent install     register with the SCM, auto-start
    python -m agent start
    python -m agent stop
    python -m agent remove

The working directory of a service is ``%SystemRoot%\\system32``, so nothing
here may depend on a relative path. `agent.config` anchors relative
configuration entries to the repository for the same reason.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SERVICE_NAME = "URDSAgent"
SERVICE_DISPLAY = "URDS Ransomware Protection Agent"
SERVICE_DESCRIPTION = (
    "Watches the configured protected folders, attributes each write to the "
    "process that made it via the Windows Security channel, and suspends a "
    "process that is encrypting rather than working. Records every decision "
    "in a hash-chained ledger. Suspends before terminating, and terminates "
    "only on evidence that names exactly one process."
)

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    HAVE_PYWIN32 = True
except ImportError:  # pragma: no cover - the non-Windows path
    HAVE_PYWIN32 = False
    win32serviceutil = None  # type: ignore[assignment]


def log_path() -> Path:
    base = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "URDS"
    base.mkdir(parents=True, exist_ok=True)
    return base / "agent.log"


def configure_logging(level: int = logging.INFO) -> None:
    """File logging, because a service has no console to print to."""
    handlers: list[logging.Handler] = []
    try:
        handlers.append(logging.FileHandler(log_path(), encoding="utf-8"))
    except OSError:
        pass
    handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


if HAVE_PYWIN32:

    class URDSAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        # Run this file under this interpreter, rather than letting pywin32
        # host the service in its own `pythonservice.exe`.
        #
        # This is not a preference. `pythonservice.exe` finds the service class
        # from the registry and imports it off whatever `sys.path` it
        # constructs for itself, and that path does not include this checkout.
        # Installed the default way the service registers cleanly, reports
        # AUTO_START and LocalSystem, and then fails to start with error 1053
        # having written nothing anywhere - because `import agent` raised
        # before any logging existed. Naming the interpreter and the script
        # makes the venv, and this repository, the thing that runs.
        _exe_name_ = sys.executable
        _exe_args_ = f'-u "{Path(__file__).resolve()}"'

        def __init__(self, args) -> None:
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.agent = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.agent is not None:
                try:
                    self.agent.stop()
                except Exception:  # noqa: BLE001
                    logging.getLogger("urds-agent").exception("stop failed")
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self) -> None:
            configure_logging()
            logger = logging.getLogger("urds-agent")
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                from agent.agent import Agent

                self.agent = Agent()
                started = self.agent.start()
                logger.info("urds-agent started: %s", started)
            except Exception:  # noqa: BLE001
                # A service that fails to start must say why somewhere durable.
                # The SCM only reports that it stopped.
                logger.exception("urds-agent failed to start")
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)
                raise

            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            logger.info("urds-agent stopped")


def main(argv: list[str] | None = None) -> int:
    if not HAVE_PYWIN32:
        print("pywin32 is required to install or run the Windows Service.",
              file=sys.stderr)
        print("  python -m pip install pywin32==308", file=sys.stderr)
        return 2
    win32serviceutil.HandleCommandLine(URDSAgentService, argv=argv)
    return 0


if __name__ == "__main__":
    if not HAVE_PYWIN32:
        raise SystemExit(main())
    if len(sys.argv) == 1:
        # No arguments means the SCM started us via _exe_args_ above. Hand the
        # process to the service dispatcher; anything printed from here goes
        # nowhere, which is why SvcDoRun configures file logging first.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(URDSAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        raise SystemExit(main())
