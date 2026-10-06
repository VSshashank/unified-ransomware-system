"""A stand-in for the Response service that takes one lease and then hangs.

Used by test_lease_watchdog.py to kill "the service" outright while it holds a
suspension. It builds the real LeaseTable with the real Watchdog and the real
actions, takes the lease, prints one line and waits to be killed. Its reaper is
deliberately never started: it stands for a service that is dead or stuck, and
only the watchdog can end the lease.

    python _holder.py <pid> <started_at> <lease_seconds> <grace_seconds>
"""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import actions  # noqa: E402
from lease_watchdog import Watchdog  # noqa: E402
from leases import LeaseTable  # noqa: E402


def main() -> int:
    pid, started_at, seconds, grace = int(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
    table = LeaseTable(resume=actions.resume_process, watchdog=Watchdog(grace=grace))
    table.watchdog.start()
    lease, _ = table.acquire(
        pid,
        incident_id="inc-holder",
        lease_seconds=seconds,
        reason="holder",
        vet=lambda: actions.vet_suspend(pid, None, started_at, extra_protected=table.protected_pids()),
        suspend=actions.suspend_process,
    )
    watchdog_pids = ",".join(str(p) for p in sorted(table.watchdog.pids()))
    print(f"held {os.getpid()} {lease.lease_id} {watchdog_pids}", flush=True)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        time.sleep(0.1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
