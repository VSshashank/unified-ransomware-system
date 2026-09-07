"""TC-11 - multiple simultaneous attacks.

Table 5.8: "Multiple simultaneous attacks -> All processes detected and
terminated, system remains stable."

The response half lives here: N real processes, terminated concurrently, all of
them, with the service still answering correctly afterwards. The detection half
- N files encrypted at once, all flagged - is in
services/monitor/tests/test_tc11_concurrent.py, because the two services own
different sides of the requirement and their suites run separately.

"Remains stable" is asserted rather than assumed: no unrelated process is
touched, every call returns a well-formed result, and the module still
terminates a fresh process after the storm.
"""

import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psutil
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from actions import TerminationError, terminate_process

ATTACK_COUNT = 8
KILL_TIME_TARGET_S = 2.0


@pytest.fixture
def victim_swarm():
    """ATTACK_COUNT real child processes standing in for concurrent ransomware."""
    processes = [
        subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        for _ in range(ATTACK_COUNT)
    ]
    time.sleep(0.4)  # let them all be schedulable before we measure
    yield processes
    for process in processes:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


@pytest.fixture
def bystander():
    """A process that must survive. Nothing about a storm justifies collateral."""
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.2)
    yield process
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)


def test_tc11_all_simultaneous_attacks_are_terminated(victim_swarm, bystander):
    """Every attacking process dies and the bystander does not.

    The time bound asserted here is per-termination, which is what TC-07
    actually specifies. Batch wall-clock is reported but not asserted: TC-11
    states no timing requirement, and eight threads racing on a machine that is
    also running the rest of the suite makes wall-clock a measure of how busy
    the host is rather than of anything this code does.
    """
    pids = [process.pid for process in victim_swarm]
    assert all(psutil.pid_exists(pid) for pid in pids), "swarm did not start"

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=ATTACK_COUNT) as pool:
        results = list(pool.map(terminate_process, pids))
    elapsed = time.perf_counter() - started

    assert len(results) == ATTACK_COUNT
    for result in results:
        assert result["status"] == "terminated", result
        assert result["termination_time_ms"] < KILL_TIME_TARGET_S * 1000, (
            f"a single termination took {result['termination_time_ms']}ms, over the TC-07 budget"
        )

    # wait() is the authoritative check: it reaps the child and returns its exit
    # status. Polling pid_exists() instead would race the exit and, on Windows,
    # could observe a recycled PID belonging to something else entirely.
    for process in victim_swarm:
        assert process.wait(timeout=5) is not None, "a process in the swarm survived termination"

    assert bystander.poll() is None, "an unrelated process was killed during the storm"

    print(
        f"\nTC-11: {ATTACK_COUNT} concurrent terminations, batch {elapsed * 1000:.1f}ms, "
        f"slowest single {max(r['termination_time_ms'] for r in results):.1f}ms (per-kill target <2000ms)"
    )


def test_tc11_service_remains_stable_after_the_storm(victim_swarm):
    """The point of "system remains stable": the module still works afterwards.

    A handler that survives eight kills but is then wedged has not passed.
    """
    with ThreadPoolExecutor(max_workers=ATTACK_COUNT) as pool:
        list(pool.map(lambda p: terminate_process(p.pid), victim_swarm))

    # A fresh process, terminated normally, after the storm.
    survivor = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    time.sleep(0.3)
    try:
        result = terminate_process(survivor.pid)
        assert result["status"] == "terminated"
    finally:
        if survivor.poll() is None:
            survivor.kill()
            survivor.wait(timeout=5)

    # And the guards still refuse nonsense rather than having been loosened.
    with pytest.raises(TerminationError):
        terminate_process(0)


def test_tc11_repeated_termination_of_the_same_pid_is_refused(victim_swarm):
    """Concurrent detections can name the same PID twice. The second must be a
    clean refusal, not a crash and not a kill of whatever reused the PID."""
    target = victim_swarm[0]
    first = terminate_process(target.pid)
    assert first["status"] == "terminated"
    target.wait(timeout=5)

    with pytest.raises(TerminationError):
        terminate_process(target.pid)
