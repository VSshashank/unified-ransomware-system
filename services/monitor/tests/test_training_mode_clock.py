"""Training mode measured its window and its dwell on the wall clock.

Found re-testing fix/windows-integration-defects on the Windows VM, 2026-10-04.
`test_a_file_that_has_dwelled_does_raise_a_ceiling` failed in two consecutive
Monitor runs in a fresh venv - state `idle`, not `active`, after sleeping 80 ms
against a 50 ms dwell - and then passed 15 of 15 runs in each venv. Measured on
the same VM against a pypi.org HTTP `Date` reference over 41 s:

    time.time()          0.801x
    time.perf_counter()  1.002x
    time.monotonic()     1.002x

and, over an earlier 60 s, `time.time()` gained 26.5 s on `perf_counter` -
1.44x. Windows Time was not synchronising (source "Local CMOS Clock"); the slew
is VirtualBox's guest time sync (VBoxService), which steers the system clock by
changing its rate. No backward step was seen, but nothing rules one out.

A duration measured on that clock is wrong by the slew, in either direction.
Both things `TrainingMode` times are durations - when the training window
closes, and how long a path has been watched before its reading may raise a
ceiling - and neither is ever reported as a time of day (`status` gives
`seconds_remaining`). So both now run on `time.monotonic()`. At 0.62x or slower,
the old code turned an 80 ms sleep into less than the 50 ms dwell, which is the
failure above. At 1.44x a 60 s operator window closed after about 42 s, and a
dwell set to keep a poison write from raising a ceiling was shortened by the
same factor.

These tests freeze the wall clock the module sees - the limit of a slew - and
require both durations to elapse anyway. Against the old code each one fails:
the dwell never completes, the window never closes, the countdown never moves.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import suppression  # noqa: E402
from suppression import TrainingMode  # noqa: E402

BENIGN = {
    "verdict": "benign",
    "entropy": 7.9,
    "entropy_delta": None,
    "ransom_extension": False,
    "suspicious": False,
    "signal": None,
    "container_format": None,
    "container_valid": None,
}


def freeze_wall_clock(monkeypatch) -> None:
    """The module's view of the wall clock stands still.

    `raising=False` because the fixed module no longer imports `time` by that
    name: the patch then lands on nothing the module reads, which is the point.
    """
    frozen = time.time()
    monkeypatch.setattr(suppression, "time", lambda: frozen, raising=False)


def test_a_dwell_completes_while_the_wall_clock_stands_still(monkeypatch):
    freeze_wall_clock(monkeypatch)
    training = TrainingMode(dwell_seconds=0.05)
    training.start(duration_seconds=60)
    training.observe("/watch/render/frame.rndr", 7.9, BENIGN)

    time.sleep(0.08)
    training.finish()

    assert training.state == TrainingMode.ACTIVE


def test_a_training_window_closes_while_the_wall_clock_stands_still(monkeypatch):
    freeze_wall_clock(monkeypatch)
    training = TrainingMode(dwell_seconds=0.0)
    training.start(duration_seconds=0.05)
    training.observe("/watch/render/frame.rndr", 7.9, BENIGN)

    time.sleep(0.08)

    # Expired and promoted on its own, without finish(): the window is over.
    assert training.state == TrainingMode.ACTIVE


def test_the_countdown_moves_while_the_wall_clock_stands_still(monkeypatch):
    freeze_wall_clock(monkeypatch)
    training = TrainingMode()
    training.start(duration_seconds=60)

    time.sleep(0.25)

    assert training.status()["seconds_remaining"] < 60
