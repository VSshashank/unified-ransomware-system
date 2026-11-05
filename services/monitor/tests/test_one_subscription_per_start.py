"""One Security-channel subscription per Monitor start, and the old one closed.

Seen on the VM in the 2026-10-04 re-check and carried over by the full test:
the Monitor subscribed to the Security channel twice per start. `build_source`
starts a `SecurityLogSource` to find out whether the host can subscribe, and
`/monitor/start` then handed it to `Attributor.start`, which started it again.
The second handle replaced the first without closing it, and `stop()` dropped
its handle without closing it either.

pywin32 is replaced by a fake that counts subscriptions and closes, so this
runs the same on Linux CI as on Windows.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402


class FakeHandle:
    def __init__(self) -> None:
        self.closed = False

    def Close(self) -> None:  # noqa: N802 - pywin32's spelling
        self.closed = True


class FakeEvtlog:
    """The part of win32evtlog the source uses."""

    EvtSubscribeToFutureEvents = 1
    EvtSubscribeActionDeliver = 1
    EvtRenderEventXml = 1

    def __init__(self) -> None:
        self.handles: list[FakeHandle] = []

    def EvtSubscribe(self, *args, **kwargs):  # noqa: N802
        handle = FakeHandle()
        self.handles.append(handle)
        return handle

    def open_handles(self) -> list[FakeHandle]:
        return [h for h in self.handles if not h.closed]


@pytest.fixture
def evtlog(monkeypatch):
    fake = FakeEvtlog()
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    monkeypatch.setattr(attribution, "_on_windows", lambda: True, raising=False)
    monkeypatch.setenv("ATTRIBUTION_SOURCE", "auto")
    return fake


def test_a_monitor_start_makes_one_subscription(evtlog, monkeypatch, tmp_path):
    """Through the real endpoint, with a fresh attributor as at process start."""
    fresh = attribution.Attributor()
    monkeypatch.setattr(monitor_app, "attributor", fresh)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", False)
    try:
        response = monitor_app.start_monitoring(monitor_app.MonitorStartRequest(watch_path=str(tmp_path)))
        assert response.status_code == 200
        assert fresh.available is True
        assert len(evtlog.handles) == 1, f"{len(evtlog.handles)} subscriptions for one start"
        assert len(evtlog.open_handles()) == 1
    finally:
        monitor_app.stop_monitoring()
        fresh.stop()
    assert evtlog.open_handles() == []


def test_starting_a_subscribed_source_again_closes_the_first_handle(evtlog):
    source = attribution.SecurityLogSource(attribution.WriteLog())
    assert source.start() and source.start()

    assert len(evtlog.handles) == 2
    assert evtlog.handles[0].closed is True
    assert len(evtlog.open_handles()) == 1


def test_stopping_the_source_closes_its_handle(evtlog):
    source = attribution.SecurityLogSource(attribution.WriteLog())
    assert source.start()

    source.stop()

    assert evtlog.open_handles() == []
    assert source.available is False
