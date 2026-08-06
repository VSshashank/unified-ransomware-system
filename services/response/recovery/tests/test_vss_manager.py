"""VSS manager tests.

Everything Windows-specific is mocked so this suite passes on the Linux and
macOS machines teammates use, and inside CI.
"""

import platform
import sys
import types

import pytest

from recovery.vss_manager import (
    SnapshotCreationError,
    Snapshot,
    VSSManager,
    VSSUnavailableError,
    normalise_snapshot_id,
)


class FakeLedger:
    """Stands in for LedgerClient; records what would have been logged."""

    def __init__(self):
        self.events = []

    def try_log_event(self, event_type, event_data):
        self.events.append((event_type, event_data))
        return len(self.events)

    def log_event(self, event_type, event_data):
        return self.try_log_event(event_type, event_data)


@pytest.fixture
def ledger():
    return FakeLedger()


@pytest.fixture
def manager(ledger):
    return VSSManager(ledger_client=ledger)


def force_status(monkeypatch, **overrides):
    """Pretend the host is a supported, elevated Windows box."""
    status = {
        "supported": True,
        "platform": "Windows",
        "version": "10.0.26100",
        "edition": "client",
        "backend": "wmi:Win32_ShadowCopy",
        "elevated": True,
    }
    status.update(overrides)
    monkeypatch.setattr(VSSManager, "platform_status", lambda self: status)
    return status


# --------------------------------------------------- platform detection (§4.5.3)


def test_non_windows_is_unsupported_with_a_clear_reason(manager, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    status = manager.platform_status()

    assert status["supported"] is False
    assert "Windows" in status["reason"]
    assert status["platform"] == "Linux"


def test_old_windows_is_rejected_by_version(manager, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(platform, "version", lambda: "5.1.2600")  # Windows XP

    status = manager.platform_status()
    assert status["supported"] is False
    assert "older than the minimum" in status["reason"]


def test_missing_pywin32_is_named_explicitly(manager, monkeypatch):
    """Deterministic whether or not pywin32 is installed on the test machine.

    A None entry in sys.modules makes `import win32com.client` raise ImportError.
    """
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(platform, "version", lambda: "10.0.26100")
    monkeypatch.setitem(sys.modules, "win32com", None)
    monkeypatch.setitem(sys.modules, "win32com.client", None)

    status = manager.platform_status()

    assert status["supported"] is False
    assert "pywin32" in status["reason"]
    assert "pip install pywin32" in status["reason"]


def test_supported_windows_reports_the_wmi_backend(manager, monkeypatch):
    """The positive branch, so the check above can't pass by always failing."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(platform, "version", lambda: "10.0.26100")
    monkeypatch.setitem(sys.modules, "win32com", types.ModuleType("win32com"))
    monkeypatch.setitem(sys.modules, "win32com.client", types.ModuleType("win32com.client"))

    status = manager.platform_status()

    assert status["supported"] is True
    assert status["backend"] == "wmi:Win32_ShadowCopy"
    assert "elevated" in status


def test_ensure_supported_raises_the_unavailable_error(manager, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    with pytest.raises(VSSUnavailableError, match="Windows"):
        manager.ensure_supported()


# ------------------------------------------------ failing clearly, not crashing


def test_create_snapshot_on_linux_raises_instead_of_crashing(manager, monkeypatch):
    """Phase 3 acceptance: teammates on Linux get an explanation, not a crash."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")

    with pytest.raises(VSSUnavailableError) as exc:
        manager.create_snapshot("C:\\")
    assert "Windows" in str(exc.value)


def test_list_snapshots_on_linux_raises_instead_of_crashing(manager, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    with pytest.raises(VSSUnavailableError):
        manager.list_snapshots()


def test_unelevated_windows_explains_the_elevation_requirement(manager, monkeypatch):
    force_status(monkeypatch, elevated=False)

    with pytest.raises(SnapshotCreationError, match="[Ee]levated"):
        manager.create_snapshot("C:\\")


# --------------------------------------------------------------- snapshot create


def test_create_snapshot_returns_the_id_and_logs_to_the_ledger(manager, ledger, monkeypatch):
    force_status(monkeypatch)
    monkeypatch.setattr(VSSManager, "_create_via_wmi", lambda self, volume: "{SNAP-1}")
    monkeypatch.setattr(VSSManager, "_device_object_for", lambda self, sid: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1")

    snapshot_id = manager.create_snapshot("C:\\")

    assert snapshot_id == "{SNAP-1}"
    assert len(ledger.events) == 1

    event_type, event_data = ledger.events[0]
    assert event_type == "snapshot_created"
    assert event_data["snapshot_id"] == "{SNAP-1}"
    assert event_data["volume"] == "C:\\"
    assert "duration_seconds" in event_data


def test_create_snapshot_records_duration_under_the_30s_target(manager, ledger, monkeypatch):
    force_status(monkeypatch)
    monkeypatch.setattr(VSSManager, "_create_via_wmi", lambda self, volume: "{SNAP-2}")
    monkeypatch.setattr(VSSManager, "_device_object_for", lambda self, sid: "")

    manager.create_snapshot("C:\\")

    duration = ledger.events[0][1]["duration_seconds"]
    assert duration < 30, "creation target is under 30s (Table 5.9)"


def test_ledger_being_down_does_not_lose_the_snapshot(manager, monkeypatch):
    """The snapshot already exists; a failed audit write must not discard it."""
    force_status(monkeypatch)
    monkeypatch.setattr(VSSManager, "_create_via_wmi", lambda self, volume: "{SNAP-3}")
    monkeypatch.setattr(VSSManager, "_device_object_for", lambda self, sid: "")
    monkeypatch.setattr(manager.ledger, "try_log_event", lambda *a, **k: None)

    assert manager.create_snapshot("C:\\") == "{SNAP-3}"


def test_wmi_error_codes_become_readable_messages(manager, monkeypatch):
    force_status(monkeypatch)

    def failing_create(self, volume):
        raise SnapshotCreationError(
            "Win32_ShadowCopy.Create failed for C:\\: Insufficient storage (code 6)"
        )

    monkeypatch.setattr(VSSManager, "_create_via_wmi", failing_create)

    with pytest.raises(SnapshotCreationError, match="Insufficient storage"):
        manager.create_snapshot("C:\\")


# ---------------------------------------------------------------- enumeration


def test_list_snapshots_falls_back_to_vssadmin_when_wmi_fails(manager, monkeypatch):
    force_status(monkeypatch)

    def broken_wmi(self):
        raise RuntimeError("WMI initialization failure")

    monkeypatch.setattr(VSSManager, "_list_via_wmi", broken_wmi)
    monkeypatch.setattr(VSSManager, "_list_via_vssadmin", lambda self: [{"snapshot_id": "{FALLBACK}"}])

    assert manager.list_snapshots() == [{"snapshot_id": "{FALLBACK}"}]


VSSADMIN_SAMPLE = r"""
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {aaaaaaaa-0000-0000-0000-000000000001}
   Contained 1 shadow copies at creation time: 8/6/2026 10:15:23 AM
      Shadow Copy ID: {11111111-2222-3333-4444-555555555555}
         Original Volume: (C:)\\?\Volume{bbbbbbbb-0000-0000-0000-000000000002}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: DESKTOP-TEST

Contents of shadow copy set ID: {aaaaaaaa-0000-0000-0000-000000000003}
   Contained 1 shadow copies at creation time: 8/6/2026 16:15:23 PM
      Shadow Copy ID: {66666666-7777-8888-9999-000000000000}
         Original Volume: (C:)\\?\Volume{bbbbbbbb-0000-0000-0000-000000000002}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
         Originating Machine: DESKTOP-TEST
"""


def test_vssadmin_output_parses_into_snapshots():
    snapshots = VSSManager.parse_vssadmin_output(VSSADMIN_SAMPLE)

    assert [s["snapshot_id"] for s in snapshots] == [
        "{11111111-2222-3333-4444-555555555555}",
        "{66666666-7777-8888-9999-000000000000}",
    ]
    assert snapshots[0]["volume"] == "C:\\"
    assert snapshots[0]["device_object"] == r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"


def test_vssadmin_parser_handles_empty_output():
    assert VSSManager.parse_vssadmin_output("No items found that satisfy the query.") == []


def test_wmi_datetime_converts_to_iso():
    assert VSSManager._parse_wmi_datetime("20260806101523.000000+000") == "2026-08-06T10:15:23Z"
    assert VSSManager._parse_wmi_datetime("") == ""
    assert VSSManager._parse_wmi_datetime("garbage") == ""


# ------------------------------------------------------------------ snapshot ids


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("{11111111-2222-3333-4444-555555555555}", "{11111111-2222-3333-4444-555555555555}"),
        ("11111111-2222-3333-4444-555555555555", "{11111111-2222-3333-4444-555555555555}"),
        ("vss_11111111-2222-3333-4444-555555555555", "{11111111-2222-3333-4444-555555555555}"),
        ("  {11111111-2222-3333-4444-555555555555}  ", "{11111111-2222-3333-4444-555555555555}"),
    ],
)
def test_snapshot_ids_normalise_to_the_windows_form(raw, expected):
    """The spec's `vss_...` example and Windows' braced GUID must both work."""
    assert normalise_snapshot_id(raw) == expected


def test_snapshot_dataclass_round_trips():
    snapshot = Snapshot(snapshot_id="{S}", volume="C:\\", device_object=r"\\?\GLOBALROOT\X")
    as_dict = snapshot.as_dict()
    assert set(as_dict) == {"snapshot_id", "volume", "device_object", "created_at"}
    assert as_dict["created_at"].endswith("Z")


# ------------------------------------------------------------------- scheduling


def test_scheduler_refuses_to_start_on_linux_without_raising(manager, monkeypatch):
    """Starting the Response service on Linux must not take it down."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    assert manager.start_scheduler() is False


def test_scheduler_registers_a_six_hour_job(manager, monkeypatch):
    force_status(monkeypatch)
    started = manager.start_scheduler(interval_hours=6)
    try:
        assert started is True
        job = manager._scheduler.get_job("vss_snapshot")
        assert job is not None
        assert job.trigger.interval.total_seconds() == 6 * 3600
    finally:
        manager.stop_scheduler()

    assert manager._scheduler is None


def test_a_failing_scheduled_snapshot_is_logged_not_raised(manager, ledger, monkeypatch):
    """An exception escaping the job would kill the schedule."""
    force_status(monkeypatch)

    def failing(self, volume=None):
        raise SnapshotCreationError("volume in use")

    monkeypatch.setattr(VSSManager, "create_snapshot", failing)

    manager._scheduled_snapshot()  # must not raise

    assert ledger.events[-1][0] == "snapshot_failed"
    assert "volume in use" in ledger.events[-1][1]["error"]
