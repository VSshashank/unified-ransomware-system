"""Windows Volume Shadow Copy management.

Backend choice: WMI `Win32_ShadowCopy.Create` via pywin32, not `vssadmin`.

`vssadmin` has no `Create Shadow` verb on client editions of Windows - only
Server SKUs get it. Checked on the target machine (Windows 11 Home, build
26100), `vssadmin /?` lists only Delete Shadows, List Providers, List Shadows,
List ShadowStorage, List Volumes, List Writers and Resize ShadowStorage. The
WMI class exposes Create on the same machine. Since the team develops and demos
on client Windows, shelling out to vssadmin would fail everywhere except a
server, so WMI is the creation path.

`vssadmin list shadows` *is* available on client editions, so it stays as a
fallback for enumeration when WMI querying is blocked.

Neither path exists inside the Response container, which is Linux. Snapshot
operations there raise VSSUnavailableError with an explanatory message rather
than crashing the service - see the platform notes in README-SI.md.
"""

import logging
import platform
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from recovery.ledger_client import LedgerClient

logger = logging.getLogger(__name__)

SNAPSHOT_TIMEOUT_SECONDS = 30  # spec Table 5.9 target for creation
DEFAULT_INTERVAL_HOURS = 6
MIN_WINDOWS_VERSION = (6, 1)  # Windows 7 / Server 2008 R2 - first with a usable VSS API

# Return codes from Win32_ShadowCopy.Create. Mapped so a failure says what went
# wrong instead of surfacing a bare integer.
VSS_RETURN_CODES = {
    0: "Success",
    1: "Access denied (run the service elevated)",
    2: "Invalid argument",
    3: "Specified volume not found",
    4: "Specified volume not supported",
    5: "Unsupported shadow copy context",
    6: "Insufficient storage",
    7: "Volume is in use",
    8: "Maximum number of shadow copies reached",
    9: "Another shadow copy operation is already in progress",
    10: "Shadow copy provider vetoed the operation",
    11: "Shadow copy provider not registered",
    12: "Shadow copy provider failure",
    13: "Unknown error",
}


class VSSError(RuntimeError):
    """Base class for shadow copy failures."""


class VSSUnavailableError(VSSError):
    """VSS cannot run here at all - wrong OS, missing pywin32, too old.

    Distinct from SnapshotCreationError because callers treat it differently:
    this one means "don't bother retrying on this machine".
    """


class SnapshotCreationError(VSSError):
    """VSS is available but this particular snapshot failed."""


_com_apartment = threading.local()


def ensure_com_apartment() -> None:
    """Initialise COM once per thread, and leave it initialised.

    Pairing CoInitialize/CoUninitialize around each call reads as tidier, but
    it is wrong here. A failed WMI query raises `com_error`, and that exception
    keeps a COM pointer alive inside its own traceback - which outlives the
    call it was raised in, because callers chain it (`raise VSSError(...) from
    exc`). Releasing that pointer after the apartment has been torn down is
    what makes pywin32 print "Win32 exception occurred releasing IUnknown" to
    stderr at shutdown, once per failed enumeration. Verified on Windows 11
    build 26200: keeping the apartment up for the thread's lifetime removes it,
    on both the request thread and the scheduler's worker.

    An apartment is per-thread state that the OS reclaims with the thread, so
    there is nothing to leak by holding it.
    """
    if getattr(_com_apartment, "ready", False):
        return

    import pythoncom  # type: ignore

    pythoncom.CoInitialize()
    _com_apartment.ready = True


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Snapshot:
    snapshot_id: str
    volume: str
    device_object: str = ""
    created_at: str = field(default_factory=utc_now)

    def as_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "volume": self.volume,
            "device_object": self.device_object,
            "created_at": self.created_at,
        }


def normalise_snapshot_id(snapshot_id: str) -> str:
    """Accept `{GUID}`, `GUID`, or the spec's illustrative `vss_<GUID>` form.

    The API contract example in the spec shows "vss_...", but Windows hands back
    a braced GUID. Rather than force one on the caller, normalise to what
    Windows uses so lookups match.
    """
    value = snapshot_id.strip()
    if value.lower().startswith("vss_"):
        value = value[4:]
    if value and not value.startswith("{"):
        value = "{" + value + "}"
    return value.upper()


class VSSManager:
    def __init__(
        self,
        ledger_client: Optional[LedgerClient] = None,
        default_volume: str = "C:\\",
        interval_hours: int = DEFAULT_INTERVAL_HOURS,
    ) -> None:
        self.ledger = ledger_client or LedgerClient()
        self.default_volume = default_volume
        self.interval_hours = interval_hours
        self._scheduler: Any = None

    # -------------------------------------------------------- platform support

    @staticmethod
    def _windows_version() -> tuple:
        try:
            return tuple(int(part) for part in platform.version().split("."))
        except ValueError:
            return ()

    def platform_status(self) -> dict:
        """Whether VSS can run here, and if not, precisely why.

        Returned by /response/recover/status so teammates on Linux or macOS get
        an explanation instead of a mystery failure.
        """
        system = platform.system()
        if system != "Windows":
            return {
                "supported": False,
                "platform": system or "unknown",
                "reason": (
                    f"Volume Shadow Copy is a Windows feature; this host reports '{system}'. "
                    "Snapshot creation and restore-from-snapshot are unavailable here."
                ),
            }

        version = self._windows_version()
        if version and version[:2] < MIN_WINDOWS_VERSION:
            return {
                "supported": False,
                "platform": "Windows",
                "version": platform.version(),
                "reason": (
                    f"Windows {platform.version()} is older than the minimum supported "
                    f"{'.'.join(str(p) for p in MIN_WINDOWS_VERSION)} (Windows 7 / Server 2008 R2)."
                ),
            }

        try:
            import win32com.client  # noqa: F401
        except ImportError:
            return {
                "supported": False,
                "platform": "Windows",
                "version": platform.version(),
                "reason": "pywin32 is not installed. Install it with: pip install pywin32",
            }

        return {
            "supported": True,
            "platform": "Windows",
            "version": platform.version(),
            "edition": "client" if not self._is_server() else "server",
            "backend": "wmi:Win32_ShadowCopy",
            "elevated": self._is_elevated(),
        }

    @staticmethod
    def _is_server() -> bool:
        try:
            return platform.win32_edition() is not None and "server" in platform.win32_edition().lower()
        except AttributeError:
            return False

    @staticmethod
    def _is_elevated() -> bool:
        """Snapshot creation needs an elevated process; report it up front."""
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def ensure_supported(self) -> dict:
        status = self.platform_status()
        if not status["supported"]:
            raise VSSUnavailableError(status["reason"])
        return status

    # ------------------------------------------------------------ snapshotting

    def create_snapshot(self, volume: Optional[str] = None) -> str:
        """Create a shadow copy and return its ID.

        Logs a `snapshot_created` event to the ledger on success. Target for
        creation is under 30 seconds (spec Table 5.9); a slower one still
        succeeds but is recorded and warned about, because a snapshot that
        exists is worth more than a tidy metric.
        """
        status = self.ensure_supported()
        volume = volume or self.default_volume

        if not status.get("elevated", False):
            raise SnapshotCreationError(
                "Creating a shadow copy requires an elevated process. "
                "Start the Response service from an Administrator shell."
            )

        started = time.perf_counter()
        shadow_id = self._create_via_wmi(volume)
        duration = time.perf_counter() - started

        if duration > SNAPSHOT_TIMEOUT_SECONDS:
            logger.warning(
                "Snapshot %s took %.1fs, over the %ss target", shadow_id, duration, SNAPSHOT_TIMEOUT_SECONDS
            )

        snapshot = Snapshot(
            snapshot_id=shadow_id,
            volume=volume,
            device_object=self._device_object_for(shadow_id),
        )

        block_id = self.ledger.try_log_event(
            "snapshot_created",
            {**snapshot.as_dict(), "duration_seconds": round(duration, 3)},
        )
        logger.info("Created snapshot %s for %s in %.1fs (ledger block %s)", shadow_id, volume, duration, block_id)
        return shadow_id

    def _create_via_wmi(self, volume: str) -> str:
        import win32com.client  # type: ignore

        ensure_com_apartment()
        try:
            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
            shadow_class = wmi.Get("Win32_ShadowCopy")
            params = shadow_class.Methods_("Create").InParameters.SpawnInstance_()
            params.Volume = volume if volume.endswith("\\") else volume + "\\"
            params.Context = "ClientAccessible"

            result = shadow_class.ExecMethod_("Create", params)
            return_value = int(result.ReturnValue)

            if return_value != 0:
                raise SnapshotCreationError(
                    f"Win32_ShadowCopy.Create failed for {volume}: "
                    f"{VSS_RETURN_CODES.get(return_value, 'Undocumented error')} (code {return_value})"
                )
            return str(result.ShadowID)
        except SnapshotCreationError:
            raise
        except Exception as exc:  # COM errors are not a useful type to callers
            raise SnapshotCreationError(f"Shadow copy creation failed for {volume}: {exc}") from exc

    # -------------------------------------------------------------- enumeration

    def list_snapshots(self) -> list:
        """Enumerate shadow copies, newest first.

        Tries WMI, then falls back to parsing `vssadmin list shadows` - that verb
        does exist on client editions, unlike Create.
        """
        status = self.ensure_supported()
        try:
            return self._list_via_wmi()
        except Exception as exc:
            logger.warning("WMI enumeration failed (%s), falling back to vssadmin", exc)
            try:
                return self._list_via_vssadmin()
            except VSSError as fallback:
                # Both paths need admin: querying Win32_ShadowCopy as a standard
                # user fails with a bare OLE 0x80041014, and vssadmin refuses
                # outright. Say that once, instead of making the operator decode
                # a COM error followed by an exit code.
                if not status.get("elevated", False):
                    raise VSSError(
                        "Enumerating shadow copies requires an elevated process. "
                        "Neither Win32_ShadowCopy nor vssadmin is readable as a standard "
                        "user; start the Response service from an Administrator shell."
                    ) from fallback
                raise

    def _list_via_wmi(self) -> list:
        import win32com.client  # type: ignore

        ensure_com_apartment()
        wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
        snapshots = [
            Snapshot(
                snapshot_id=str(item.ID),
                volume=str(item.VolumeName or ""),
                device_object=str(item.DeviceObject or ""),
                created_at=self._parse_wmi_datetime(str(item.InstallDate or "")),
            ).as_dict()
            for item in wmi.ExecQuery("SELECT * FROM Win32_ShadowCopy")
        ]
        return sorted(snapshots, key=lambda s: s["created_at"], reverse=True)

    def _list_via_vssadmin(self) -> list:
        try:
            completed = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                timeout=SNAPSHOT_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise VSSError(f"vssadmin enumeration failed: {exc}") from exc

        if completed.returncode != 0:
            # vssadmin writes its errors to stdout, not stderr - reading stderr
            # here reported an empty reason for every failure.
            detail = (completed.stdout or completed.stderr or "").strip()
            detail = " ".join(line for line in detail.splitlines() if line.strip().startswith("Error"))
            raise VSSError(
                f"vssadmin list shadows failed (exit {completed.returncode}). "
                f"{detail[:200] or 'No detail reported; it usually requires an elevated shell.'}"
            )
        return self.parse_vssadmin_output(completed.stdout)

    @staticmethod
    def parse_vssadmin_output(output: str) -> list:
        """Pull snapshot IDs, volumes and device paths out of vssadmin text."""
        snapshots = []
        current: dict = {}
        for line in output.splitlines():
            line = line.strip()

            shadow_id = re.search(r"Shadow Copy ID:\s*(\{[0-9a-fA-F\-]+\})", line)
            if shadow_id:
                if current.get("snapshot_id"):
                    snapshots.append(current)
                current = {"snapshot_id": shadow_id.group(1), "volume": "", "device_object": "", "created_at": ""}
                continue

            volume = re.search(r"Original Volume:.*?\(([A-Za-z]:)\)", line)
            if volume and current:
                current["volume"] = volume.group(1) + "\\"
                continue

            device = re.search(r"(\\\\\?\\GLOBALROOT\S+)", line)
            if device and current:
                current["device_object"] = device.group(1)

        if current.get("snapshot_id"):
            snapshots.append(current)
        return snapshots

    def _device_object_for(self, shadow_id: str) -> str:
        """Device path of a snapshot - the root you copy files out of."""
        target = normalise_snapshot_id(shadow_id)
        try:
            for snapshot in self._list_via_wmi():
                if normalise_snapshot_id(snapshot["snapshot_id"]) == target:
                    return snapshot["device_object"]
        except Exception as exc:
            logger.warning("Could not resolve device object for %s: %s", shadow_id, exc)
        return ""

    @staticmethod
    def _parse_wmi_datetime(value: str) -> str:
        """WMI CIM_DATETIME (yyyymmddHHMMSS.ffffff+UUU) to ISO-8601."""
        if not value or len(value) < 14:
            return ""
        try:
            parsed = datetime.strptime(value[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return ""
        return parsed.isoformat().replace("+00:00", "Z")

    # ---------------------------------------------------------------- scheduling

    def start_scheduler(self, interval_hours: Optional[int] = None, run_immediately: bool = False) -> bool:
        """Snapshot every N hours (default 6).

        Returns False rather than raising when VSS is unavailable, so importing
        or starting the Response service on Linux does not take it down - the
        acceptance criterion for Phase 3.
        """
        status = self.platform_status()
        if not status["supported"]:
            logger.warning("Snapshot scheduler not started: %s", status["reason"])
            return False

        from apscheduler.schedulers.background import BackgroundScheduler

        hours = interval_hours or self.interval_hours
        self._scheduler = BackgroundScheduler(daemon=True)
        self._scheduler.add_job(
            self._scheduled_snapshot,
            trigger="interval",
            hours=hours,
            id="vss_snapshot",
            replace_existing=True,
            max_instances=1,  # a slow snapshot must not stack up behind itself
            coalesce=True,
            next_run_time=datetime.now(timezone.utc) if run_immediately else None,
        )
        self._scheduler.start()
        logger.info("Snapshot scheduler started: every %s hours", hours)
        return True

    def _scheduled_snapshot(self) -> None:
        """Scheduled runs must never raise - that would kill the job."""
        try:
            self.create_snapshot()
        except VSSError as exc:
            logger.error("Scheduled snapshot failed: %s", exc)
            self.ledger.try_log_event(
                "snapshot_failed", {"volume": self.default_volume, "error": str(exc), "occurred_at": utc_now()}
            )

    def stop_scheduler(self) -> None:
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
            logger.info("Snapshot scheduler stopped")
