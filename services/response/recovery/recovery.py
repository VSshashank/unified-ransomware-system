"""File recovery - SI's slice of the Response service.

    POST /response/recover  {snapshot_id, files, verify_integrity}
                         -> {status, files_recovered, integrity_verified, timestamp}

A restore is: find the file inside the snapshot, copy it back over the damaged
one, and - if asked - check the restored bytes against the last hash the ledger
recorded for that path. Every restore is written back to the ledger, so the
recovery itself is auditable.

Integrity verification depends on the ledger already holding a hash for the
path. If nothing ever logged one, the file is still restored but reported as
unverified rather than silently passed: claiming verification we did not do
would be worse than admitting we could not.
"""

import hashlib
import logging
import ntpath
import os
import posixpath
import shutil
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from recovery.ledger_client import LedgerClient
from recovery.vss_manager import VSSError, VSSManager, VSSUnavailableError, normalise_snapshot_id

logger = logging.getLogger(__name__)

# Dev/CI fallback: treat <RECOVERY_SNAPSHOT_ROOT>/<snapshot_id> as a snapshot.
# Lets the whole pipeline be exercised on Linux, in the container, and in CI,
# where VSS does not exist. Not a production backup mechanism.
SNAPSHOT_ROOT_ENV = "RECOVERY_SNAPSHOT_ROOT"

CHUNK_SIZE = 1024 * 1024


class RecoveryError(RuntimeError):
    """A recovery could not be carried out at all (e.g. unknown snapshot)."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def to_relative(file_path: str) -> str:
    """Strip the volume so a path can be re-rooted inside a snapshot.

    C:\\data\\report.doc -> data\\report.doc
    /data/report.doc     -> data/report.doc

    `os.path.splitdrive` is `posixpath.splitdrive` off Windows, which does not
    recognise a drive letter and hands the path back untouched. The response
    service runs in a Linux container, so a Windows-sourced path has to be
    split with `ntpath` explicitly or it never gets re-rooted.
    """
    _, tail = ntpath.splitdrive(file_path)
    if tail == file_path:  # no drive letter; may still be a POSIX path
        _, tail = posixpath.splitdrive(file_path)
    return tail.lstrip("\\/")


# ------------------------------------------------------------------- API models


class RecoverRequest(BaseModel):
    snapshot_id: str = Field(min_length=1)
    files: list[str] = Field(min_length=1)
    verify_integrity: bool = True
    # Optional: keep the damaged file alongside the restored one for forensics.
    preserve_damaged_copy: bool = False


class RecoveredFile(BaseModel):
    file_path: str
    restored: bool
    integrity_verified: bool
    restored_hash: Optional[str] = None
    expected_hash: Optional[str] = None
    reason: Optional[str] = None


class RecoverResponse(BaseModel):
    status: str
    files_recovered: int
    integrity_verified: bool
    timestamp: str
    files: list[RecoveredFile] = []


# ---------------------------------------------------------------------- manager


class RecoveryManager:
    def __init__(
        self,
        vss_manager: Optional[VSSManager] = None,
        ledger_client: Optional[LedgerClient] = None,
        snapshot_root: Optional[str] = None,
    ) -> None:
        self.ledger = ledger_client or LedgerClient()
        self.vss = vss_manager or VSSManager(ledger_client=self.ledger)
        self.snapshot_root = snapshot_root or os.getenv(SNAPSHOT_ROOT_ENV)

    # ------------------------------------------------------------- snapshot root

    def resolve_snapshot_root(self, snapshot_id: str) -> str:
        """Directory that the snapshot's contents hang off.

        On Windows that is the shadow copy's device object; otherwise the dev
        fallback directory, if one is configured.
        """
        searched = []

        if self.snapshot_root:
            candidate = os.path.join(self.snapshot_root, snapshot_id)
            if os.path.isdir(candidate):
                return candidate
            searched.append(f"snapshot root {self.snapshot_root}")

        target = normalise_snapshot_id(snapshot_id)
        try:
            for snapshot in self.vss.list_snapshots():
                if normalise_snapshot_id(snapshot.get("snapshot_id", "")) == target:
                    device = snapshot.get("device_object") or ""
                    if not device:
                        raise RecoveryError(
                            f"Snapshot {snapshot_id} has no device object; cannot read files from it."
                        )
                    return device
            searched.append("Windows shadow copies")
        except VSSUnavailableError as exc:
            # This host cannot do VSS at all - that is context for "not found",
            # not a lookup failure. Reported either way so a teammate on Linux
            # sees both places we looked.
            searched.append(f"VSS unavailable ({exc})")
        except VSSError as exc:
            # VSS exists but the query failed - a real operational problem.
            raise RecoveryError(f"Cannot access snapshot {snapshot_id}: {exc}") from exc

        raise RecoveryError(
            f"Snapshot {snapshot_id} not found. Searched: {'; '.join(searched) or 'nowhere configured'}"
        )

    # ------------------------------------------------------------------ restore

    def restore_file(self, snapshot_root: str, file_path: str, preserve_damaged_copy: bool = False) -> str:
        """Copy one file out of the snapshot back to its original path."""
        source = os.path.join(snapshot_root, to_relative(file_path))
        if not os.path.isfile(source):
            raise RecoveryError(f"{file_path} is not present in the snapshot")

        destination_dir = os.path.dirname(os.path.abspath(file_path))
        if destination_dir:
            os.makedirs(destination_dir, exist_ok=True)

        if preserve_damaged_copy and os.path.isfile(file_path):
            damaged = f"{file_path}.damaged-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
            shutil.copy2(file_path, damaged)
            logger.info("Preserved damaged copy at %s", damaged)

        shutil.copy2(source, file_path)
        return sha256_file(file_path)

    # ----------------------------------------------------------------- orchestration

    def recover(
        self,
        snapshot_id: str,
        files: list,
        verify_integrity: bool = True,
        preserve_damaged_copy: bool = False,
    ) -> dict:
        snapshot_root = self.resolve_snapshot_root(snapshot_id)
        results: list = []

        for file_path in files:
            results.append(
                self._recover_one(snapshot_root, snapshot_id, file_path, verify_integrity, preserve_damaged_copy)
            )

        recovered = [r for r in results if r["restored"]]
        # An unverifiable file is not a verified one. With verify_integrity off
        # we make no claim either way, so the flag stays False.
        all_verified = bool(verify_integrity) and bool(results) and all(r["integrity_verified"] for r in results)

        if len(recovered) == len(files):
            overall = "success" if (all_verified or not verify_integrity) else "partial"
        elif recovered:
            overall = "partial"
        else:
            overall = "failed"

        summary = {
            "status": overall,
            "files_recovered": len(recovered),
            "integrity_verified": all_verified,
            "timestamp": utc_now(),
            "files": results,
        }

        self.ledger.try_log_event(
            "recovery_completed",
            {
                "snapshot_id": snapshot_id,
                "status": overall,
                "files_requested": len(files),
                "files_recovered": len(recovered),
                "integrity_verified": all_verified,
            },
        )
        return summary

    def _recover_one(
        self,
        snapshot_root: str,
        snapshot_id: str,
        file_path: str,
        verify_integrity: bool,
        preserve_damaged_copy: bool,
    ) -> dict:
        outcome = {
            "file_path": file_path,
            "restored": False,
            "integrity_verified": False,
            "restored_hash": None,
            "expected_hash": None,
            "reason": None,
        }

        try:
            restored_hash = self.restore_file(snapshot_root, file_path, preserve_damaged_copy)
        except (RecoveryError, OSError) as exc:
            outcome["reason"] = str(exc)
            logger.error("Failed to restore %s: %s", file_path, exc)
            self.ledger.try_log_event(
                "recovery_failed",
                {"file_path": file_path, "snapshot_id": snapshot_id, "error": str(exc)},
            )
            return outcome

        outcome["restored"] = True
        outcome["restored_hash"] = restored_hash

        if verify_integrity:
            known = self._known_hash(file_path)
            if known is None:
                outcome["reason"] = "No prior hash for this path in the ledger; integrity could not be verified"
            else:
                outcome["expected_hash"] = known["file_hash"]
                outcome["integrity_verified"] = known["file_hash"] == restored_hash
                if not outcome["integrity_verified"]:
                    outcome["reason"] = (
                        f"Restored file hash does not match ledger block {known['block_id']}"
                    )

        self.ledger.try_log_event(
            "file_recovered",
            {
                "file_path": file_path,
                "snapshot_id": snapshot_id,
                "file_hash": restored_hash,
                "integrity_verified": outcome["integrity_verified"],
                "verification_requested": verify_integrity,
            },
        )
        return outcome

    def _known_hash(self, file_path: str) -> Optional[dict]:
        """Last hash the ledger holds for this path, if the ledger is reachable."""
        try:
            return self.ledger.last_known_hash(file_path)
        except Exception as exc:
            logger.warning("Could not read prior hash for %s: %s", file_path, exc)
            return None


# ----------------------------------------------------------------------- router

router = APIRouter(prefix="/response", tags=["recovery"])

_manager: Optional[RecoveryManager] = None


def get_recovery_manager() -> RecoveryManager:
    global _manager
    if _manager is None:
        _manager = RecoveryManager()
    return _manager


def error_body(request: Request, code: str, message: str, details: Optional[dict] = None) -> dict:
    from uuid import uuid4

    return {
        "error": {
            "code": code,
            "message": message,
            "timestamp": utc_now(),
            "request_id": request.headers.get("X-Request-ID") or f"req_{uuid4().hex[:12]}",
        },
        "details": details or {},
    }


@router.post("/recover")
def recover_files(
    payload: RecoverRequest,
    request: Request,
    manager: RecoveryManager = Depends(get_recovery_manager),
) -> JSONResponse:
    try:
        result = manager.recover(
            snapshot_id=payload.snapshot_id,
            files=payload.files,
            verify_integrity=payload.verify_integrity,
            preserve_damaged_copy=payload.preserve_damaged_copy,
        )
    except RecoveryError as exc:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=error_body(request, "SNAPSHOT_UNAVAILABLE", str(exc), {"snapshot_id": payload.snapshot_id}),
        )
    except VSSError as exc:
        # Wrong platform or no VSS - say so plainly instead of a 500.
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=error_body(request, "VSS_UNAVAILABLE", str(exc)),
        )

    return JSONResponse(status_code=status.HTTP_200_OK, content=RecoverResponse(**result).model_dump())


@router.get("/recover/status")
def recovery_status(manager: RecoveryManager = Depends(get_recovery_manager)) -> dict:
    """Whether snapshots work on this host, and where they'd come from.

    Exists so a teammate hitting a 503 on Linux can see why in one request.
    """
    platform_status = manager.vss.platform_status()
    return {
        "vss": platform_status,
        "snapshot_root_override": manager.snapshot_root,
        "ledger_url": manager.ledger.base_url,
    }
