"""Decoy documents, and the one rule in this system that needs no threshold.

Every other signal here is a judgement about content or behaviour, and every
judgement has a false-positive rate. A canary does not. Nothing on the machine
has any reason to open these files: they are not referenced by anything, no
application knows about them, and a user will never find them interesting. A
write to one by a process that is not on the allowlist is therefore not
evidence of encryption - it is evidence of something walking the directory and
rewriting whatever it finds, which is the behaviour, not a proxy for it.

So a canary hit suspends immediately. No scoring, no threshold, no wait for a
second opinion. It is the lowest-false-positive signal in the system and the
only one allowed to act alone.

They are real documents. Minimal but valid OOXML, written with ZIP_STORED so
the bytes stay low-entropy: a canary that was itself high-entropy would be
indistinguishable from a file that had already been encrypted, and the first
thing the detector saw on startup would be twenty apparent victims. Storing
uncompressed also means an encryptor's rewrite produces an obvious entropy
jump against the ledger's baseline.

Naming is deliberate, and it is checked rather than assumed. Half the field
sorts before everything (`!_...`) and half after everything (`~$zzz_...`), so a
process walking a directory in either direction meets a decoy before it reaches
the user's real documents. That is the whole reason the trap is worth setting:
it converts "we noticed after twenty files" into "we noticed on the first".

The byte values matter and are easy to get backwards - see the comment above
FIRST_PREFIX, and `test_canaries_bracket_the_real_documents`, which asserts the
ordering against a directory of realistic filenames instead of trusting it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_NAME = "canaries.json"

_NOTE = (
    "This file is a URDS decoy. It is placed here by the URDS ransomware "
    "protection agent and is not used by anything. Nothing on this machine "
    "should ever write to it. If a process does, the agent suspends that "
    "process immediately. You can safely ignore this file; deleting it only "
    "removes one tripwire. Run `python -m agent canary --seed` to restore it."
)

_CONTENT_TYPES_DOCX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

_RELS_DOCX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

_DOCUMENT_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t xml:space="preserve">{note}</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">{tag}</w:t></w:r></w:p></w:body>
</w:document>"""

_CONTENT_TYPES_XLSX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""

_RELS_XLSX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

_WORKBOOK_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Notice" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""

_WORKBOOK_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""

_SHEET_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="1"><c r="A1" t="inlineStr"><is><t xml:space="preserve">{note}</t></is></c></row>
<row r="2"><c r="A2" t="inlineStr"><is><t xml:space="preserve">{tag}</t></is></c></row>
</sheetData>
</worksheet>"""


def _write_ooxml(path: Path, parts: dict[str, str]) -> None:
    """Write a valid OOXML package, uncompressed.

    ZIP_STORED, not ZIP_DEFLATED. A deflated package is high-entropy, which
    would make every canary look like an already-encrypted file to the very
    detector that is supposed to notice when one becomes encrypted.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, body in parts.items():
            archive.writestr(name, body)


def _docx_parts(tag: str) -> dict[str, str]:
    return {
        "[Content_Types].xml": _CONTENT_TYPES_DOCX,
        "_rels/.rels": _RELS_DOCX,
        "word/document.xml": _DOCUMENT_XML.format(note=_NOTE, tag=tag),
    }


def _xlsx_parts(tag: str) -> dict[str, str]:
    return {
        "[Content_Types].xml": _CONTENT_TYPES_XLSX,
        "_rels/.rels": _RELS_XLSX,
        "xl/workbook.xml": _WORKBOOK_XML,
        "xl/_rels/workbook.xml.rels": _WORKBOOK_RELS,
        "xl/worksheets/sheet1.xml": _SHEET_XML.format(note=_NOTE, tag=tag),
    }


# Both ends of the sort order, and the byte values are the reason these are
# what they are.
#
# The obvious choice for "sorts first" is `~$`, Word's own lock-file prefix,
# which is camouflage as well as a name. It is also wrong: `~` is 0x7E and `z`
# is 0x7A, so `~$aaa_` sorts *after* `zzz_`. Seeded that way both halves of the
# field land at the same end of the directory and nothing at all sits ahead of
# the user's real documents - which is the half that matters, because a
# traversal in the ordinary direction would reach every real file first and the
# trap would spring after the damage.
#
# So `!` (0x21) takes the front, ahead of digits and letters, and `~$` keeps
# the back, where its camouflage still costs nothing.
FIRST_PREFIX = "!_urds_canary"
LAST_PREFIX = "~$zzz_urds_canary"


@dataclass
class Hit:
    path: str
    pid: int | None
    image: str | None
    at: str
    changed: bool
    #: The decoy is gone. Recorded separately from `changed` because a file
    #: that no longer exists cannot be hashed, and "the hash did not match"
    #: and "there was nothing left to hash" are different findings.
    deleted: bool = False

    def as_dict(self) -> dict:
        return {"path": self.path, "pid": self.pid, "image": self.image,
                "at": self.at, "content_changed": self.changed,
                "deleted": self.deleted}


@dataclass
class CanaryField:
    """The decoys under every protected root, and what has touched them."""

    config: object
    _paths: dict[str, str] = field(default_factory=dict)   # lowered path -> sha256
    _hits: list[Hit] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # -- lifecycle ---------------------------------------------------------

    @property
    def manifest_path(self) -> Path:
        return Path(self.config.data_dir) / MANIFEST_NAME

    def seed(self) -> dict:
        """Create the decoys. Idempotent: an existing canary is left alone."""
        created, existing = [], []
        per_root = int(self.config.canaries_per_root)

        # Drop anything the manifest remembers from a root that is no longer
        # configured. Without this, changing protected_paths leaves the old
        # root's decoys in the manifest for ever and the agent reports a field
        # larger than the one that exists - a count that overstates the
        # protection in place, which is the one direction this project does not
        # get to be wrong in.
        with self._lock:
            self._paths = {
                path: digest for path, digest in self._paths.items()
                if self.config.protects(path)
            }
        for root in self.config.protected_paths:
            root = Path(root)
            root.mkdir(parents=True, exist_ok=True)
            for index in range(per_root):
                first_half = index < (per_root + 1) // 2
                prefix = FIRST_PREFIX if first_half else LAST_PREFIX
                suffix = ".docx" if first_half else ".xlsx"
                name = f"{prefix}_{index:02d}{suffix}"
                path = root / name
                tag = f"URDS canary {index:02d} under {root}"
                if path.exists():
                    existing.append(str(path))
                else:
                    parts = _docx_parts(tag) if suffix == ".docx" else _xlsx_parts(tag)
                    _write_ooxml(path, parts)
                    created.append(str(path))
                with self._lock:
                    self._paths[str(path).lower()] = _sha256(path)

        self._save_manifest()
        logger.info("canaries: %d created, %d already present, %d total",
                    len(created), len(existing), len(self._paths))
        return {"created": created, "existing": existing, "total": len(self._paths)}

    def load(self) -> dict:
        """Read the manifest written by a previous seed."""
        if not self.manifest_path.is_file():
            return {"loaded": 0, "reason": f"no manifest at {self.manifest_path}"}
        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"loaded": 0, "reason": f"unreadable manifest: {exc}"}
        with self._lock:
            self._paths = dict(payload.get("canaries") or {})
        return {"loaded": len(self._paths)}

    def remove(self) -> dict:
        """Delete every decoy. Used by uninstall."""
        removed, failed = [], []
        with self._lock:
            paths = list(self._paths)
        for lowered in paths:
            try:
                Path(lowered).unlink(missing_ok=True)
                removed.append(lowered)
            except OSError as exc:
                failed.append({"path": lowered, "error": str(exc)})
        with self._lock:
            self._paths.clear()
        self.manifest_path.unlink(missing_ok=True)
        return {"removed": len(removed), "failed": failed}

    def _save_manifest(self) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            payload = {
                "schema": "urds.canaries/1",
                "written_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "note": "Paths of the decoy documents and their SHA-256 when "
                        "seeded. A write to any of these by a process not on "
                        "the allowlist suspends that process immediately.",
                "canaries": dict(self._paths),
            }
        with self.manifest_path.open("w", encoding="utf-8", newline="") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")

    # -- the rule ----------------------------------------------------------

    def is_canary(self, path: str | os.PathLike) -> bool:
        with self._lock:
            return str(path).lower() in self._paths

    def paths(self) -> list[str]:
        with self._lock:
            return sorted(self._paths)

    def allowlisted(self, image: str | None) -> bool:
        """Images permitted to write a canary. Empty by default, on purpose."""
        if not image:
            return False
        allowed = {entry.lower() for entry in self.config.allowlist_images}
        return image.lower() in allowed

    def touched(self, path: str, pid: int | None, image: str | None) -> Hit | None:
        """Record a write to - or a deletion of - a canary, if that is what this was."""
        if not self.is_canary(path):
            return None
        with self._lock:
            expected = self._paths.get(str(path).lower())
        gone = not Path(path).exists()
        current = None if gone else _sha256(Path(path))
        hit = Hit(
            path=str(path),
            pid=pid,
            image=image,
            at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            # A hit is a hit either way. The hash says whether the bytes
            # actually changed, which separates "something rewrote this" from
            # "something opened it and the filesystem reported a touch".
            #
            # A deleted decoy counts as changed without a hash to prove it.
            # Requiring the comparison would mean the one outcome nobody can
            # mistake for ordinary activity - the file is gone - recorded as
            # the weakest kind of hit.
            changed=bool(gone or (expected and current and current != expected)),
            deleted=gone,
        )
        with self._lock:
            self._hits.append(hit)
            if len(self._hits) > 1000:
                del self._hits[:500]
        logger.warning("canary %s: %s by pid %s (%s), content changed=%s",
                       "deleted" if gone else "touched", path, pid, image,
                       hit.changed)
        return hit

    def hits(self, pid: int | None = None) -> list[dict]:
        with self._lock:
            found = list(self._hits)
        if pid is not None:
            found = [h for h in found if h.pid == pid]
        return [h.as_dict() for h in found]

    def hit_count(self, pid: int | None = None) -> int:
        return len(self.hits(pid))


def _sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
