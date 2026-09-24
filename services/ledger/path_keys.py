"""How a lookup by file path matches a block, in any spelling - defect 4.

The Windows integration test found recovery verification depending on how a
path was spelled. The Monitor had stored

    C:/URDS-main/watched_files\\tc01\\file.docx

- the watch path was posted with forward slashes, and watchdog joins with
backslashes - and `GET /ledger/blocks?file_path=` matched only that exact
spelling. So `POST /response/recover` with

    C:\\URDS-main\\watched_files\\tc01\\file.docx

- the spelling anyone would type - restored the right bytes and then reported
`partial`: "No prior hash for this path in the ledger". The ledger knew the
hash. It could not find it.

The Monitor now stores one spelling (normpath of the absolute path). That
fixes new rows only, and the rows already on the chain cannot be rewritten:
`event_data` is inside each block's hash, and this service has no update path
on purpose. So lookups compare *keys* derived from the stored path, and
nothing about how a row is stored changes.

WHY A COMPUTED KEY AND NOT A `path_key` COLUMN

A non-hashed, indexed `path_key` column would make the lookup an index probe.
Two things rule it out here:

  * The rows already on the chain would need it filled in - an UPDATE of every
    existing row. This service has no update path, and adding one to an
    append-only audit store to serve a read is the wrong trade.
  * It would sit outside the chain. `verify_chain` hashes `event_data`, not a
    side column, so anyone able to edit the database file could re-point a
    `path_key` - aim recovery's reference hash at another file's block - and
    the chain would still verify. Recovery trusts what this lookup returns;
    deriving the match from `event_data` means every block it returns names
    the path in hashed, verified bytes.

The cost is a broader SQL prefilter (the file's name, which every spelling
shares) and a Python comparison of the candidates. At this ledger's scale -
the benchmarks run on 1,000 blocks - that is a few decoded rows per lookup.
If it ever is not, the answer is a derived index table rebuilt from
`event_data` at startup, which can be regenerated and so cannot be trusted
over the chain; not a column the chain does not cover.

THE CASE POLICY

A path is compared as a Windows path when it looks like one - a drive letter
or a UNC prefix - and as a POSIX path otherwise. That is decided by the path,
not by the OS this runs on: the ledger runs in a Linux container and is asked
about files on a Windows host.

  * Windows: `\\\\?\\` prefix dropped, `/` and `\\` equivalent, `.` and `..`
    resolved (ntpath.normpath), then `lower()`. NTFS compares names through a
    one-to-one upcase table, so `lower()` is the nearer model; `casefold()`
    would also equate `straße` with `strasse`, which NTFS keeps apart. A
    directory made case-sensitive (fsutil setCaseSensitiveInfo, used by WSL)
    is the residual: two files differing only in case there share a key.
    The worst that does to recovery is compare a restored file against the
    other file's hash and report the mismatch - a false alarm, never a false
    pass, because the check is a hash comparison.
  * POSIX: posixpath.normpath only. Case-sensitive, as the filesystem is.
"""

from __future__ import annotations

import ntpath
import posixpath
import re

from database import json_fragment

_DRIVE = re.compile(r"^[A-Za-z]:(?:[\\/]|$)")
_SEPARATORS = re.compile(r"[\\/]")


def _like_escape(value: str) -> str:
    """Escape LIKE wildcards so a path containing % or _ can't widen the match."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def is_windows_path(path: str) -> bool:
    """A drive-letter or UNC path (`\\\\server\\share`, or `//server/share`)."""
    return bool(_DRIVE.match(path)) or path.startswith(("\\\\", "//"))


def path_key(path: object) -> str | None:
    """The form every spelling of one file shares. Compared, never stored.

    None for anything that is not a non-empty string, so a block without a
    `file_path` never matches a lookup.
    """
    if not isinstance(path, str) or not path:
        return None
    if is_windows_path(path):
        spelled = path.replace("/", "\\")
        if spelled.startswith("\\\\?\\UNC\\"):
            spelled = "\\\\" + spelled[len("\\\\?\\UNC\\"):]
        elif spelled.startswith("\\\\?\\"):
            spelled = spelled[len("\\\\?\\"):]
        return ntpath.normpath(spelled).lower()
    return posixpath.normpath(path)


def same_file(stored: object, key: str | None) -> bool:
    """Whether a block's stored `file_path` names the file `key` was made from."""
    return key is not None and path_key(stored) == key


def prefilter(path: str) -> str:
    """A LIKE pattern that every stored spelling of `path` satisfies.

    Only the file's name is common to every spelling - the directories differ in
    separators and case - so the pattern is the name as canonical JSON would
    write it, at the end of a `file_path` value:

        %"file_path":"%quarterly.docx"%

    SQLite's LIKE ignores ASCII case, which covers `Quarterly.DOCX`. It does
    not fold anything else, and canonical JSON writes non-ASCII characters as
    `\\uXXXX` escapes whose digits differ between cases, so each run of them
    becomes a `%`. That can only let more rows through; `same_file` decides.
    """
    key = path_key(path) or ""
    name = _SEPARATORS.split(key)[-1]
    body: list[str] = []
    for char in name:
        if ord(char) < 128:
            body.append(_like_escape(json_fragment(char)))
        elif not body or body[-1] != "%":
            body.append("%")
    return '%"file_path":"%' + "".join(body) + '"%'
