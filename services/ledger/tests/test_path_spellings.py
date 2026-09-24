"""Defect 4 of the Windows integration test: a lookup depended on how the path was spelled.

The Monitor stored `C:/URDS-main/watched_files\\tc01\\file.docx` - the watch
path posted with forward slashes, watchdog joining with backslashes - and
`GET /ledger/blocks?file_path=` matched only that exact spelling. Recovery,
asked about `C:\\URDS-main\\watched_files\\tc01\\file.docx`, found no prior
hash and reported `partial` for a file it had restored byte for byte.

What has to hold, each asserted below:

    1. every spelling of one file finds its blocks - mixed, backslash,
       forward slash, different case, `.`/`..`, `\\\\?\\` - including blocks
       stored in the old mixed form                                      (a)
    2. no spelling finds another file's blocks                           (b)
    3. POSIX paths stay case-sensitive                                   (c)
    4. paging and `total` count matches, not prefilter hits              (d)
    5. nothing stored changes: the rows and the chain are as they were   (e)

These run the same on Linux and Windows: whether a path is compared as a
Windows path is decided by its shape, because the ledger runs in a Linux
container and is asked about files on a Windows host.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main  # noqa: E402
from hash_chain import HashChainLedger  # noqa: E402
from path_keys import is_windows_path, path_key, prefilter  # noqa: E402

# Exactly what the VM's Monitor stored: posted watch path, watchdog's tail.
RECORDED = "C:/URDS-main/watched_files\\tc01\\file.docx"
TYPED = "C:\\URDS-main\\watched_files\\tc01\\file.docx"

SAME_FILE = [
    pytest.param(RECORDED, id="recorded-mixed"),
    pytest.param(TYPED, id="backslash"),
    pytest.param("C:/URDS-main/watched_files/tc01/file.docx", id="forward-slash"),
    pytest.param("c:\\urds-main\\WATCHED_FILES\\TC01\\FILE.DOCX", id="different-case"),
    pytest.param("C:\\URDS-main\\watched_files\\tc01\\..\\tc01\\.\\file.docx", id="dot-segments"),
    pytest.param("C:\\URDS-main\\\\watched_files\\tc01\\file.docx", id="doubled-separator"),
    pytest.param("\\\\?\\C:\\URDS-main\\watched_files\\tc01\\file.docx", id="verbatim-prefix"),
]


@pytest.fixture
def ledger(tmp_path):
    chain = HashChainLedger(str(tmp_path / "ledger.db"))
    yield chain
    chain.close()


@pytest.fixture
def client(ledger):
    main.app.dependency_overrides[main.get_ledger] = lambda: ledger
    with TestClient(main.app) as test_client:
        yield test_client
    main.app.dependency_overrides.clear()


def _baseline(ledger, path: str, digest: str = "a" * 64) -> dict:
    return ledger.add_block("file_baseline", {"file_path": path, "file_hash": digest})


def _rows(db_path: str) -> list[tuple]:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT * FROM blocks ORDER BY id").fetchall()
    finally:
        conn.close()


# --------------------------------------------------- (a) every spelling finds it


@pytest.mark.parametrize("spelling", SAME_FILE)
def test_a_every_spelling_finds_a_block_stored_in_the_old_mixed_form(ledger, spelling):
    _baseline(ledger, RECORDED)

    page = ledger.get_blocks(file_path=spelling)

    assert page["total"] == 1
    assert page["blocks"][0]["event_data"]["file_path"] == RECORDED  # as stored, untouched


@pytest.mark.parametrize("spelling", SAME_FILE)
def test_a_every_spelling_finds_a_block_stored_in_the_normalised_form(ledger, spelling):
    _baseline(ledger, TYPED)

    assert ledger.get_blocks(file_path=spelling)["total"] == 1


def test_a_one_file_under_several_spellings_is_one_history(ledger):
    """Rows from before and after the Monitor normalised: one file, three rows."""
    _baseline(ledger, RECORDED, "a" * 64)
    ledger.add_block("file_event", {"file_path": TYPED, "file_hash": "b" * 64})
    ledger.add_block("file_recovered", {"file_path": "c:/urds-main/watched_files/tc01/file.docx", "file_hash": "a" * 64})

    page = ledger.get_blocks(file_path=TYPED, newest_first=True)

    assert page["total"] == 3
    assert [b["event_type"] for b in page["blocks"]] == ["file_recovered", "file_event", "file_baseline"]


def test_a_non_ascii_names_match_in_either_case_on_a_windows_path(ledger):
    """Canonical JSON writes these as \\uXXXX escapes, whose digits differ by case."""
    _baseline(ledger, "C:\\Données\\Été 2026\\Rapport-Été.docx")

    assert ledger.get_blocks(file_path="c:/données/été 2026/rapport-été.docx")["total"] == 1
    assert ledger.get_blocks(file_path="C:\\DONNÉES\\ÉTÉ 2026\\RAPPORT-ÉTÉ.DOCX")["total"] == 1


def test_a_unc_paths_match_across_separators_and_the_verbatim_form(ledger):
    _baseline(ledger, "\\\\fileserver\\finance\\q3\\ledger.xlsx")

    for spelling in (
        "//fileserver/finance/q3/ledger.xlsx",
        "\\\\FILESERVER\\Finance\\Q3\\Ledger.xlsx",
        "\\\\?\\UNC\\fileserver\\finance\\q3\\ledger.xlsx",
    ):
        assert ledger.get_blocks(file_path=spelling)["total"] == 1, spelling


def test_a_the_api_matches_any_spelling(client):
    client.post("/ledger/log", json={"event_type": "file_baseline", "event_data": {"file_path": RECORDED, "file_hash": "c" * 64}})

    body = client.get("/ledger/blocks", params={"file_path": TYPED}).json()

    assert body["total"] == 1
    assert body["blocks"][0]["event_data"]["file_hash"] == "c" * 64


# ------------------------------------------------ (b) never another file's blocks


@pytest.mark.parametrize(
    "other",
    [
        pytest.param("C:\\URDS-main\\watched_files\\tc02\\file.docx", id="same-name-other-folder"),
        pytest.param("C:\\URDS-main\\watched_files\\tc01\\file.docx.bak", id="longer-name"),
        pytest.param("C:\\URDS-main\\watched_files\\tc01\\myfile.docx", id="name-ending-the-same"),
        pytest.param("D:\\URDS-main\\watched_files\\tc01\\file.docx", id="other-drive"),
        pytest.param("/URDS-main/watched_files/tc01/file.docx", id="posix-path-with-the-same-tail"),
    ],
)
def test_b_a_different_file_is_never_matched(ledger, other):
    _baseline(ledger, RECORDED)

    assert ledger.get_blocks(file_path=other)["blocks"] == []


def test_b_ntfs_keeps_strasse_and_strasse_with_eszett_apart_and_so_does_this(ledger):
    """`casefold()` would equate them; NTFS's one-to-one upcase table does not."""
    _baseline(ledger, "C:\\docs\\straße.docx")

    assert ledger.get_blocks(file_path="C:\\docs\\strasse.docx")["blocks"] == []


def test_b_like_wildcards_in_a_name_still_do_not_widen_the_match(ledger):
    _baseline(ledger, "C:\\data\\real.doc")
    _baseline(ledger, "C:\\data\\r_al.doc")

    assert ledger.get_blocks(file_path="C:\\data\\%.doc")["blocks"] == []
    assert [b["event_data"]["file_path"] for b in ledger.get_blocks(file_path="c:/data/R_AL.doc")["blocks"]] == [
        "C:\\data\\r_al.doc"
    ]


def test_b_a_block_with_no_file_path_never_matches(ledger):
    ledger.add_block("snapshot_created", {"snapshot_id": "snap_1", "note": "file.docx"})
    ledger.add_block("analysis", {"file_path": None})

    assert ledger.get_blocks(file_path=TYPED)["blocks"] == []


# ---------------------------------------------------- (c) POSIX stays case-sensitive


def test_c_posix_paths_are_compared_case_sensitively(ledger):
    ledger.add_block("file_baseline", {"file_path": "/watch/Report.doc", "file_hash": "d" * 64})
    ledger.add_block("file_baseline", {"file_path": "/watch/report.doc", "file_hash": "e" * 64})

    page = ledger.get_blocks(file_path="/watch/report.doc")

    assert page["total"] == 1
    assert page["blocks"][0]["event_data"]["file_hash"] == "e" * 64


def test_c_posix_paths_still_normalise_separators_and_dots(ledger):
    _baseline(ledger, "/watch/sub/report.doc")

    for spelling in ("/watch//sub/report.doc", "/watch/./sub/report.doc", "/watch/other/../sub/report.doc"):
        assert ledger.get_blocks(file_path=spelling)["total"] == 1, spelling


def test_c_the_shape_decides_not_the_host():
    assert is_windows_path("C:\\a") and is_windows_path("c:/a") and is_windows_path("\\\\srv\\share")
    assert not is_windows_path("/watch/a.doc")
    assert path_key("C:/A/B.DOCX") == path_key("c:\\a\\b.docx")
    assert path_key("/A/B.DOCX") != path_key("/a/b.docx")
    assert path_key(None) is None and path_key("") is None


# ------------------------------------------------- (d) paging counts matches


def test_d_paging_and_total_count_matches_not_prefilter_hits(ledger):
    """Another folder's `file.docx` passes the name prefilter and must not be counted."""
    for index in range(6):
        _baseline(ledger, RECORDED if index % 2 == 0 else TYPED, f"{index:064d}")
        _baseline(ledger, "C:\\elsewhere\\file.docx", "f" * 64)

    first = ledger.get_blocks(file_path=TYPED, limit=4)
    second = ledger.get_blocks(file_path=TYPED, offset=4, limit=4)

    assert first["total"] == second["total"] == 6
    assert len(first["blocks"]) == 4 and len(second["blocks"]) == 2
    hashes = [b["event_data"]["file_hash"] for b in first["blocks"] + second["blocks"]]
    assert hashes == [f"{index:064d}" for index in range(6)]


def test_d_the_prefilter_is_the_name_at_the_end_of_a_file_path_value():
    assert prefilter(TYPED) == '%"file_path":"%file.docx"%'
    assert prefilter("C:\\data\\100%_done.doc") == '%"file_path":"%100\\%\\_done.doc"%'
    assert prefilter("C:\\Été\\Été.docx") == '%"file_path":"%%t%.docx"%'


# ----------------------------------------------------- (e) nothing stored changes


def test_e_lookups_change_no_row_and_the_chain_still_verifies(ledger):
    _baseline(ledger, RECORDED)
    ledger.add_block("file_event", {"file_path": TYPED, "file_hash": "b" * 64})
    before = _rows(ledger.db_path)

    for spelling in (RECORDED, TYPED, "c:/urds-main/watched_files/tc01/file.docx"):
        ledger.get_blocks(file_path=spelling)

    assert _rows(ledger.db_path) == before
    assert ledger.verify_chain()["valid"] is True
