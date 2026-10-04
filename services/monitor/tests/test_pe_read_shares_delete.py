"""The PE parser does not stop anyone deleting or renaming the file (defect 9's residual).

Defect 9 (FIXES.md) made every read the Monitor takes open with
FILE_SHARE_DELETE on Windows, and left one residual: `pefile.PE(path)` in
`pe_features.py` opened and memory-mapped the file itself. For as long as it
parsed, the file could not be deleted. It runs only for on-demand `/features`
analysis, not on file events, so the cost was a delete that failed while an
analysis ran.

Here the file is deleted from inside the parse: `pefile.PE` is wrapped so the
delete happens after the parser has the file, and the wrapper records whether
it succeeded.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pe_features  # noqa: E402

windows_only = pytest.mark.skipif(os.name != "nt", reason="share modes are a Windows concept")
needs_pefile = pytest.mark.skipif(pe_features.pefile is None, reason="pefile is not installed")


def _deleting_parser(monkeypatch, target: Path) -> list:
    """pefile.PE, but the file is deleted once the parser has it."""
    outcomes: list = []

    # A subclass, not a function: pefile reads its own class attributes
    # through the module-level name `PE` while it parses.
    class DeletingPE(pe_features.pefile.PE):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            try:
                os.remove(target)
                outcomes.append("deleted")
            except OSError as exc:
                outcomes.append(exc)

    monkeypatch.setattr(pe_features.pefile, "PE", DeletingPE)
    return outcomes


@pytest.fixture
def copied_pe(tmp_path) -> Path:
    target = tmp_path / "sample.exe"
    shutil.copyfile(sys.executable, target)
    assert pe_features.is_pe(str(target))
    return target


@windows_only
@needs_pefile
def test_a_pe_being_parsed_can_be_deleted(monkeypatch, copied_pe):
    outcomes = _deleting_parser(monkeypatch, copied_pe)

    features = pe_features.extract_pe_features(str(copied_pe))

    assert outcomes == ["deleted"], f"the delete failed while the parser held the file: {outcomes}"
    assert not copied_pe.exists()
    # The parse went on from the bytes already read.
    assert features["is_pe"] == 1
    assert features["pe_file_size"] == os.path.getsize(sys.executable)


@windows_only
@needs_pefile
def test_a_pe_whose_imports_are_being_read_can_be_deleted(monkeypatch, copied_pe):
    outcomes = _deleting_parser(monkeypatch, copied_pe)

    pe_features.suspicious_api_names(str(copied_pe))

    assert outcomes == ["deleted"], f"the delete failed while the parser held the file: {outcomes}"
