"""The simulator's `--restore` when the manifest itself was torn by the kill.

The manifest is rewritten in place after every encrypted file, so a process killed
inside one of those writes leaves it truncated or empty. On the 2026-10-06 VM run
the freeze-first kill landed there for `spoofer` and `--restore` died with a
JSON error (rc 1) and left the directory encrypted.

The writes into the watched target are deliberately unchanged (the golden sequence
in `test_simulator_interrupt_restore.py` pins them, and they are what the Monitor
measures). The fix is on the restore side: a torn manifest is rebuilt from the
journal beside the saved originals, which is replaced atomically.

Nothing here kills a real process and nothing sleeps.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).parent))

import ransomware_simulator as sim  # noqa: E402
from test_simulator_interrupt_restore import (  # noqa: E402
    ALL_FAMILIES,
    decoy_bytes,
    listing,
    restore,
    run_simulator,
)


@pytest.fixture(autouse=True)
def _isolated_save_root(tmp_path, monkeypatch):
    root = tmp_path / "saved-originals-root"
    monkeypatch.setenv("URDS_SIMULATOR_SAVE_ROOT", str(root))
    return root


TEARS = {
    "empty": lambda raw: b"",
    "half": lambda raw: raw[: max(1, len(raw) // 2)],
    "garbage": lambda raw: b"\x00\x00\x00",
}


@pytest.mark.parametrize("tear", sorted(TEARS))
@pytest.mark.parametrize("family", ALL_FAMILIES)
def test_a_torn_manifest_restores_byte_identical(family, tear, tmp_path, monkeypatch):
    expected = decoy_bytes(tmp_path)
    dry = run_simulator(monkeypatch, tmp_path / "dry", family)
    steps = sorted(set(dry.phase_ops))
    target = tmp_path / "torn"
    run_simulator(monkeypatch, target, family, tear_at=steps[len(steps) // 2])
    manifest = target / sim.MANIFEST_NAME
    manifest.write_bytes(TEARS[tear](manifest.read_bytes()))

    restore(monkeypatch, target)

    assert listing(target) == expected


def test_a_second_restore_after_a_torn_one_is_a_no_op(tmp_path, monkeypatch):
    expected = decoy_bytes(tmp_path)
    target = tmp_path / "torn"
    run_simulator(monkeypatch, target, "spoofer", tear_at=6)
    (target / sim.MANIFEST_NAME).write_bytes(b"")
    restore(monkeypatch, target)
    restore(monkeypatch, target)
    assert listing(target) == expected


def test_a_torn_manifest_with_no_saved_originals_fails_cleanly_not_with_a_traceback(
    tmp_path, monkeypatch, capsys
):
    target = tmp_path / "torn"
    run_simulator(monkeypatch, target, "spoofer", tear_at=6)
    (target / sim.MANIFEST_NAME).write_bytes(b"")
    for leftover in (tmp_path / "saved-originals-root").rglob("*"):
        if leftover.is_file():
            leftover.unlink()
    with monkeypatch.context() as patch:
        patch.setattr(sys, "argv", ["ransomware_simulator.py", "--target-dir", str(target), "--restore"])
        assert sim.main() == 1
    assert "cannot restore" in capsys.readouterr().out


def test_only_the_journal_for_this_target_is_used(tmp_path, monkeypatch):
    mine, other = tmp_path / "mine", tmp_path / "other"
    run_simulator(monkeypatch, mine, "copycat", tear_at=6)
    run_simulator(monkeypatch, other, "copycat", tear_at=6)
    other_before = listing(other)
    (mine / sim.MANIFEST_NAME).write_bytes(b"")
    restore(monkeypatch, mine)
    assert listing(mine) == decoy_bytes(tmp_path)
    assert listing(other) == other_before, "restoring one target touched another"
