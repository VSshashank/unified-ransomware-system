"""F3 / defect 24 - the simulator's `--restore` after the process is killed mid-rewrite.

The module docstring of `scripts/ransomware_simulator.py` promised "Originals are
kept, so `--restore` puts the directory back exactly". It was false for the one
file that was in flight when the process died: the manifest only recorded a file
after its encryption had finished, so an in-place family killed halfway through
`write_bytes` left a partial file that `decrypt` cannot undo (the VM saw
`grinder` restore 9 of 10).

Nothing here kills a real process and nothing sleeps. The interruption is a
`BaseException` raised from inside a patched `Path.write_bytes` / `rename` /
`unlink`, after half of the bytes have been written, at **every** step of the
second decoy's rewrite and at the manifest update that follows it. That is the
same state a `taskkill` leaves, reproducible and deterministic, and it covers all
thirteen families.

The last group pins what must NOT change: the sequence of operations the
simulator performs inside the watched directory (the golden file was recorded on
the base commit, before the fix), so detection measurements are unaffected by
where the originals are saved.
"""

import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import ransomware_simulator as sim  # noqa: E402

FILES = 3
GOLDEN = Path(__file__).with_name("simulator_ops_golden.json")
ALL_FAMILIES = sorted(sim.FAMILIES)


class Killed(BaseException):
    """Stands in for the process being killed: nothing in the simulator may catch it."""


def _norm(path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


class OpRecorder:
    """Records, and optionally tears, the operations the simulator does in `target`."""

    def __init__(self, target: Path):
        self.target = _norm(target)
        self.ops: list[list] = []
        self.manifest_writes = 0
        self.tear_at: int | None = None  # global op index to die on
        self.phase_ops: list[int] = []  # op indexes belonging to the second decoy

    def _mine(self, path) -> bool:
        return _norm(Path(path).parent) == self.target

    def _step(self, entry: list) -> bool:
        index = len(self.ops)
        self.ops.append(entry)
        return self.tear_at == index

    def install(self, monkeypatch):
        recorder = self
        real_write_bytes = Path.write_bytes
        real_write_text = Path.write_text
        real_rename = Path.rename
        real_unlink = Path.unlink

        def write_bytes(path, data):
            if not recorder._mine(path):
                return real_write_bytes(path, data)
            entry = ["write_bytes", path.name, len(data)]
            if recorder.manifest_writes == 2:
                recorder.phase_ops.append(len(recorder.ops))
            if recorder._step(entry):
                real_write_bytes(path, bytes(data)[: max(1, len(data) // 2)])
                raise Killed(f"killed mid write_bytes of {path.name}")
            return real_write_bytes(path, data)

        def write_text(path, data, *args, **kwargs):
            if not recorder._mine(path):
                return real_write_text(path, data, *args, **kwargs)
            entry = ["write_text", path.name]
            if recorder.manifest_writes == 2:
                recorder.phase_ops.append(len(recorder.ops))
            recorder.manifest_writes += 1
            if recorder._step(entry):
                raise Killed("killed before the manifest update")
            return real_write_text(path, data, *args, **kwargs)

        def rename(path, target):
            if not recorder._mine(path):
                return real_rename(path, target)
            if recorder.manifest_writes == 2:
                recorder.phase_ops.append(len(recorder.ops))
            if recorder._step(["rename", path.name]):
                raise Killed(f"killed before renaming {path.name}")
            return real_rename(path, target)

        def unlink(path, *args, **kwargs):
            if not recorder._mine(path):
                return real_unlink(path, *args, **kwargs)
            if recorder.manifest_writes == 2:
                recorder.phase_ops.append(len(recorder.ops))
            if recorder._step(["unlink", path.name]):
                raise Killed(f"killed before deleting {path.name}")
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "write_bytes", write_bytes)
        monkeypatch.setattr(Path, "write_text", write_text)
        monkeypatch.setattr(Path, "rename", rename)
        monkeypatch.setattr(Path, "unlink", unlink)
        monkeypatch.setattr(time, "sleep", lambda seconds: None)


def run_simulator(monkeypatch, target: Path, family: str, tear_at: int | None = None) -> OpRecorder:
    """Run main() in-process; returns the recorder. A tear raises Killed to the caller."""
    recorder = OpRecorder(target)
    recorder.tear_at = tear_at
    argv = ["ransomware_simulator.py", "--target-dir", str(target), "--files", str(FILES),
            "--delay-ms", "0", "--family", family]
    with monkeypatch.context() as patch:
        patch.setattr(sys, "argv", argv)
        recorder.install(patch)
        try:
            sim.main()
        except Killed:
            pass
    return recorder


def restore(monkeypatch, target: Path) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(sys, "argv", ["ransomware_simulator.py", "--target-dir", str(target), "--restore"])
        patch.setattr(time, "sleep", lambda seconds: None)
        sim.main()


def decoy_bytes(tmp_path: Path) -> dict[str, bytes]:
    """What the decoys are before anything touches them (build_decoys is deterministic)."""
    reference = tmp_path / "reference"
    reference.mkdir(exist_ok=True)
    sim.build_decoys(reference, FILES)
    return {p.name: p.read_bytes() for p in reference.iterdir()}


def listing(target: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in target.iterdir() if p.is_file() and p.name != sim.MANIFEST_NAME}


@pytest.fixture(autouse=True)
def _isolated_save_root(tmp_path, monkeypatch):
    # Where the originals are saved is the simulator's business; keep it under the
    # test's own tmp_path so no test can leave anything in the real temp directory.
    root = tmp_path / "saved-originals-root"
    monkeypatch.setenv("URDS_SIMULATOR_SAVE_ROOT", str(root))
    return root


@pytest.mark.parametrize("family", ALL_FAMILIES)
def test_every_family_restores_byte_identical_after_an_interrupt_at_every_step(
    family, tmp_path, monkeypatch
):
    expected = decoy_bytes(tmp_path)

    # A dry run, to learn which operations belong to the second decoy's rewrite.
    dry = run_simulator(monkeypatch, tmp_path / "dry", family)
    steps = sorted(set(dry.phase_ops))
    assert steps, f"{family}: found no operations for the second decoy"
    restore(monkeypatch, tmp_path / "dry")
    assert listing(tmp_path / "dry") == expected

    failures = []
    for step in steps:
        target = tmp_path / f"{family}-tear-{step}"
        recorder = run_simulator(monkeypatch, target, family, tear_at=step)
        assert len(recorder.ops) == step + 1, f"{family}: the run did not stop at op {step}"
        torn = dry.ops[step]
        restore(monkeypatch, target)
        got = listing(target)
        if got != expected:
            missing = sorted(set(expected) - set(got))
            extra = sorted(set(got) - set(expected))
            changed = sorted(n for n in expected if n in got and got[n] != expected[n])
            failures.append(f"torn at {torn}: missing={missing} extra={extra} changed={changed}")
    assert not failures, f"{family} did not restore byte-identical:\n  " + "\n  ".join(failures)


@pytest.mark.parametrize("family", ["grinder", "staged"])
def test_the_two_families_the_vm_saw_fail_are_torn_mid_write_and_restored(family, tmp_path, monkeypatch):
    """The named cases of F3: the file in flight is a partial write, not just a missing manifest line."""
    expected = decoy_bytes(tmp_path)
    dry = run_simulator(monkeypatch, tmp_path / "dry", family)
    writes = [s for s in sorted(set(dry.phase_ops)) if dry.ops[s][0] == "write_bytes"]
    assert len(writes) >= 2, "this family rewrites its file more than once"
    target = tmp_path / "torn"
    run_simulator(monkeypatch, target, family, tear_at=writes[-1])
    in_flight = target / dry.ops[writes[-1]][1]
    assert in_flight.read_bytes() != expected[in_flight.name], "the interrupt left the file untouched"
    restore(monkeypatch, target)
    assert listing(target) == expected


def test_restore_removes_the_saved_originals_and_the_extra_files(tmp_path, monkeypatch, _isolated_save_root):
    for family in ("notedrop", "poisoner"):
        target = tmp_path / family
        run_simulator(monkeypatch, target, family)
        restore(monkeypatch, target)
        assert sorted(p.name for p in target.iterdir() if p.name != sim.MANIFEST_NAME) == sorted(
            decoy_bytes(tmp_path)
        )
    leftovers = list(_isolated_save_root.rglob("*")) if _isolated_save_root.exists() else []
    assert not [p for p in leftovers if p.is_file()], f"restore left saved copies behind: {leftovers}"


def test_the_originals_are_saved_outside_the_watched_target(tmp_path, monkeypatch, _isolated_save_root):
    target = tmp_path / "watched"
    run_simulator(monkeypatch, target, "silent", tear_at=None)
    # Interrupt a second run to look at the saved state before restore deletes it.
    target2 = tmp_path / "watched2"
    run_simulator(monkeypatch, target2, "silent", tear_at=3)
    saved = [p for p in _isolated_save_root.rglob("*") if p.is_file()]
    assert saved, "nothing was saved before the rewrite"
    for path in saved:
        assert target2.resolve() not in path.resolve().parents, f"{path} is inside the watched target"
        assert target.resolve() not in path.resolve().parents
    assert not [p for p in target2.iterdir() if "saved" in p.name.lower() or "original" in p.name.lower()]


# ---------------------------------------------------------------- safety guards


def test_a_foreign_file_still_refuses_the_run_and_nothing_is_saved(tmp_path, monkeypatch, _isolated_save_root):
    target = tmp_path / "precious"
    target.mkdir()
    precious = target / "taxes.docx"
    precious.write_bytes(b"eight months of work")
    argv = ["ransomware_simulator.py", "--target-dir", str(target), "--files", "3", "--delay-ms", "0"]
    with monkeypatch.context() as patch:
        patch.setattr(sys, "argv", argv)
        assert sim.main() == 2
    assert precious.read_bytes() == b"eight months of work"
    assert sorted(p.name for p in target.iterdir()) == ["taxes.docx"]
    assert not [p for p in _isolated_save_root.rglob("*") if p.is_file()]


def test_restore_never_touches_a_file_the_journal_does_not_name(tmp_path, monkeypatch):
    target = tmp_path / "t"
    run_simulator(monkeypatch, target, "silent", tear_at=5)
    bystander = target / "notes.txt"
    bystander.write_bytes(b"not ours")
    restore(monkeypatch, target)
    assert bystander.read_bytes() == b"not ours"


def test_a_tampered_journal_cannot_write_outside_the_target(tmp_path, monkeypatch, _isolated_save_root):
    target = tmp_path / "t"
    run_simulator(monkeypatch, target, "silent", tear_at=5)
    journals = list(_isolated_save_root.rglob("journal.json"))
    assert journals, "the simulator keeps a journal beside the saved originals"
    journal = json.loads(journals[0].read_text())
    victim = tmp_path / "outside.txt"
    victim.write_bytes(b"outside the target")
    first = next(iter(journal["originals"]))
    journal["originals"]["../outside.txt"] = dict(journal["originals"][first])
    journals[0].write_text(json.dumps(journal))
    restore(monkeypatch, target)
    assert victim.read_bytes() == b"outside the target"


# ----------------------------------------------------------- legacy manifests


def test_a_legacy_manifest_without_saved_originals_still_restores(tmp_path, monkeypatch):
    """Runs from before manifest v2 (and before this fix) have only `files` / `entries`."""
    target = tmp_path / "legacy"
    target.mkdir()
    seed = b"tc01-simulator"
    originals = sim.build_decoys(target, 3)
    expected = {p.name: p.read_bytes() for p in originals}
    for path in originals:
        path.write_bytes(sim._xor(path.read_bytes(), seed))
        path.rename(path.with_suffix(path.suffix + ".locked"))
    (target / sim.MANIFEST_NAME).write_text(json.dumps({"files": sorted(expected)}))
    restore(monkeypatch, target)
    assert listing(target) == expected


def test_a_v2_manifest_without_saved_originals_still_restores_finished_files(tmp_path, monkeypatch):
    target = tmp_path / "v2"
    target.mkdir()
    seed = b"tc01-simulator"
    originals = sim.build_decoys(target, 3)
    expected = {p.name: p.read_bytes() for p in originals}
    entries = []
    for path in originals:
        path.write_bytes(sim._xor(path.read_bytes(), seed))
        entries.append({"original": path.name, "encrypted": path.name})
    (target / sim.MANIFEST_NAME).write_text(json.dumps({"family": "silent", "entries": entries, "extra": []}))
    restore(monkeypatch, target)
    assert listing(target) == expected


def test_restore_on_a_directory_with_no_manifest_is_still_a_no_op(tmp_path, monkeypatch):
    target = tmp_path / "empty"
    target.mkdir()
    (target / "mine.txt").write_bytes(b"hello")
    restore(monkeypatch, target)
    assert (target / "mine.txt").read_bytes() == b"hello"


# ------------------------------------------- what the watched directory sees


@pytest.mark.parametrize("family", ALL_FAMILIES)
def test_the_operations_in_the_watched_directory_are_unchanged(family, tmp_path, monkeypatch):
    """Same files, same operations, same order, same sizes as before the fix.

    The golden sequence was recorded on the base commit. Saving the originals
    must not add a write, a rename or a delete inside the watched tree, or the
    detection measurements (and the 13/13 sweep) would be measuring something else.
    """
    golden = json.loads(GOLDEN.read_text())
    assert sorted(golden) == ALL_FAMILIES
    recorder = run_simulator(monkeypatch, tmp_path / "w", family)
    ops = [list(op) for op in recorder.ops]
    # The manifest is the one file whose bytes legitimately differ (it now names the
    # saved copies), so its size is not part of the pin; its position and count are.
    assert ops == golden[family]


# ---------------------------------------------------------------- the real CLI


def test_the_command_line_restores_a_torn_run_and_refuses_a_save_dir_inside_the_target(
    tmp_path, monkeypatch
):
    import subprocess

    expected = decoy_bytes(tmp_path)
    target = tmp_path / "cli"
    run_simulator(monkeypatch, target, "grinder", tear_at=12)
    script = str(REPO_ROOT / "scripts" / "ransomware_simulator.py")
    done = subprocess.run(
        [sys.executable, script, "--target-dir", str(target), "--restore"],
        capture_output=True, text=True, timeout=60,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert listing(target) == expected

    refused = subprocess.run(
        [sys.executable, script, "--target-dir", str(tmp_path / "t2"), "--save-dir", str(tmp_path / "t2" / "saves")],
        capture_output=True, text=True, timeout=60,
    )
    assert refused.returncode == 2 and "refusing to run" in refused.stdout
    assert not (tmp_path / "t2").exists() or not any((tmp_path / "t2").iterdir())


# ------------------------------------------------------------ saved-copy hygiene


def test_saved_copies_of_a_deleted_run_are_pruned_and_a_live_run_is_kept(
    tmp_path, monkeypatch, _isolated_save_root
):
    import shutil

    live = tmp_path / "live"
    dead = tmp_path / "dead"
    run_simulator(monkeypatch, live, "silent", tear_at=5)
    run_simulator(monkeypatch, dead, "silent", tear_at=5)
    stranger = _isolated_save_root / "somebody-elses-folder"
    stranger.mkdir()
    (stranger / "keep.txt").write_bytes(b"not ours")
    assert len(list(_isolated_save_root.glob("urds-sim-*"))) == 2

    shutil.rmtree(dead)  # killed, then the directory was simply deleted
    run_simulator(monkeypatch, tmp_path / "next", "silent")  # any later run prunes

    kept = [json.loads((p / "journal.json").read_text())["target"] for p in _isolated_save_root.glob("urds-sim-*")]
    assert any(Path(t) == live for t in kept), "the live torn run lost its saved originals"
    assert not any(Path(t) == dead for t in kept), "the deleted run's copies were not pruned"
    assert (stranger / "keep.txt").read_bytes() == b"not ours"
    restore(monkeypatch, live)
    assert listing(live) == decoy_bytes(tmp_path)
