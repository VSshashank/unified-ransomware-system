## 24. `--restore` could not return the file the simulator was killed on (F3)

Left open by the full VM test of 2026-10-05 (F3 in
`reports/VM_TEST_REPORT_2026-10-05_dc089ff.md`).

**What was wrong:** `scripts/ransomware_simulator.py` said "Originals are kept,
so `--restore` puts the directory back exactly". That was not true for the one
file in flight when the process died.

**Measured:** on the VM, `grinder` was killed by the response engine and
`--restore` returned 9 of 10 files. The one it did not return was
`quarterly_report_03.jpg`, the file being rewritten at the time. On this branch,
a test that stops each of the 13 families inside the second decoy's rewrite
(after half of a `write_bytes`, or just before a rename or delete, or just before
the manifest update) and then restores found the directory not byte-identical for
all 13 families, at every step that leaves the file half written or renamed.

**Cause:** `--restore` undid a run by decrypting the files the manifest listed,
and the manifest listed a file only after its encryption had finished. A process
killed during `write_bytes` left a partial file that no manifest entry described
and that `decrypt` cannot undo (a half-written XOR is not a keystream XOR of
anything). `copycat`, `spoofer`, `locker` and `renamer` had a second form of the
same fault: killed between the rewrite and the manifest update, the new file
(`.enc`, `.zip`, `.locked`, a random hex name) was on disk and in no entry, so
restore left it behind.

**What changed** (`scripts/ransomware_simulator.py` only):
- Before the first rewrite, every original is copied to a directory **outside the
  target** (`<save root>/urds-sim-<run id>/`, with a `journal.json` beside the
  copies). The default save root is `<system temp>/urds-simulator-originals`;
  `--save-dir` or `URDS_SIMULATOR_SAVE_ROOT` chooses another. A save root that
  contains the target, or that the target contains, is refused. The copies are
  made once, up front, so the encryption loop does nothing new inside the watched
  directory and the pace is not touched.
- The journal records each file as `pending`, `in_flight` or `done`, with the
  SHA-256 of its saved copy. A file is marked `in_flight` before its encryptor is
  called; the previous file is marked `done` in the same atomic write
  (`os.replace`). The journal exists only once every copy is complete.
- The manifest in the target gains one key, `saved_dir`. `entries`, `family`,
  `extra` and the order and number of manifest writes are unchanged, so
  `simulator_sweep.py`, `test_tc01_simulator.py` and `test_tc13_simulator_families.py`
  read it as before.
- `--restore` puts back every `in_flight` or `done` file from its saved copy
  (checksum-verified) and deletes every name that file could have become:
  the manifest's `encrypted` name plus `FAMILY_OUTPUTS` for the families that
  rename or copy (`.locked`, `.enc`, `.zip`, the `renamer` hex name). It then
  removes `extra` files as before, and finally the saved copies, naming each file
  from the journal rather than deleting a directory tree.
- **Fallbacks keep every old reader:** a manifest with no `saved_dir` (legacy
  `files` manifests, v2 manifests from before this fix) and a run whose saved
  copy is missing or fails its checksum take the old decrypt path, unchanged.
- **Guards kept:** only files the script created (the marker check) and the
  refusal of a non-empty foreign directory are unchanged. Restore also now acts
  only on bare file names (a tampered journal or manifest naming `../x` is
  ignored), and only on a journal whose name, shape and recorded target match.
- Saved copies of a run that was killed and then deleted (a test's temp dir, a
  sweep's work dir) would pile up in the save root, so each new run first
  prunes saved directories whose journal names a target that is gone or whose
  manifest no longer points at them. A run in progress is never pruned (its
  manifest is written before its saved directory exists), and only
  `urds-sim-*` directories holding a journal are touched.
- The module docstring no longer promises more than this.

**Tests:** `services/monitor/tests/test_simulator_interrupt_restore.py` (38),
plus `simulator_ops_golden.json` beside it. No process is killed and nothing
sleeps: a `BaseException` is raised from inside patched `Path.write_bytes`
(after half the bytes), `rename`, `unlink` and the manifest update, and
`time.sleep` is a no-op. The cases:
- all 13 families: interrupt at **every** operation of the second decoy's
  rewrite and at the manifest update after it (grinder: 7 points, staged: 3,
  notedrop and poisoner include the note and the poison files), `--restore`, and
  the directory must equal the original decoys exactly (no missing, extra or
  changed file);
- `grinder` and `staged` torn mid-write specifically, asserting the interrupt
  really left the file changed before restoring;
- restore removes the saved copies and the `notedrop`/`poisoner` extras;
- the originals are saved outside the target;
- a foreign file still refuses the run and nothing is saved; restore leaves a
  bystander file alone; a tampered journal cannot write outside the target;
- legacy `files` manifest and v2 manifest without `saved_dir` still restore;
  no manifest is still a no-op;
- the real command line restores a torn run, and refuses a `--save-dir` inside
  the target;
- orphaned saved copies are pruned, a live torn run's are kept, a stranger's
  folder is untouched;
- **the operations in the watched directory are unchanged**: for each family
  (`--files 3`), the ordered list of writes (with sizes), renames, deletes and
  manifest writes inside the target equals a golden list recorded on the base
  commit, before any change.

**19 of 38 fail on `dc089ff`** (the 13 interrupt cases, `grinder`/`staged` mid-write,
the saved-outside-the-target case, the tampered-journal case, the CLI case, the
pruning case). The other 19 pass on both, by design: the 13 golden pins, the
foreign-directory refusal, the bystander, the legacy and v2 manifests, the
no-manifest no-op and the extras case. On base, for example:

    AssertionError: grinder did not restore byte-identical:
      torn at ['write_bytes', 'quarterly_report_01.xlsx', 34016]: missing=[] extra=[] changed=['quarterly_report_01.xlsx']
      ... (the same at each of the six writes, and at the manifest update)

All 38 pass now, three runs in a row (11.6, 11.9 and 12.8 s). The simulator's
existing tests (`test_tc01_simulator.py`, `test_tc13_simulator_families.py`,
`test_tc13_suppression_e2e.py`, `test_tc17_pasted_header.py`: 67) pass before and
after, unedited. `scripts/simulator_sweep.py --files 8` drives the real detection
path in-process against a watchdog on a temp directory and needs no elevation:
after the change it reports 13/13 detected, 13 within 2.0 s, and `restore ok` for
all 13 (`URDS_WRITE_REPORTS` unset, nothing written to `reports/`).

**Not changed:**
- The pace, the families, the target, and every byte and every operation the
  simulator performs inside the watched directory. The only additions are outside
  it: the saved copies (once, before the first rewrite) and one journal write per
  file.
- `simulator_sweep.py` (needed no change).
- `scripts/phase5_baseline.py` and `scripts/artefact_manifest.py` hash this
  script; `reports/artefact_manifest.json` must be regenerated at integration.
- What this does not cover: a power loss or a kill of the OS between the write
  and its flush. The copies are written and closed, not `fsync`ed.
- A run that is killed and never restored leaves its copies in the save root
  until the next run prunes them, or until `--restore` is run.

**Check on Windows:** run `grinder` and `staged` against the live Monitor with
the response engine on, so each is killed mid-run, then
`ransomware_simulator.py --target-dir <dir> --restore`: all 10 files
byte-identical against `pre_attack_manifest`, no `.enc`/`.locked`/`.zip` or hex
file left, and the `urds-sim-*` folder gone from
`%TEMP%\urds-simulator-originals`. Then `simulator_sweep.py` elevated: 13/13
detected, the same `files_encrypted` per family as the 2026-10-05 recording.
