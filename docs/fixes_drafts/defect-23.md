## 23. The demo recorded the wrong PID and matched the wrong events (R14(b))

Seen in the 2026-10-05 VM run (`VM_TEST_REPORT_2026-10-05_dc089ff.md`, fault 1
second half). The system's own `certain` answer was right in all four runs; the
demo's bookkeeping was wrong, in two independent ways.

**What was wrong** (`scripts/attack_chain_demo.py`):
- `Writer.pid` was `Popen(...).pid`. From a venv `sys.executable` is
  `.venv\Scripts\python.exe`, a launcher that starts the base interpreter as a
  child. The system named and killed the process that ran the code; the demo
  judged it against the launcher's PID. TC-07 failed with "WRONG PROCESS" on a
  correct attribution.
- Events, ledger blocks and the probe and control files were found with
  `file_path.endswith(<file name>)`, in five places. Every run writes
  `annual_report.docx.locked`, so an earlier run's event for that name in
  another folder was judged as this run's (the system named 4272; the demo also
  counted 8240 from the earlier folder).

**Measured:**
- On the VM, earlier: `Popen(...).pid = 11800`, the child's `os.getpid() =
  11756`.
- Here, on base (`dc089ff`), with `C:\urds-venv` as the launcher: the PID the
  `Writer` reports has a child process of its own, i.e. it is the launcher
  (`_is_leaf(9688)` is false in the failing run below).

**Cause:** the demo asked the OS who it had started, not the process that did the
writing; and it identified "this run's file" by a suffix that every run shares.

**What changed** (`scripts/attack_chain_demo.py` only; attribution untouched):
- The writer prints `WROTE <sha256> <os.getpid()>`. `Writer.pid` is that PID,
  right for any launcher. It is not solved with `sys._base_executable`, which
  would fix one launcher and leave the demo trusting the OS's answer.
  `Writer.process` stays as the handle that watches for the writer's exit
  (`finish`, `exited_at`). A line that does not carry three fields, the last a
  number, raises as before.
- `Writer` takes an optional `interpreter` argv prefix (default
  `[sys.executable]`) so a test can put a launcher of its own in front.
- One helper, `is_this_runs_event(event_path, event_hash, expected_path,
  expected_hash)`, replaces all five `endswith` uses (control, victim detection,
  pipeline, ledger blocks, closed events for TC-07, and the probe). It matches
  the **full path**, `normpath(abspath(...))` and `normcase`d as the Monitor
  and the ledger compare them (so case and separators do not matter on
  Windows), and, where the event carries a hash and the run knows its own,
  the **payload hash** too. An event with no hash is judged on its path.
- The expected path is where the Monitor was told to watch
  (`--watch-container`) plus the file's place under `--watch-host`. That is the
  spelling its events carry; the help text says so. For a native run the two
  arguments name the same folder.
- `judge_tc07` and `exit_code` are unchanged: the five judgements and both exit
  codes are the same.

**Tests:** `services/monitor/tests/test_demo_process_bookkeeping.py` (13; one
more, the case-insensitivity test, runs on Windows only). It is a new file;
`test_demo_integrity.py` (18) and `test_demo_reports_gate.py` (6) pass
unchanged.
- A fake launcher that spawns the interpreter as a child (so `Popen.pid !=
  getpid()`): `Writer.pid` is the child's, it is a descendant of the handle's
  PID, and it has no children of its own.
- The same through the real Windows venv launcher (`sys.executable` as the
  default), Windows and venv only: the reported PID is the leaf.
- Run by the base interpreter (no launcher): the reported and handle PIDs
  agree. Exit is still watched through the handle.
- `is_this_runs_event`: same name in another folder is not this run's; same
  path with another hash is not; no hash falls back to the path; spellings
  (`.`/`..`, `/` against `\`) compare equal; case folds on Windows; a name
  that only ends the same way does not match.
- The five judgements and both exit codes, unchanged.
- The whole `main()` against a fake gateway that serves the files the demo
  really wrote, the real writer's PID (the fake kills the writer the way the
  system would), and, listed **before** the real events, the leftovers of
  earlier runs: the same name in another folder and the same path with another
  hash, each naming another process, plus a stale suspicious control event and
  a stale ledger block. It asserts the transcript names the writer's PID once
  and never the other one, reads `evt-this` and block 91, TC-03 and TC-07 pass,
  every other check passes, and the demo made no `/response/terminate` call.

**On base (`dc089ff`), 12 of the 13 fail** (the 13th, the unchanged-judgements
test, is a guard and passes on both):
```
E  TypeError: Writer.__init__() got an unexpected keyword argument 'interpreter'   (x4)
E  AssertionError: the PID is the launcher's: it still has a child
E    where False = _is_leaf(9688)    # the real venv launcher, default sys.executable
E  AttributeError: module ... has no attribute 'is_this_runs_event'                (x6)
E  AssertionError: assert '8240' not in '...'    # the whole demo
E      WRONG PROCESS: attribution named [8240], which did not write the file
   15/19 checks passed
   failed: tc03_no_false_positive, tc07_attributed_pid_is_the_writer,
           tc07_process_terminated, kill_time_under_2s
```
The first, third and last are the real faults reproduced; the `TypeError` and
`AttributeError` ones fail because the seam they need does not exist on base,
which is why the real-launcher test and the whole-demo test call neither.
After: 37 passed (13 new + 24 existing, 18 + 6) in each of 3 runs. No timing in the new
tests beyond a 0.2 s writer hold and 5 s join bounds; each test reaps its
writers.

**Check on Windows:** elevated, from `.venv\Scripts\python.exe` and from the
base interpreter, two runs each, one straight after another:
`python scripts\attack_chain_demo.py --watch-host <dir> --watch-container <dir>`.
Pass: TC-07 passes naming the writer's own PID, the transcript shows one PID
for the writer (the "writer pid" line and the "writer" line agree), the old
run's `annual_report.docx.locked` event in another folder is not counted, exit
0. Unelevated it still skips TC-07 and exits 1. Not run here (unelevated
agent).

**Not changed:**
- Attribution, the kill gate, the Monitor and Response services.
- No `/response/terminate` call and no `.kill()`/`.terminate()` in the demo
  (X1); exit 0 only when every check ran and passed; `--out` and
  `URDS_WRITE_REPORTS` gating (F7). Their tests pass unchanged.
- `judge_tc07`'s five judgements and the exit codes.

**Found, outside the fix:** matching on the payload hash means an event whose
hash is of a half-written file (a `created` notification read before the
write finished) no longer counts as this run's, where `endswith` took it and
printed "hash differs from the bytes written". The demo then waits for the
event that has the right hash. If the Monitor only ever reported such a
partial hash, step 4 would now say "monitor never reported the file" in place
of the note. Not seen in the VM runs, but the elevated run is the check.
