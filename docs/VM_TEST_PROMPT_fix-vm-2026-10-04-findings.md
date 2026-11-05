# URDS - Windows VM test prompt: `fix/vm-2026-10-04-findings`

> **How to use this file.** Paste all of it as the opening message of a fresh
> Claude Code session on the Windows test VM (the URDS-CLEAN VirtualBox machine,
> Windows 11 build 26200). Start the session from an **Administrator** terminal if
> you can. If you cannot, §2.1 says what happens: the session does everything an
> unelevated process can and writes one script for you to run elevated.
>
> This is a **test** prompt, not a build prompt. The session adds no features and
> edits no product code. Its job is to find out, with measurements, whether the
> branch behaves as its own `FIXES.md` says, and to write the report in §9.

**Target:** `origin/fix/vm-2026-10-04-findings`, tip `dc089ff` (2026-10-04 21:38 IST,
"docs(attribution): the 4663 route's latency is measured, not tens of ms").
**Previous VM test of this lineage:** commit `5952218` on
`fix/windows-integration-defects`, 2026-10-04, report at
`reports/VM_TEST_REPORT_2026-10-04.md`. Everything in this prompt is aimed at
what changed since then and at keeping the old numbers comparable.

---

## 0. ROLE AND MISSION

You are a Windows test engineer running an acceptance and regression test on
**URDS** (Unified Ransomware Detection & Recovery System): six Python services
that watch a directory, classify file writes, name the process that wrote them,
terminate it, and restore damaged files from a snapshot with a hash proof.

The last VM test found 7 faults (F1-F7) and 2 carried-over defects. Since then the
branch has had **24 commits** (`git rev-list --count 5952218..HEAD`): the F1
dashboard/gateway fix (defect 13, made after that test) and defects 14-21
(`FIXES.md`). Each fix names a "Check on Windows" that its author could not run.
**Those checks are what this session is for.**

In order:

1. Record the machine and the exact commit under test.
2. Install from scratch in a fresh clone and fresh venv.
3. Run every automated suite and the project's own measurement scripts.
4. Bring the stack up natively and run detection, attribution, response and recovery.
5. Run one regression check per fixed defect (R13-R21, §7) and one status check per
   fault the branch did **not** fix (F2, F2b, F3, F6).
6. Write the report in §9. **The report is the deliverable.** Everything else exists
   to fill it.

What the branch says it did **not** do, so you do not expect it:
- **F2b (suspend-first response) is not implemented.** No suspend endpoint, no lease.
  Fast encryptors will still finish before the kill. Measure and report; do not fail
  the verdict for it (see §9.3).
- F3 (simulator `--restore` skips the file in progress when killed) and F6 (one
  incident per watchdog notification) are unchanged.

---

## 1. RULES

The project's history contains fabricated evidence (a demo that spawned its own
victim so it could "kill" it; a hardcoded PID in a tamper-evident ledger; skipped
checks that exited 0). Defect 14 removed them. Do not add new ones.

1. **Never fabricate a result.** Do not write PASS for something you did not
   measure. Do not hand-write an evidence file. A command that did not run is
   `BLOCKED`, not `PASS`.
2. **A skipped check is not a pass.** A pytest skip, a script that prints "skipped",
   and a demo that exits 1 on a skip are all findings. Report them separately and
   do not let the headline imply success.
3. **Never edit product code to make something pass.** A failure is the finding:
   record it with the traceback. You may fix *environment* problems (a missing
   package, a wrong path, an unset variable) and *harness* bugs in your own test
   scripts. Say in the report what you changed.
4. **Prove a failure is the product before you record it as one.** On 2026-10-04
   the first live run reported 13 failures; all 13 were a harness bug (it read the
   simulator manifest under the wrong name: the file is `.simulator_manifest.json`,
   with a leading dot). Two more "slow detection" results were a harness building
   its HTTP client after the clock started. Before recording a live-check failure
   as FAIL, re-run the same assertion once with a hand-made probe (a single `curl`,
   a three-line Python file) and say in the report which one you did.
5. **Never guess a PID, never kill on a guess.** Anything other than a `certain`
   attribution is recorded with its confidence and reason and left alone.
6. **Time with a monotonic clock.** VirtualBox slews this VM's wall clock
   (measured 0.8x-1.44x of real time). Use `time.monotonic()` / `perf_counter()` /
   `[Diagnostics.Stopwatch]` for every duration you report. Event and ledger
   timestamps are wall-clock: **sub-second differences between them are
   approximate**, and the report says so wherever it uses one.
7. **Stay inside the VM and inside the test directories** (§3.1). The simulator
   rewrites only files it created in this run. Do not aim anything at `C:\Users`,
   `C:\Windows`, a share, or a host folder.
8. **Do not touch what you did not create.** `URDSAgent` (a LocalSystem service
   installed from `C:\URDS`, branch `fix/evidence-integrity`) runs on this VM.
   Do not stop it, reconfigure it, or reuse `C:\URDS`. Shadow copy
   `{DD628FFD-87F5-4D25-A749-937B0FDF3F42}` is left over from the last run: leave it.
9. **Network isolation stays OFF.** `RESPONSE_ISOLATION_ENABLED=false` for every
   run. Enforced isolation rewrites the Windows Firewall policy.
10. **Never commit, push, or open a PR.** The clone is for testing. The operator
    decides what goes back to the repository.
11. **Record Windows' refusals verbatim.** An access-denied string is a
    measurement. Paste it; do not paraphrase.
12. **Do not paste secrets into the report.** `JWT_SECRET` and
    `DEV_TOKEN_BOOTSTRAP_SECRET` are generated by you (`[guid]::NewGuid()`) and kept
    in your own notes and the stack script only.

---

## 2. PRECONDITIONS

Run these first. Record every answer in the report header.

### 2.1 Elevation

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

- **True:** you can run everything. Run the stack twice (§5.4): once in
  *snapshot-folder mode*, once in *elevated native mode*.
- **False:** you cannot elevate yourself; do not try. Do every unelevated step, and
  at §5.5 write `full_elevated.ps1` (spec in §5.5) for the operator to run from an
  Administrator PowerShell, then read what it produced. Say in the report which half
  each result came from. This is how the 2026-10-04 run worked.

### 2.2 The VM

```powershell
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, CsManufacturer, CsModel, CsTotalPhysicalMemory
Get-Volume -DriveLetter C | Select-Object FileSystemType, SizeRemaining, Size
Get-Service URDSAgent -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
Get-NetTCPConnection -State Listen -LocalPort 8000,8001,8002,8003,8004,8501 -ErrorAction SilentlyContinue
vssadmin list shadows
```

Needed: Windows 10 1809+ or 11, >= 4 GB RAM, >= 25 GB free on C:, `CsModel` saying
VirtualBox/VMware/Virtual Machine, and **ports 8000-8004 and 8501 free** (stop at
the first conflict and say which process holds the port; do not kill it). If the
machine does not look like a VM, stop and ask.

Ask the operator, and record the answers:
- Is there a VM snapshot of the clean state (name it `clean-before-latest` if not)?
- Are host shared folders disabled? Is the NIC NAT or host-only?
- May the session download ~1.4 GB from Hugging Face to train the EMBER model?
  (Default **no**: the `ember_vector` path is then `NOT TESTED`, and 3 ml-engine
  tests skip for that reason. That is the expected state.)

### 2.3 Windows Defender: record it, do not change it

On 2026-10-04 Defender stayed **on** (real-time, behaviour, IOAV) for the whole run
and nothing was quarantined; Tamper Protection was already off. Keep it that way.

```powershell
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected, AntivirusSignatureLastUpdated
Get-MpPreference | Select-Object EnableControlledFolderAccess, DisableRealtimeMonitoring, MAPSReporting, SubmitSamplesConsent, ExclusionPath
```

Save as `defender_state_before.json`. Run with Defender as found. **Only if** the
simulator or its output files get quarantined (a file you created vanishes, or
`Get-MpThreatDetection` lists one), follow Appendix A, and say in the report header
that results were then measured with Defender reduced. A result measured with a live
AV is the stronger one; a result with it off is legitimate and must say so.

### 2.4 Source

The repository is `https://github.com/VSshashank/unified-ransomware-system.git`.
- Public, or already authenticated: clone directly.
- Needs credentials: the operator authenticates in their own shell. Do not ask for a
  token in this chat.
- `C:\URDS-integ` (the previous test's clone) exists: `git clone C:\URDS-integ
  C:\URDS-latest`, then `git remote set-url origin <the URL above>` and fetch.
- Offline: the operator copies the folder in.

---

## 3. SETUP

### 3.1 Paths

```powershell
$Repo   = 'C:\URDS-latest'                                  # fresh clone: never C:\URDS
$Run    = "C:\URDS-latest-run\$(Get-Date -Format yyyyMMdd_HHmmss)"
$Evid   = "$Run\evidence"
$Watch1 = "$Run\watch_snapshot_mode"      # run 1
$Watch2 = "$Run\watch_native"             # run 2 (audited)
$Snaps  = "$Run\snapshots"                # RECOVERY_SNAPSHOT_ROOT, run 1 only
New-Item -ItemType Directory -Force $Evid,$Watch1,$Watch2,$Snaps | Out-Null
```

Short paths, no spaces, outside `C:\Users`. Everything you produce goes under `$Run`
except the final copy of the report (§9).

### 3.2 The commit under test

```powershell
git clone https://github.com/VSshashank/unified-ransomware-system.git $Repo
cd $Repo
git fetch --all --prune
git checkout --detach origin/fix/vm-2026-10-04-findings
git rev-parse HEAD
git log -1 --format='%H%n%s%n%ci'
git merge-base --is-ancestor 5952218 HEAD; $LASTEXITCODE     # 0 = it descends from the last tested commit
git diff --stat 5952218 HEAD | Select-Object -Last 1
```

- Expected tip: `dc089ff`. If `origin` has moved on, **test the tip you find**, say so
  in the report header, and name both SHAs. The branch with the newest commit is
  `git for-each-ref --sort=-committerdate refs/remotes --format='%(committerdate:iso8601) %(refname:short)' --count=3`.
- `git status --porcelain` must be empty now. It is your baseline for rule 3 and
  for R15.
- Record the commit in the report. **Every number in the report is a measurement of
  this SHA.**

### 3.3 Install (fresh venv, as a reader would)

```powershell
python --version                      # expect 3.12.x
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
$t = [Diagnostics.Stopwatch]::StartNew()
foreach ($s in 'gateway','ledger','monitor','ml-engine','response','dashboard') {
  .\.venv\Scripts\pip.exe install -r "services\$s\requirements.txt"; "$s exit=$LASTEXITCODE"
}
.\.venv\Scripts\pip.exe install -r scripts\requirements.txt pytest pytest-asyncio httpx
"install seconds: $($t.Elapsed.TotalSeconds)"
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe .\.venv\Scripts\pywin32_postinstall.py -install
.\.venv\Scripts\python.exe -c "import win32evtlog, win32com.client, pythoncom, psutil, pefile; print('imports ok')"
```

Record resolver output verbatim. Last run: exit 0 in 294 s, `pip check` clean
(streamlit 1.51.0 beside Pillow 12.3.0; that conflict is defect 7).

Model (so the ML hop does not return 503):

```powershell
.\.venv\Scripts\python.exe src\train_behavioral_model.py
git status --porcelain       # must still be empty: URDS_WRITE_REPORTS is unset
(Get-FileHash models\behavioral_model.pkl -Algorithm MD5).Hash
```

Last run: 75 s, and the model was byte-identical (MD5 `f481aa17...`) to the existing
one. A different hash is a finding only if the Python and package versions match;
say what differs.

Also confirm `RECOVERY_SNAPSHOT_ROOT` is **unset in your shell** (`$env:RECOVERY_SNAPSHOT_ROOT`).

### 3.4 Secrets

```powershell
$Jwt  = [guid]::NewGuid().ToString('N')
$Boot = [guid]::NewGuid().ToString('N')
```

Same values for the gateway and the dashboard, or the dashboard cannot mint a token
the gateway trusts.

---

## 4. PHASE 1 - AUTOMATED SUITES AND MEASUREMENT SCRIPTS (stack down)

One pytest process per service, from the service's directory. The services use flat
module names (`app.py`, `main.py`) and a single process over `services/` imports the
wrong ones; CI runs one job each for that reason.

```powershell
foreach ($s in 'gateway','ledger','monitor','ml-engine','response','dashboard') {
  Push-Location "services\$s"
  ..\..\.venv\Scripts\python.exe -m pytest -q -rs 2>&1 | Tee-Object "$Evid\pytest_$s.txt"
  Pop-Location
}
powershell -ExecutionPolicy Bypass -Command "Invoke-Pester scripts/tests" 2>&1 | Tee-Object "$Evid\pester.txt"
.\.venv\Scripts\python.exe scripts\claim_matrix.py --tests 2>&1 | Tee-Object "$Evid\claim_matrix.txt"
```

### Expected (reference, from the branch's `FIXES.md` and a collection of this tip)

| Suite | Expect on Windows | Notes |
|---|---|---|
| gateway | 91 passed | +5 over the last run (defect 13) |
| ledger | 99 passed | |
| monitor | **570 collected**, all passing | up from 516; includes 2 Windows-only tests (R21) |
| ml-engine | 50 passed, 3 skipped | the 3 skip with "no EMBER model" unless you trained it |
| response | **127 passed, 2 skipped** | the 2 skip: "SIGTERM cannot be ignored on Windows" |
| dashboard | 4 passed | new suite; guards the render path |
| Pester | 30 passed | +4 (defect 17) |
| claim matrix | **16 claims, 0 failed** | C-16 is new |

These are references, not a script to match: report what you measured. Name **every**
failing and skipped test with its reason (`-rs` prints skips).

### Timing-sensitive tests

`test_detection_latency_under_100ms`, `test_tc11_detection_stays_within_budget_under_load`
and a real-watcher test in `test_api.py` are load-sensitive on this 4-vCPU VM (the
untouched base commit failed them when the host was busy). If one fails, **re-run
that test alone three times with nothing else running** before recording it, and
report all four outcomes. Close other work first; do not run suites in parallel.

### The seven new test files must run, not skip

```powershell
cd services\monitor
foreach ($t in 'test_demo_integrity','test_demo_reports_gate','test_escalation_bypasses_backlog','test_ledger_pid_integrity','test_one_subscription_per_start','test_pe_read_shares_delete','test_recorded_size_matches_content') {
  ..\..\.venv\Scripts\python.exe -m pytest "tests\$t.py" -q -rs
}
cd ..\response; ..\..\.venv\Scripts\python.exe -m pytest tests\test_chain_pid_fields.py -q -rs
cd ..\dashboard; ..\..\.venv\Scripts\python.exe -m pytest tests\test_render.py -q -rs
```

Counts: 18, 6, 1, 18, 3, **2 (Windows only: a skip here is a FAIL of R21)**, 5, then 6 and 4.

### Offline measurement scripts

Run with `URDS_WRITE_REPORTS` **unset**, and run `git status --porcelain` after each:
nothing may change.

```powershell
foreach ($s in 'simulator_sweep','tamper_sweep','failure_injection','load_test') {
  .\.venv\Scripts\python.exe "scripts\$s.py" 2>&1 | Tee-Object "$Evid\$s.txt"
}
```

Last run: sweep 13/13 families, 8/8 files each, first flag <= 16 ms; tamper in-place
20/20 and structural **0/8** (a documented limit of an unanchored chain; report it as
such, not as a failure); failure injection 5 distinct outcomes, none claiming
"verified"; load test median 52 ms, p95 113 ms, p99 151 ms, 9.3% over 100 ms (known
and documented; re-measure, do not gate on it).

**Gate 1:** all suites green except named load-sensitive tests that pass on a quiet
re-run; the seven new files pass with no skip; `git status --porcelain` empty.

---

## 5. PHASE 2 - THE LIVE STACK

### 5.1 The stack script

Write `$Run\start_stack.ps1` and keep it in the evidence. Six native processes, each
started with its **own directory as working directory** (flat module names), stdout
and stderr to `$Run\logs\<service>.log`, all on `127.0.0.1`. Parameters: `-Mode
snapshot|native`, `-Watch`, `-RunDir`.

| Service | Working dir | Command | Port |
|---|---|---|---|
| gateway | `services\gateway` | `python -m uvicorn main:app --host 127.0.0.1 --port 8000` | 8000 |
| monitor | `services\monitor` | `... app:app ... --port 8001` | 8001 |
| ml-engine | `services\ml-engine` | `... app:app ... --port 8002` | 8002 |
| ledger | `services\ledger` | `... main:app ... --port 8003` | 8003 |
| response | `services\response` | `... app:app ... --port 8004` | 8004 |
| dashboard | `services\dashboard` | `python -m streamlit run app.py --server.port 8501 --server.headless true` | 8501 |

Environment for all of them:

```powershell
$env:ML_URL='http://127.0.0.1:8002'; $env:LEDGER_URL='http://127.0.0.1:8003'
$env:RESPONSE_URL='http://127.0.0.1:8004'; $env:MONITOR_URL='http://127.0.0.1:8001'
$env:GATEWAY_URL='http://127.0.0.1:8000'
$env:WATCH_PATH = $Watch                                    # per mode
$env:LEDGER_DB_PATH = "$RunDir\data\ledger.db"              # fresh per run
$env:BEHAVIORAL_MODEL_PATH = "$Repo\models\behavioral_model.pkl"
$env:MODEL_PATH = "$Repo\models\xgboost_model.pkl"          # absent unless EMBER trained
$env:URDS_ENV='development'; $env:ALLOW_DEV_TOKENS='true'
$env:JWT_SECRET=$Jwt; $env:DEV_TOKEN_BOOTSTRAP_SECRET=$Boot
$env:RESPONSE_ISOLATION_ENABLED='false'
Remove-Item Env:\URDS_WRITE_REPORTS -ErrorAction SilentlyContinue
if ($Mode -eq 'snapshot') { $env:RECOVERY_SNAPSHOT_ROOT = $Snaps }
else { Remove-Item Env:\RECOVERY_SNAPSHOT_ROOT -ErrorAction SilentlyContinue }   # VSS must be real
```

**`RECOVERY_SNAPSHOT_ROOT` set means restores come from a folder, not a shadow copy,
and the result must be labelled "snapshot folder", never "VSS".** In native mode it
must be unset: check it, and fail the run if it is set.

Also write `stop_stack.ps1`. After starting: wait for ports, then

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health          # all four downstream services healthy
Invoke-RestMethod http://127.0.0.1:8003/ledger/verify   # valid
Invoke-RestMethod http://127.0.0.1:8501/_stcore/health  # ok
```

### 5.2 Harness requirements (the harness is not in the repository)

`C:\URDS-recheck\full\tools\` on this VM holds the previous run's harness
(`full_e2e.py`, `workload.py`, `writer.py`, `e2e_check.py`, `full_elevated.ps1`,
`analyse_elev.py`, `kill_latency.py`, `start_stack.ps1`, `stop_stack.ps1`).
**If it exists, read it first and reuse it**, record each file's SHA-256 in the
report, and say it was reused. If it does not, build equivalents to this spec. Either
way these properties are what make the numbers mean something:

1. **Every suspicious write comes from a separate child process** whose PID the
   parent knows, so "the PID the Monitor names" can be compared with "the PID that
   wrote". A harness that writes the files itself makes attribution unmeasurable.
   The simulator is already such a process: start it with `subprocess.Popen` and keep
   `proc.pid`.
2. **Durations on `time.monotonic()`**, and the HTTP client is built **before** the
   clock starts.
3. Reads the simulator manifest `<target>\.simulator_manifest.json` (leading dot).
4. **Ground truth is yours, not the system's:** before any attack, record
   `(path, sha256, byte length)` for every decoy into `$Evid\pre_attack_manifest.json`
   using your own code. Recovery and R18 are judged against it.
5. A minimal `writer.py`: arguments `--path --count --size --sleep-after`; writes
   `count` files of `size` random bytes (high entropy, so they are flagged), prints
   `{"pid":..., "t_write_mono":[...]}` as JSON, then sleeps `--sleep-after` seconds
   *alive*, so a kill is observable as the PID disappearing.
6. Reads `/monitor/events?limit=N`; the fields you need are `suspicious`, `verdict`,
   `signal`, `validation_state`, `file_path`, `file_size`, `size_changed_during_read`,
   `process_id`, `process_image`, `attribution_confidence`, `attribution_reason`,
   `detection_latency_ms`, `queue_wait_ms`, `incident_id`, `attribution_escalation`.

### 5.3 Benign workload (one separate process)

Text files created and edited three times; `.docx`/`.xlsx` saved and re-saved; a ZIP
and a gzip; five JPG/PNG copied in; three DLL/EXE copied from System32; a SQLite
database written in five transactions; a `.py` compiled to `.pyc`; a rename; a
delete; PowerShell `Compress-Archive` from another process. **0 of ~69 events may be
flagged** and that process must not be killed.

### 5.4 Run 1 - snapshot-folder mode (`-Mode snapshot`, watch `$Watch1`)

Unelevated is fine here. POST `/monitor/start` with `watch_path` normal-slashed
(`C:/...`), `recursive: true`, `file_patterns: ["*"]`, then:

| ID | Check | Pass condition |
|---|---|---|
| 5.1 | Benign workload | 0 flagged events; the workload process alive; verdicts only `benign`, `benign_compressed`, `deleted` |
| 5.2 | Genuine ZIP | `verdict: benign` (or `benign_compressed`), `validation_state: valid` |
| 5.3 | `PK\x03\x04` + 200 KB random | `suspected_encryption`, `signal: structural_mismatch`, `validation_state: forged` |
| 5.4 | 13 families x 10 decoys (`--files 10`, default pace), each started as its own process, with the decoys given a moment as benign first | every encrypted file flagged: **130/130**; first flag <= 100 ms after encryption began; `grinder` makes 5 warm-up writes first and `poisoner`'s setup files flag before its encryption starts |
| 5.5 | In-place encryption of 10 existing documents by a different process | 10/10 flagged |
| 5.6 | Flagged write visible **through the gateway** (`/monitor/events` with a token) | < 1 s from the write; with the dashboard **closed** |
| 5.7 | Recovery from the snapshot folder. Let the Monitor baseline the decoys as benign, then copy each decoy to `$Snaps\<snapshot_id>\<its path without the drive letter>` (the service looks up `<RECOVERY_SNAPSHOT_ROOT>\<snapshot_id>\` and re-roots `C:\a\b.docx` as `a/b.docx`; pick any id, e.g. `snap1`). Attack, then `POST /response/recover` with that `snapshot_id`, the file paths, and `verify_integrity: true` | 10/10 `restored: true` and `integrity_verified: true`; your own SHA-256 equals `pre_attack_manifest.json` 10/10 |
| 5.8 | `locker` (rename family): snapshot, re-attack, recover | 10/10, own hash 10/10 |
| 5.9 | `--restore` of each family's directory | byte-identical to `pre_attack_manifest.json`. **F3 expectation: `grinder` and `staged` restore 9 of 10** (the file in progress when killed is not in the manifest). Report what you get |

Unelevated, attribution is `unavailable` ("EvtSubscribe ... Access is denied") and
every incident gets `isolate_and_log`: that is the designed degradation, not a
failure. Say so.

Stop the stack. Save `data\ledger.db` and the logs.

### 5.5 Run 2 - elevated native mode (`-Mode native`, watch `$Watch2`)

**If you are elevated:** do this yourself. **If not:** write `$Run\full_elevated.ps1`
that does all of it from an Administrator PowerShell, tell the operator the one
command to run, and wait. The script must, in order, **log everything to `$Run`**:

1. Record machine state: Security log max size, `auditpol /get /subcategory:"File System"`,
   rules on the watch paths, `vssadmin list shadows` (count and IDs), firewall profiles,
   Defender status.
2. `setup_attribution_audit.ps1 -WatchPath $Watch2`, then `-Verify`.
3. Start the stack in native mode (all six processes elevated).
4. Gate: `/monitor/attribution` reports `available: true`, `source:
   windows-security-4663`, `kernel_grade: true`. If not, the `error` string is the
   most important line of your report: paste it whole.
5. Run §6 and §7's live checks.
6. `verify_vss.py --volume C:\` (creates one real shadow copy), then re-attack and
   recover from it (§6.3).
7. Stop the stack; `setup_attribution_audit.ps1 -Revert`; record machine state again.

`setup_attribution_audit.ps1` parameters: `-WatchPath <dir>`, `-Verify`, `-Revert`,
`-StatePath`. It ends with an **End-to-end probe** line: it must read `ok`. A green
exit with a failed probe is not a pass.

---

## 6. PHASE 3 - ATTRIBUTION, RESPONSE AND RECOVERY (run 2, elevated)

### 6.1 Attribution and response: the defect re-check

Same shape as the previous run's 42-check `e2e_check.py`, so the numbers compare.
**Empty the audited watch folder rather than deleting and recreating it**: a
recreated folder inherits no audit rule, Windows writes no 4663 for it, and every
answer comes back `unknown` (the previous run's first two attempts failed exactly
this way). Probe the audit first (write one file, confirm `writes_recorded` rises).

| ID | Check | Pass condition |
|---|---|---|
| 6.1 | D1: 5 single writes, each by a fresh process | 5/5 `certain`, **PID equals the writer's real PID**, writer killed |
| 6.2 | D2: write then rename by one process, x5 | rename event `certain`, correct PID; found under the old name |
| 6.3 | D3: 20-file burst by one process | last event <= ~0.2 s after the last write; `queue_wait_ms` present on every suspicious event |
| 6.4 | D4: recovery under four path spellings (as recorded, `/`, lower case, mixed) | 4/4 `integrity_verified` |
| 6.5 | Invariant: benign writer, then an encryptor 0.5 s later, x3 | **never `certain`, nobody killed** |
| 6.6 | Invariant: a second writer after the first one's detection, x2 | second writer never `certain`, never killed |
| 6.7 | **Wrong PIDs over every correlated event** | **exactly 0** (last run: 0 of 78 and 0 of 238) |
| 6.8 | 13 families x 10, each its own process, elevated | per family, record: files encrypted before the run ended, flagged, attribution confidence, terminated or not, files encrypted before termination (FEBR), time from first malicious write to the PID disappearing |

Rows 6.5-6.7 are safety invariants. A failure there is the most serious finding the
run can produce: stop and report it first.

`termination_refused_or_unreachable` on a `certain` answer whose reason reads
"PID ... does not exist" means an earlier request already killed it, or it exited in
between. That is correct and noisy (F6); count it, do not call it a failure.

### 6.2 Kill timing (F2) and the backlog fix (R16)

On a quiet VM, from the harness's monotonic clock, for each terminated writer:
`write -> PID gone`. Report min / median / max.

| Last run (`5952218`) | |
|---|---|
| terminate request after detection | 0.82-6.55 s, median **1.40 s** |
| first write after a 20-write burst | **6.92 s** from write to kill |
| FEBR < 5 | 3 of 13 families (`slowburn` 2, `grinder` 3, `poisoner` 4) |

Expected now: ten families still finish before the kill (the 1,500 ms delivery
horizon is deliberate, and F2b is not implemented). **Report the medians and the
FEBR table without a pass/fail** (`KNOWN-OPEN`), and compare them with the table
above. R16 (§7) is the one that should have moved.

### 6.3 VSS snapshot and recovery

Order matters; a wrong order gives a meaningless pass.

1. Confirm the ledger holds a `file_baseline` block for every decoy **before**
   encryption (without baselines a restore can only be `partial`).
2. Your own ground truth: `pre_attack_manifest.json` (§5.2.4).
3. Snapshot on clean files: `.\.venv\Scripts\python.exe scripts\verify_vss.py --volume C:\`.
   Record the ID, seconds (target < 30 s; last run 2.5 s), that `list_snapshots`
   shows it, and the `snapshot_created` block.
4. `--family locker` over the same directory, so every file is damaged. Re-hash and
   show the hashes differ from step 2.
5. `POST http://127.0.0.1:8004/response/recover` with `snapshot_id`, `files`,
   `verify_integrity: true`, and the `incident_id` from the detection.
6. Verify three ways: the response's `integrity_verified`; your own `Get-FileHash`
   against `pre_attack_manifest.json`; a `file_recovered` block in the ledger.

`restored: true, integrity_verified: false` is **partial**: bytes are back, nothing
confirmed them. Do not flatten it into success or failure.

| ID | Check | Pass condition |
|---|---|---|
| 6.9 | VSS available | `verify_vss.py --status-only` (creates nothing: shadow copies 0 to 0 **relative to the count you recorded**) and `platform_status` `supported: true, elevated: true` |
| 6.10 | Snapshot | created < 30 s, listed, `snapshot_created` block |
| 6.11 | Restore | `restored: true` for every file; `integrity_verified: true` for every file |
| 6.12 | Independent check | your SHA-256 matches `pre_attack_manifest.json` for every file |
| 6.13 | Logged | `file_recovered` block present and joined to the incident |
| 6.14 | Chain | `/ledger/verify` `valid: true`; verification < 50 ms (the ledger's own figure; an HTTP round trip is a different, noisier number: say which you report) |

Headline: **`N restored and independently hash-verified of M encrypted`.**

---

## 7. THE REGRESSION CHECKS (what changed since the last run)

One row per fixed defect. Each says how to run it and what failing looks like. They
are the heart of the report. **Any FAIL here means a fix did not hold on Windows.**

| ID | Defect | Method | Pass condition |
|---|---|---|---|
| **R13** | Dashboard rendered nothing and saturated the gateway (F1) | With the stack up and **the dashboard open** for >= 60 s: time gateway `/health` and `/monitor/events` 20 times each with a Stopwatch; count `GET /health` lines in the gateway log over a 20 s window with no other client; open `http://127.0.0.1:8501` (try headless Edge `msedge --headless=new --virtual-time-budget=20000 --dump-dom <url>` and search for the panel text; if inconclusive, ask the operator to look and screenshot) | gateway `/health` and `/monitor/events` each < 100 ms median with the dashboard open (previous: 6,939 ms and 2,317 ms; after the fix: 19 and 10 ms); the page shows the "System Secure"/status banner, pipeline tiles and tables, **not just the title**; about one refresh per second (>= 15 `/health` calls in 20 s). `AppTest` alone is not enough: it has no browser timer and passes on the broken commit too |
| **R14** | Fabricated evidence (X1) | (a) `git grep -n 6666 -- scripts services`; (b) `attack_chain_demo.py` elevated with the audit SACL, then unelevated; (c) `ledger_coverage.py --ledger-db <run 2 ledger.db>` (read-only) and `claim_matrix.py` C-16; (d) run `si_demo.py` and check its ledger rows | (a) empty; (b) elevated: **TC-07 passes naming the writer's own PID**, transcript shows the demo issuing no terminate; unelevated: TC-07 **skips and the run exits 1**; (c) `unsupported` **0**, exit 0; (d) no `process_id` of 6666 or 4321, forged rows name no process. Do not call `/response/terminate` through the gateway during run 2: a kill requested through it is recorded without attribution and the scan reports that block (known, `FIXES.md` defect 14) |
| **R15** | Demos wrote `reports/` unconditionally (F7) | With `URDS_WRITE_REPORTS` unset run both demos; `git status --porcelain`. Then run both with `--out $Evid\demo_<name>.txt`. Then once with `URDS_WRITE_REPORTS=1`: copy the regenerated `reports\attack_chain_*` and `si_demo_evidence.txt` into `$Evid`, then `git restore -- reports/` in your clone | unset: **`git status` stays clean**; `--out` writes only there; with the variable set the transcripts show only real PIDs. **Run the demos last in the session** (see §8): `si_demo.py` tampers the ledger it is pointed at, so save `ledger.db` first |
| **R16** | A kill waited for the pipeline backlog (F2a) | Elevated. 20 rapid high-entropy writes by process A, then **immediately** one write by a fresh process B (which stays alive 10 s). Measure B's write to B's PID gone on the monotonic clock. Repeat 5 times | each B killed in <= **2.05 s** (the branch's own bound; its unit test measures 1.565 s). Last run: 6.92 s. Also confirm B's incident carries an `incident_id` and the escalation block follows the incident's `response_action` block |
| **R17** | Audit probe reported a working folder as broken (F4) | Ten **new** folders, one after another: `setup_attribution_audit.ps1 -WatchPath <new>` then `-Verify`. Count false failures (setup fails and `-Verify` passes). Record Security log size and `auditpol` subcategory before and after. Then `-Revert` every folder | **0 false failures** (last run: 1 of 4; 0 of 6 earlier); log size and subcategory unchanged; no rule left on any folder. A failure with the wording "auditing is configured but this run could not confirm a record" is the new honest wording, still exit 1: record it, and say whether `-Verify` then passed |
| **R18** | Stale `file_size` beside the full file's hash (F5) | From the run ledger and the events, for every `file_baseline` block and event with a `file_hash`: look the hash up in `pre_attack_manifest.json` and compare `file_size` with the recorded byte length. Also count blocks with `file_size == 0` and a hash that is not SHA-256 of the empty string (`e3b0c442...`) | **0 mismatches; 0 zero-size blocks beside a non-empty hash**. `size_changed_during_read` is present on the blocks; report how many are `true` |
| **R19** | Dashboard raised `ArrowTypeError` every refresh | Dashboard open >= 60 s **after an attack that produced an adjudicated event** (so all three Field/Value tables are drawn): search `$Run\logs\dashboard.log` | no "Serialization of dataframe to Arrow table was unsuccessful", no `ArrowTypeError`/`ArrowInvalid` |
| **R20** | Two Security-channel subscriptions per Monitor start | Elevated. `POST /monitor/start`, `/monitor/stop`, `/monitor/start`, then a write by a fresh process. Repeat the cycle 5 times, recording the Monitor process's `HandleCount` before and after | after start-stop-start, attribution is still `certain` for a fresh writer, `/monitor/attribution` still `available: true`. The handle count is **informational** (no subscription count is exposed): a steady rise of about one per cycle is worth a line, not a verdict |
| **R21** | PE parser opened files without `FILE_SHARE_DELETE` | `tests\test_pe_read_shares_delete.py` (2 tests, Windows only). Live: copy `python.exe` into the watch folder, `POST /features {"path": "<copy>"}`, then delete the copy immediately | 2 passed, **not skipped**; `/features` returns PE features; the delete succeeds |
| R9-R12 | Carried from the previous run (Monitor reads do not lock files; training-mode clocks; probable-answer order; "unreadable" means a lock) | Covered by the Monitor suite and rows 6.1-6.7 | no separate row: cite the rows |

### Status checks for what was **not** fixed

| ID | Item | What to do | Report as |
|---|---|---|---|
| F2 | Kill arrives after fast encryptors finish | §6.2 | `KNOWN-OPEN`, measured |
| F2b | Suspend-first response | `Invoke-RestMethod -Method Post http://127.0.0.1:8004/response/suspend` | expect 404 / no such route; report "not implemented, as `FIXES.md` says". A suspend route that **does** exist means this is not the described branch: stop and say so |
| F3 | Simulator `--restore` skips the in-progress file | Row 5.9 | `KNOWN-OPEN` if 9 of 10, else say it changed |
| F6 | 2-3 incidents and ~5 ledger blocks per encrypted file | From the run ledger: `file_event` blocks / files encrypted, and blocks per encrypted file | `KNOWN-OPEN`, with the numbers (last run: 317 `file_event` blocks for ~170 files; 1,556 blocks in 2 minutes) |

---

## 8. ORDER OF WORK AND ACCOUNTING

1. §2 preconditions -> §3 setup (record the SHA).
2. §4 suites and offline scripts. Gate 1.
3. Run 1 (§5.4), unelevated or elevated. Save ledger and logs.
4. Run 2 (§5.5, §6, §7). R13 and R19 need the dashboard running during §6.
5. R17 (ten audit setups) is independent of the stack; do it before or after run 2.
6. **Last:** the demos for R14(b)(d) and R15. Save `ledger.db` first; `si_demo.py`
   edits the ledger it is given and may leave the chain invalid (it restores its own
   tamper, `8cf1527`, but do not rely on that).
7. Ledger tamper evidence on the saved ledger (not the live one): edit one block in
   SQLite (not through the API), `GET /ledger/verify` must say `valid: false` and name
   the block id; then `tamper_sweep.py`'s numbers (in-place 20/20; structural 0/8 is the
   documented limit).
8. Write the report (§9) **before** teardown (§10). The report is the one thing that
   must survive.

While you work:
- Append to `$Run\run_log.md` as you go: timestamp, command, outcome. Do not
  reconstruct it from memory.
- Raw outputs go in `$Evid` (the report cites those paths): `pytest_<svc>.txt`,
  `pester.txt`, `claim_matrix.txt`, the offline scripts, `defender_state_before.json`
  and `_after.json`, `machine_state_before.txt` and `_after.txt`, `attribution_status.json`,
  `monitor_events_<run>.json`, `ledger_blocks_<run>.json`, `vss_verify.txt`,
  `recover_response_<run>.json`, `full_elevated.log` if used.
- Tell the operator at each phase gate, in one line: what passed, what did not, what
  is next.
- **Stuck on one obstacle for ~15 minutes: stop and report it** with the exact error.
  The operator can revert the VM snapshot.

---

## 9. THE DELIVERABLE: THE TEST REPORT

Write both, in `$Run`, then copy into `$Repo\reports\` under the names below (they are
new, untracked files; `git diff --stat` must still show **no tracked file changed**):

- `VM_TEST_REPORT_<yyyy-MM-dd>_<sha7>.md`
- `vm_test_results_<yyyy-MM-dd>_<sha7>.json` (the same rows: `id`, `test`, `target`,
  `measured`, `result`, `evidence`)

Use exactly these result values: **PASS**, **FAIL**, **BLOCKED** (a prerequisite
failed), **NOT TESTED** (deliberately out of scope: say why), **KNOWN-OPEN** (a
fault the branch's own docs record as unfixed; measured, with the evidence).

### 9.1 Template

```markdown
# URDS full test on the Windows VM: `fix/vm-2026-10-04-findings` at `<sha7>`

**Date:** <date>, <start>-<end> <tz>.
**Tested:** branch <name>, commit <40-char SHA>; descends from 5952218: <yes/no>.
**Machine:** URDS-CLEAN, <Windows build>, <vCPU>, <RAM>, VirtualBox; last boot <time>.
**Session:** <elevated | unelevated, with the operator running the elevated half>.

## Verdict
<PASS | PASS WITH EXCEPTIONS | FAIL> - one sentence saying what was and was not
demonstrated, naming every exception and every KNOWN-OPEN item on this line.

## Headline numbers
| Area | This run | Last run (5952218) |
|---|---|---|
| Fresh install | exit <n> in <s> s; `pip check` <result> | exit 0 in 294 s, clean |
| Suites | <passed>/<skipped>/<failed> per service | 898 passed, 5 skipped, 0 failed |
| Claim matrix | <n> claims, <n> failed | 15 claims, 0 failed |
| Detection, live | <n>/130 families x files flagged; first flag <min>-<max> ms | 130/130; 16-78 ms |
| False positives, benign | <n> of <n> events | 0 of 69 |
| Attribution (elevated) | **<n> wrong PIDs** in <n> named events; two-writer rule <k> of <k> | 0 of 78 / 238; 5 of 5 |
| Termination | requested <min>-<max> s after detection, median <x>; kill itself <x> ms; FEBR < 5 for <n> of 13 | 0.8-6.6 s, median 1.40; 10-30 ms; 3 of 13 |
| First write after a burst (R16) | <x> s | 6.92 s |
| VSS shadow copy | <x> s | 2.5 s |
| Recovery | snapshot folder <n>/<m>; VSS <n>/<m>; own SHA-256 <n>/<m> | 10/10; 10/10; 10/10 |
| Ledger | <n> blocks valid; verify <x> ms; live tamper caught: <y/n> | 1,556 valid; 7-9 ms; yes |
| Gateway `/health`, dashboard open | <x> ms | 6,939 ms |
| Dashboard | <renders every panel? refreshes/20 s> | title only |

## Environment
Windows build, RAM, free disk, Python, pip, streamlit, commit, URDSAgent (untouched),
ports, clock slew if measured, stack run natively, isolation forced off.

## Security posture  <- REQUIRED
Defender state before and after (real-time, behaviour, IOAV, Tamper Protection,
signature date). Whether anything was changed. If Appendix A was used: exactly what,
when, and when it was restored. Audit policy and Security log size before and after.
A result measured with Defender on is a coexistence result; a result with it reduced
must say so here, not in a footnote.

## Results
| # | Test | Target | Measured | Result | Evidence |
|---|---|---|---|---|---|
| 1.1 | Fresh install | exit 0 | ... | ... | evidence/... |
... one row for every check in §3-§6 ...

## Regression checks (what changed since 5952218)
| ID | Defect | Method | Measured | Result | Evidence |
|---|---|---|---|---|---|
| R13 | ... | ... | ... | ... | ... |
... R14-R21, then F2, F2b, F3, F6 status rows ...

## Faults found this run
For each: what failed, the exact error, which link in the chain broke, what it means
for the project's claims, what would have to change, and the reproduction. "Unknown"
where it is unknown. No speculation presented as diagnosis.

## Apparent failures that were not product faults
Every harness bug or environment issue that looked like a product failure, and how
you proved it was not (rule 4).

## Not tested
EMBER static-PE model (unless trained); a reboot (it ends this session); Docker
(not installed here); enforced network isolation; multi-process or multi-threaded
encryptors and live ransomware; coexistence with a live AV if Defender was reduced;
anything the run could not reach, with the reason.

## Machine state after
Shadow copies created this run (IDs); audit rules (none); services stopped, ports
closed; Defender state; files left in `$Run`; whether any tracked file in the clone
changed.

## Reproduction
The commands, in order, that a reader runs to get this result.
```

### 9.2 Rules for the verdict line

- **PASS** only if every row passed.
- **PASS WITH EXCEPTIONS** if the core chain (detect -> attribute -> respond -> snapshot
  -> restore -> verify) completed, rows 6.5-6.7 held, **and R13-R21 all passed**, but
  peripheral rows failed or were blocked. List them in the sentence.
- **FAIL** if any link of the core chain did not complete, if a safety invariant
  (6.5-6.7) failed, **or if any of R13-R21 failed**: a fix that does not hold on the
  VM is the main thing this run exists to find.
- `BLOCKED` and `NOT TESTED` rows count against the verdict. Do not write "n of m
  passed" over a table containing one without saying so on the same line.

### 9.3 KNOWN-OPEN does not fail the verdict, but it is never hidden

F2, F3 and F6 are recorded by the branch as unfixed and F2b as blocked. They are
measured and shown beside the previous run's numbers, and **named in the verdict
sentence**. They do not turn PASS WITH EXCEPTIONS into FAIL on their own. A result
*worse* than the previous run's on the same row does: say so as a regression.

---

## 10. TEARDOWN (after the report is written)

1. `stop_stack.ps1`; confirm ports 8000-8004 and 8501 are closed.
2. `setup_attribution_audit.ps1 -Revert` for every path it was run on; confirm no audit
   rule remains and the subcategory and log size match `machine_state_before.txt`.
3. `--restore` for every simulator directory; hash against `pre_attack_manifest.json`.
4. If you used Appendix A, undo it exactly as written there. Otherwise there is nothing
   to undo: state that Defender was not changed.
5. List the shadow copies this run created (`vssadmin list shadows`, minus the ones you
   recorded at the start, minus `{DD628FFD-...}`). **Delete one only with the operator's
   say-so**, by ID, with `vssadmin delete shadows /shadow=<id>`. Reverting the VM
   snapshot removes them all at once.
6. Tell the operator to copy `VM_TEST_REPORT_*.md`, `vm_test_results_*.json` and
   `$Evid\` out of the VM before any revert.

## 11. IF YOU CANNOT FINISH

Write the report anyway: everything you measured, every row you could not reach marked
`BLOCKED` with the obstacle and what the operator must do. A partial report with an
honest boundary is the deliverable. A run with no report is not.

---

## Appendix A - Defender fallback (use only if files were quarantined)

Only after §2.3's trigger. Disposable VM only. Tamper Protection **cannot be scripted
off**: if `IsTamperProtected` is `True`, stop and give the operator these steps: Windows
Security -> Virus & threat protection -> Manage settings -> Tamper Protection **Off**
(accept UAC); in the same screen turn off Real-time protection, Cloud-delivered
protection and Automatic sample submission; under Controlled folder access turn it
**Off**. Re-check `IsTamperProtected` is `False` before continuing.

Then, from the elevated shell, **verify each setting after setting it** (`Set-MpPreference`
fails silently):

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -EnableControlledFolderAccess Disabled
Set-MpPreference -MAPSReporting 0            # no cloud lookups
Set-MpPreference -SubmitSamplesConsent 2     # never send a sample
Add-MpPreference -ExclusionPath $Repo, $Run
Add-MpPreference -ExclusionProcess 'python.exe'
Add-MpPreference -ExclusionExtension '.locked'
```

`MAPSReporting 0` and `SubmitSamplesConsent 2` matter even if you skip the rest: without
them the machine can upload the simulator to Microsoft as a suspected sample.

Prove it with the project's own artefact before relying on it: run
`scripts\ransomware_simulator.py --target-dir $Run\defender_probe --family locker`,
wait 20 s, and confirm every file it created is still there; clean up with `--restore`.
If a file vanished, show `Get-MpThreatDetection | Select -First 10` and
`& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Restore -ListAll`, and say so.

**Undo, in teardown:** reverse each setting (`$false` / `Enabled` / `2` / `1`),
`Remove-MpPreference` each exclusion, confirm with `Get-MpComputerStatus`, and tell the
operator to turn Tamper Protection back on (you cannot).

## Appendix B - Baseline from the last run (2026-10-04, `5952218`)

Copy from `reports/VM_TEST_REPORT_2026-10-04.md` when you need a comparison:
898 tests passed, 5 skipped, 0 failed; 13/13 families, 130/130 files flagged, first flag
16-78 ms; 0/69 false positives; 0 wrong PIDs; 28 kills (request 0.82-6.55 s after
detection, median 1.40 s; kill 10-30 ms); FEBR < 5 for `slowburn`, `grinder`, `poisoner`;
snapshot folder 10/10 and 10/10, VSS 10/10 in 4.25 s, shadow copy 2.5 s; ledger 1,556 and
1,923 blocks valid, live tamper caught on block 881, in-place tampers 20/20, structural
0/8; gateway `/health` 5.5-10.3 s with the dashboard open (F1); defect re-check 42 of 42.
