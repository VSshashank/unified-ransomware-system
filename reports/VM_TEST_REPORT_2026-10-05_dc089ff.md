# URDS full test on the Windows VM: `fix/vm-2026-10-04-findings` at `dc089ff`

**Date:** 2026-10-05, 20:30-22:00 IST (UTC+05:30).
**Tested:** branch `fix/vm-2026-10-04-findings`, commit `dc089ffe2bf8b978a4782b1abe33d9da9183bb7d` (the expected tip; origin had not moved); descends from `5952218`: yes (24 commits, 48 files, +4,672/-674).
**Machine:** URDS-CLEAN, Windows 11 Enterprise Evaluation 10.0.26200, 4 vCPU, 6.0 GB RAM, VirtualBox (innotek GmbH); last boot 2026-10-05 20:26:31 IST.
**Session:** unelevated (Claude Code, `IsInRole(Administrator) = False`). The operator ran the elevated half: `full_elevated.ps1` (21:06-21:41 IST, run 2) and `followup_elevated.ps1` (21:48-21:51 IST: cleanup, R17, rule-4 re-runs). Every row says which half it came from: run 1 = unelevated, snapshot-folder mode; run 2 and the follow-up = elevated, native mode with VSS.

## Verdict

**FAIL** - the core chain (detect -> attribute -> respond -> snapshot -> restore -> verify) completed on Windows with 0 wrong PIDs and every safety invariant held, but **two of the fixes did not hold on the VM**:

- **R16:** a fresh writer behind another process's 20-write burst was killed 2.0-8.7 s after its write; 1 of 8 runs met the branch's own 2.05 s bound. The kill no longer waits for the pipeline backlog, but it now waits behind the burst writer's escalations, which run one at a time, about 0.35 s each.
- **R14(b):** `attack_chain_demo.py`'s TC-07 fails elevated. The attribution it judges was correct every time; the demo's own process bookkeeping is wrong.

R13, R15, R17, R18, R19, R20 (on re-run) and R21 passed, as did R14(a), (c) and (d). KNOWN-OPEN and measured: F2 (FEBR < 5 for 3 of 13 families, unchanged), F2b (suspend still 404), F3 (`grinder` restores 9/10), F6 (1.9 `file_event` blocks and 2 incidents per encrypted file). Not tested: EMBER, reboot, Docker, enforced isolation; in-place encryption of pre-existing documents was measured unelevated only.

**Harness incident, disclosed here because it touched the machine:** my R17 loop in `full_elevated.ps1` created nine empty folders under `C:\WINDOWS\system32` and put the project's audit rule on one of them. It was found the same evening and fully undone by the follow-up; see "Machine state after".

## Headline numbers

| Area | This run (`dc089ff`) | Last run (`5952218`) |
|---|---|---|
| Fresh install | 7 installs exit 0 in 330 s; `pip check` clean | exit 0 in 294 s, clean |
| Suites | gateway 91, ledger 99, monitor 570, ml-engine 50 (+3 skipped), response 127 (+2 skipped), dashboard 4: **941 passed, 5 skipped, 0 failed**; Pester 30 | 898 passed, 5 skipped, 0 failed |
| Claim matrix | 16 claims, 0 failed | 15 claims, 0 failed |
| Detection, live | 130/130 (run 1); every encrypted file flagged in run 2 (107 written before kills); first flag 17-29 ms (run 2), 22-76 ms (run 1; 4 families re-measured with a tight probe) | 130/130; 16-78 ms |
| False positives, benign | 0 of 69, both runs | 0 of 69 |
| Attribution (elevated) | **0 wrong PIDs** in 68 + 227 named events and 205 ledger blocks; two-writer rule 5 of 5 | 0 of 78 / 238; 5 of 5 |
| Termination | kill requested median 1.57 s after the read (1.23-10.28 s, 44 kills, wall clock); kill itself 11.7-73.8 ms; write -> PID gone median 1.58 s (n=25, monotonic); FEBR < 5 for 3 of 13 | 0.8-6.6 s, median 1.40; 10-30 ms; 3 of 13 |
| First write after a burst (R16) | **2.0-8.7 s** (8 runs; 1 within 2.05 s) | 6.92 s |
| VSS shadow copy | 2.8 s | 2.5 s |
| Recovery | snapshot folder 10/10 and 10/10; VSS 10/10 + D4 4/4; own SHA-256 10/10, 10/10, 10/10, 4/4 | 10/10; 10/10; 10/10 |
| Ledger | 2,134 (run 1) and 2,454 (run 2) blocks valid; verify 9-11 / 14 ms (ledger's figure); tamper caught on saved copies (blocks 1068, 1228) and live by `si_demo` (2152) | 1,556 valid; 7-9 ms; yes |
| Gateway `/health`, dashboard open | median 17.2 ms (run 1), 11.7 ms (run 2) | 6,939 ms |
| Dashboard | every panel drawn; 20 refreshes in 20 s | title only |

## Environment

- **OS and VM:** Windows 11 Enterprise Evaluation 10.0.26200 on VirtualBox, 4 vCPU, 6,422,401,024 bytes RAM; C: NTFS, 51.5 GB free of 84.4 GB.
- **Network:** NAT, host shared folders off (operator). The operator took VM snapshot `clean-before-latest` at the start.
- **Python:** 3.12.10, pip 26.2.1, streamlit 1.51.0, Pillow 12.3.0, pyarrow 21.0.0, pywin32 308.
- **Clone:** fresh clone in `C:\URDS-latest`, venv `C:\URDS-latest\.venv`.
- **URDSAgent** (LocalSystem, `C:\URDS`): Running throughout, not touched; `C:\URDS` not used.
- **Ports:** 8000-8004 and 8501 were free at the start and closed at the end.
- **Clock:** VirtualBox slews the wall clock (0.8x-1.44x, measured 2026-10-04). Every duration here is on `perf_counter`/`Stopwatch`; sub-second differences between wall-clock stamps are marked approximate.
- **Stack:** six native processes, one log each; network isolation forced off (`RESPONSE_ISOLATION_ENABLED=false`); `URDS_WRITE_REPORTS` unset except in R15's deliberate step.
- **Recovery source:** `RECOVERY_SNAPSHOT_ROOT` was set only in run 1. In native mode `start_stack.ps1` refuses to start if it is set, and `/response/recover/status` reported `snapshot_root_override: null`.
- **EMBER:** not trained (operator: no download).
- **Secrets:** generated per run as GUIDs and kept only in `tools\secrets.json`.

## Security posture

- **Windows Defender stayed ON and was not changed**, before, during and after:
  - Before: AMRunningMode Normal, real-time on, behaviour on, IOAV on, Tamper Protection off (as found), Controlled Folder Access off, MAPSReporting 0, SubmitSamplesConsent 0, signatures 1.459.560.0 (2026-10-05 05:40).
  - After: identical except the routine signature update to 1.459.561.0.
  - The elevated script recorded `defender_as_before: true`.
- **Nothing from this run was quarantined.** `Get-MpThreatDetection` lists 5 detections, all from 2026-09-20 to 09-23, against `C:\URDS\agent\procmon.py` and `...\AppData\Local\URDS\tools\quickbuck.exe`; none relate to this run. Appendix A was not used. Every result here is a **coexistence result with a live AV**.
- **Audit policy and Security log:**
  - Before: File System subcategory `Success`, Security log 1 GiB (1,073,741,824 bytes).
  - After every revert, and at the end: the same; the project script never changed either.
  - Audit rules were added to and removed from `watch_native`, `r17_redo\f01-f10` and `watch_followup` under the run folder; none remain, and the state file `C:\ProgramData\URDS\attribution_audit_state.json` is gone.
  - Plus the System32 incident below.
- **Firewall profiles:** unchanged (`firewall_as_before: true`).

## Results

| # | Test | Target | Measured | Result | Evidence |
|---|---|---|---|---|---|
| 1.1 | Fresh clone and checkout | tip of origin/fix/vm-2026-10-04-findings; descends from 5952218; porcelain empty | dc089ffe2bf8b978a4782b1abe33d9da9183bb7d (= expected tip); merge-base --is-ancestor exit 0; 24 commits; 48 files, +4,672/-674; porcelain empty | PASS | run_log.md |
| 1.2 | Fresh install (6 services + scripts) | exit 0; pip check clean | 7 pip installs exit 0 in 329.7 s; pip check: No broken requirements; pywin32 postinstall exit 0 (COM samples not registered: no admin); imports ok; streamlit 1.51.0, Pillow 12.3.0, pyarrow 21.0.0 | PASS | evidence/install.txt |
| 1.3 | Behavioural model | trains; same MD5 as last run if versions match; porcelain empty | 72.5 s; MD5 F481AA17F5C777596288F71229BA4661 (= C:\URDS-integ copy); porcelain empty | PASS | evidence/train_behavioral.txt |
| 2.1 | pytest gateway | 91 passed | 91 passed | PASS | evidence/pytest_gateway.txt |
| 2.2 | pytest ledger | 99 passed | 99 passed | PASS | evidence/pytest_ledger.txt |
| 2.3 | pytest monitor | 570, all passing | 570 passed, first pass (no load-sensitive failure) | PASS | evidence/pytest_monitor.txt |
| 2.4 | pytest ml-engine | 50 passed, 3 skipped (no EMBER) | 50 passed, 3 skipped: 'no EMBER model' x3 | PASS | evidence/pytest_ml-engine.txt |
| 2.5 | pytest response | 127 passed, 2 skipped | 127 passed, 2 skipped: 'SIGTERM cannot be ignored on Windows' x2 | PASS | evidence/pytest_response.txt |
| 2.6 | pytest dashboard | 4 passed | 4 passed | PASS | evidence/pytest_dashboard.txt |
| 2.7 | Pester scripts/tests | 30 passed | Passed: 30 Failed: 0 Skipped: 0 | PASS | evidence/pester.txt |
| 2.8 | claim_matrix.py --tests | 16 claims, 0 failed | 16 claims (14 made, 2 not claimed), 0 failed verification; C-16 ok | PASS | evidence/claim_matrix.txt |
| 2.9 | Seven new test files run, not skip | 18, 6, 1, 18, 3, 2 (Windows), 5; 6; 4 | 18, 6, 1, 18, 3, 2, 5 passed; test_chain_pid_fields 6; test_render 4; 0 skipped | PASS | evidence/new_test_files.txt |
| 2.10 | simulator_sweep.py | 13/13, 8/8 each | 13/13 families, 8/8 each, restore ok; first flag 0-125 ms (renamer 125, locker 47; last run <= 16 ms); script criterion <= 2 s met | PASS | evidence/simulator_sweep.txt |
| 2.11 | tamper_sweep.py | in-place 20/20; structural 0/8 is the documented limit | in-place 20/20; structural 0/8 (documented limit of an unanchored chain) | PASS | evidence/tamper_sweep.txt |
| 2.12 | failure_injection.py | 5 distinct outcomes, none 'verified' | all five ran, distinct, none reported as verified, every outcome explained | PASS | evidence/failure_injection.txt |
| 2.13 | load_test.py (not gated) | re-measure | 1st: median 91.9 / p95 270 / p99 365 ms, 44.9% > 100 ms; re-runs on a quiet VM: 51.8/110.8/143.3 (8.0%) and 49.5/106.5/146.9 (7.1%). Last run 52/113/151 (9.3%) | PASS | evidence/load_test.txt, load_test_rerun2.txt, load_test_rerun3.txt |
| 2.14 | Gate 1: porcelain after every offline script | empty | empty after each of the 4 scripts and after the suites | PASS | evidence/*.txt (porcelain_after lines) |
| 3.1 | Run 1 stack (snapshot mode) | 6 services healthy; ledger valid; dashboard ok | all 6 up in <= 6 s; gateway /health healthy; ledger valid (0 blocks); /_stcore/health ok; recover/status snapshot_root_override set, elevated false | PASS | evidence/run1_health.txt |
| 3.2 | Run 2 stack (native, elevated) | 6 healthy; RECOVERY_SNAPSHOT_ROOT unset; VSS elevated | all 6 up in <= 6 s; recover/status snapshot_root_override null, vss supported true, elevated true | PASS | evidence/run2_health.txt |
| 5.1 | Benign workload (69 events) | 0 flagged; workload alive; verdicts benign/benign_compressed/deleted | run 1: 0 of 69; run 2 (attribution live): 0 of 69; workload exit 0 both; verdicts {benign, benign_compressed, deleted} | PASS | evidence/full_e2e_run1.json, full_e2e_run2.json |
| 5.2 | Genuine ZIP | benign, valid | benign / valid (created + modified), both runs | PASS | evidence/full_e2e_run1.json |
| 5.3 | PK\x03\x04 + random | suspected_encryption, structural_mismatch, forged | suspected_encryption, 'declares a zip container but the zip structure is not there', validation_state forged, both runs | PASS | evidence/full_e2e_run1.json |
| 5.4 | 13 families x 10, each its own process | 130/130 flagged; first flag <= 100 ms | run 1: 130/130 flagged; harness first flag 32-118 ms (grinder 41 ms from its first malicious write); the 4 over 100 ms re-measured 3x with a tight probe: 21.6-76.2 ms after encryption began (grinder 24-42 ms after its first malicious write) (rule 4). Run 2: every encrypted file flagged (107 of 107 written before the kills; 130 decoys), first flag 20-29 ms, grinder 17 ms from first malicious write, poisoner setup flagged 1.08 s before encryption | PASS | evidence/full_e2e_run1.json, flag_probe_run1.json, full_e2e_run2.json |
| 5.5 | In-place encryption of 10 existing documents (other process) | 10/10 flagged | run 1: 10/10 encrypted, 10/10 files flagged (run 2 skipped this phase: its restore needs a snapshot folder) | PASS | evidence/full_e2e_run1.json |
| 5.6 | Flagged write visible through the gateway (dashboard closed) | < 1 s | run 1: 0.020-0.063 s (5/5); run 2: 0.022-0.117 s (5/5) | PASS | evidence/full_e2e_run1.json, full_e2e_run2.json |
| 5.7 | Recovery from the snapshot folder | 10/10 restored + integrity_verified; own SHA-256 10/10 | HTTP 200 success, recovered 10, integrity_verified true, own-hash 10/10 in 4.46 s (label: snapshot folder, not VSS) | PASS | evidence/full_e2e_run1.json, teardown_manifest_check.json |
| 5.8 | locker: snapshot folder, re-attack, recover | 10/10, own hash 10/10 | HTTP 200 success, 10 recovered, integrity_verified true, own-hash 10/10 in 4.52 s | PASS | evidence/full_e2e_run1.json |
| 5.9 | --restore of each family directory | byte-identical; F3 expects grinder/staged 9/10 when killed | run 1 (nothing killed): 13 x 10/10. Run 2: 12 families 10/10, grinder 9/10 (quarterly_report_03.jpg, in progress when killed). staged was killed after 8 files and restored 10/10 | KNOWN-OPEN | evidence/teardown_manifest_check.json |
| 5.10 | D4 recovery, four spellings, snapshot folder (run 1) | 4/4 integrity_verified | 4/4 (as recorded, '/', lower case, mixed) integrity_verified, bytes match | PASS | evidence/e2e_check_run1.json |
| 5.11 | Unelevated attribution degradation | unavailable, isolate_and_log | error 'could not subscribe to the Security channel: (5, 'EvtSubscribe', 'Access is denied.')'; every response network_isolation_planned + admin_notified; 0 PIDs named | PASS | evidence/e2e_check_run1.console.txt |
| 6.0a | Audit setup + -Verify on watch_native | exit 0; End-to-end probe ok | setup exit 0, probe ok 'on attempt 2'; -Verify exit 0 | PASS | evidence/setup_watch_native.txt |
| 6.0b | Attribution gate | available, windows-security-4663, kernel_grade | available=True source=windows-security-4663 kernel_grade=True error=None; audit probe writes_recorded 0 -> 5 | PASS | evidence/e2e_check_run2.console.txt |
| 6.1 | D1: 5 single writes, fresh process each | 5/5 certain, PID = writer, writer killed | 5/5 certain with the writer's PID, 5/5 killed; write -> PID gone 4.03 (first, after the D3 burst), 1.62, 1.58, 1.64, 1.58 s | PASS | evidence/e2e_check_run2.json |
| 6.2 | D2: write then rename x5 | rename certain, correct PID | 5/5 rename events certain, PID = writer, outcome verified, writer killed; rename attempts 1 each | PASS | evidence/e2e_check_run2.json |
| 6.3 | D3: 20-file burst | last event <= ~0.2 s after last write; queue_wait_ms on every suspicious event | 20 writes in 0.077 s; last full-size event +0.255 s (wall clock: approximate, +/-0.1 s at this VM's slew; run 1 +0.166 s); queue_wait_ms on 40/40 (max 3.1 ms) | PASS | evidence/e2e_check_run2.json |
| 6.4 | D4: four spellings, recovery from the real shadow copy | 4/4 integrity_verified | 4/4 HTTP 200 success, integrity_verified true, own hash true; file_recovered blocks 2360-2394 joined to incidents | PASS | evidence/full_e2e_run2.json |
| 6.5 | Invariant: benign writer then encryptor 0.5 s later x3 | never certain, nobody killed | 3/3: answers only probable (naming the encryptor), nobody killed | PASS | evidence/e2e_check_run2.json |
| 6.6 | Invariant: second writer after first one's detection x2 | second never certain, never killed | 2/2: second writer only probable, never killed (first writer certain and killed) | PASS | evidence/e2e_check_run2.json |
| 6.7 | Wrong PIDs over every correlated event | exactly 0 | 0 of 68 events (e2e_check), 0 of 227 (full_e2e: 33 certain, 194 probable), 0 of 205 ledger blocks; ledger_coverage: 410 blocks name a process, 0 unsupported | PASS | evidence/e2e_check_run2.json, full_e2e_run2.json, analysis_run2.json |
| 6.8 | 13 families x 10, elevated: FEBR, attribution, termination | record (KNOWN-OPEN, F2) | terminated: grinder (FEBR 3), poisoner (4), slowburn (2), staged (8); notedrop certain+terminated after it finished (10); the other 8 finished first (FEBR 10). First malicious write -> PID gone 0.52-1.63 s for the killed ones. No wrong PID in any family | KNOWN-OPEN | evidence/full_e2e_run2.json |
| 6.9 | VSS available, --status-only creates nothing | shadow copies unchanged; supported, elevated | 1 -> 1 (only {DD628FFD...}); supported True, elevated True, list_snapshots ok (1) | PASS | evidence/vss_status_only.txt |
| 6.10 | Snapshot | < 30 s, listed, snapshot_created block | {1D563C09-87F1-4033-A72C-39447130114B} in 2.8 s (3.4 s with process start); listed PASS; snapshot_created block 2290 | PASS | evidence/full_e2e_run2.console.txt |
| 6.11 | Restore (locker over the same directory) | restored + integrity_verified for every file | 10/10 damaged before; HTTP 200 success, 10 recovered, integrity_verified true, 4.33 s; baselines present for all 10 before encryption | PASS | evidence/full_e2e_run2.json |
| 6.12 | Independent check | own SHA-256 = pre_attack_manifest for every file | 10/10 locker + 4/4 D4 match pre_attack_manifest_run2.json | PASS | evidence/pre_attack_manifest_run2.json, teardown_manifest_check.json |
| 6.13 | Logged | file_recovered joined to the incident | 14 file_recovered blocks (2340-2394), each with incident_id, integrity_verified true, expected = restored hash | PASS | evidence/ledger_run2_saved.db |
| 6.14 | Chain | valid; verify < 50 ms (ledger's own figure) | 2,445 blocks valid in 14.0 ms (ledger's figure); HTTP round trip median 16.2 ms, max 31.0 ms (20 runs) | PASS | evidence/full_e2e_run2.json |
| 8.7 | Ledger tamper on saved copies (separate ledger on 8013) | valid:false naming the edited block | run 1 copy: block 1068 edited -> valid false, invalid_block_id 1068; run 2 copy: 1228 -> 1228; si_demo live TC-05 caught block 2152 and restored | PASS | evidence/tamper_saved_run1.json, tamper_saved_run2.json |

## Regression checks (what changed since 5952218)

| ID | Defect | Method | Measured | Result | Evidence |
|---|---|---|---|---|---|
| R13 | Dashboard rendered nothing and saturated the gateway (F1) | dashboard held open by headless Edge >= 60 s; 20x /health and /monitor/events (token) on perf_counter; gateway access-log count over 20 s; render in the app's browser pane | open: /health median 17.2 ms (run 1) and 11.7 ms (run 2); /monitor/events 11.0 and 8.7 ms; closed: 16.9/10.5 and 11.4/8.6 ms. 20 GET /health + 20 POST /predict in 20 s (both runs; 0 with it closed). Every panel drawn: 'System Secure' banner, pipeline tiles, Model Decision, Entropy Trend, Ledger Evidence, Service Health, Recent File Events, Model Quality; Uptime tile advanced 299 -> 303 s in 5 s. Headless --dump-dom was inconclusive (Streamlit shell only) | PASS | evidence/r13_run1_*.json, r13_run2_*.json, r13_run1_browser_render.txt |
| R14 | Fabricated evidence (X1) | (a) git grep 6666; (b) attack_chain_demo.py unelevated and elevated; (c) ledger_coverage --ledger-db, C-16; (d) si_demo rows | (a) empty (exit 1). (b) unelevated: TC-07 skip, exit 1, no terminate issued - as required. Elevated: TC-07 FAIL 'WRONG PROCESS' in all 4 runs (2 venv, 2 base interpreter) although the system's own certain answer named the real writer and terminated it every time: the demo records the venv launcher's PID (Popen(sys.executable) from a venv; measured 11800 vs writer 11756), and it matches events by file name only, so a previous run's event for the same name in another folder is judged as this run's (base-interpreter run: system named 4272 = its writer, demo also counted 8240 from the earlier folder). (c) 2,454 blocks, 410 name a process, 0 unsupported, exit 0, file unchanged; C-16 ok. (d) file_encrypted rows process_id None / unknown; no 6666 or 4321 anywhere | FAIL | evidence/r14a_grep_6666.txt, demo_attack_unset.console.txt, demo_attack_chain_elevated*.txt, demo_followup_*.txt, venv_launcher_pid_probe.txt, ledger_coverage_run2.txt, r14d_si_demo_rows.txt |
| R15 | Demos wrote reports/ unconditionally (F7) | both demos with URDS_WRITE_REPORTS unset; with --out; with =1, copy and git restore | unset: porcelain empty after each; --out wrote only evidence/demo_*; =1: 3 tracked reports modified, copied to evidence/regenerated_*, git restore -> porcelain empty. Transcript PIDs are real processes, but the 'writer pid' printed from a venv is the launcher, not the writing process (see R14) | PASS | evidence/run1_demos.console.txt, regenerated_* |
| R16 | A kill waited for the pipeline backlog (F2a) | elevated: 20 rapid writes by A, then one write by fresh B (alive 10 s); B write -> B PID gone on perf_counter; x5, then x3 re-run | 5.55, 8.73, 3.01, 5.47, 2.86 s; re-run 2.39, 6.25, 2.00 s: 1 of 8 within 2.05 s (last run 6.92 s). Ledger: B's question closes at the horizon (~1.55 s after the read) but its terminate request waits behind 4-22 of A's escalations, dispatched serially 0.30-0.38 s apart, all but the first refused for a PID already dead. Incident IDs present 8/8; file_event < trigger < attribution_escalation holds; the Response service's terminate blocks precede the file_event (the kill no longer waits for _work). D1 #1 after the D3 burst: 4.03 s (FIXES expects ~1.6 s) | FAIL | evidence/r16_backlog.json, r16_rerun.json, ledger_run2_saved.db |
| R17 | Audit probe reported a working folder as broken (F4) | ten new folders: setup then -Verify, then -Revert each (follow-up script; the first attempt was a harness failure, see 'Apparent failures') | 10/10 setup exit 0 with 'End-to-end probe ok', 10/10 -Verify exit 0, 0 false failures; reverts 10/10 exit 0; log size 1 GiB and subcategory Success unchanged; no rule left | PASS | evidence/r17_redo.json, followup_elevated.log |
| R18 | Stale file_size beside the full file's hash (F5) | every file_baseline block and event with a hash vs pre_attack_manifest; zero-size beside non-empty hash | run 1: 352 baselines / 1,233 events, 290 / 516 in the manifest, 0 mismatches, 0 zero-size; run 2: 182 / 1,358, 134 / 475, 0 mismatches, 0 zero-size. size_changed_during_read present on all; true on 5+36 (run 1) and 6+68 (run 2) | PASS | evidence/analysis_run1.json, analysis_run2.json |
| R19 | Dashboard raised ArrowTypeError every refresh | dashboard open >= 60 s after attacks; search its log | 0 'Serialization of dataframe to Arrow table was unsuccessful', 0 ArrowTypeError/ArrowInvalid, 0 Traceback (run 1: 153 KB of log; run 2: 69,510 lines - all a use_container_width deprecation warning) | PASS | evidence/../run1/logs/dashboard.log, ../run2/logs/dashboard.log |
| R20 | Two Security-channel subscriptions per Monitor start | start/stop/start then a fresh writer, x5, HandleCount before/after; re-run x5 (rule 4) | first run 4/5: cycle 5's write answered unknown (no_record) and was not killed; the Security log holds its 4663 (PID 0x26cc = the writer, 16:07:38.030Z) - it reached the Monitor after the 1.5 s horizon; attribution stayed available and full_e2e right after attributed normally. Re-run 5/5 certain, killed at 1.57-1.59 s. Handles 299 -> 290 and 224 -> 296 (first start) then flat: no steady rise | PASS | evidence/r20_cycles.json, r20_rerun.json, r20_security_log_4663.txt |
| R21 | PE parser opened files without FILE_SHARE_DELETE | test_pe_read_shares_delete.py; live: copy python.exe into the watch folder, POST /features, delete at once, x5 per run | 2 passed, not skipped; live 10/10: /features 200 with PE fields (pe_imports_count 44, api_calls), delete succeeded with 0 sharing violations | PASS | evidence/new_test_files.txt, r21_run1.json, r21_run2.json |
| F2 | Kill arrives after fast encryptors finish | 6.2 | FEBR < 5 for 3 of 13 (grinder 3, poisoner 4, slowburn 2), as last run; staged killed at 8; write -> PID gone for single writers 0.52-4.03 s, median 1.58 s (n=25); kill request after the read median 1.57 s (wall clock, 44 kills), kill itself 11.7-73.8 ms | KNOWN-OPEN | evidence/full_e2e_run2.json, analysis_run2.json |
| F2b | Suspend-first response | POST /response/suspend | HTTP 404 NOT_FOUND (both runs); routes: recover, recover/status, health, terminate, isolate, trigger. Not implemented, as FIXES.md says | KNOWN-OPEN | evidence/f2b_suspend_probe.txt |
| F3 | --restore skips the file in progress when killed | row 5.9 | grinder 9/10 (KNOWN-OPEN); staged 10/10 this run (killed between files) | KNOWN-OPEN | evidence/teardown_manifest_check.json |
| F6 | 2-3 incidents and ~5 blocks per encrypted file | run ledger | run 2: 522 file_event blocks for 273 distinct suspicious files (1.91 each), incidents per file median 2 (max 4), 6.06 ledger blocks per suspicious file, 2,454 blocks; 99 'termination_refused_or_unreachable' escalations on certain answers (PID already dead) - and these now cost time (R16). Last run: 317 file_event for ~170 files; 1,556 blocks | KNOWN-OPEN | evidence/analysis_run2.json |

## Faults found this run

### 1. R16: a fresh writer's kill still waits behind a burst (defect 16 does not hold on Windows)

**What failed.** 20 rapid high-entropy writes by process A, then one write by a fresh process B that stays alive. B's write to B's PID gone, on `perf_counter`:
- First run: 5.55, 8.73, 3.01, 5.47 and 2.86 s.
- Re-run (rule 4, same script, fresh audited folder, follow-up): 2.39, 6.25 and 2.00 s.
- 1 of 8 within the 2.05 s bound.
- The branch's own "Check on Windows" (D1 straight after the D3 burst) measured 4.03 s where FIXES expects about 1.6 s.

**Which link broke.** Two independent records agree: the harness's monotonic timing, and the product's own ledger stamps (wall clock, approximate). B's attribution question closes on time: `horizon_closed_at` about 1.55 s after `observed_at`. Its terminate request is then dispatched 0.9-8.7 s later.

In every repetition the Response service's `terminate` blocks for A and B come in this order:
- `A+ A- A- ... A- B+ B-`: one successful kill of A, then 12, 21, 4, 12, 3 refused requests for A's PID, which is already dead (counting from the ledger order).
- These are dispatched one at a time, 0.30-0.38 s apart.

B's delay grows with the number of A's escalations queued ahead of it. Defect 16 did remove the original cause: B's `terminate` block now lands *before* its own `file_event` block, so the kill no longer waits for `_work`. But `_escalate_loop` handles escalations serially, and every incident of the burst (two per file, F6) gets its own terminate request, including after the PID is gone.

**What it means.** The F2a claim, "a fresh writer is killed about 1.6 s after its write, not 6.9 s", holds only when no other writer's escalations are pending. With another sole writer active it degrades by about 0.35 s per queued escalation of that writer. Attribution and the safety invariants are unaffected: B was named `certain` with its own PID every time.

**What would have to change** (for the maintainer; not diagnosed beyond the ledger):
- Skip or batch escalations for a PID already terminated (the ledger shows `termination_refused_or_unreachable` for them).
- Or run the escalation actions concurrently.
- `test_escalation_bypasses_backlog.py` stubs the Response call, so it cannot see this. A test with a Response stub that takes about 300 ms per call, and with A's escalations queued, would reproduce it.

**Reproduction:** `tools\r16_backlog.py --watch <audited dir> --reps 5` against the elevated native stack. Ledger evidence: `evidence\ledger_run2_saved.db`, blocks 408-502 for rep 1.

### 2. R14(b): `attack_chain_demo.py` TC-07 fails elevated; attribution was right

**What failed.** Four elevated demo runs (two from the venv, two from the base interpreter) all report `tc07_attributed_pid_is_the_writer FAIL` with "WRONG PROCESS", and the demo exits 1.

**Which link broke: the demo, twice.**

1. **It records the wrong PID from a venv.** `Writer` starts `Popen([sys.executable, ...])`. From a venv, `sys.executable` is `.venv\Scripts\python.exe`, a launcher that starts the base interpreter as a child. Measured: `Popen(.venv python).pid = 11800`, while the process that ran the code reported `os.getpid() = 11756` (`evidence\venv_launcher_pid_probe.txt`). In `demo_venv` the system named 8240 (image `...\Python312\python.exe`, "verified as the writer by image and start time") and terminated it; the launcher 8896 then exited, so the demo also saw its writer "end early". (The reused `writer.py` harness already avoided this by starting the base interpreter.)
2. **It matches events by file name only** (`e["file_path"].endswith(victim.name)`, five places). Every run writes `annual_report.docx.locked`, so a previous run's events still in the Monitor's buffer are judged as this run's. In `demo_base` (base interpreter, a fresh folder, 8 s later) the system named the demo's own writer, 4272, `certain`, and terminated it. The demo still printed `attributed (certain): [4272, 8240]` and failed on 8240, which came from the earlier folder.

**What it means.** The X1 port made the demo honest about skips and removed the fabricated victim; that part holds (unelevated: skip, exit 1, nothing terminated). As shipped, though, the elevated demo cannot pass TC-07 when run the way the README installs it (a venv). Neither defect invents evidence; both make a correct attribution read as a wrong one.

**What would have to change:**
- Start the writer with `sys._base_executable`, or have the writer report `os.getpid()`, as `writer.py` does.
- Match events by full path.

**Reproduction:** `followup_elevated.ps1` step D4; transcripts `evidence\demo_followup_venv.txt` and `demo_followup_base.txt`; ledger `evidence\ledger_followup_saved.db`, blocks 598 and 618.

### 3. Minor: one 4663 delivered after the 1.5 s horizon (R20, first run)

- **What happened.** Cycle 5's write was answered `unknown` (`no_record`) and its writer was not killed: the correct safe outcome.
- **Evidence.** The Security log holds its record: RecordId 218696, 16:07:38.0302584Z, ProcessId 0x26cc (the writer), `python.exe`. So the record existed but reached the Monitor after the horizon.
- **Context.** Across run 2, the matched records of the 44 terminations arrived 25-1,269 ms late, median 985 ms, close to the 1,500 ms horizon. 7 of 522 escalations closed `no_record` in run 2.
- **Verdict.** Informational: the re-run was 5/5 and the horizon is a documented design bound.

### 4. Minor: dashboard log noise

While open, the dashboard logs Streamlit's `use_container_width` deprecation warning about 7 times per refresh: 69,510 lines in about 35 minutes in run 2. No error; R19's Arrow errors are gone.

### 5. Observation: the in-process sweep's first flags

`simulator_sweep.py`'s first flags were 0-125 ms (`renamer` 125, `locker` 47). The last report quotes ≤ 16 ms. The script's own criterion (≤ 2 s) passes; this was not re-run.

## Apparent failures that were not product faults

| Looked like | Cause | How it was shown |
|---|---|---|
| Run 1 `full_e2e.py`: `grinder` first flag 364 ms | harness basis: `grinder`'s 5 warm-up writes happen inside its encrypt call, after "beginning simulated encryption" | `encrypt_grinder` source; first flag was 41 ms after its first malicious write; harness changed for run 2 (17 ms) |
| Run 1: `renamer` 112, `spoofer` 101, `staged` 118 ms | harness poller fetched 300 events every 30 ms | rule-4 probe (20 events, 5 ms poll), 3x each: `renamer` 26-27, `spoofer` 23-76, `staged` 22-41, `locker` control 26-31 ms; poller changed for run 2 (20-29 ms) |
| R16 "ledger order not ok" | my check compared with the earliest `response_action`, which is the Response service's own `terminate` record | the order FIXES specifies (`file_event` < `trigger` < `attribution_escalation`) holds 8/8; the terminate block being first is the fix working |
| R16 script ran 28 min | nothing in the product ran then: the ledger has no block between 15:39:37 and 16:07:19 and all reps had finished | most likely a paused console: the operator says they probably clicked in the elevated PowerShell window then, and a selection in QuickEdit mode suspends a process writing to that console (R16 was printing its summary). Not otherwise confirmed; no measurement affected |
| First saved-ledger tamper "not caught" | PowerShell mangled the quotes of an inline Python edit, so nothing was edited | moved the edit to `tools\tamper_edit.py`; caught at blocks 1068 and 1228 |
| R17 in `full_elevated.ps1`: setup exits 1,0,2,2,... | **my bug:** `$r17` (results) and `$R17` (folder) are the same variable in PowerShell; the results list replaced the folder, and paths resolved against `C:\WINDOWS\system32` | redone in the follow-up with distinct names and a scan for case collisions: 10/10, 0 false failures |
| R14(b) base-interpreter control (first attempt) | ran 3 s after the venv demo on the same file: a competitor inside the 3 s window, plus the demo's name-only matching | redone in fresh folders 8 s apart (Fault 2) |
| Run 2 D4 not run by `e2e_check.py` | by design: native mode has no snapshot folder | D4 ran against the real shadow copy in `full_e2e.py`, 4/4 |
| Headless Edge `--dump-dom` showed no panels | virtual time does not wait for Streamlit's websocket (2.9 KB shell, then 0 bytes elevated) | rendered in the app's browser pane: every panel, Uptime advancing |
| Run 1 `load_test.py` p95 270 ms | first run after the suites; not reproduced | two quiet re-runs: 110.8 and 106.5 ms |

## Not tested

- **EMBER static-PE model:** not trained; the operator declined the 1.4 GB download, so 3 ml-engine tests skip with "no EMBER model".
- **A reboot:** it ends the session.
- **Docker:** not installed.
- **Enforced network isolation:** kept off by rule.
- **Multi-process or multi-threaded encryptors, and live ransomware.**
- **In-place encryption of pre-existing documents with attribution live:** row 5.5 was measured in run 1 only. In run 2 the phase was skipped because its restore uses a snapshot folder, which native mode forbids. Instead, the D4 files (written by one process, encrypted by another) were detected, attributed, killed and restored from VSS.
- **F2c:** blocked with F2b.
- **The dashboard render in run 2:** its refresh rate and gateway latency were measured; the panels were viewed in run 1.

## Machine state after

- **Shadow copies:** this run created one, `{1D563C09-87F1-4033-A72C-39447130114B}` (C:, 2026-10-05 ~21:38 IST). Left in place: delete only on the operator's word, with `vssadmin delete shadows /shadow={1D563C09-87F1-4033-A72C-39447130114B}`, or revert the VM snapshot. `{DD628FFD-87F5-4D25-A749-937B0FDF3F42}` was not touched.
- **System32 incident, undone:**
  - What happened: `full_elevated.ps1` step 16 created `C:\WINDOWS\system32\System.Collections.Specialized.OrderedDictionary\f02`-`f10`, all empty, and `setup_attribution_audit.ps1` added `Everyone: WriteData, AppendData (Success)` auditing to `...\f02`. The revert loop failed for the same reason.
  - Undo: `followup_elevated.ps1` ran the project's `-Revert` for `...\f02` (exit 0; rules after: none; state file removed), then removed the nine folders and their parent, each only after checking it was empty and unaudited.
  - Result: `stray_root_exists_after: false`. Log size and subcategory were unchanged throughout. Nothing else under `C:\Windows` was written.
- **Audit rules:** none left on any folder this run used; state file absent.
- **Services and processes:** all stopped; ports 8000-8004, 8013, 8501 and 9333 closed; no Edge process using this run's profiles.
- **Defender:** as found (see Security posture).
- **Test data:** all under `C:\URDS-latest-run\20261005_203206`. Every simulator folder matches `pre_attack_manifest_*.json` except run 2's `fam_grinder\quarterly_report_03.jpg`, the F3 file, still encrypted (a decoy the simulator created).
- **Clone:** `git status --porcelain` empty at the end; the only tracked-file changes were R15's deliberate regeneration, restored with `git restore -- reports/`. This report and its JSON are new, untracked files.

## Reproduction

```powershell
# unelevated
git clone https://github.com/VSshashank/unified-ransomware-system.git C:\URDS-latest
git -C C:\URDS-latest checkout --detach dc089ffe2bf8b978a4782b1abe33d9da9183bb7d
cd C:\URDS-latest; python -m venv .venv
foreach ($s in 'gateway','ledger','monitor','ml-engine','response','dashboard') { .\.venv\Scripts\pip.exe install -r "services\$s\requirements.txt" }
.\.venv\Scripts\pip.exe install -r scripts\requirements.txt pytest pytest-asyncio httpx
.\.venv\Scripts\python.exe src\train_behavioral_model.py
# per service, from its own folder: ..\..\.venv\Scripts\python.exe -m pytest -q -rs
powershell -ExecutionPolicy Bypass -Command "Invoke-Pester scripts/tests"
.\.venv\Scripts\python.exe scripts\claim_matrix.py --tests
# offline: simulator_sweep, tamper_sweep, failure_injection, load_test (URDS_WRITE_REPORTS unset)
# run 1 (tools\ in the run folder):
tools\start_stack.ps1 -Mode snapshot -Watch <run>\watch_snapshot_mode -RunDir <run>\run1 -SnapshotRoot <run>\snapshots
python tools\e2e_check.py --watch <run>\watch_snapshot_mode\e2e --snapshot-root <run>\snapshots --out ...
python tools\full_e2e.py --repo C:\URDS-latest --venv-python C:\URDS-latest\.venv\Scripts\python.exe --watch <run>\watch_snapshot_mode\full --snapshot-root <run>\snapshots --evid <run>\evidence --label run1 --out ...
python tools\flag_probe.py <dir> <out> renamer,spoofer,staged,grinder,locker 3
python tools\r21_features_delete.py; tools\r13_run1.ps1; tools\run1_demos.ps1; tools\tamper_saved.ps1
# run 2, from an Administrator PowerShell:
full_elevated.ps1        # (its step 16 is the faulty R17 loop: use followup_elevated.ps1 part B instead)
followup_elevated.ps1
# analysis: tools\analyse_run.py, scripts\ledger_coverage.py --ledger-db <saved copy>, tools\build_report.py
```

Harness:
- Reused from `C:\URDS-recheck\full\tools`, with SHA-256 of each original recorded in `evidence\harness_reused_sha256.json`.
- Changed for this run: `writer.py`, `full_e2e.py`, `e2e_check.py` (each change marked "2026-10-05", patch scripts kept as `tools\_patch_*.py`), and `start_stack.ps1` (rewritten with `-Mode`).
- New: `r13_dashboard.py`, `r16_backlog.py`, `r20_cycles.py`, `r21_features_delete.py`, `flag_probe.py`, `analyse_run.py`, `tamper_saved.ps1`, `dash_open.ps1`, `build_report.py`.
- No product code was edited.
