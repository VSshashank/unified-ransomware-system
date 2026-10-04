# URDS full test on the Windows VM: `fix/windows-integration-defects` at `5952218`

**Date:** 2026-10-04, from 15:00 to 18:45 IST.
**Tested:** branch `fix/windows-integration-defects` at commit `5952218d8f2e3898453e1ac74f72ae3cce90f301`. The checkout matches `origin`.
**Machine:** the URDS-CLEAN test VM.
**Updated:** the same evening. F1 was fixed after the test, in `820d7a4`; see [After the test: F1 fixed](#after-the-test-f1-fixed). Every other figure is from the test of `5952218`.

## Verdict

**The system works end to end, with two faults that affect normal use.** Since the test, F1 has been fixed (`820d7a4`); F2 remains open.

**What works:**
- **Installation, training and tests:** a fresh install succeeds. Model training is reproducible, byte for byte. Every automated suite passes: 898 tests, 0 failed.
- **Detection:**
  - all 13 simulated ransomware families detected
  - every encrypted file flagged
  - first alert visible within 16–78 ms
  - ordinary office work flagged **0** times
- **Attribution:**
  - correct in every case: no event named a wrong process, in about 300 named events across both elevated runs
  - the safety rule held: when two processes write to the same file, the attribution is never `certain` and nobody is killed
- **Recovery:**
  - files restored and hash-verified from a snapshot folder: 10/10 encrypted in place, and 10/10 from the `locker` family
  - a real VSS shadow copy created in 2.5 s and restored from, 10/10 verified with my own SHA-256
- **Ledger:** a live tamper was caught and the edited block named.

**Faults that affect normal use:**

| # | Fault | Severity |
|---|---|---|
| **F1** | **The dashboard never shows any data, and while it is open the gateway slows down for everyone.** The page shows only its title. Gateway calls take 2.4–10 s instead of 0.2–0.9 s. Found in this test, not reported before. **Fixed after the test in `820d7a4`.** | High |
| **F2** | **The kill comes too late for fast encryptors.** Termination is sent a median 1.40 s after detection and up to 6.6 s during a burst. Ten of 13 families, and the in-place encryptor, encrypted every file before termination. The project's TC-01 target is under 5 files encrypted; it was met by 3 families, all slow ones. | High (design limit) |
| F3 | The test simulator's `--restore` cannot restore the file it was encrypting when it was killed. Test tooling only. | Low |
| F4 | `setup_attribution_audit.ps1` once reported "Attribution will not work on this path" for a folder where it did work. | Low |
| F5 | Some events and ledger blocks record `file_size: 0` beside the full file's hash. Already known. | Low |
| F6 | Each file-system notification becomes its own incident: 2–3 incidents and about 5 ledger blocks per encrypted file. | Low |
| F7 | `attack_chain_demo.py` and `si_demo.py` write into `reports/` without honouring `URDS_WRITE_REPORTS`. Found by reading the code; neither script was run. | Low |

## Headline numbers

| Area | Result |
|---|---|
| Fresh install, all six services and the scripts | exit 0 in 294 s; `pip check` reports no broken requirements |
| Behavioural model training | exit 0 in 75 s; model byte-identical to the previous one (MD5 `f481aa17…`) |
| Automated suites | **898 passed, 5 skipped, 0 failed**: gateway 86, ledger 99, ML engine 50 (+3 skipped), response 121 (+2 skipped), monitor 516, Pester 26 |
| Claim matrix with its regressions | 15 claims; 13 made, 2 recorded as not claimed; **0 failed** |
| Detection, in-process sweep | 13 of 13 families, 8 of 8 files each, first flag ≤ 16 ms |
| Detection, live stack | 13 of 13 families, **130 of 130** encrypted files flagged in each run. First flag visible 16–78 ms after encryption began; for `grinder`, 47 ms after its first file (it makes 5 warm-up writes first). `poisoner`'s setup files were flagged before its encryption started. |
| False positives, benign workload | **0 of 69 events**, in both runs |
| Attribution (elevated) | **0 wrong PIDs**: 78 named events in the defect re-check, 238 in the full test. The two-writer rule held in 5 of 5 cases. |
| Termination (elevated) | 28 kills. Request sent 0.8–6.6 s after detection, median 1.40 s; the kill itself took 10–30 ms. **FEBR < 5 for 3 of 13 families.** |
| Recovery | snapshot folder 10/10 and 10/10 (`locker`); VSS 10/10. All integrity-verified, all matching my own SHA-256, 4.1–4.8 s per batch. |
| VSS shadow copy | created in 2.5 s (target < 30 s); listed; logged to the ledger |
| Ledger | chain valid at 1,556 and 1,923 blocks; live SQL tamper caught and the block named; in-place tampers 20/20; structural tampers 0/8 (documented limit) |
| Gateway | authentication, the forged-token refusal and every route work. A flagged write is visible through the gateway in 0.17–0.36 s **with the dashboard closed** (F1). |
| Dashboard | **fails**: only the title renders (F1). Renders and refreshes each second after the fix (`820d7a4`). |
| Defect re-check on the final commit | **42 of 42**. The earlier 42/42 was at `ec21a43`, before the defect 12 fix. |

## Environment

| | |
|---|---|
| OS | Windows 11 Enterprise Evaluation 10.0.26200, 64-bit |
| VM | VirtualBox, 4 vCPU, 6 GB RAM; last boot 2026-10-04 14:52 |
| Python | 3.12.10, with a **fresh venv** made for this test (`C:\URDS-integ\.venv`, gitignored) |
| Windows Defender | **On for the entire test**: real-time, behaviour, IOAV and on-access, signatures dated 2026-10-04. Unlike the 2026-09-23 run, nothing was disabled, so these results include coexistence with a live antivirus. Tamper Protection was already off and was not changed. |
| Other URDS software | `URDSAgent` (LocalSystem, installed from `C:\URDS`, branch `fix/evidence-integrity`) ran throughout and was not touched. |
| Privileges | The Claude session runs unelevated. The elevated half was run by the operator from an Administrator PowerShell (`full_elevated.ps1`). |
| Clock | VirtualBox guest time sync slews this VM's wall clock (measured at 0.8x–1.44x of real time). Harness durations use `time.monotonic()`. Ledger and event timestamps are wall-clock, so **sub-second differences between them are approximate**. |
| Stack | Run natively (there is no Docker on this VM): six services on 127.0.0.1, ports 8000–8004 and 8501. Network isolation was **forced off** (`RESPONSE_ISOLATION_ENABLED=false`) so the firewall policy could never be changed. |

## How it was tested

1. **Install:** a fresh venv, then every service's `requirements.txt` plus `scripts/requirements.txt`, then `pip check`.
2. **Model:** `src/train_behavioral_model.py`, with `URDS_WRITE_REPORTS` unset so no tracked file changed (`git status` stayed clean).
3. **Suites:**
   - the five service suites, one process per service, as CI runs them
   - `scripts/tests` (Pester 3.4)
   - `claim_matrix.py --tests`
4. **Offline measurements:**
   - `simulator_sweep.py` (13 families, in-process Monitor)
   - `tamper_sweep.py`
   - `failure_injection.py`
   - `load_test.py`
5. **Live stack, unelevated:** started with `start_stack.ps1`, then `full_e2e.py`, a harness written for this test. Every potentially suspicious write is made by a separate child process, so the PID the Monitor names is the PID that wrote. It covers:
   - health of all six services
   - an API smoke test of all 36 documented routes
   - the benign workload and the two ZIP controls
   - all 13 families
   - in-place encryption of files the attacker did not create
   - recovery
   - gateway checks
   - a live ledger tamper
6. **Dashboard:** opened in a browser and measured.
7. **Live stack, elevated** (run by the operator):
   - audit setup on two empty folders
   - `verify_vss.py --status-only`
   - `e2e_check.py`, the 42-check defect re-check
   - `full_e2e.py` again with attribution on and a real VSS snapshot
   - stop, revert, and a comparison of machine state before and after

Raw outputs are in `C:\URDS-recheck\full\` (`pytest_*.txt`, `unelev_20261004_151537\`, `elev_20261004_183527\`).

## Results

### A. Installation and model

| Check | Result |
|---|---|
| `pip install -r` for gateway, ledger, monitor, ml-engine, response, dashboard and scripts | **PASS**: exit 0, 294 s |
| `pip check` | **PASS**: "No broken requirements found". The 2026-09-23 Pillow/streamlit conflict is gone (defect 7). |
| `train_behavioral_model.py` | **PASS**: exit 0, 74.8 s; `models/behavioral_model.pkl` byte-identical to the existing one; `reports/` untouched |

### B. Automated suites (fresh venv)

| Suite | Result | Notes |
|---|---|---|
| gateway | **86 passed** | 1,049 warnings, all third-party deprecations (`python-jose` `utcnow`) |
| ledger | **99 passed** | |
| ml-engine | **50 passed, 3 skipped** | skipped: "no EMBER model" (the model is gitignored and not trained here) |
| response | **121 passed, 2 skipped** | skipped: "SIGTERM cannot be ignored on Windows" |
| monitor | **516 passed** | about 90 s |
| `scripts/tests` (Pester 3.4) | **26 passed** | `setup_attribution_audit.ps1` against an in-memory machine |
| `claim_matrix.py --tests` | **15 claims, 0 failed** | each claim's regressions passed |

### C. Offline measurements

| Script | Result |
|---|---|
| `simulator_sweep.py` | 13/13 families detected, 8/8 files each; first flag 0.0–0.016 s; `--restore` OK for all |
| `tamper_sweep.py` | in-place 20/20 detected (100%); structural 0/8, the documented limit of an unanchored chain |
| `failure_injection.py` | all 5 injected failures recorded; all distinct, none reported as verified, every one explained |
| `load_test.py` | 1,200 events at concurrency 16: median 52 ms, p95 113 ms, **p99 151 ms**, max 240 ms; 112 (9.3%) over the 100 ms budget. Fan-out queue unbounded (peak depth 604, about 36 s to clear). Seen-file set unbounded (214 bytes per path). These are known, documented limits; re-measured here. |

### D. Live stack, unelevated (`full_e2e.py`: 73 of 73)

The first run reported 13 failures. All were **a harness bug**: it read the simulator's manifest under the wrong file name (`simulator_manifest.json` instead of `.simulator_manifest.json`), so it counted 0 encrypted files. After the fix, the re-run passed 73/73.

| Check | Result |
|---|---|
| Health of six services and the dashboard's `/_stcore/health` | PASS; behavioural model loaded, EMBER model not loaded |
| API smoke: 36 calls (GETs as they are, mutations with an empty body) | PASS: no 5xx. The gateway refuses every protected route without a token. |
| Attribution status | unavailable, "EvtSubscribe … Access is denied" (expected when unelevated). Every incident got `isolate_and_log`: isolation planned, not enforced, plus admin notified. |
| Benign workload (below) | PASS: **0 of 69 events flagged**, 21 paths; verdicts `benign`, `benign_compressed`, `deleted` |
| Genuine ZIP control | PASS: `benign`, `validation_state: valid` |
| ZIP magic over random bytes | PASS: `suspected_encryption`, `structural_mismatch`, `forged` |
| 13 families × 10 files | PASS: **130/130 encrypted files flagged**. Queue wait ≤ 4.6 ms; `detection_latency_ms` ≤ 68.6 ms. `--restore` byte-identical 130/130. |
| In-place encryption of 10 existing documents by a different process | PASS: 10/10 flagged |
| Recovery from a snapshot folder (`RECOVERY_SNAPSHOT_ROOT`) | PASS: 10/10 `integrity_verified`, my own SHA-256 matches 10/10, 4.6 s |
| `locker` (rename family): snapshot, re-attack, recover | PASS: 10/10 verified, own SHA-256 10/10, 4.8 s |
| Gateway: bootstrap-secret rule, forged token, six routes, `/analyze` | PASS |
| Flagged write → visible through the gateway | PASS: 0.17–0.27 s |
| Ledger | PASS: 1,760 blocks valid; verify 9.9–13.2 ms over HTTP |
| Live tamper (SQL edit of block 881) | PASS: `valid: false, invalid_block_id: 881`; valid again after the revert |

The **benign workload** ran as one separate process:
- text files created, then edited three times
- `.docx` and `.xlsx` saved and re-saved
- a ZIP archive and a gzip
- five JPG/PNG wallpapers copied in
- three DLLs/EXEs copied from System32
- a SQLite database written in five transactions
- a `.py` compiled to `.pyc`
- a rename and a delete
- PowerShell `Compress-Archive` from another process

The unelevated run had `grinder` and `strider` first flags at 1.0–1.4 s. That was **harness latency**: its poller built its HTTP client after the clock had started. A trace on the Monitor showed 5–6 ms. After the harness fix, the elevated run measured 0.036–0.047 s from the first finished file.

### E. Live stack, elevated

**Machine-state guard: all PASS.**
- Security log 1 GiB before and after.
- File System audit subcategory `Success` before and after.
- Both folders' audit rules removed.
- Firewall profiles, Defender state and URDSAgent unchanged.
- `verify_vss.py --status-only` created nothing (0 → 0 shadow copies).
- The only thing left behind is the shadow copy made by the VSS acceptance check, `{DD628FFD-87F5-4D25-A749-937B0FDF3F42}`.

**Defect re-check (`e2e_check.py`): 42 of 42 on `5952218`.**

| Defect | Result |
|---|---|
| D1, single write by a fresh process | 5/5 `certain`, correct PID, writer killed. #1 was killed 6.92 s after its write (the backlog case, F2); #2–#5 at 1.86–2.07 s. |
| D2, write then rename | 5/5 found the writer under the old name; 4 `certain` and verified, 1 `process_exited` after the earlier kill |
| D3, 20-file burst | last event 0.177 s after the last write; `queue_wait_ms` present on all 40 suspicious events |
| D4, recovery under four path spellings | 4/4 `integrity_verified`, bytes match |
| D8, attribution wording before start | PASS |
| Invariant | benign writer then encryptor 0.5 s later: 3/3 never `certain`, nobody killed. Second writer after the detection: 2/2 never `certain`, never killed. |
| Wrong PIDs | 0 of 78 named events |

**Full test (`full_e2e.py`): 89 passed, 14 failed.**

| Family (10 decoys, default pace 120 ms per file) | Files encrypted before the run ended | Flagged | Attribution | Terminated | FEBR < 5 |
|---|---|---|---|---|---|
| copycat | 10 | 10/10 | `probable` (the writer had exited) | no | **FAIL** |
| grinder | 3 | 3/3 | `certain` → killed | yes | PASS |
| headerspoof | 10 | 10/10 | `certain`, killed after its last file | after finishing | **FAIL** |
| locker | 10 | 10/10 | `certain`, killed after its last file | after finishing | **FAIL** |
| notedrop | 10 | 10/10 | `certain`, killed after its last file | after finishing | **FAIL** |
| partial | 10 | 10/10 | `probable` (exited) | no | **FAIL** |
| poisoner | 4 | 4/4 | `certain` → killed | yes | PASS |
| renamer | 10 | 10/10 | `probable` (exited) | no | **FAIL** |
| silent | 10 | 10/10 | `probable` (exited) | no | **FAIL** |
| slowburn (800 ms per file) | **2** | 2/2 | `certain` → killed | yes | PASS |
| spoofer | 10 | 10/10 | `certain` and verified, but it had exited 0.4 s later: "PID 8288 does not exist" | no | **FAIL** |
| staged | 7 | 7/7 | `certain` → killed | yes | **FAIL** (7) |
| strider | 10 | 10/10 | `certain`, refused (had exited) | no | **FAIL** |
| in-place encryptor (10 existing files, 120 ms per file) | 10 | 10/10 | `certain` → killed 1.9 s after detection, after its last file | after finishing | **FAIL** |
| `locker` again, for the VSS check | 6 | 6/6 | `certain` → killed | yes | (6) |

The other rows of the full test:
- **Benign:** 0 flagged; the benign workload process was **not** killed, so there was no false termination.
- **Controls:** pass.
- **Wrong PIDs:** none, in any family.
- **Recovery from a snapshot folder:** 10/10 verified.
- **VSS:**
  - `verify_vss.py` passed: created in 2.5 s, listed, in the ledger
  - `locker` was re-run, then restored from the shadow copy: **10/10 verified, own SHA-256 10/10, 4.25 s**
- **Gateway visibility:** 0.22–0.36 s.
- **Ledger:** 1,556 blocks valid; live tamper caught.

**The 14 failures:**
- 11 are F2: 10 families, plus the in-place encryptor.
- 2 are F3: the simulator's `--restore` returned 9 of 10 for `grinder` and `staged`.
- 1 is a ledger-verify timing outlier: one of 20 HTTP round trips took 65.3 ms. The median was 11.7 ms and the ledger's own verification time 7–9 ms. Not a product fault; it coincided with the pipeline draining.

### F. Dashboard

**FAIL.** `http://127.0.0.1:8501` showed the title and caption and nothing else, with no error, for as long as it was observed (over 20 s). The gateway's access log shows every dashboard call returning 200, but overlapping. See F1, fixed after the test.

## Faults

### F1. The dashboard never renders, and it saturates the gateway (High, new)

**Status: fixed after this test** in `820d7a4` (FIXES.md, defect 13). The fixed gateway answers `/health` in 18-19 ms with the dashboard open or closed, and the dashboard renders and refreshes each second.

**Symptom.**
- The Streamlit page shows "URDS Operations Dashboard" and the caption, and no data, banner, health tiles or tables.
- While the page is open, gateway latency rises for every client:

| Measured on this VM | Dashboard closed | Dashboard open |
|---|---|---|
| Each service's own `/health` (direct) | 3–30 ms | 3–30 ms |
| One proxied GET through the gateway (e.g. `/monitor/events`) | 205–230 ms | 2,440–2,710 ms |
| Gateway `/health` | 808–875 ms | **5,500–10,300 ms** |
| One dashboard refresh's five GETs, in sequence | 1,850 ms | 18,900 ms |

**Cause.**
1. `services/gateway/routers/proxy.py:24` builds a **new `httpx.AsyncClient` for every downstream call**. On this VM one construction takes **267–376 ms** (8 samples), nearly all of it loading certifi's CA bundle (270–300 ms). This is synchronous CPU work on the gateway's event loop, so it serialises every request the gateway is handling.
2. `services/gateway/main.py:147-160`: `/health` calls the four services one after another, which means four constructions.
3. `services/dashboard/app.py:122`: `st_autorefresh(interval=1000)` reruns the page every second. Each run makes six gateway calls (`/health`, four GETs and `/predict`), which costs about 2 s of gateway time even when idle. So runs pile up.
4. Streamlit interrupts a run at its next element when a rerun is pending, so no run ever gets past the title.

**Proof.**
- A copy of `app.py` with only the interval changed to 5000 ms, run on port 8502 against the same gateway, **rendered every panel**: the "System Secure" banner, pipeline tiles, files watched (241), events (500), model decision and entropy trend.
- The Monitor already fixed the same construction cost for its own escalation thread; see the docstring of `_ensure_escalator` in `services/monitor/app.py`. The gateway never got the same treatment.

**Impact.**
- The operator's only UI is unusable on the project's own test VM.
- While it is open, API users and `/analyze` wait seconds, and "dashboard-visible within 1 s" fails.
- Detection, attribution, response and recovery are **not** affected, because the Monitor calls the services directly, not through the gateway.

**Why no test caught it.** The live checks fetch the dashboard's HTML shell (1,522 bytes) and its health endpoint, never a rendered page. No suite covers the gateway's per-call client cost.

**Suggested fix, as written at the time of the test:**
- one shared `httpx.AsyncClient` created at gateway startup and reused
- gateway `/health` checks run concurrently (`asyncio.gather`)
- in the dashboard, a 3–5 s refresh or `st.cache_data(ttl=…)`, and a shared `requests.Session`

The first two were applied. The dashboard kept its 1 s refresh, with the live panels in a timed `st.fragment` instead; see [After the test](#after-the-test-f1-fixed).

### F2. Termination arrives after a fast encryptor has finished (High, design limit)

**Measured.**
- 28 terminations. The request went out a median **1.40 s** after detection (0.82–6.55 s, wall clock). The kill itself took 10–30 ms.
- The matched 4663 records arrived a median 888 ms after the write (116–1,228 ms).
- At the simulator's default pace (about 8 files per second), 10 files take about 1.2 s. So 10 of 13 families finished first:
  - they were never killed (`process_exited` → `not_escalated`), or
  - the kill landed after the last file.
- Families met TC-01 (< 5 files) only when slower: `slowburn` 2, `grinder` 3, `poisoner` 4.

**Why.**
- The first answer at detection is almost always `unknown` or "one writer so far", because the 4663 is still in flight.
- The answer becomes final, and a kill becomes possible, only after the **1,500 ms delivery horizon** (`ATTRIBUTION_HORIZON_MS`, `services/monitor/attribution.py:184`). This is deliberate: a competing writer's record can still arrive up to about 1.2 s late (1,228 ms measured here). Killing before the horizon is how the wrong process would get killed.
- A process that has already exited is never `certain`.
- **Backlog:** the first write after a 20-write burst was killed **6.92 s** after the write (terminate sent 6.55 s after detection). This is the third reproduction of the serial-pipeline finding from the previous re-test, which measured 5.2 s twice: one worker does ML, ledger and response for each queued detection in turn, and the question opens only after that.

**Compared with `main`** (the 2026-09-23 report):
- `main` killed `slowburn` 291 ms after detection, but attributed 0 of 20 `locker` files and missed first writes entirely.
- This branch attributes everything correctly, with 0 wrong PIDs and the invariant holding, but always about 1.4 s or more after detection.

**Impact.** On this Windows build, URDS stops an encryptor about 1.5–2 s after its first detected file. That is about 12–16 files at 8 files per second. Longer during a burst. For fast families, protection rests on detection and recovery. Both work: 10/10 from the snapshot folder and 10/10 from VSS.

**Options for the maintainer (not applied):**
- **Suspend instead of waiting.** On "one writer so far", suspend the process (which is reversible). Kill it at the horizon if it is still the only writer; resume it if a second writer appears. The `fix/evidence-integrity` branch's P2 commit ("suspends a real PID") may already go this way; it was not tested here.
- Let escalation bypass the serial pipeline queue.

### F3. The test simulator cannot restore the file it was encrypting when killed (Low, test tooling)

`scripts/ransomware_simulator.py` adds a file to its manifest only after `encrypt()` returns (lines 624–628). The file in progress when the process is terminated is not recorded, so `--restore` skips it.
- **Measured:** `grinder` `quarterly_report_03.jpg` and `staged` `quarterly_report_07.pdf` are left scrambled in `C:\URDS-recheck\full\watchF`.
- **Product impact:** none. URDS recovery would restore them from a snapshot.
- **Suggested fix:** record the entry before encrypting.

### F4. The audit setup's end-to-end probe gave a false failure (Low)

**What happened.** The first `setup_attribution_audit.ps1 -WatchPath C:\URDS-recheck\full\watchE`:
- applied the audit rule correctly
- then reported `[ FAIL ] End-to-end probe - no 4663 within 4s`, exit 1, and told the operator "Attribution will not work on this path"

Minutes later, `-Verify` passed on the same folder and attribution there was `certain` for every writer.

**Frequency:** 1 of 4 setups today, and 0 of 6 in the earlier re-test.

**Likely cause (not proven):**
- `Invoke-AuditProbe` (lines 247–280) times its 4 s budget with `Get-Date`, which is the wall clock, slewed on this VM.
- The budget also has to cover `Get-WinEvent` queries over a 1 GiB Security log of 216,645 records.

**Impact:** an operator may believe attribution is broken when it is not.

**Suggested fix:** a `Stopwatch`-based budget, a retry, or an XPath filter on the probe's file name.

### F5. Stale `file_size` beside a correct hash (Low, already known)

**Observed:**
- In the re-check, 2 `file_baseline` blocks record `file_size: 0` while their `file_hash` is the full file's.
- A Monitor trace showed suspicious events with `size=0` and entropy 5.86.

`FIXES.md` (defect 12, "Not changed") already records this. Recovery verifies the hash, so restores are unaffected; the size field in the ledger and on the dashboard is misleading.

### F6. One incident per watchdog notification, not per file (Low)

Windows delivers 1–3 notifications per write (`created`, then one or two `modified`), and each suspicious one becomes its own incident:
- its own `file_event` and two `response_action` blocks (the Response service's and the Monitor's)
- an `attribution_escalation` block
- possibly its own terminate request

**Effect:**
- The elevated test wrote 317 `file_event` blocks for about 170 encrypted files, and 1,556 blocks in 2 minutes.
- When the first request has killed the process, later requests for the same PID are recorded as refused, "PID … does not exist".
- This is correct, but noisy for an operator, and the ledger grows about 5 blocks per suspicious notification.

### F7. Two demo scripts ignore `URDS_WRITE_REPORTS` (Low, found by reading)

- `scripts/attack_chain_demo.py` writes `reports/attack_chain_evidence.txt` and `attack_chain_results.json` unconditionally.
- `scripts/si_demo.py` writes `reports/si_demo_evidence.txt` unconditionally.

Every other measurement script writes `reports/` only when `URDS_WRITE_REPORTS=1`. Running either demo would overwrite tracked evidence. Neither was run.

### Carried over from the previous re-test (not re-investigated)

- The Monitor subscribes to the Security channel twice per start; the second handle replaces the first. Harmless.
- `pefile.PE(path)` still opens PE files with the builtin `open`, without `FILE_SHARE_DELETE` (defect 9 fixed this for every other read).
- The Monitor has no priority boost under CPU saturation. Latency benchmarks fail when other work saturates the 4 vCPUs.

## Apparent failures that were not product faults

| Seen | Explanation |
|---|---|
| First unelevated live run: 13 "family detected" failures | Harness bug: wrong manifest file name. Detection had fired, with incidents raised 31–62 ms after encryption. Fixed and re-run: 73/73. |
| `grinder` and `strider` first flag about 1 s (unelevated) | Harness poller built its HTTP client after the clock started. Monitor trace: 5–6 ms. Elevated re-measure: 0.036–0.047 s. |
| `termination_refused_or_unreachable` on `certain` answers | All 26 refusals in the elevated runs read "PID … does not exist". The process had already been killed by an earlier request, or had exited between the identity check and the request. No live process was refused, and no other process was killed. Requests: 28 terminated, 26 refused. |
| Ledger verify 65.3 ms (one of 20) | A single HTTP round-trip outlier during pipeline drain; the ledger's own figure is 7–9 ms |
| Pytest reports 120 s for a suite that took 90 s | pytest times with the slewed wall clock |

## Not tested

- **The EMBER static-PE model.** It is not trained (dataset download of about 1.4 GB from Hugging Face); 3 tests skip for that reason. This needs your go-ahead to download.
- **A reboot.** Persistence was verified on `main` on 2026-09-23 and not repeated here.
- **Docker deployment.** Docker is not installed on this VM; the stack ran natively.
- **Enforced network isolation.** Deliberately off, because it rewrites the Windows Firewall policy.
- **Multi-process or multi-threaded encryptors, and live ransomware.** The simulator is a single-process, stdlib-only stand-in.
- **The dashboard on a fast host.** F1 depended on how long client construction takes. After the fix, neither half depends on it.

## Machine state after the test

| Item | State |
|---|---|
| Audit rules on `watchE` and `watchF` | removed, as found |
| Security log size, File System audit subcategory | 1 GiB and `Success`, as found |
| Firewall, Defender, URDSAgent | unchanged; Defender on |
| Shadow copy `{DD628FFD-87F5-4D25-A749-937B0FDF3F42}` | **left on disk** (from the VSS acceptance check). To remove it, from an elevated shell: `vssadmin delete shadows /shadow={DD628FFD-87F5-4D25-A749-937B0FDF3F42}` |
| Services | all stopped; ports 8000–8004, 8501 and 8502 closed |
| Test data | `C:\URDS-recheck\full\`: harness, logs, run ledgers, watch folders including the two scrambled decoys from F3 |
| Repository `C:\URDS-integ` | no tracked file changed; new: `.venv\` (gitignored) and this report. The report was committed afterwards, with the F1 fix. |

## After the test: F1 fixed

Fixed on the branch in `820d7a4`, documented in `4032740` (`FIXES.md`, defect 13). F2 to F7 are unchanged.

**Cause, refined.** The page failed only with both causes present:
- the gateway's per-call client
- the dashboard's full-page rerun, which cancels the run in progress

With either one fixed, the page rendered on this VM.

**What changed:**
- **Gateway:** one `httpx.AsyncClient`, built at startup, reused for every call, closed at shutdown. `/health` asks the four services at once.
- **Dashboard:** the live panels are a `st.fragment(run_every="1s")`. A timed fragment rerun waits for the run in progress instead of cancelling it. `streamlit-autorefresh` was removed.

**Re-measured live** (run `f1_20261004_192031`). The base commit's gateway ran on port 8010 beside the fixed one, against the same services, with one dashboard per old/new combination. Latency was timed with `perf_counter`:

| | `5952218` | `820d7a4` |
|---|---|---|
| Gateway `/health`, no dashboard open | 819 ms median | 18 ms |
| Gateway `/monitor/events`, no dashboard open | 205 ms | 10 ms |
| Gateway `/health`, dashboard open | 6,939 ms | 19 ms |
| Gateway `/monitor/events`, dashboard open | 2,317 ms | 10 ms |
| Dashboard | title only | every panel, 19 refreshes in 20 s |

**The cross pairs:**
- New dashboard on the old gateway: rendered, 9 refreshes in 20 s.
- Old dashboard on the new gateway: rendered, about 1 refresh a second.

**Smoke on the fixed stack, 9 of 9:**
- `/analyze`, for a document and for random bytes
- a forged token: 401, and its `auth_failure` block reached the ledger
- `/health` after idle gaps of 4.5–8 s

The gateway logged 1,275 requests and no error.

**Tests added:**
- **Gateway, 5 tests (91 in the suite):** 4 of them fail on `5952218`.
- **Dashboard, a new 3-test `AppTest` suite:** it guards the render path. It passes on `5952218` too, because it has no browser timer.
- **Claim matrix:** 0 failed.

**Newly visible, pre-existing.** Now that the page renders, the dashboard logs a caught pyarrow `ArrowTypeError` for its "Field / Value" tables, which mix text and numbers. The tables still show. The base dashboard logs the same once it gets that far.

## Reproduction

The harness is in `C:\URDS-recheck\full\tools\` and is not in the repository: `start_stack.ps1`, `stop_stack.ps1`, `full_e2e.py`, `workload.py`, `writer.py`, `e2e_check.py`, `full_elevated.ps1`, `analyse_elev.py`, `kill_latency.py`. The F1 re-measure uses `f1_start_extra.ps1`, `f1_seed.py`, `f1_probe.py` and `f1_smoke.py` from the same folder.

```powershell
cd C:\URDS-integ
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r services\gateway\requirements.txt -r services\ledger\requirements.txt -r services\monitor\requirements.txt -r services\ml-engine\requirements.txt -r services\response\requirements.txt -r services\dashboard\requirements.txt -r scripts\requirements.txt pytest pytest-asyncio httpx
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe src\train_behavioral_model.py
foreach ($s in 'gateway','ledger','ml-engine','response','monitor') { Push-Location services\$s; ..\..\.venv\Scripts\python.exe -m pytest -q; Pop-Location }
powershell -ExecutionPolicy Bypass -Command "Invoke-Pester scripts/tests"
.\.venv\Scripts\python.exe scripts\claim_matrix.py --tests
foreach ($s in 'simulator_sweep','tamper_sweep','failure_injection','load_test') { .\.venv\Scripts\python.exe scripts\$s.py }
# live, unelevated
powershell -File C:\URDS-recheck\full\tools\start_stack.ps1 -Repo C:\URDS-integ -Python C:\URDS-integ\.venv\Scripts\python.exe -RunDir <run> -SnapshotRoot C:\URDS-recheck\full\snapshots
.\.venv\Scripts\python.exe C:\URDS-recheck\full\tools\full_e2e.py --watch C:\URDS-recheck\full\watchU --snapshot-root C:\URDS-recheck\full\snapshots --ledger-db <run>\data\ledger.db --out <run>\full_e2e.json
# live, elevated (Administrator PowerShell)
powershell -ExecutionPolicy Bypass -File C:\URDS-recheck\full\tools\full_elevated.ps1
```
