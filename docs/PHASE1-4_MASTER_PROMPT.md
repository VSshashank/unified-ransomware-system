# Master prompt — finish Phases 1–4 completely

Copy everything below the line into a fresh Claude Code session opened at
`D:\Unified_Ransomware_Project`.

---

You are completing Phases 1–4 (Semester 1, Weeks 1–16) of the **Unified Ransomware
Detection & Recovery System** so that *every* item the reference document plans for
that window is actually built, actually measured, and actually documented.

## 0. Sources of truth

1. **The reference document** — `C:\Users\nikhi\OneDrive\Desktop\College\Unified Ransomware Detection System.pdf`
   (v1.6, 31 Jan 2026, 68 pages). This is the specification. Where it and the code
   disagree, the document decides what *should* exist; the code decides what *does*.
   `poppler` is not installed, so the Read tool cannot page it. Extract it first:

   ```bash
   .venv/Scripts/python.exe -c "from pypdf import PdfReader; r=PdfReader(r'C:\Users\nikhi\OneDrive\Desktop\College\Unified Ransomware Detection System.pdf'); open('spec.txt','w',encoding='utf-8').write('\n'.join((p.extract_text() or '') for p in r.pages))"
   ```

   Read all 68 pages before you change anything. Do not work from the summaries below
   alone — they are a starting index, not a substitute.
2. **Current state** — `docs/PHASE1-4_COMPLETION_SUMMARY.md` and
   `docs/PHASE1-4_COMPLIANCE_AUDIT.md`. Treat every claim in them as an assertion to
   re-verify, not as evidence.
3. **The code** — 126 tracked files. Branch `fix/phase1-4-remediation`.

## 1. Definition of done

Phases 1–4 are complete when all of the following hold simultaneously:

- Every Weeks 1–16 row in Tables 4.1–4.4 and 5.3–5.6 is implemented and demonstrated.
- Every "Solution:" the document names for a Key Technical Challenge (pp. 38, 40, 42, 45)
  either exists in the code, or is refused in writing with a measured reason.
- Every mitigation in Table 5.7 exists.
- §6.1's dataset description is literally true of the model on disk.
- §6.4's two testing scenarios have been run and their real numbers recorded.
- Chapter 7's three evidence items are real artefacts, not placeholders.
- All 10 Table 5.9 benchmarks pass, measured by the **measurement method Table 5.9
  states** (note: CPU is "average during a 1-hour monitoring period", RAM is "peak
  during stress test" — a 5-second sample does not satisfy either).
- §5.6.1 and §5.6.2 are met in full; §5.6.3 is met except for the items the document's
  own Tables 5.4–5.6 place in Weeks 17–32.
- Test suite green, no regression below the current baseline of **371 passed, 2 skipped,
  0 failed**.

## 2. Ground rules — these are not negotiable

1. **Measure, never assert.** Every number that lands in a doc, a report, or a commit
   message must come from a command you ran in this session. If you did not measure it,
   do not write it. If a previously committed number is wrong, correct it and say so.
2. **Reproduce before fixing.** For every defect, demonstrate the failure first, then
   fix, then demonstrate the fix. Add the regression test in between.
3. **Do not regress what works.** Before and after every item, run:
   ```bash
   for svc in gateway ledger monitor ml-engine response; do (cd services/$svc && python -m pytest -q); done
   ```
   The false-positive rate must stay at 0/40 and all 10 Table 5.9 targets must stay met.
   If a change trades one criterion for another, stop and report the trade rather than
   choosing silently.
4. **Reports are gated.** `reports/` is only written when `URDS_WRITE_REPORTS=1`. Keep it
   that way. Refresh committed evidence deliberately, never as a test side effect.
5. **Windows first.** Use `.venv\Scripts\python.exe`. VSS work needs an elevated shell.
6. **Commit per item**, using Listing 4.1's convention (`feat(monitor): …`,
   `fix(ml): …`, `test(api): …`, `docs(readme): …`). Message body states what was
   measured. Work on a branch off `fix/phase1-4-remediation`.
7. **Never silently drop scope.** If an item turns out to be impossible, harmful to a
   graded criterion, or genuinely out of the Weeks 1–16 window, finish everything else
   and list it explicitly in the final report with the reason and the evidence.
8. **Never fabricate an artefact.** No mocked screenshots, no hand-written "log output",
   no invented dataset rows. Evidence comes from running the system.

## 3. Work items

Each item gives the spec citation, what is there today, what "done" means, and how it is
proven. Verify the "today" column yourself — it was checked on 12 Aug 2026 and may have
moved.

### Group A — Machine learning (NI role: Table 4.2, Table 5.4, p. 40)

**A1. CLEAR must be a training input, not just EDA.**
§6.1 states the model was "trained and evaluated using a subset of the EMBER dataset …
**augmented with behavioral logs from the CLEAR dataset**". Today CLEAR
(`data/clear_io/`) is used only for exploratory analysis; the classifier is EMBER-only.
Done = the training pipeline consumes both, the resulting model is the one in
`models/`, and §6.1's sentence is true as written. Every metric cited anywhere in the
repo must then be restated from the new model (see A9).

**A2. RanSAP must be acquired and analysed.**
§4.5.2 Core Responsibilities and Table 5.4 Weeks 1–4 both name "EMBER, CLEAR, and
RanSAP". `data/ransap_logs/{benign,ransomware}` exists and `src/verify_ransap.py`
touches it. Done = the EDA report covers all three datasets with characteristics
documented (Table 5.4's stated deliverable), and RanSAP's role — training input or
justified EDA-only — is stated.

**A3. SMOTE.**
p. 40, NI Challenge 1, prescribes "SMOTE oversampling **+** class weights in XGBoost".
Only `scale_pos_weight` exists; `imblearn` is not installed anywhere. The corpus is
balanced 25,000/25,000, so SMOTE is close to a no-op on EMBER — but CLEAR augmentation
(A1) may unbalance it. Done = either SMOTE is implemented and its effect measured
(metrics with and without), or its omission is justified with the measured class ratio
after A1. Decide *after* A1, not before.

**A4. Hyperparameter tuning and cross-validation — currently missing entirely.**
Table 5.4, Weeks 9–12: "Train XGBoost model, **hyperparameter tuning**,
**cross-validation**, model evaluation". Grep confirms no `GridSearchCV`,
`RandomizedSearchCV`, `cross_val_score` or `StratifiedKFold` anywhere in `src/`. The
model uses hand-picked constants (`n_estimators=300, max_depth=6, learning_rate=0.1`).
Done = a real search over a stated grid with stratified k-fold CV, the search results
written to `reports/`, the chosen hyperparameters justified by the CV score, and the
fold-level variance reported alongside the headline metric. This is the largest genuine
Weeks 9–12 gap in the project.

**A5. The preprocessing stage in Figure 4.7.**
Figure 4.7's pipeline is Raw Executables → PE Parser → Feature Extraction →
**Preprocessing (Scaling, Encoding, Feature selection)** → XGBoost Training →
Deployment. The middle box does not exist: 2,381 raw EMBER columns go straight into
XGBoost. Done = either the stage is implemented (feature selection at minimum, since
scaling is a no-op for trees) with its effect on accuracy and inference time measured,
or the diagram's box is explicitly annotated as not required for tree models, with the
reasoning recorded in `APPROACH.md`.

**A6. `pe_imports_count` and `api_calls` are accepted and thrown away.**
Listing 3.5 sends both. `services/ml-engine/features.py` has a 7-element
`FEATURE_ORDER` containing neither, so `POST /predict` silently discards them —
while §1.4 claims "Behavioral Fingerprinting: creates unique behavioral profiles for
processes based on **API call sequences**", §2.3 names `CryptEncrypt`, `WriteFile`,
`MoveFile` as the markers integrated "into the feature vector for the ML engine", and
Listing 3.22's own error example lists those two fields as the ones that can be missing.
Done = both features are genuinely used by the behavioural model (retrain with them and
report the recall change), or `/predict` rejects/warns on them instead of pretending.
Silently dropping a documented input is the one option that is not acceptable.

**A7. Feature drift mitigation (p. 40, Challenge 2): "Ensemble methods + online learning
preparation."** A Random Forest baseline exists but is a *comparison* for Table 8.1, not
an ensemble in the serving path, and nothing addresses online learning. Done = either a
real ensemble at inference (with measured accuracy and latency), or a documented design
for incremental retraining plus the reason it is deferred.

**A8. Inference optimisation (p. 40, Challenge 3): "Model quantization + feature
caching."** Inference is already 1.95 ms p95 against a 100 ms target, so the *goal* is
met — but neither named technique exists. Done = implement feature caching (cheap, and
it matters under the concurrent load of TC-11), and record measured before/after; state
plainly that quantization is unnecessary at the measured latency, with the number.

**A9. Restate every metric, everywhere, after A1–A8.**
Retraining invalidates: `reports/model_metrics.json`, `reports/baseline_comparison.json`,
`reports/ransomware_specific_metrics.json`, `reports/shap_feature_importance.json` and
its plot, `reports/confusion_matrix.png`, `GET /model/metrics`, `docs/APPROACH.md`,
`docs/FLOW.md`, `docs/test_cases.md` (TC-06), `README.md`, and Table 8.1's row values.
The repository has already been burned once by a stale `model_metrics.json` that
overstated the deployed classifier by two points — verify the model on disk is the model
the metrics describe by checking the SHA-256 and the training timestamp, not by assuming.

### Group B — Detection and response (AS role: Table 4.1, Table 5.3, Table 5.7)

**B1. Whitelist mechanism.**
Table 5.7 lists four mitigations for "High false positive rate": differential entropy
(now built), magic byte verification (built), **training mode**, **whitelist**. §8.4
also names manual whitelisting as the remedy for VeraCrypt-class false positives, and
§8.5 puts signature-based whitelisting in future work. Done = a whitelist the Monitor
actually consults (path, publisher, or hash), configurable, tested, and shown to
suppress an alert that would otherwise fire — without moving the false-positive rate off
0 % or hiding a true positive.

**B2. Training mode.**
Table 5.7: "Training mode for learning legitimate patterns." Nothing exists. Done = a
mode that observes normal activity for a window, records the baseline (which paths,
which extensions, what entropy distribution), and uses it to suppress known-benign
patterns afterwards. Prove it with a run that learns a legitimate workload and then
declines to alert on it, while still catching the simulator.

**B3. Cross-platform abstraction layer.**
§4.5.1 Core Responsibilities: "Cross-Platform Support: Ensure Windows + Linux
compatibility." Challenge 2's solution is an "Abstraction layer with platform-specific
adapters". §1.3.1 scopes the system to "Windows environments (with partial Linux support
for the backend)". Today platform handling is scattered `sys.platform` checks. Done = a
named adapter boundary, and the monitor + detection suites demonstrated green on Linux
(the Docker containers are Linux — run them there), with the Windows-only surface (VSS,
`pywin32`) isolated behind the boundary and explicitly listed.

**B4. VSS deletion protection.**
§2.5 reviews ransomware running `vssadmin delete shadows` and calls active defence of
VSS interactions "**a key component of our Response Engine**". Nothing in the repo
hardens or intercepts it. It is not on a weekly deliverable list, so if you conclude it
belongs in Semester 2, say so — but §2.5's sentence must then be reconciled, because as
written the document claims the Response Engine already does this. Preferred: detect the
command/API attempt and log it to the ledger as a critical event, which is achievable
within Weeks 1–16 scope and makes the claim true.

**B5. Process attribution.**
Figure 3.4's chain ends in "KILL PROCESS", and Listing 7.1 shows
`Terminating PID 4512 (wannacry.exe)`. Today `process_id` is always null — watchdog
reports *what* changed, never *who* — so the Response Engine is only ever handed a PID
by a caller that already knew it. Done = either real attribution on Windows (ETW, minifilter,
or `handle`-style enumeration for the open writer), or the demo path documented honestly:
state exactly how the PID reaches the Response Engine in the attack-chain demo, and
record the limitation against Figure 3.4 in `APPROACH.md` §8. Do not let the thesis imply
attribution that does not exist.

**B6. Ten ransomware simulators, 10/10 detected within 2 s.**
§6.4.1: "we executed 10 different ransomware simulators (e.g., RanSim) … detected and
terminated 10/10 instances within 2 seconds" — marked *(To be replaced with real
evidence)*. Today `scripts/ransomware_simulator.py` has 4 families and `partial`
(intermittent encryption) is detected 0/8. §5.6.2's "3+ simulators" is already met;
§6.4.1's ten is not. Done = ten behaviourally distinct simulated families, each
round-trippable via `--restore`, each measured, with a per-family detection table and the
end-to-end time. If a family is genuinely undetectable without breaking the 0 % false
positive rate — `partial` is the known case, since per-block entropy also flags the
compressed blocks inside any `.docx` — keep the failing test that asserts it as a blind
spot and report the honest N/10. **Do not tune the detector until it reports 10/10 by
weakening the container exemption.**

**B7. Scenario B — benign high-entropy workload.**
§6.4.2: zip 1 GB of files, run an encryption tool (VeraCrypt-class), measure the share of
legitimate operations classified correctly. Placeholder value is 95 %. Done = actually
run it at 1 GB scale, record the measured rate, and if it is below 95 % say so.

**B8. Benchmarks measured the way Table 5.9 says.**
Two of the ten do not currently match their stated measurement method: System CPU is
"Average during **1-hour** monitoring period" (measured over ~5 s today) and System RAM
is "Peak memory consumption during **stress test**". Done = a genuine one-hour monitored
run with the average recorded, and a defined stress test with the peak recorded, both
written to `reports/` under the env gate.

### Group C — Ledger and recovery (SI role: Table 4.3, Table 5.5)

**C1.** Weeks 1–16 SI deliverables are met. Re-verify rather than assume: hash chain
integrity, genesis = 64 zeros, `DEFAULT_INTERVAL_HOURS = 6` firing on a real clock (not
just configured), 100 % restoration, backup creation under 30 s, ledger verification
under 50 ms over 1,000 blocks. Record fresh numbers.

**C2.** The document defines the hash three incompatible ways — §3.2.2
`SHA256(Timestamp + Data + Hash_{N-1})`, Listing 4.7
`f"{timestamp}{event_type}{event_data}{previous_hash}"`, Figure 4.8
`SHA256(id + data + prev_hash)`. The code follows Listing 4.7, which is correct. Make sure
that choice is footnoted where a reader would otherwise see a mismatch.

### Group D — Integration and DevOps (SH role: Table 4.4, Table 5.6, p. 45)

**D1. TLS 1.3.**
Table 3.1's Security layer names "JWT authentication, cryptography library, **TLS 1.3**".
All six services are plain HTTP. This is a Chapter 3 architecture commitment, not a
Semester 2 item. Done = TLS terminated in front of the gateway with a 1.3-capable config
and generated dev certificates, `docker-compose` wired for it, the dashboard talking
HTTPS, and a test asserting the negotiated version. Keep the loopback binding on the four
backends as defence in depth. If you conclude TLS between *internal* containers is out of
scope, TLS at the gateway edge is not — do that at minimum and state the boundary.

**D2. `docker compose up -d --scale ml_engine=3` must work.**
Listing 3.21 documents it as a supported command. It cannot work today: every service in
`docker-compose.yml` sets a fixed `container_name` (`ransomware_ml` etc.), and Compose
refuses to scale a service with one. Reproduce the failure, then fix it (drop
`container_name` on the scalable service, or add a documented override file), then show
three replicas up and the gateway still routing.

**D3. Real-time dashboard transport.**
p. 45 Challenge 2's solution is "WebSocket connections + Server-Sent Events". The
dashboard polls. The 1-second target (Table 5.9) is already met at ~10 ms to queryable,
so this is about the documented mechanism, not the number. Done = SSE or WebSocket
implemented, or the polling design justified in `APPROACH.md` with the measured latency
that makes it sufficient.

**D4. Service coordination (p. 45, Challenge 1): "Message queue (Redis) + webhook
callbacks."** Neither exists; services call each other synchronously over HTTP. Done =
implemented, or refused in writing with the measured latency/complexity argument. Note
that adding Redis expands the deployment surface — if you refuse it, refuse it clearly
rather than leaving Figure 3.2's flow ambiguous.

**D5. Code review artefacts.**
§4.4.2 requires a PR template containing Description, Testing done, Screenshots. Add
`.github/PULL_REQUEST_TEMPLATE.md` with exactly those sections.

**D6. Test coverage measurement.**
§4.5.4 Success Metrics names "95%+ test coverage" with no week attached, and §5.6.3 lists
CI/CD at Distinction. Coverage is not measured anywhere — no `pytest-cov` configuration
exists. Done = coverage measured per service and in aggregate, the real number recorded
in `reports/`, and the gap to 95 % stated honestly. Do not write tests whose only purpose
is to raise the percentage.

### Group E — Evidence and documentation

**E1. Chapter 7 evidence — all three items are placeholders in the document.**
- Figure 7.1: a real screenshot of the Streamlit dashboard, one in "System Secure" state
  and one during an active detection.
- Figure 7.2: real before/after evidence of a file restored via VSS.
- Listing 7.1: a real detection log in that format, from a real run, showing the full
  chain — modification → high entropy → features → prediction → termination → ledger
  block number.
Save under `reports/evidence/` and reference them from the docs.

**E2. Table 6.1.**
The document specifies i7-12700K / 32 GB DDR5 / 1 TB NVMe / Windows 11 Pro 22H2 /
Python 3.9.13. The actual machine is a Core Ultra 5 225H, 14 cores, 15 GB, Windows 11
build 26200, Python 3.13.9. Produce the corrected table, with the delta stated, so the
thesis can drop it in.

**E3. Table 8.1 and Figure 8.1.**
Table 8.1's values (RF 0.88/0.87/0.89/0.88, XGBoost 0.94/0.93/0.95/0.94) are marked
*(Preliminary)* placeholders, and §8.1.1's "94% accuracy" and §8.1.2's "92ms average
latency" are narrative placeholders too. Produce the real replacements from the final
model, on the same split and seed for both models so the comparison is fair, plus the
real confusion matrix.

**E4. Test cases: reach 12 (§5.6.3 wants 12–15).**
Table 5.8 defines 12. TC-12 is "Blockchain anchoring **(if implemented)**" and Polygon is
Weeks 17–24 by Table 5.5, so TC-12 stays deferred. Add TC-13 upward to cover the new
capability from this session — whitelist suppression, training mode, VSS deletion
protection, Scenario B, the 10-family simulator sweep — until at least 12 in-scope cases
pass, each with a `tc*`-named test. Update `docs/test_cases.md`.

**E5. Documentation, last.**
Update `README.md`, `docs/APPROACH.md` (especially §8 deviations and §9 not-built),
`docs/FLOW.md`, `docs/test_cases.md`, `docs/openapi/gateway.yaml`, and rewrite
`docs/PHASE1-4_COMPLETION_SUMMARY.md` to describe the finished state. Delete or clearly
mark the dead code the audit flagged: `src/ml_api.py` (superseded stub returning 501) and
`docs/api_spec.md` (Phase 2 era, contradicts the final contract).

## 4. Explicitly out of scope

Do not build these; they are Weeks 17–32 by the document's own Tables 5.4–5.6 and
Figure 4.2. Confirm each is still correctly deferred and say so in the final report:

- Polygon anchoring, Solidity, web3.py, TC-12 (Table 5.5, Weeks 17–24)
- GitHub Actions CI/CD pipeline (Table 5.6, Weeks 17–24) — *exception:* §4.4.2 makes "CI
  pipeline must pass" a standing review rule, so a minimal test-on-push workflow is
  defensible to add early. Your call; if you add it, keep it minimal and say why.
- SHAP served per-prediction (offline SHAP already exists and is ahead of schedule)
- Production identity management, load balancer, PostgreSQL (§3.7.3, production only)
- Research paper, thesis chapters, user manual (Weeks 25–32)
- Blue-green deployment (p. 45, Challenge 3 — a deployment-phase concern)

## 5. Suggested order

A1–A2 → A4 → A3 → A5–A8 → A9 (ML first: everything downstream cites its numbers).
Then B1–B5 (detection capability), then B6–B8 and C1–C2 (measurement),
then D1–D6 (infrastructure), then E1–E5 (evidence and docs, last, so nothing is
written twice).

Work item by item. After each: run the full suite, commit, and state in one line what you
measured. Do not batch commits.

## 6. Final report

When finished, write `docs/PHASE1-4_FINAL.md` containing:

1. A table of every item A1–E5: done / refused, with the measured evidence or the reason.
2. Re-measured Table 5.9 — all ten, by their stated measurement methods.
3. Final model metrics, with the dataset composition that produced them, and proof the
   model on disk is the model described (hash + timestamp).
4. §5.6.1 / §5.6.2 / §5.6.3 checklists with each box's evidence.
5. Table 5.8 status, all cases, with the test name that proves each.
6. Everything still not built, with the document's own citation for why it is deferred.
7. Commit list.

Then tell me, in plain terms: what is finished, what is not, and what a careful reader of
the reference document would still notice.
