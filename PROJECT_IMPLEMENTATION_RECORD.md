# Project implementation record

**The artefact Table 9.9 requires.** The claim *"The project team designed and
implemented a six-service ransomware detection and recovery system"* is only
permitted against this document. Everything below is read from the repository's
own history by `scripts/implementation_record.py` and stored in
`reports/implementation_record.json`; re-run it and the numbers regenerate.

```bash
URDS_WRITE_REPORTS=1 python scripts/implementation_record.py
```

Generated from commit `f6c5835`, 5 September 2026. **92 commits on `HEAD`, 98
across all refs, 209 tracked files, four contributors.**

---

## 1. Who contributed what

| | Contributor | Commits on `HEAD` | Files first authored | Active | Branches under §9.15's convention |
|---|---|---|---|---|---|
| **NI** | nikhil-k3312 | 72 | 116 | 2026-08-05 → 2026-09-05 | `feature/NI-ml-engine-service`, `feature/NI-ml-training` |
| **SH** | Shashank V S | 12 | 65 | 2026-02-01 → 2026-08-25 | `feature/SH-gateway-ledger-routes` |
| **AS** | apekshashetty22 | 5 | 0 | 2026-07-19 → 2026-08-06 | `feature/AS-container-exemption-repair`, `feature/AS-response-engine` |
| **SI** | siddhi subhash gaikwad | 3 | 21 | 2026-08-06 | `feature/SI-hash-chain`, `feature/SI-ledger-tamper-visibility`, `feature/SI-recovery-path-portability` |

Every set of initials owns at least one branch under the
`feature/<INITIALS>-<topic>` convention §9.15 records, which is what the
generator checks the email-to-initials mapping against. That mapping is the only
hand-entered table in the script; everything else is git.

### What each contributor created

*First-authorship — whoever first committed a file that is still in the tree.*

**SH** created the system's shape. The repository's first commit is theirs
(1 February 2026, "Initial structure and API rules"), and they first authored the
gateway (14 files), the monitor's original detection path (10), the ML engine
(8), the response service (8), the ledger's first four files and the dashboard.
**Six services, and SH created files in all six.**

**SI** created the audit and recovery internals: 9 files in `services/ledger` —
the hash chain and its tamper surface — and 8 in `services/response`, the
recovery and snapshot code.

**NI** created 116 files, concentrated in what Semester 2 added: 27 reports, 21
monitor files (the capability model, the container registry, the policy switch
and the Phase 5–7 test suites), 20 documents, 17 measurement scripts, 16 `src/`
research files and the CI workflow.

**AS** first authored no file that survives in the tree, and that count
understates what AS did. All five of AS's commits edit files inside
`services/monitor` that already existed — 172 insertions — and what they added is
the monitor's detection primitives: Shannon entropy calculation (5 August 2026),
magic-byte detection (6 August), and the watchdog integration that turns
filesystem events into detection input. **Those three are the inputs every
Semester 2 measurement is taken on.** A first-authorship count cannot see that,
which is exactly the limit recorded next.

### Volume is not the same as contribution

The table above is a count of commits and files, and it should be read with
three limits in mind — they are recorded in the report itself under
`what_this_does_not_show`:

1. **Design leaves no commit.** Discussion, review and pair work do not appear
   here at all, so a low commit count understates a contributor's share of the
   design. SH's twelve commits include the decision to split the system into six
   services, which shaped every commit that followed.
2. **First-authorship credits the committer.** A file added inside a squashed
   import is credited to whoever pushed the import.
3. **Insertions measure volume.** 26,131 of NI's insertions on `HEAD` are into
   `reports/`, which are generated files. Insertions are reported per area in
   the JSON so a reader can discount them.

**The honest summary is that the contribution is lopsided.** One contributor
made 78% of the commits on `HEAD`, all of them after 5 August 2026. That is what
the history shows and the thesis says so rather than presenting a four-way
division of labour the repository does not support.

---

## 2. AI assistance

**82 of the 92 commits on `HEAD` (89.1%) carry a `Co-Authored-By: Claude`
trailer**, the first on 6 August 2026.

Those commits were produced with an AI assistant in the loop, under the named
author's account, with that author accepting each change. The number is
published here rather than left to be inferred because a thesis that claims a
team built something has to say how it was built, and 89.1% is not a footnote.

What the trailer does and does not mean:

- It marks a commit where an assistant wrote or substantially edited the diff.
- It does **not** mean the result is unreviewed. Every measurement in this
  repository is produced by a script that a reader can run, and the numbers in
  the thesis come from those runs rather than from anything an assistant stated.
  That is the whole design of the evidence discipline in §9.4 — it exists partly
  because assertion is cheap.
- It does **not** transfer authorship. The commits are authored by the named
  contributor, who is answerable for them.

Ten commits on `HEAD` carry no trailer: **all five of AS's**, four of SH's (the
three February 2026 structural commits and the June gateway stack), and one of
NI's (the EMBER feature pipeline and the trained XGBoost model, 5 August 2026).
So the monitor's entropy, magic-byte and watchdog primitives and the detection
model itself are hand-written, and the Semester 2 measurement and documentation
layer built on top of them largely is not.

---

## 3. What was built, by phase

| Phase | What it produced | Principally |
|---|---|---|
| 1–4 | The six services: monitor, ml-engine, ledger, response, gateway, dashboard. Hash-chain audit log, VSS/local snapshot recovery, XGBoost detection model, watchdog file monitoring, Docker Compose wiring | SH, SI, NI |
| 5 | Capability calibration of ten attack strategies; the predeclared bounds; the frozen benign corpus | NI |
| 6 | The container-exemption repair behind a five-value policy switch; the five-arm experiment; the benign-cost analysis; the decision-rule evaluation | NI, AS |
| 7 | TC-14 … TC-25 (165 cases); the CI matrix; tamper sweep, load test and security audit; the paper draft | NI |
| 8 | The thesis, the claim matrix, the defence material, the reproducibility appendix | NI |

Phases 1–4 are the system. Phases 5–8 are the study of one mechanism inside it.
**This work audits that mechanism and does not re-derive the rest of the system**
— `docs/PHASE1-4_COMPLETION_SUMMARY.md` records what Phases 1–4 delivered, and
the thesis cites it rather than reclaiming it.

---

## 4. Inputs, named as inputs

Per Table 9.9, these are named wherever they appear and are **not** presented as
contributions of this project:

| Input | Used for | Where |
|---|---|---|
| XGBoost | the gradient-boosted detection model | `services/ml-engine`, `src/` |
| FastAPI | every service's HTTP surface | all six services |
| watchdog | filesystem event capture | `services/monitor` |
| EMBER | static PE features for model training | `src/`, `models/` |
| CLEAR | labelled ransomware corpus | `src/` |
| RanSAP | I/O behavioural traces | `src/` |
| scikit-learn, SHAP, pandas, numpy | training, interpretability, analysis | `src/` |
| Python standard library `gzip`, `zlib`, `base64`, `hashlib` | attack witnesses in the calibration | `scripts/capability_calibration.py` |

---

## 5. Working practice

From §9.15, and what the repository shows of it:

- **Branch convention.** `feature/<INITIALS>-<topic>`. Nine branches follow it
  across four contributors; the generator verifies each contributor against it.
- **Freeze commits.** Four, tagged, and their hashes are quoted in the thesis:

  | Tag | Commit | Date | What it froze |
  |---|---|---|---|
  | `corpus-frozen-week19` | `2175d9c` | 2026-09-02 | the benign corpus manifest |
  | `cost-table-frozen-week20` | `9a4269b` | 2026-09-02 | the declared capability cost table |
  | `corpus-frozen-week21` | `38f32ed` | 2026-09-03 | the corpus as re-frozen for the experiment |
  | `repair-accepted-week24` | `a230245` | 2026-09-03 | the Week 24 gate decision |

- **Reproduction pairs.** §9.15 sets the ring AS↔NI and SI↔SH, with the
  reproducing member recording their result before seeing the original
  conclusion. **This was not achieved.** Every capability level was derived
  twice, in opposite decision orders, over the same recorded facts and without
  reference to the first conclusion — which is the protocol — but both
  derivations were written by one author in one session. Every record in
  `reports/capability_calibration.json` carries
  `reproduction.independent_human_reviewer: false`, and no result in this
  repository claims independent human reproduction. It is limitation 2 of the
  thesis and it is not presented as met.
- **Pull requests with one approval and a green CI run.** The CI matrix exists
  (`.github/workflows/tests.yml`) and **no CI run has been observed**. That is
  recorded in `docs/PHASE7_COMPLETION_REPORT.md` §6 and no green badge is
  claimed anywhere.

---

## 6. Regenerating this record

```bash
URDS_WRITE_REPORTS=1 python scripts/implementation_record.py
```

The script prints the table above and writes
`reports/implementation_record.json`. If the email-to-initials mapping ever goes
stale, the script reports the unmapped addresses rather than silently attributing
their commits, and any contributor with no branch under the convention is flagged
as unverified.
