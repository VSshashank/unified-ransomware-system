# URDS user manual

**Item P7.4 (NI + SH). Phase 7, Week 27.**

For an operator running the system, and for a reader reproducing its numbers.
Everything here has been run on Windows 11 with Python 3.13 in `.venv`. Where a
step needs something this machine did not have — an elevated shell, a running
Docker daemon — it says so rather than assuming.

---

## 1. What the system does, in one page

Six services. `monitor` watches a directory and classifies each file event;
`ml-engine` scores the features the Monitor extracts; `ledger` keeps a hash chain
of what happened; `response` terminates, isolates and restores; `gateway` fronts
them; `dashboard` displays them.

The Monitor's verdict is one of six:

| verdict | meaning | suspicious |
|---|---|---|
| `benign` | entropy below threshold | no |
| `benign_compressed` | high entropy explained by a container format | no |
| `suspected_encryption` | content looks encrypted | **yes** |
| `suspicious_extension` | a known ransomware extension | **yes** |
| `deferred` | the validator ran and could not finish; no conclusion is claimed | **yes** |
| `unreadable` | the bytes could not be obtained; no verdict was possible | no verdict |

`unreadable` is not `benign`. A locked file is common on Windows, and folding it
into "benign" would hide real encryption behind a failed read.

Every suspicious verdict carries a **signal** naming which of five detections
fired. The signal, not the verdict, is what the governance layer ranks against.

---

## 2. Running it

### Natively, one service at a time

```bash
python -m venv .venv
.venv\Scripts\pip install -r services/monitor/requirements.txt
.venv\Scripts\python.exe scripts/start_monitor.py
```

### The whole stack

```bash
docker compose up --build
```

Needs a running Docker daemon. The gateway comes up on 8000, the ledger on 8003.

### Watching a directory

```bash
curl -X POST http://localhost:8001/monitor/start -H "Content-Type: application/json" -d "{\"watch_path\": \"C:/data\", \"recursive\": true}"
```

---

## 3. Configuration

Every one of these is read from the environment. The defaults are what ships.

| variable | default | what it does |
|---|---|---|
| `ENTROPY_THRESHOLD` | `7.5` | whole-file entropy at which a file is called encrypted |
| `HIGH_ENTROPY_BLOCK` | `7.9` | per-4KB-block threshold for intermittent encryption |
| `ENTROPY_RISE_THRESHOLD` | `2.0` | how far entropy must rise on a watched path to count as replacement |
| `ENTROPY_RISE_FLOOR` | `7.0` | where a rise must *end* for it to mean anything |
| `CONTAINER_EXEMPTION_POLICY` | `legacy` | **see below** |
| `TRAINING_DWELL_SECONDS` | `30` | how long a file must be watched before its entropy can raise a learned ceiling |
| `PIPELINE_ENABLED` | `true` | whether detections fan out to ML, ledger and response |
| `BASELINE_LOGGING_ENABLED` | `true` | whether a first-sighting benign file records a recovery baseline |
| `URDS_WRITE_REPORTS` | unset | measurement scripts write to `reports/` only when this is `1` |

### `CONTAINER_EXEMPTION_POLICY`

Five settings. **The default is `legacy` and that is deliberate.**

| value | behaviour |
|---|---|
| `legacy` | a recognised container header explains high entropy. **Deployed.** |
| `strict-unvalidated` | only a *structurally validated* container explains it |
| `strict-unvalidated+ratio` | …and only if the container actually compressed something |
| `strict-unvalidated+ratio+inner` | …with an appeal to what the container carries |
| `off` | the exemption is disabled entirely |

An unrecognised value raises at import rather than falling back, so a typo cannot
become a silent policy change.

**Do not set this to anything but `legacy` without reading
`docs/PHASE6_COMPLETION_REPORT.md`.** The stricter settings close a real attack —
21 of 21 header-over-ciphertext witnesses, where `legacy` catches 7 — and they
cost 120 false positives on a 275-file benign corpus against 0 for `legacy`. On
the unvalidated × incompressible stratum every non-legacy setting flags **90 of
90** legitimate files, because bzip2, xz, GIF and RIFF have no structural
validator for the policy to consult. That measurement is why the repair is
available and not default.

---

## 4. Operator rules, and what they can and cannot do

Two suppressions exist: a whitelist (by path or by content hash) and a training
mode that learns a per-extension entropy ceiling.

Neither can silently cancel an alert. Every match is **adjudicated**: the system
prices what it would cost an attacker to make your rule fire on a file they
control, against what it would cost them to avoid the detection your rule is
cancelling, and admits the rule only if forging it costs strictly more.

- **Admitted** → the alert is cancelled, and the decision is written to the
  ledger as a `suppression_decision` block with both costs and the verdict it
  silenced. A cancelled alert is still a recorded alert.
- **Attenuated** → the alert stands. Your rule was consulted, was outranked, and
  the record says by how much.

What this means in practice:

| your rule | cancels | does not cancel |
|---|---|---|
| hash whitelist | everything | — |
| path whitelist | ransomware extensions, static entropy | structural mismatch, intermittent encryption, entropy rise |
| training mode | ransomware extensions, static entropy | structural mismatch, intermittent encryption, entropy rise |

A path whitelist is forged by writing into a directory you approved, which an
attacker running on the machine can usually do. A hash whitelist needs a SHA-256
preimage, which they cannot produce. That is the whole ordering.

---

## 5. Reading a verdict

```json
{
  "verdict": "suspected_encryption",
  "signal": "structural_mismatch",
  "reason": "the file declares a zip container but the zip structure is not there behind it, and the content is high entropy (8.0)",
  "validation_state": "forged",
  "policy_version": "legacy",
  "suppressed_by": null,
  "admissibility": {
    "rule": "path",
    "outcome": "attenuated",
    "forgery_cost": "low",
    "avoidance_cost": "moderate",
    "reason": "forging the path rule costs low; avoiding the structural_mismatch signal costs moderate - the suppression is cheaper than the evidence, so the alert stands"
  }
}
```

- `signal` is what fired; `reason` is why.
- `validation_state` is the validator's own word: `valid`, `forged`,
  `incomplete`, `unvalidated` (no validator exists for this format) or
  `unreadable`. It is the field that tells "we have no validator for RAR" from
  "the ZIP validator could not finish".
- `policy_version` is the exemption policy that decided this event, so the
  decision can be re-derived later from its own record.
- `admissibility` is present whenever any operator rule matched, **including one
  that was outranked**.

---

## 6. Recovery

`POST /response/recover` restores from a snapshot and verifies the restored bytes
against the hash the ledger recorded while the file was still known-good.

Four outcomes, and they are distinct on purpose:

| status | `restored` | `integrity_verified` | meaning |
|---|---|---|---|
| `success` | true | true | back, and it is the file the ledger saw |
| `partial` | true | false | back, and nothing could confirm it — either no baseline, or the hash disagreed |
| `failed` | false | false | not back; the snapshot had no copy |

`restored: true, integrity_verified: false` is not a failure to restore. Told
"not restored", an operator would go looking for a backup that is already on
disk.

**Snapshot creation needs an elevated shell.** Run the Response service from an
Administrator prompt, or `list_snapshots` and `create_snapshot` both refuse with
an explicit elevation error. `scripts/verify_vss.py --status-only` reports what
your host says without creating anything.

---

## 7. The ledger, and what it is evidence of

Every event is chained with SHA-256 over its timestamp, type, payload and the
previous block's hash. `GET /ledger/verify` walks the chain, recomputes every
hash, and names the first block that fails.

**What it detects:** any in-place edit. A rewritten payload, type, timestamp or
either hash, a deleted interior row, two rows with swapped payloads. Measured at
20 of 20 across three positions.

**What it does not detect:** a chain that has been rebuilt to be self-consistent
— a block appended, the newest deleted, the tail truncated, or one block rewritten
and every hash after it recomputed. Measured at 0 of 8. The hash is unkeyed and
all its inputs are public, so anyone who can write the database file can
recompute exactly what the verifier will recompute.

Treat the chain as evidence against tampering by someone who does not recompute.
Protecting it against someone who does needs a signing key they do not hold or an
external anchor recording the tip before they arrived, and neither is in this
system.

---

## 8. Reproducing the numbers

Reports are written only when `URDS_WRITE_REPORTS=1`. Without it every script
prints its result and writes nothing, which is how you check a figure without
replacing the artefact a frozen tag pins.

```bash
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/capability_calibration.py
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/admission_recompute.py
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/three_arm_experiment.py
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/benign_tradeoff.py
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/ledger_coverage.py
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/pipeline_governance.py
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/failure_injection.py
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/tamper_sweep.py
URDS_WRITE_REPORTS=1 .venv/Scripts/python.exe scripts/load_test.py
.venv/Scripts/python.exe scripts/verify_vss.py --status-only
```

`benign_tradeoff.py` reads `three_arm_experiment.json`, and
`admission_recompute.py` reads `capability_calibration.json`, so run them in the
order above. Each refuses rather than substituting a number nobody measured.

### The tests

```bash
foreach ($s in "gateway","ledger","monitor","ml-engine","response") { Push-Location "services\$s"; python -m pytest -q; Pop-Location }
```

**Per service, and it has to be.** The services use flat module names matching
their container layout — each has its own `app.py` — so one pytest process over
`services/` imports whichever reached `sys.path` first. `.github/workflows/tests.yml`
runs them as a matrix.

---

## 9. Known limits an operator should hold in mind

Each of these is measured; `docs/SECURITY_AUDIT.md` gives the command.

1. **A base64-encoded payload evades every entropy signal.** 6.000 bits/byte is
   below all three thresholds. One standard-library call, 33% larger output.
2. **Eleven of seventeen recognised container formats have no structural
   validator.** Under the default policy, four bytes of RAR magic in front of
   ciphertext reads as benign.
3. **Under sustained load the Monitor accepts events 18.7× faster than it
   forwards them**, into an unbounded queue. Queued items are ledger writes that
   have not happened.
4. **Detection latency misses its 100 ms budget at p99** under 16-way
   concurrency: 110.550 ms, with 3.0% of 1200 events over budget.
5. **`_SEEN_FILES` never shrinks** — 214 bytes per distinct path, for the life of
   the process.
6. **VSS-backed restore is unverified.** Local restore is 13/13.
