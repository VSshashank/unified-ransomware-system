# Demonstration — the runbook, and what is not here

**Item P7.4 (NI + SH). Phase 7, Week 27.**

> ## No video has been recorded.
>
> P7.4 asks for a demonstration video. **This session did not produce one**, and
> no file in this repository is a recording. Two things stood in the way and both
> are stated rather than worked around: the Docker daemon was not running on the
> measurement host, so the Compose stack this demonstration drives could not be
> brought up; and creating a VSS snapshot needs an elevated shell this session did
> not have, so step 7 could not be performed at all.
>
> What is here instead is the runbook: the exact sequence, the command for each
> step, what the operator should see, and where the evidence for it lands. A
> person with a Docker daemon and an Administrator prompt can record it from this
> document without deciding anything.
>
> A screenshot or a transcript written by hand to stand in for a recording would
> be a fabricated artefact, and this project's whole method is that a claim is
> backed by a command that was actually run.

---

## Before recording

```bash
docker compose up -d --build
```

Wait for six containers. Gateway on 8000, Monitor on 8001, Ledger on 8003,
Response on 8004, Dashboard on 8501.

Open the dashboard at `http://localhost:8501` and leave it visible. Steps 3, 5
and 8 are the ones worth having on screen.

Run the recording from an **Administrator** PowerShell if step 7 is included.
Everything else works unelevated.

---

## The sequence

Total running time about six minutes. `scripts/attack_chain_demo.py` performs
steps 1–6 unattended and writes a transcript to
`reports/attack_chain_evidence.txt`; the steps are broken out here so a narrator
can talk over them.

### 1 — A legitimate file is not an alert  *(30s)*

```bash
.venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'scripts'); import synthetic_corpus, pathlib; pathlib.Path('watched_files/quarterly.zip').write_bytes(synthetic_corpus.build_zip(200000))"
```

**Expect:** `verdict: benign_compressed`, `suspicious: false`. Entropy is 8.00 —
as high as ciphertext — and the file is not flagged, because the ZIP structure is
really there.

**Say:** this is the false-positive mitigation the rest of the demonstration is
about. Without it every archive on the machine is an alert.

### 2 — A pasted header is  *(30s)*

```bash
.venv\Scripts\python.exe -c "import os, pathlib; pathlib.Path('watched_files/invoice.zip').write_bytes(b'PK\x03\x04' + os.urandom(200000))"
```

**Expect:** `verdict: suspected_encryption`, `signal: structural_mismatch`,
`validation_state: forged`. The reason names it: *the file declares a zip
container but the zip structure is not there behind it*.

**Say:** four bytes used to buy the exemption outright. The simulator's spoofer
family went undetected eight times out of eight before structural validation
existed.

### 3 — Four bytes still buy it, for eleven formats  *(45s)*

```bash
.venv\Scripts\python.exe -c "import os, pathlib; pathlib.Path('watched_files/backup.rar').write_bytes(b'Rar!\x1a\x07' + os.urandom(200000))"
```

**Expect:** `benign_compressed`. **This is the finding, not a bug in the demo.**
RAR is one of eleven formats in the registry with no structural validator, so
there is nothing to contradict the header.

**Say:** the same file under `CONTAINER_EXEMPTION_POLICY=strict-unvalidated+ratio`
is flagged — and that setting costs 90 false positives on 90 legitimate
bzip2/xz/GIF/RIFF files, which is why it is not the default. Show
`reports/benign_tradeoff.json`.

### 4 — An operator rule that is outranked  *(45s)*

```bash
curl -X POST http://localhost:8001/monitor/whitelist -H "Content-Type: application/json" -d "{\"paths\": [\"watched_files/*\"], \"hashes\": []}"
```

Then repeat step 2.

**Expect:** the alert **still fires**. `suppressed_by: null`,
`admissibility.outcome: "attenuated"`, and the reason reads *forging the path rule
costs low; avoiding the structural_mismatch signal costs moderate — the
suppression is cheaper than the evidence, so the alert stands*.

**Say:** the operator's rule was not ignored and not silently dropped. It was
priced, it lost, and the record says by how much.

### 5 — A rule that wins, and is recorded anyway  *(30s)*

Whitelist the file's SHA-256 instead of its path, then repeat step 2.

**Expect:** `suspicious: false`, and a `suppression_decision` block in the ledger
carrying the verdict it silenced, both capability costs, the validation state and
the policy version.

**Say:** a cancelled alert is still a recorded alert. Before this existed, the one
decision an auditor most needs to see was the only one the chain never held —
measured at 50% coverage, now 100%.

### 6 — The chain, and its limit  *(60s)*

```bash
curl http://localhost:8003/ledger/verify
```

**Expect:** `valid: true`. Then tamper directly in SQLite — not through the API —
and verify again: `valid: false`, with `invalid_block_id` naming the block.

**Then show the limit.** Run `scripts/tamper_sweep.py` and read the summary
aloud: 20 of 20 in-place tampers detected, **0 of 8 structural ones**, and none of
those can be. An attacker who can write the database recomputes exactly what the
verifier recomputes.

**Say:** tamper-evident against an attacker who does not recompute. That is the
claim, and it is smaller than the phrase usually implies.

### 7 — Recovery  *(60s, needs elevation)*

```bash
.venv\Scripts\python.exe scripts/verify_vss.py --volume C:\
```

Then restore the file from step 2 and show the four outcomes from
`scripts/failure_injection.py`: restored-and-verified, restored-but-unverifiable
(no baseline), restored-but-mismatched, and not-restored.

**Say:** "partial" is not a failure to restore. Told "not restored", an operator
would go looking for a backup that is already on disk.

**If unelevated:** run `scripts/verify_vss.py --status-only` instead and show the
host reporting VSS supported, `elevated: false`, and both operations refusing.
State on camera that the VSS path is unverified in this project and why.

### 8 — The result the project would defend  *(45s)*

Show `docs/ADMISSION_RECOMPUTE.md`, policy F.

**Say:** the same question — are the whitelist and training mode cost-justified? —
produces opposite answers on two capability ladders over one set of recorded
facts. On the deployed four-point scale, no cell flips in the predicted
direction. On the governing document's five-level scale, four do, and the path
whitelist cancels nothing at all. The answer is a property of the scale, not of
the system. That is the contribution.

---

## What to show on screen, and what not to

**Show:** the dashboard's governance banner (Cancelled / Attenuated / Deferred as
three distinct labels), the reason strings — they are written to be read aloud —
and the JSON artefacts.

**Do not show:** any figure that is not in an artefact. If a number is worth
saying on camera it is in `reports/`, and if it is not in `reports/` it should not
be said.

---

## Recording checklist

- [ ] `docker compose up -d --build`, six containers healthy
- [ ] `watched_files/` empty at the start
- [ ] Dashboard open at `http://localhost:8501`
- [ ] Administrator prompt if step 7 is included
- [ ] `reports/` present, so the artefacts can be opened on screen
- [ ] Whitelist reset between steps 4 and 5:
      `curl -X POST http://localhost:8001/monitor/whitelist -d "{\"paths\":[],\"hashes\":[]}"`
- [ ] After recording, `reports/attack_chain_evidence.txt` holds the transcript of
      steps 1–6 as the machine saw them
