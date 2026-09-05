# Defence presentation

**Item P8.3 (NI + SH). Phase 8, Week 31.**

Twenty slides, 20 minutes, 10 minutes of questions. Every slide's headline is a
sentence that survives being asked "how do you know?", and the answer is on the
slide.

**The presentation leads with the negative result.** A defence that opens with
what was built and closes with what failed invites the examiner to discover the
failure themselves, which reads as concealment. Opening with it makes the rest of
the talk an explanation of how it was measured.

---

## Slide 1 — Title

> **Capability-governed exception admissibility in a ransomware monitor**
> A study of one mitigation, the governance layer it never reaches, and a repair
> that was measured and rejected.

*Say:* "This is a study of one rule inside a system the team built. It is not a
claim that the system detects more ransomware — it does not, and I will show you
why we decided against the change that would have tried."

---

## Slide 2 — The result, first

> **The repair works and does not ship.**
> Closes 34 of 34 attack cases.
> Costs 25.323 pp against a bound of 2.00 that was declared and tagged before the
> corpus existed.
> `CONTAINER_EXEMPTION_POLICY` still defaults to `legacy`.

*Say:* "I want the least comfortable slide first. We built the fix, it closed
every attack we built for it, and we are not shipping it. The next eighteen
slides are how we know that is the right call."

---

## Slide 3 — The mechanism

```python
if entropy > 7.5:
    if identify_container(head) is not None:
        return "benign_compressed", not_suspicious   # alert cancelled
```

> Seventeen recognised container formats. Structural validators for six.
> **Eleven are accepted on their first four bytes.**

*Say:* "A ZIP, a JPEG and an MP4 are near-uniform by construction, so a detector
without this exemption is unusable. That is not a hypothesis — I measured it, and
it is slide 9."

---

## Slide 4 — Why an exemption is a security problem

> An exception in a security control is **a rule an attacker can satisfy**.
> If four bytes cancel an alert, four bytes cancel an alert.

---

## Slide 5 — URDS has a component for exactly this question

> `admissibility.adjudicate` prices avoiding each signal against forging each
> suppression, and admits only when forging costs strictly more.

*Say:* "This is a good idea and it is already in the codebase. The problem is not
that the team didn't think about it."

---

## Slide 6 — The exemption never reaches it

| Population | Events | Adjudicated |
|---|---|---|
| cancelled | 12 | 12 |
| attenuated | 12 | 12 |
| **ungoverned (container)** | **12** | **0** |

> `handle_event` adjudicates a verdict that is *already suspicious*.
> The exemption's whole effect is to make it not suspicious first.

*Say:* "Nobody decided this. It falls out of putting the cheap check first. No
review caught it and no test failed, because nothing asserted the layer was
reached."

---

## Slide 7 — Method: measure, never assert

> Ten attack strategies. **Built, run against the deployed code, level derived
> from what the run recorded.** Twice, in opposite decision orders.
> 10 of 10 empirical. 0 unresolved.

*Say:* "No capability level in this work is assigned by reasoning about how hard
an attack sounds. That matters, because slide 8 is what happened when we stopped
reasoning and started building."

---

## Slide 8 — Five of ten cost-table entries were wrong

| Signal | Declared | Measured |
|---|---|---|
| `structural_mismatch` | moderate | **negligible** |
| `entropy_rise` | moderate | **low** |
| `partial_entropy` | moderate | **negligible** |
| `ml_confidence_gate` | high | **negligible** |

> **Not one came out more expensive than declared.**

*Say:* "That asymmetry is the finding. An author estimating the cost of an attack
they have not built estimates high, and does it consistently."

---

## Slide 9 — The cheapest attack we found

```python
base64.b64encode(ciphertext)     # exactly 6.000 bits/byte
```

| Threshold | Value | 6.000 below it? |
|---|---|---|
| whole file | 7.5 | yes |
| per 4 KB block | 7.9 | yes |
| differential floor | 7.0 | yes |

> **One standard-library call defeats all three entropy signals at once**, for
> 33% in file size.

*Say:* "Three tests of the same statistic are one test wearing three names. And
we have written no detector for it — the obvious counter fires on PEM files,
`.eml` attachments and JWTs, and we have not measured that cost. Proposing an
unmeasured mitigation here while rejecting a measured one on slide 14 would be
incoherent."

---

## Slide 10 — The experiment

> Five arms. 34 attacks in seven families. 275-file frozen corpus.
> **Paired** — every arm scores the same file from one read.
> Corpus frozen and tagged at `corpus-frozen-week21`; bounds declared at
> `cost-table-frozen-week20`.

---

## Slide 11 — Attack closure

| Family | A (live) | B (null) | C1 | **C (repair)** | D |
|---|---|---|---|---|---|
| A1 header over ciphertext (21) | 7 | 21 | 21 | **21** | 21 |
| A2 stdlib container (3) | 0 | 3 | 0 | **3** | 3 |
| A7 forged inner content (3) | 0 | 3 | 0 | **3** | 1 |

> The repair closed the evaluated bypass.
> **A7 defeats Arm D** — a family list is not a proof of closure.

---

## Slide 12 — The null control is what makes this readable

> Delete the exemption entirely: **185 false positives of 275 — 67.3%**
> against a 5% budget.

*Say:* "This is decision rule D3, and it is the only rule whose branch came out
favourable to the project. It came out favourable because we ran a control
specifically to give it the chance to come out either way."

---

## Slide 13 — The benign cost, per stratum

| Stratum | Files | Arm C FP | 95% upper limit |
|---|---|---|---|
| unvalidated × compressible | 30 | 0 | 9.503 pp |
| **unvalidated × incompressible** | **90** | **90** | **100.0 pp** |
| validated × compressible | 60 | 0 | 4.870 pp |
| validated × incompressible | 95 | 30 | 40.312 pp |

> Both compressible strata cost **nothing**. The repair is precise, and precisely
> wrong about incompressible files.

---

## Slide 14 — Bound 1 fails, and D5 fires

> **25.323 pp against 2.00.** McNemar p ≈ 9 × 10⁻¹⁰.
> **100.0 pp against 15.0** on unvalidated × incompressible.
> The 100 pp figure is **identical across arms B, C1, C and D**.

*Say:* "That last line is the point. If this were a threshold set too
aggressively, a different threshold would move it. It does not move, because
eleven formats have no validator — so the moment 'no validator ran' stops
counting as a pass, every genuine file in those formats flags. **The cost is not
tunable because it is not a parameter.**"

---

## Slide 15 — The result I would defend hardest

> **D1 fires on one capability ladder and not on the other.**
> Same question. Same recorded facts. No new measurement.
> The two ladders differ by **one rung**.

| | code | plan §5.2 |
|---|---|---|
| "a path the attacker can write to" | LOW | **Level 0** |

> Four cells flip. Under the plan's ladder the path whitelist and training mode
> cancel **nothing at all**.

*Say:* "Phase 5 answered this question 'no cells flip' and published it. That
answer was right about the scale it used and wrong about the scale the method
document makes governing. **The answer is a property of the scale, not of the
system.**"

---

## Slide 16 — What the audit trail is, and is not

| | |
|---|---|
| In-place tampering detected | **20 / 20** |
| Structural rewriting detected | **0 / 8** |

> Unkeyed SHA-256 over public inputs: anyone who can write the database
> recomputes exactly what the verifier recomputes.
> **"Tamper-evident" means tamper-evident against an attacker who does not
> recompute.**

---

## Slide 17 — What we did not fix, and why

> **The Monitor accepts events 18.7× faster than it forwards them**, into an
> unbounded queue. The backlog grows fastest during exactly the burst it exists
> to record.

*Say:* "The obvious fix is to bound the queue. The obvious implementation drops
on overflow, which discards the governance records the queue exists to preserve —
converting a latency problem into an evidence problem. The defensible shape
records its own overflow, and that is a different change needing its own
measurement. We measured rather than guessed."

---

## Slide 18 — Limitations, stated not buried

1. Synthetic 275-file corpus — every false-positive figure is about *it*.
2. **No independent human reproduction.** §9.15's ring was not achieved; every
   record says `independent_human_reviewer: false`.
3. In-process measurement — the Compose stack is unmeasured.
4. VSS-backed restore is **not measured**; the blocker is elevation, and that is
   recorded rather than asserted.
5. **No CI run has been observed.** No badge is claimed.
6. **89.1% of the studied commits are AI-assisted**, and the figure is published.

---

## Slide 19 — What the reproducibility gate found in our own work

> Running the appendix instead of writing it took **six attempts** and found
> **ten defects in our own work**. Undeclared dependencies. A crash on every
> clean checkout. A headline figure that needed a gitignored file. And the one
> that matters: **the appendix's own corpus command built the wrong corpus** —
> 149 files where every benign figure is about 275 — so Bound 1 came out
> 27.1752 pp instead of 25.3235, and nothing said so.

*Say:* "That command ran without error and exited zero. A document that was
accurate, a command that ran, and an exit status of zero together produced the
wrong number. **An appendix that is written and not run is a description of a
reproduction, not a reproduction.** The sixth run passed: 27 stages, every
digest matched, every claim re-checked, 659 tests green."

---

## Slide 20 — Contribution

1. A method for pricing a mitigation against the signal it cancels, every price
   **built and run**.
2. The finding that **a capability level without its ladder is not a fact**.
3. A repair **reported as rejected**, against a bound declared before the data
   existed.
4. An audit trail carried to every hop, with a measured statement of what it is
   **not** evidence of.

> Ransomware detection improved generally is **not claimed**.
> Patentability is **never inferred from this work**.

---

# Anticipated questions

The ones worth rehearsing are the hostile ones. Each answer below is short,
concedes what is true, and names the artefact.

**"Isn't this just saying signature checks are weaker than parsing? Everyone
knows that."**
Yes, and that is not the finding. The finding is that a system with a governance
layer built to notice exactly this difference did not apply it here, and that the
reason was an ordering in `handle_event` rather than a position anyone took. The
second finding — the ladder dependence — is not folklore.

**"You built the attacks and the repair. Isn't that circular?"**
Partly, and it is limitation 11.7. The partial defence is family A7, which was
built to defeat Arm D and does, 2 of 3. But a family built by the author of the
repair is not an adversary, and I would not claim otherwise. An independent
red-team pass is the fix and was not in scope.

**"Your corpus is synthetic. Why should I believe any false-positive number?"**
You should believe them as figures about that corpus and nothing more, which is
how they are worded throughout. What the corpus buys is that you can rebuild it
byte-identically from seed `20260902` and check every file's hash. A real
filesystem sample would be better and is future work with a privacy dimension.

**"You changed the strict rule to `>`. Didn't that fix the result you wanted?"**
No — it is a no-op on the deployed table. All fifteen live cells decide
identically either way, which is why policy B is cell-for-cell identical to
policy A. That is precisely why it was safe to adopt and why adopting it settles
nothing. It only does work where a tie exists, and the ties only exist on the
plan's ladder.

**"So which ladder is right?"**
The plan's, because §9.1 makes it governing. But the more useful answer is that
the question exposes the problem: two reasonable ladders written by the same
project for the same purpose give opposite answers, so a project that wants a
particular answer can obtain it by choosing a ladder. The defence against that is
publishing the computation on every ladder in play, which is what policies A
through F are.

**"If D1 fires, why haven't you disabled those two mitigations?"**
Because deploying policy F would invalidate every arm of the experiment, all of
which were measured against the declared table. Changing a ladder mid-experiment
makes the experiment unreadable. The computation is published and the deployment
decision is stated as deferred, not as settled.

**"Arm D clears Bound 1. Why not ship Arm D?"**
Two reasons. It was chosen after its own benign numbers were visible, so claiming
the bound for it would be claiming a bound against data that selected the arm.
And family A7 defeats it 2 of 3 by prepending a real JPEG marker chain. The
variant that looks best on the benign corpus is the one the attacks beat.

**"Your ledger doesn't detect a rewrite. Isn't that a serious flaw?"**
It is a real limit and it is stated as one. It is also not fixable by better
code: an unkeyed hash chain over public inputs cannot distinguish an attacker who
recomputes from a legitimate writer, because there is no secret between them.
Closing it needs a signing key or an external anchor. §9.13 excluded anchoring; a
key is not excluded and is the simpler fix.

**"You found a base64 bypass and did nothing about it."**
Correct, and deliberately. The obvious counter fires on PEM certificates, `.eml`
attachments, JWTs and data URIs, and its benign cost is unmeasured. The rule this
project applied to the container repair — a mitigation whose benign cost is not
measured is not a mitigation — has to apply here too, or it was never a rule.

**"How much of this did an AI write?"**
82 of 92 commits on the studied branch carry a `Co-Authored-By: Claude` trailer —
89.1%, published in `PROJECT_IMPLEMENTATION_RECORD.md` rather than left to be
inferred. What answers the underlying concern is not a claim about the assistant
but the evidence discipline: every number here comes from a script you can run,
and `scripts/claim_matrix.py` re-checks all fifteen claims against their
artefacts. Assertion is cheap regardless of who is asserting.

**"Is the suite green in CI?"**
**No CI run has been observed.** The workflow exists and has never executed on a
runner. What has been verified is the clean-checkout half: a fresh clone, a fresh
virtual environment, dependencies installed from the declared requirements, and
the full suite run. That result is in `reports/reproduction_check.json`. No badge
is claimed.

**"Did you demonstrate the running system?"**
Not on video, and not on the Compose stack — no recorded run had a Docker daemon.
`docs/DEMONSTRATION_SCRIPT.md` carries the runbook with the expected output and
evidence path for each of eight steps. A screenshot standing in for a recording
would have been a fabricated artefact, and this project does not produce those.

---

# Live demonstration

If a daemon is available on the day, `docs/DEMONSTRATION_SCRIPT.md` is the
runbook. If not, three commands are safe to run live from the repository and
take under two minutes between them:

```bash
python scripts/claim_matrix.py --tests
```
*Every claim re-checked against its artefact, with the regressions run.*

```bash
python scripts/artefact_manifest.py --verify
```
*Every deterministic artefact's digest compared against the committed manifest.*

```bash
python scripts/capability_calibration.py
```
*The ten attacks built and run, live, with the base64 result on screen.*

The third is the one to run if there is time for only one. It builds the attacks
in front of the examiner and prints the level each one measures — which is the
method, demonstrated rather than described.
