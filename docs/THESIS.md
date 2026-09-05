# Capability-governed exception admissibility in a ransomware detection and recovery system

**A study of one mitigation, the governance layer it never reaches, and a repair
that was measured and rejected.**

Unified Ransomware Detection & Recovery System (URDS)
Final thesis — Phase 8, Week 32. 5 September 2026.

---

## Abstract

The project team designed and implemented a six-service ransomware detection and
recovery system. This thesis does not re-derive that system. It examines one
mechanism inside it: the rule that lets a recognised container header cancel a
high-entropy alert.

In the reviewed URDS Monitor, that rule is applied outside the system's own
governance layer. Twelve events that trigger it produce **zero** adjudications,
while the twelve cancelled and twelve attenuated events beside them produce
twelve each. The most-used evidence-cancelling path in the detector is the one
path the layer that prices mitigations never sees.

Under the declared capability model, forging that exemption costs an attacker
four bytes for eleven of the seventeen container formats the current registry
contains, and one standard-library call for the rest. Ten attack strategies were
built and run against the deployed code, and three of the five detection signals
turned out cheaper to avoid than the cost table says. The cheapest is
`base64.b64encode(ciphertext)`, which lands at exactly 6.000 bits per byte and
falls below all three of the Monitor's entropy thresholds at once.

A repair was predeclared, implemented behind a five-value policy switch, and
evaluated in five arms against a frozen 275-file corpus with paired scoring. The
repair closed the evaluated bypass — 21/21, 3/3, 2/2, 3/3 and 3/3 across five
attack families. Its benign cost exceeded the bound declared before the corpus
existed: on the evaluated corpus, the one-sided 95% upper limit on the
false-positive difference for validated formats is **25.323 percentage points
against a tolerance of 2.00**, and on the unvalidated × incompressible stratum
every arm including the null control flags 90 of 90 files — 100.0 pp against a
15.0 pp tolerance. **The repair does not ship.**

The strongest result is methodological and was not the one the work set out to
find. Decision rule D1 asks whether two deployed mitigations remain justified
under calibrated costs. Asked on the code's four-point capability ladder the
answer is no cells flip; asked on the governing method document's five-level
ladder, with the strict tie rule that document mandates, four cells flip and both
mitigations cancel nothing at all. **The answer to a capability-governance
question is a property of the scale it is asked on, not of the system being
asked about.**

Ransomware detection improved generally is not claimed. Patentability and legal
novelty are never inferred from this work.

---

## Contents

| | Chapter |
|---|---|
| 1 | Introduction |
| 2 | Background and related work |
| 3 | The system under study |
| 4 | Method |
| 5 | Capability calibration |
| 6 | Admission recomputation, and the two ladders |
| 7 | The experiment |
| 8 | Integration: does the decision reach the hops that act on it |
| 9 | What this system does not stop |
| 10 | Negative results |
| 11 | Limitations |
| 12 | Conclusion and future work |
| A | Authorship record |
| B | Reproducibility |
| C | Claim-to-artefact matrix |
| D | Superseded figures, with dates |
| E | Decision rules D1–D6, and how each was answered |
| F | Test inventory |
| G | Glossary |
| H | The full admission matrix, all 120 cells |
| I | The benign corpus, cell by cell |

Every numeric claim in this thesis carries a pointer to a report, a test or a
stated assumption. A sentence with no pointer is framing rather than result. If a
pointer does not resolve, the sentence is wrong and the pointer is how a reader
finds out.

---

# 1. Introduction

## 1.1 The problem this work actually addresses

Ransomware detectors that watch a filesystem almost all use entropy. Encrypted
output is near-uniform, ordinary documents are not, and a file whose entropy
jumps toward 8.0 bits per byte during a write is a reasonable thing to alert on.

The difficulty is that a great many perfectly ordinary files are also
near-uniform. A ZIP archive, a JPEG photograph, an MP4 video and a PDF with
embedded images are all compressed by construction and all sit near the ceiling.
A detector that alerts on entropy alone flags them constantly, and a detector
that flags constantly is switched off.

So detectors add exceptions. URDS adds one of the common ones: if a file's first
bytes match a recognised container signature, the high-entropy alert is
cancelled and the verdict becomes `benign_compressed`. The exception is
necessary. Deleting it, measured here as the null control, takes the
false-positive rate on a 275-file benign corpus from 0 to **185 of 275 — 67.3%**
[`reports/three_arm_experiment.json`, Arm B].

But an exception in a security control is a rule an attacker can satisfy. If
"this file starts with `PK\x03\x04`" is enough to cancel an alert, then writing
four bytes in front of the ciphertext is enough to cancel it. The question is not
whether the exception is useful — it demonstrably is — but whether the system
knows what the exception costs to defeat, and whether anything in the system
checks that the cost is worth paying.

URDS has a component for exactly that question. `admissibility.adjudicate` prices
what it costs an attacker to *avoid* each detection signal and what it costs to
*forge* each suppression, and admits the suppression only when forging is
strictly more expensive than avoiding. It is a small piece of code and a good
idea.

**The container exemption does not reach it.** That is the finding this thesis
begins from, and everything after Chapter 4 is an attempt to say precisely what
follows from it and what does not.

## 1.2 What this thesis claims

Five things, in descending order of how hard the work would defend them.

1. **A method for pricing a false-positive mitigation against the detection
   signal it cancels**, in which every price is built and run rather than
   assigned by judgement. Ten strategies, ten empirical source trails, no level
   asserted from reasoning alone [Chapter 5].
2. **That the answer to a capability-governance question depends on the ladder
   the question is asked on** — demonstrated by one question producing opposite
   answers on two scales over a single set of recorded operational facts
   [Chapter 6]. This is the result the work would defend hardest, and it was
   found by accident, correcting an earlier error.
3. **That the container exemption in the reviewed URDS Monitor is applied
   outside the governance layer**, and that forging it is negligible-cost under
   the declared model [Chapters 4 and 5].
4. **A repair that closes the evaluated bypass and is rejected on its measured
   benign cost** — reported as a negative result rather than tuned until it
   passed [Chapter 7].
5. **An audit trail that carries the decision to every hop that acts on it**,
   with a measured statement of what that trail is and is not evidence of
   [Chapters 8 and 9].

## 1.3 What this thesis does not claim

Stated here rather than buried in Chapter 11, because the temptation to overstate
is strongest in an introduction.

- **Ransomware detection is not claimed to have improved.** No external-detector
  comparison was run — §9.13 places it out of scope — and the repair that was
  measured does not ship. The defensible statement is that one bypass in one
  monitor was priced, and one repair was rejected on measured cost.
- **Nothing here is claimed to generalise beyond URDS.** The method might;
  whether it does is not something this work measured.
- **Patentability and legal novelty are never inferred.** No prior-art search and
  no legal review were conducted, so the question is not one this project can
  answer either way.
- **The system was not built for this study.** Phases 1–4 built it; Phases 5–8
  study one mechanism in it. `PROJECT_IMPLEMENTATION_RECORD.md` records who built
  what, including the fact that 82 of the 92 commits on the studied branch carry
  an AI co-authorship trailer.
- **Recovery is verified locally and not through VSS.** Thirteen of thirteen
  local restore round-trips verify; snapshot-backed restore through the Volume
  Shadow Copy Service is not measured, because it needs an elevated shell no
  recorded run had.

## 1.4 How to read this document

The thesis is arranged so that a reader who wants only the results can stop
early, and a reader who wants to check them can go further.

- **Chapters 1–3** set up the problem and describe the system. A reader who
  already knows URDS can skip Chapter 3.
- **Chapter 4** is the method. It is the chapter to read if you want to judge
  whether the results mean anything.
- **Chapters 5–8** are the results, in the order they were produced.
- **Chapter 9** is what the system does not stop, including two findings that
  weaken claims made earlier in the project.
- **Chapter 10** collects the negative results in one place. Plan §9.4 of the
  governing plan requires this and it is the most useful chapter for anyone
  building something similar.
- **Chapter 11** is the limitations chapter, required and deliberately long.
- **Appendices A–G** are the machinery: authorship, reproduction, the claim
  matrix, superseded figures with the dates they were superseded, the decision
  rules, the test inventory and a glossary.

---

# 2. Background and related work

## 2.1 Entropy as a ransomware signal

Shannon entropy over a byte histogram is the standard cheap test for "does this
look encrypted". For a file of *n* bytes with symbol frequencies *p<sub>i</sub>*:

> H = − Σ p<sub>i</sub> log₂ p<sub>i</sub>, bounded above by 8.0 bits per byte.

Plain text sits between 4.0 and 5.0. English prose compresses well and rarely
exceeds 4.8. Encrypted or well-compressed data sits above 7.9 and typically
above 7.99.

URDS uses three entropy-derived signals, and the distinction between them matters
throughout this thesis:

| Signal | Test | Threshold |
|---|---|---|
| `static_entropy` | whole-file entropy | > 7.5 |
| `partial_entropy` | any 4 KB block's entropy | > 7.9 |
| `entropy_rise` | entropy increase against a learned per-directory baseline | floor 7.0 |

The three exist because they fail differently. Whole-file entropy misses a file
that is mostly plaintext with an encrypted region; per-block catches it.
Per-block misses a file that was always high-entropy; the differential catches a
change. **Chapter 5 shows one attack that defeats all three at once**, which is
possible precisely because all three are thresholds on the same statistic.

## 2.2 The container false-positive problem

The literature on entropy-based ransomware detection returns repeatedly to
compressed and media files. The usual mitigations are:

1. **Signature exemption** — recognise the container's magic bytes and exempt.
   Cheap, and what URDS does.
2. **Structural validation** — parse the container and confirm it is really one.
   More expensive and much harder to forge.
3. **Compression-yield tests** — if data is already compressed it will not
   compress further, so a poor compression ratio is evidence of genuine
   compression rather than of encryption. This is one clause of the repair
   evaluated in Chapter 7.
4. **Behavioural context** — process lineage, write rate, extension churn. URDS
   has these as separate signals; they are not the subject here.

The gap this work occupies is not that (1) is worse than (2) — that is obvious
and stated in the literature. It is that **a system with a governance layer
capable of noticing the difference did not apply it here**, and that the reason
turns out to be a one-line ordering decision in `handle_event` rather than a
design position anyone took.

## 2.3 Capability models in security argument

Reasoning about attacker capability is standard in threat modelling: an attack
that needs a preimage on SHA-256 is not the same as one that needs a text editor.
The specific idea used here — assigning each mitigation and each signal a
*capability level* and comparing them — comes from the URDS design itself, in two
incompatible forms that Chapter 6 shows are the whole story.

`services/monitor/admissibility.py` declares a four-point scale:

| Level | Name | Meaning |
|---|---|---|
| 0 | NEGLIGIBLE | trivially achievable |
| 1 | LOW | requires a location or a condition the attacker likely controls |
| 2 | MODERATE | requires format-aware engineering |
| 3 | HIGH | requires a secret or a preimage |

`NOVELTY_PROOF_PLAN.md` §5.2 — the governing method document — declares five:

| Level | Name | Examples the document gives |
|---|---|---|
| 0 | direct attacker control | write bytes, **choose a path**, rename a file, prefix a recognised magic value |
| 1 | public primitive | call a standard library: gzip, zlib, base64 |
| 2 | format-aware construction | build a structurally valid archive by hand |
| 3 | new engineering | write distribution-shaping code |
| 4 | secret or preimage | forge a hash |

They are not the same scale with different names, and Chapter 6 shows that the
single rung where they disagree is enough to reverse a decision rule.

## 2.4 Named inputs

Per Table 9.9 these are inputs to this work and are never presented as
contributions of it: **XGBoost** (the gradient-boosted detection model),
**FastAPI** (every service's HTTP surface), **watchdog** (filesystem event
capture), **EMBER** (static PE features), **CLEAR** (labelled ransomware corpus),
**RanSAP** (I/O behavioural traces), and scikit-learn, SHAP, pandas and numpy for
training and analysis. The Python standard library's `gzip`, `zlib`, `base64` and
`hashlib` build the attack witnesses in Chapter 5 — which is the point of those
witnesses, since an attack that needs only the standard library is cheap by
definition.

## 2.5 The seventeen formats, and why the registry has two sizes

The container exemption rests on two tables in `services/monitor/containers.py`
that are easy to mistake for one table.

`identify_container` matches a signature against the head of a file and returns
a format name. It recognises seventeen: `zip`, `gzip`, `bzip2`, `xz`, `7z`,
`rar`, `lz4`, `zstd`, `png`, `jpeg`, `gif`, `pdf`, `iso-bmff`, `mp3`, `ogg`,
`flac` and `riff`. Most are a constant at offset zero; `iso-bmff` is the
exception and is matched on a separate branch, because an MP4 file's `ftyp` box
begins four bytes in rather than at the start. The signature table has twenty-one entries naming
sixteen distinct formats - ZIP has three signatures and GIF and MP3 have two
each - so counting names in that table gives sixteen and the correct answer is
seventeen — a discrepancy this thesis records in Appendix C rather than
silently reconciling, because the project's own Table 9.9 says "11 of 16".

`_VALIDATORS` maps a format to a function that parses it and says whether the
structure is really there. It holds six: `zip`, `gzip`, `png`, `jpeg`, `pdf`,
`iso-bmff`. Each is a bounded read — the ZIP validator walks local headers and
looks for a central directory within a tail sample, the gzip validator inflates
a bounded prefix, the PNG validator walks the chunk list — so none of them is
a full decoder and none of them will read an arbitrary amount of an attacker's
file.

`validate_container` returns one of four things, and the fourth is the one that
matters:

| Returned | When |
|---|---|
| `VALID` | a validator ran and the structure is there |
| `FORGED` | a validator ran and the structure is not there |
| `INCOMPLETE` | a validator ran, found a real beginning, and did not reach the end within its bounded read |
| `None` | no validator exists for this format |

Not every validator can produce every state, and the exceptions are documented
in the module rather than left to be discovered. The gzip validator has **no
INCOMPLETE state at all**: gzip's only terminal structure is a CRC-32 over the
whole member, checking it would mean inflating the whole member, and the
validator does not - so **a truncated gzip reads as VALID**. The JPEG validator
reads a file caught between the first bytes of a write as FORGED rather than
INCOMPLETE, for the opposite reason. Neither is an oversight; both are bounded
reads choosing which error to make, and both are attack surface that this thesis
does not measure because no attack family was built against them.

Legacy policy admits `VALID`, `INCOMPLETE` and `None` alike. §7.2.1 measures
what each of those costs: `None` is the eleven-format hole, and `INCOMPLETE` is
a third state the attacker can aim at even in a validated format.

## 2.6 The statistical method, and one place it does not apply

The benign-cost comparison in Chapter 7 is paired: the same 275 files are
scored under every arm, so each file contributes a matched pair rather than an
independent sample. Two standard procedures follow from that design and both are
implemented in `scripts/benign_tradeoff.py` rather than quoted from elsewhere.

**Exact McNemar, one-sided.** Only the discordant pairs carry information: *b*
is the count of files the arm flags and the baseline does not, *c* the reverse.
Under the null, each discordant pair is a fair coin, so the one-sided p-value is
P(B ≥ b) for B ~ Binomial(b + c, ½), computed exactly by summation rather than
by the chi-squared approximation. One-sided because the question is
non-inferiority in one direction: an arm that *removes* false positives is not a
concern this bound is protecting against.

**Clopper–Pearson, one-sided, 95%, and the upper limit is what is judged.** The
interval is exact rather than normal-approximate, which matters at the corpus
sizes here — a stratum of 30 files with zero events has a 95% upper limit of
9.503 pp, and a normal approximation would put it at zero and be wrong.
Reporting the *upper* limit rather than the point estimate is what makes the
predeclared tolerances meaningful: a bound of 2.00 pp is a claim that the true
rate is below 2.00 pp, not that the observed rate was.

**The place it does not apply is worth stating, because the code checks for it.**
The Clopper–Pearson limit on *b* successes in *n* trials bounds the paired
difference only when *c* = 0 — that is, only when the baseline has no false
positives in the cell, so every discordant pair points one way and the
difference is exactly *b*/*n*. When *c* is not zero the identity breaks and the
limit does not bound what it appears to bound. `compare()` therefore returns
`upper_limit_pp: None` with a stated basis in that case rather than a number,
and the predeclared analysis's assumption that the baseline sits at zero is
recorded as an assumption that a cell can violate.

In this experiment the baseline is Arm A, which has zero false positives on all
275 files, so *c* = 0 everywhere and every limit is computed. **That the check
never fires here is not a reason to remove it**; the arms are configuration
values and a future baseline need not be Arm A.

## 2.7 What this chapter does not do

This is not a systematic literature survey, and it should not be read as one.
The related work above is stated at the level of technique — signature
exemption, structural validation, compression yield, behavioural context — and
the claim it supports is deliberately narrow: that the *gap* this thesis
occupies is not "signature exemption is weaker than structural validation",
which is well understood, but the specific and local fact that **a system with a
governance layer capable of pricing that difference did not apply it here, for a
reason that turns out to be an ordering decision in `handle_event` rather than a
position anyone took**.

Two consequences follow and both are limits on what the thesis may claim.

First, **no priority claim is made.** Nothing here asserts that capability-based
admissibility for exception rules is new, and Chapter 12 does not argue
novelty from absence of a citation. The contribution claimed is the measurement
on this system, under the wording Table 9.9 requires, and no more.

Second, **no comparison against external detectors is made**, and plan §9.13
puts such a comparison out of scope. Every figure in this thesis is URDS against
URDS under five policy values. That is enough to answer the questions asked and
it is not enough to say anything about how URDS compares to any other system,
which §11.8 states again where a reader is most likely to over-read.

---

# 3. The system under study

## 3.1 Six services

The project team designed and implemented URDS as six services behind a Docker
Compose deployment [`PROJECT_IMPLEMENTATION_RECORD.md`;
`docs/PHASE1-4_COMPLETION_SUMMARY.md`].

| Service | Responsibility |
|---|---|
| **monitor** | watchdog filesystem events, entropy and signature detection, the capability governance layer, fan-out to the other services |
| **ml-engine** | XGBoost model serving; scores file bytes and returns a ransomware probability |
| **ledger** | append-only audit log over an unkeyed SHA-256 hash chain |
| **response** | process termination, isolation rules, recovery and snapshot restore |
| **gateway** | the external HTTP surface and JWT authentication |
| **dashboard** | a Streamlit operator view |

This thesis touches monitor, ledger, response and gateway directly, and ml-engine
only to establish that it deliberately does not receive the policy record.

## 3.2 The detection path

The path a file event takes, and the four places this work intervenes:

```
watchdog event
   → detection.classify()          entropy, signatures, container exemption   ← Ch 4, 7
   → admissibility.adjudicate()    capability comparison, admit or attenuate  ← Ch 5, 6
   → pipeline.log_governance_decision()   the chained record                  ← Ch 8
   → fan-out: ml-engine, ledger, response                                     ← Ch 8
```

`classify` returns a verdict, a suspicion flag, the signal that fired and — since
this work — a container validation state and the policy version that decided the
event.

## 3.3 The mechanism this thesis is about

Reduced to its essentials, and this is the whole of it:

```python
# services/monitor/detection.py
if entropy > ENTROPY_THRESHOLD:
    container = identify_container(head)
    if container is not None and container_explains_entropy(...):
        return "benign_compressed", not_suspicious      # the alert is cancelled
    return "suspected_encryption", suspicious
```

`identify_container` matches the leading bytes against 20 signatures covering 16
format names, and recognises a seventeenth — `iso-bmff` — on a separate `ftyp`
branch. `containers._VALIDATORS` structurally validates six of those seventeen:
zip, gzip, png, jpeg, pdf and iso-bmff. **The other eleven — rar, 7z, xz, bzip2,
lz4, zstd, gif, mp3, ogg, flac and riff — are accepted on their header alone.**

For those eleven, the entire cost of cancelling a high-entropy alert is writing
the right four bytes at offset zero.

## 3.4 The governance layer, and why it does not see this

`admissibility.adjudicate` takes a mitigation and the detection signal it would
cancel, looks up each one's capability cost, and admits the suppression only if
forging it is strictly more expensive than avoiding the signal. The reasoning is
sound: a suppression that is easier to forge than the evidence it cancels is not
a mitigation, it is a bypass with a docstring.

The exemption never arrives there. In `services/monitor/app.py`, `handle_event`
adjudicates only a verdict that is *already suspicious*, and the container
exemption's whole effect is to make the verdict not suspicious before that point
is reached. The ordering is not a decision anyone recorded; it is what falls out
of putting the cheap check first.

Measured, across three populations of twelve events each pushed through the real
pipeline [`reports/ledger_coverage.json`]:

| Population | Events | Adjudicated | Reaching the ledger |
|---|---|---|---|
| cancelled (whitelist, hash rule) | 12 | 12 | 12 |
| attenuated (training mode) | 12 | 12 | 12 |
| **ungoverned (container exemption)** | **12** | **0** | **0** |

## 3.5 What Phases 1–4 delivered, and what is not reclaimed here

Phases 1–4 produced the six services, the hash-chain audit log, VSS and local
snapshot recovery, the trained XGBoost model, watchdog monitoring and the Compose
wiring. That work is recorded in `docs/PHASE1-4_COMPLETION_SUMMARY.md` and
`docs/PHASE4_VERIFICATION_REPORT.md`, and this thesis **cites it rather than
reclaiming it**. Where a Phase 1–4 figure is quoted here it is quoted as prior
work of the same project, with its own report named.

## 3.6 The six services in more detail

The table in §3.1 is the shape of the system; this section is the part of it a
reader needs in order to follow Chapters 7 and 8, and no more than that. Sizes
are measured from the tree at the freeze commit; test counts are from the
clean-checkout run recorded in `reports/reproduction_check.json`.

| Service | Source lines | Test files | Tests passing | Published port |
|---|---|---|---|---|
| monitor | 3,746 | 20 | 382 | `127.0.0.1:8001` |
| ml-engine | 492 | 5 | 30 (+18 skipped) | `127.0.0.1::8002` (ephemeral) |
| ledger | 568 | 3 | 67 | `127.0.0.1:8003` |
| response | 520 | 4 | 95 (+2 skipped) | `127.0.0.1:8004` |
| gateway | 555 | 5 | 86 | `0.0.0.0:8000` |
| dashboard | 541 | 0 | — | `0.0.0.0:8501` |

**Two ports are reachable off-host and four are not.** The four loopback binds
are a deliberate choice recorded by `scripts/package_release.py`'s audit: the
ledger's `/ledger/blocks` and `/ledger/entries` are unauthenticated, and the
difference between `127.0.0.1:8003` and `0.0.0.0:8003` is the difference between
a loopback service and an unauthenticated audit-log endpoint on the LAN. The
gateway is the authenticated surface and is meant to be reachable; the dashboard
is a Streamlit view and is reachable because Streamlit is.

**The dashboard has no tests.** It is excluded from the reproduction gate for
that reason, and the exclusion is recorded in the gate's own report rather than
being silently absent — §11 and Appendix F both carry it. Nothing in this thesis
measures the dashboard or claims anything about it.

### 3.6.1 monitor

The service this thesis is about. It carries the watchdog observer, the four
detection signals, the container registry and its validators, the whitelist and
training-mode suppressions, the capability governance layer, and the fan-out
worker.

Its HTTP surface is twelve endpoints: `/health`, `/monitor/start`,
`/monitor/stop`, `/monitor/status`, `/monitor/events`, `/monitor/whitelist`
(GET and PUT), `/monitor/training-mode` with `start`, `finish` and `reset`, and
`/features`.

Three of those matter to the argument. `PUT /monitor/whitelist` is how the path
and hash rules of §6.1 get set, and it takes paths and hashes with no
content-based check — which is the mechanism §9.7's finding is about.
`/monitor/training-mode/start` opens the learning window that the
`training_mode` strategy of §5.6.9 poisons. And `/monitor/events` is the read
model the dashboard shows, which is not the same record as the ledger's — a
distinction Chapter 8 turns out to need.

At 3,746 source lines and 382 tests it is by a wide margin the largest service,
and every measurement script in `scripts/` imports from it directly rather than
over HTTP. §11.3 says what that costs.

### 3.6.2 ml-engine

Three endpoints: `/health`, `/predict`, `/model/metrics`. It loads a trained
XGBoost model from `models/` and returns a ransomware probability for supplied
file bytes.

**XGBoost is an input to this work and not a contribution of it**, and neither
is the EMBER-derived training data. The model is not in the repository —
`models/` is gitignored — which is why eighteen of its tests skip on a clean
checkout and why the confidence-gate strategy of §5.6.10 is the one headline
figure that cannot be reproduced from the repository alone. §11.6 is about that
gap and Appendix B records it as a stated limit of the reproducibility claim
rather than as an omission.

The service is deliberately *not* sent the governance record. Chapter 8 measures
this and treats it as a finding about scope rather than a defect: a model that
scores bytes does not need to know why an alert was suppressed, but a reader
looking at the pipeline cannot tell whether that was decided or merely happened.

### 3.6.3 ledger

Five endpoints: `/health`, `/ledger/log`, `/ledger/verify`, `/ledger/blocks`,
`/ledger/entries`. It maintains an append-only log in SQLite whose blocks are
linked by an **unkeyed** SHA-256 hash chain — each block hashes its own contents
together with its predecessor's digest.

Unkeyed is the whole of §9.1. A chain with no secret can be recomputed by
anyone who can write to the database, so it detects an *edit* — a change to a
block whose successors still carry the old digest — and does not detect a
*rewrite*, where the whole chain is recomputed after the change. `tamper_sweep`
measures both classes across 28 cases and finds exactly that split. Adding a key
is out of scope under plan §9.13, and the finding is reported open rather than
closed by a design note.

### 3.6.4 response

Four endpoints: `/health`, `/response/terminate`, `/response/isolate`,
`/response/trigger`. It carries process termination, isolation rules, file-copy
recovery, and the VSS snapshot backend.

Recovery has two paths and this thesis measures one of them. The file-copy path
is exercised thirteen times over — every simulator family round-trips through it
and all thirteen restore correctly. The snapshot path refuses without
elevation and is recorded as not measured (§9.8). **The correct reading of "all
restore round-trips true" is therefore "through the file-copy path", and that
qualifier is carried in every place the figure appears.**

### 3.6.5 gateway

Two endpoints of its own — `/health` and `POST /auth/token` — plus a proxy that
forwards to the four internal services through one `SERVICE_URLS` map with a
five-second client timeout. JWT authentication lives here and nowhere else,
which is the reason the other four services bind to loopback.

Eighty-six tests, and none of them are in the argument of this thesis. The
gateway appears in Chapter 8 only as one of the hops a governance decision does
not reach, and in Appendix F because a suite that passes is part of what the
reproduction gate checks.

### 3.6.6 dashboard

A Streamlit operator view, 541 lines, no tests, excluded from the gate. It reads
`/monitor/events`. It is listed here for completeness and because leaving a
service out of the table would be the kind of quiet omission plan §9.4 forbids,
not because anything in this thesis depends on it.

---

# 4. Method

This chapter is the one to read if you want to judge whether anything in
Chapters 5–8 means what it says.

## 4.1 The governing document, and an error about it

The method this work follows is set by `NOVELTY_PROOF_PLAN.md`, which plan §9.1 makes
governing. **Phases 5 and 6 were carried out believing that document did not
exist.**

The belief came from a finding, made early and recorded confidently, that the
file had never existed in the repository — supported by a `git log --all` search
that returned nothing. The search was wrong: the file was on a remote branch that
the local clone had a ref for but whose objects the search did not reach.
`docs/METHOD_DOCUMENT_STATUS.md` records the error, how it was found, and what it
cost.

What it cost is not small, and Chapter 6 is the largest item: **D1 was answered on
the wrong ladder and reversed when asked again on the right one.** The error is
kept in this thesis rather than smoothed away, because the strongest result the
work has exists only because the error was corrected, and a reader is entitled to
know that the finding is a repair rather than a plan.

## 4.2 Measure, never assert

The single rule the whole evidence discipline reduces to: **every number in this
thesis comes from a command that was actually run.**

Operationally this means:

- No capability level is assigned from reasoning about how hard an attack sounds.
  Each is built as a working attack, run against the deployed detector, and the
  level derived from what the run recorded [Chapter 5].
- No report is written unless `URDS_WRITE_REPORTS=1`, so a script run for a look
  cannot quietly overwrite an artefact.
- No artefact is fabricated. There are no mocked screenshots in this thesis, no
  hand-written log output, no invented corpus rows and no capability level
  asserted from source reading alone.
- Where a figure could not be measured, it is reported as not measured, with the
  blocker named. `reports/vss_status.json` exists precisely so that "not
  measured" can be distinguished from "measured and refused".

## 4.3 A negative result is a result

Decision rules D1–D6 were declared before the measurements they govern, and each
has a branch that is unfavourable to the project. **Those branches were taken
where the measurement took them.**

The largest is D5. The repair evaluated in Chapter 7 closes every attack family
built for it and is rejected on measured benign cost, and
`CONTAINER_EXEMPTION_POLICY` still defaults to the pre-repair behaviour. The
temptation at that point is to tune the threshold until the bound passes. The
bound was predeclared, in a document committed and tagged before the corpus
existed, and it is reported as failed.

## 4.4 Predeclaration and freezing

§9.15 requires the cost table and the corpus manifest to be frozen and tagged
before dependent work begins, with the commit hashes quoted:

| Tag | Commit | Date | Froze |
|---|---|---|---|
| `corpus-frozen-week19` | `2c242d6` | 2026-09-02 | the benign corpus manifest |
| `cost-table-frozen-week20` | `0354d8f` | 2026-09-02 | the declared capability cost table |
| `corpus-frozen-week21` | `9a40bc6` | 2026-09-03 | the corpus, re-frozen for the experiment |
| `repair-accepted-week24` | `e69bb3a` | 2026-09-03 | the Week 24 gate decision |

`docs/PHASE5_PREDECLARED_BOUNDS.md` declares the benign-cost bounds — Bound 1 at
2.00 pp on validated formats, Bound 2 corpus-wide, and D5's 15.0 pp tolerance on
the unvalidated × incompressible stratum — and was committed before the corpus
was built.

**One arm was not predeclared in the same sense.** Arm D, the inner-content
variant, is listed in plan §7.1 as one of five candidate repair variants, so the
*variant* was predeclared; but it was chosen among variants after its own benign
numbers were visible. This thesis therefore does not claim Bound 1 for Arm D even
though Arm D clears it. That is stricter than the plan requires and it is left
standing rather than relaxed once it became convenient.

## 4.5 Paired measurement

Every arm of the experiment scores the same file from **one** disk read. The
corpus is read once per file and the resulting bytes are handed to all five arms
in turn, so no arm can differ from another because of a filesystem effect, a
cache state or a timing accident. Differences between arms are differences in
policy and nothing else.

Statistics follow from the pairing:

- **Clopper–Pearson one-sided 95% upper bounds** on false-positive differences,
  because the counts are small and the normal approximation is not safe at
  n = 155.
- **Exact McNemar** on discordant pairs where two arms are compared directly.
- **Per-stratum reporting.** The corpus is stratified by validator coverage
  (validated / unvalidated) and by compressibility (compressible /
  incompressible), and every benign figure is reported per stratum as well as
  corpus-wide. A corpus-wide average would hide the 100 pp stratum inside a
  tolerable-looking mean, which is exactly what D5 exists to prevent.

## 4.6 The corpus

275 files, procedurally generated from seed `20260902`, byte-identically
reproducible, stratified into four cells by validator coverage and
compressibility [`scripts/build_benign_corpus.py`;
`reports/benign_corpus_manifest.json`].

Each file draws from `random.Random(f"{seed}:{stem}:{index}")` rather than from a
single sequential generator, so a file's content depends only on its own name and
position. Adding a file to the corpus does not change any other file's bytes,
which is what let the corpus be grown at Week 21 without invalidating Week 19's
measurements.

**It is synthetic and that is a limitation, not a design flourish.** It is not a
sample of anyone's real filesystem. Every false-positive figure in this thesis is
a figure about this corpus. What the corpus buys is that a reader can rebuild it
and get the same bytes, and `--verify` checks each file's SHA-256 against the
manifest rather than trusting the rebuild.

## 4.7 What is out of scope, and stays out

§9.13 places the following outside this work. They are listed here because a
reader should be able to tell an absence from an oversight:

adaptive RECF-DR search; Pareto optimisation; a `recf_dr/` framework; **new
structural validators for the eleven unvalidated formats**; external-detector
comparison; Polygon or any blockchain anchoring; mobile support; any claim that
the result generalises beyond URDS; any claim of patentability or legal novelty.

Two of these are load-bearing. Writing the eleven validators is the correct
long-term fix for the finding in Chapter 7 and it is named as such rather than
attempted. An external anchor is the correct fix for the finding in Chapter 9 and
it is named as such rather than attempted.

---

# 5. Capability calibration

## 5.1 The question

The declared cost table in `services/monitor/admissibility.py` assigns each
detection signal a cost to avoid and each suppression a cost to forge. Those
numbers were assigned by judgement when the file was written. **Are they right?**

The way to find out is not to argue about them. It is to build each attack, run
it against the deployed detector, and derive the level from what the run
recorded.

## 5.2 Protocol

Ten strategies [`scripts/capability_calibration.py`;
`reports/capability_calibration.json`]. For each one:

1. **Build the attack.** Real bytes, written to a real file.
2. **Run it against the deployed code** — `detection.classify`, not a
   reimplementation of it.
3. **Record the operational facts** of what the attack needed: third-party
   dependencies, whether a public primitive performed the operation, whether it
   ships an encoder, whether it needs format-specific knowledge, how many
   independent statements the attacker had to make, whether a secret or preimage
   was required, and whether a write location was all it needed.
4. **Derive the level twice from those facts, in opposite decision orders** —
   once top-down from the highest level, once bottom-up from the lowest. Two
   derivations that disagree mark the level unresolved under D2.
5. **Hash the artefact** so the attack bytes are checkable.

The double derivation is §9.15's reproduction protocol applied to the derivation
step. **It is not independent human reproduction and is not presented as such** —
see §11.2.

## 5.3 Results

**10 of 10 levels carry an empirical source trail. 10 of 10 reproduce. 0 are
unresolved under D2.** No level in this thesis is derived from reading source
code alone [`reports/capability_calibration.json`, `summary`].

One qualification that Chapter 11 returns to: the tenth level scores a feature
vector against a trained model that `models/` gitignores, so on a clean checkout
the figure is **9 of 10, with that level recorded unresolved under D2** rather
than assumed. That is D2 working as designed, and the distinction is stated here
rather than left for a reader to discover.

Five strategies disagree with the declared cost table, and all five disagree in
the same direction — cheaper than declared:

| Strategy | Declared | Measured | The attack |
|---|---|---|---|
| `container_exemption` / standard-library container | moderate | **negligible** | `gzip.compress(ciphertext, mtime=0)` |
| `container_exemption` / ZIP_STORED container | moderate | **negligible** | a stored-mode ZIP wrapping ciphertext |
| `entropy_rise` / unobserved path | moderate | **low** | write where nothing has measured a baseline |
| `partial_entropy` / never reach ciphertext entropy | moderate | **negligible** | `base64.b64encode(ciphertext)` |
| `C_forge(ml_confidence_gate)` / hold confidence under 0.7 | high | **negligible** | keep the model's score below the gate |

**Not one measured level came out more expensive than declared.** That asymmetry
is itself a finding about how cost tables get written: an author estimating the
cost of an attack they have not built estimates high, and does so consistently.

## 5.4 The base64 finding

The strongest single result in the calibration, and it was missed on the first
pass.

Phase 5 priced `partial_entropy` avoidance at **moderate**, reasoning that
holding every 4 KB block below 7.9 bits per byte requires distribution-aware
code. That reasoning is correct about one family of attacks and wrong about the
cheapest one.

Base64 spends eight output bits for every six bits of input. Uniform ciphertext
encoded into a 64-symbol alphabet therefore lands at **exactly 6.000 bits per
byte** — not approximately: the output alphabet has exactly 2⁶ symbols and the
input is uniform over them.

The Monitor's three thresholds are 7.5 (whole file), 7.9 (per block) and 7.0
(differential floor). **6.000 is below all three.**

| Encoding | Measured bits/byte | Size cost | Verdict |
|---|---|---|---|
| `base64.b64encode` | **6.000** | +33% | `benign` |
| `base64.b32encode` | 5.000 | +60% | `benign` |
| `base64.a85encode` | 6.410 | +25% | `benign` |

One standard-library call, no format knowledge, no distribution-shaping code —
and all three entropy signals fail together, precisely because all three are
thresholds on the same statistic. A defence built from three tests of one
quantity is one test wearing three names. `partial_entropy` moves from moderate
to **negligible**, and that single change takes the flip count in Chapter 6 from
twelve to sixteen.

**No detector is written for this, deliberately.** The obvious counter — flag
high-printable content that decodes to high entropy — fires on PEM certificates,
`.eml` attachments, JWTs, data URIs and every base64-embedded image on disk, and
its benign cost has not been measured. This project's rule is that a mitigation
is not proposed until its benign cost is measured, and it is the same rule that
rejects the repair in Chapter 7. Proposing an unmeasured counter here while
rejecting a measured repair there would be incoherent. It is recorded as S-1 in
`docs/SECURITY_AUDIT.md` and left open.

## 5.5 Both ladders, per strategy

Every strategy carries a level on both scales, each derived twice in opposite
orders from the same recorded facts:

| Entry | Kind | Code ladder | Plan §5.2 ladder |
|---|---|---|---|
| `hash` | forgery | high | 4 secret/preimage |
| `path` | forgery | low | **0 direct attacker control** |
| `training_mode` | forgery | low | **0 direct attacker control** |
| `container` | forgery | negligible | 0 direct attacker control |
| `ransom_extension` | avoidance | negligible | 0 |
| `static_entropy` | avoidance | negligible | 0 |
| `structural_mismatch` | avoidance | negligible | **1 public primitive** |
| `partial_entropy` | avoidance | negligible\* | **1 public primitive** |
| `entropy_rise` | avoidance | low | **0 direct attacker control** |

\* measured; declared moderate.

Both of the plan's own §5.3 calibration hypotheses hold: an unvalidated magic
prefix is Level 0, and standard-library container generation is Level 1. The rows
in bold are where the two ladders disagree, and Chapter 6 is about what those
rows do.

## 5.6 The ten strategies, one at a time

Every strategy below was built, written to a real file, and scored by
`detection.classify` as the deployed code runs it. Each entry gives the
construction, why it works against the deployed detector, the operational facts
that were recorded, and the level both derivations reached. The full records —
including the artefact SHA-256 for each attack's bytes — are in
`reports/capability_calibration.json`.

### 5.6.1 `container_exemption` / standard-library valid container

```python
gzip.compress(ciphertext, mtime=0)
```

**Declared moderate. Measured negligible.** Plan Level 1, public primitive.

`containers._validate_gzip` inflates a bounded prefix of the stream, and the
stream really does inflate — because it really is a gzip member, produced by the
same library the validator uses. So `container_status` is VALID, the exemption
fires, and `classify` returns `benign_compressed` for a file that is 8.0
bits/byte of ciphertext wrapped in nine bytes of header.

**This is the attack the structural validator cannot stop**, and it is worth
being precise about why. The validator is not defective and it is not evaded. It
is asked "is this a real gzip container?", it answers correctly, and the answer
is not evidence about whether the content is ransomware. A structural validator
answers a structural question; the detector needs a semantic one.

Operational facts: no third-party dependencies, a public primitive performed the
operation, no encoder shipped, no format-specific knowledge, one attacker
statement, no secret required. Top-down and bottom-up derivations both return
Level 1.

### 5.6.2 `container_exemption` / ZIP_STORED valid container

```python
ZipFile(path, "w", ZIP_STORED).writestr(name, ciphertext)
```

**Declared moderate. Measured negligible.** Plan Level 1.

A real local header, a real central directory, a real end-of-central-directory
record. `ZIP_STORED` means the payload is carried byte for byte, so **the
attacker gives up nothing to get the exemption** — no compression, no
transformation, no loss. The ciphertext inside is the ciphertext they wanted to
write.

The distinction from 5.6.1 is two attacker statements rather than one, which is
why the strategy is recorded separately rather than folded in. It does not change
the level.

### 5.6.3 `static_entropy` / magic bytes over ciphertext

```python
b"Rar!\x1a\x07" + ciphertext
```

**Declared negligible. Measured negligible** — the one avoidance strategy the
declared table priced correctly. Plan Level 0, direct attacker control.

`rar` is one of the eleven formats with no validator, so `validate_container`
returns `None`, the exemption admits it, and the verdict is `benign_compressed`.
Six bytes, no library, no knowledge of the RAR format beyond its signature.

Against a *validated* format the same attack fails: a `PK\x03\x04` prefix with no
ZIP structure behind it returns FORGED, which is what family A6's control
demonstrates in Chapter 7. The attack works precisely and only because the format
registry is larger than the validator registry.

### 5.6.4 `entropy_rise` / write to an unobserved path

```python
open(new_path, "wb").write(ciphertext)
```

**Declared moderate. Measured low.** Plan Level 0.

`EntropyHistory.observe` returns `None` on a first sighting, so `entropy_delta`
is `None` and the differential branch is unreachable. **A signal that compares
against a baseline has no baseline for a path it has never seen**, and the
attacker chooses the path.

The measurement records both sides, which matters: on a fresh path the verdict is
`suspected_encryption` on `static_entropy`; on an observed path it is
`suspected_encryption` on `entropy_rise`. The file is still caught — by a
different signal. So this strategy avoids one signal rather than defeating
detection, and the level reflects avoiding that signal and nothing more. The
`write_location_only: true` fact is what puts it at LOW on the code ladder and
Level 0 on the plan's, and that single fact is the whole of D1.

### 5.6.5 `partial_entropy` / never reach ciphertext entropy in any block

```python
base64.b64encode(ciphertext)      # exactly 6.000 bits/byte
```

**Declared moderate. Measured negligible.** Plan Level 1. Treated in full at
§5.4; recorded here for completeness with its measurement: entropy 6.0, container
status `unvalidated`, verdict `benign`, `suspicious` false, size cost ×1.333.

### 5.6.6 `ransom_extension` / do not rename the file

```python
# do nothing
```

**Declared negligible. Measured negligible.** Plan Level 0. Zero attacker
statements — the cheapest possible attack, because it consists of not doing
something.

The signal reads the filename and nothing else. An attacker who encrypts in place
without renaming avoids it entirely, and the measurement confirms the signal that
fires is `static_entropy` with or without the extension.

It is in the calibration because a table that lists only interesting attacks
understates how many of its rows are free.

### 5.6.7 `whitelist path rule` / write into an approved directory

```python
open(approved_dir / name, "wb").write(ciphertext)
```

**Declared low. Measured low** on the code ladder — **Level 0 on the plan's.**
This is one of the two strategies where the ladders disagree, and Chapter 6 is
about the consequence.

`Whitelist.match` fnmatches the path and returns a rule **with no reference to
the content**. The adjudication outcome is `cancelled`, `admitted: true`, forgery
cost low against avoidance cost negligible — admitted because 1 > 0 on the code's
scale. On the plan's scale both are 0, the strict rule refuses the tie, and the
suppression is attenuated.

The recorded fact that decides it is `write_location_only: true`. The code ladder
has a rung for "a location the attacker can already write to"; the plan's ladder
does not, because it considers choosing a path to be direct attacker control.

### 5.6.8 `whitelist hash rule` / produce a file with an approved SHA-256

**Declared high. Measured high.** Plan Level 4, secret or preimage. The only
strategy in the calibration that is **infeasible rather than merely expensive**.

There is no artefact, because the artefact would be a SHA-256 second preimage.
What was run is a negative control: an attacker-controlled file offered against a
populated hash whitelist, which did not match. `attack_succeeded: false`.

This record is why the calibration counts "empirical source trail" by whether an
attack was *executed and its outcome recorded* rather than by whether an artefact
hash exists. A negative control is a measurement. The alternative definition
would have marked the one genuinely strong mitigation in the system as
unevidenced.

### 5.6.9 `training_mode` / poison the learned ceiling during the window

```python
# write 6 files during the training window, then write the payload
```

**Declared low. Measured low** on the code ladder — **Level 0 on the plan's.**
The second of the two disagreeing strategies.

`TrainingMode` learns from writes, and the attacker can write. After six observed
events the learned state carries an entropy ceiling of 8.0 for `.zip` in the
watched directory — which is to say, the mode has learned that ciphertext-grade
entropy is normal there, because the attacker showed it six examples.

The dwell requirement and the structural-class requirement raise the price. They
do not change **who supplies the training data**, and that is the fact the level
turns on.

### 5.6.10 `C_forge(ml_confidence_gate)` / hold ransomware confidence under 0.7

**Declared high. Measured negligible** — the largest single disagreement in the
calibration. Plan Level 1.

Six variations were tried around unchanged high-entropy content, varying the
declared container, its validity and the block statistics. **Two of the six came
in under the 0.7 gate while the content was still ciphertext**: "valid container,
softened block statistics" and "valid container, entropy at the detector
threshold".

The gate is not in the cost table at all — the ML confidence path is ungoverned
in the same way the container exemption is — which is why this strategy's
`cost_table_key` reads *not in the cost table*. It is calibrated anyway, because
a suppression that is not in the table is not thereby free.

**This is the one strategy that needs a trained model**, and therefore the one
that cannot be reproduced from a clean checkout. §11.6 says what that costs the
reproducibility claim.

## 5.7 What the ten strategies say together

Three things stand out when the records are read as a set rather than one at a
time.

**Six of the ten need one attacker statement or fewer.** Two need one, one needs
zero, three need two to six. Nothing in the calibration required an attacker to
do something a competent programmer could not do in an afternoon, except the one
that requires a preimage.

**The expensive mitigation is the one that does not depend on attacker-supplied
data.** The hash whitelist is Level 4 because a SHA-256 value is not something an
attacker can arrange to match. Every other suppression in the system takes its
key from something the attacker controls: the path, the training window, the
container header. **That is the pattern worth taking away** — a suppression keyed
on attacker-supplied data is forgeable by definition, and the only question is
the price.

**Three of the five detection signals are cheaper to avoid than declared, and the
one priced correctly was priced negligible to begin with.** The cost table is not
uniformly wrong; it is wrong wherever it estimated an attack rather than running
one. The three strategies whose declared value survived contact were the ones
already priced at the bottom of the scale, where an over-estimate has nowhere to
go.

---

# 6. Admission recomputation, and the two ladders

## 6.1 The matrix

Twenty mitigation × signal cells, recomputed under six policies
[`scripts/admission_recompute.py`; `docs/ADMISSION_RECOMPUTE.md`]:

| Policy | Rule | Costs | What it is |
|---|---|---|---|
| A | `>=` | declared | the behaviour before P6.8 |
| B | `>` | declared | the rule change alone — **deployed** |
| C | `>=` | measured | the calibration alone |
| D | `>` | measured | the rule change and the calibration |
| E | `>=` | plan §5.2 | the plan's ladder alone |
| F | `>` | plan §5.2 | the plan's ladder and the plan's rule |

**Sixteen cells flip**, each attributed to the change that caused it:

| Policy | Flips | Direction | Attributed to |
|---|---|---|---|
| C | 6 | attenuated → cancelled | the calibration alone |
| D | 4 | attenuated → cancelled | the rule and the calibration together |
| E | 2 | attenuated → cancelled | the plan's ladder alone |
| **F** | **4** | **cancelled → attenuated** | the plan's ladder and the plan's strict rule |

The direction matters. Policies C, D and E flip cells *toward* suppression: the
calibration made signals cheaper to avoid, so mitigations that were merely
attenuated now cancel outright. Policy F flips four cells the other way —
suppressions that used to cancel now only attenuate. Those four are D1.

## 6.2 The strict rule is free, and that is why it was safe to adopt

§5.3 of the governing document is explicit: *equal capability does not
demonstrate that the mitigation is harder to forge*. A tie is not evidence, so a
tie must not admit. The code admitted on `>=`.

Adopting `>` was checked before it was made: **all fifteen live rule × signal
cells decide identically either way**, which is why policy B is cell-for-cell
identical to policy A. The change is a no-op against the deployed table.

That is exactly why it was safe to adopt, and exactly why adopting it settles
nothing on its own. A strict rule only does work where a tie exists, and on the
deployed table there are none.

## 6.3 D1: the same question, two answers

**D1 asks:** do the path-whitelist and training-mode admissions flip from
admitted to attenuated under the calibrated rule? Plan §9.7 predicts they will.

**Phase 5 answered: no. Zero cells flip in that direction.**

That answer is correct on `admissibility.py`'s four-point ladder and false on
`NOVELTY_PROOF_PLAN.md` §5.2's five-level one, which plan §9.1 makes governing.

**The whole disagreement is one rung.** The code prices "a location the attacker
can already write to" at **LOW**. Plan §5.2 puts *write bytes, choose a path, rename a
file, or prefix a recognised magic value* together in **Level 0**. A path
whitelist is forged by choosing a path.

On the code's scale, LOW (1) outranks NEGLIGIBLE (0): the whitelist is more
expensive to forge than `static_entropy` is to avoid, and the suppression is
admitted. On the plan's scale both are Level 0 — a tie — and plan §5.3's strict rule
breaks the tie *against* the suppression.

Four cells flip, all in the direction plan §9.7 predicted:

| Suppression | Signal | Policy E (`>=`) | Policy F (`>`) |
|---|---|---|---|
| `path` | `ransom_extension` | cancelled | **attenuated** |
| `path` | `static_entropy` | cancelled | **attenuated** |
| `training_mode` | `ransom_extension` | cancelled | **attenuated** |
| `training_mode` | `static_entropy` | cancelled | **attenuated** |

**Under policy F the path whitelist and training mode cancel nothing at all.**

## 6.4 What this means

**The answer to a capability-governance question is a property of the scale the
question is asked on, not of the system being asked about.**

This is the result the work would defend hardest, and it deserves the strong
form. Two ladders, both reasonable, both written by the same project for the same
purpose, differing on one rung — and one decision rule comes out yes on one and
no on the other over an identical set of recorded operational facts. No new
measurement was taken between the two answers. Nothing about the system changed.

Phase 5's answer was not wrong about what it measured. It was measured against
the wrong scale, and the reason it was measured against the wrong scale is the P0
error in §4.1. The finding is a repair, and it is presented as one.

The practical consequence for anyone building such a system: **a capability level
quoted without its ladder is not a fact.** Every record in
`reports/capability_calibration.json` carries both levels, and
`scripts/admission_recompute.py` reads both from that file rather than restating
them, so the two cannot drift apart.

There is a second, less comfortable reading. A project that wants a particular
answer to a governance question can obtain it by choosing a ladder, and both
choices here look defensible in isolation. The defence against that is not a
better ladder; it is publishing the computation on every ladder in play, which is
what policies A–F are for.

## 6.5 Policy F is not deployed

Deploying it would disable two shipped mitigations, and it would invalidate every
arm of the Chapter 7 experiment, all of which were measured against the declared
table. Changing a ladder mid-experiment makes the experiment unreadable.

Neither ladder is retro-fitted to produce a preferred answer. Both are recorded,
both are computed, and the difference between them is reported as the result.

---

# 7. The experiment

## 7.1 Design

Five arms behind one policy switch, 34 attack cases in seven families, and a
frozen 275-file benign corpus — every file scored by every arm from a single
read [`scripts/three_arm_experiment.py`; `reports/three_arm_experiment.json`;
corpus tag `corpus-frozen-week21`].

| Arm | `CONTAINER_EXEMPTION_POLICY` | What it is |
|---|---|---|
| A | `legacy` | current deployed behaviour — the baseline |
| B | `off` | the exemption deleted — the null control |
| C1 | `strict-unvalidated` | exempt only formats a validator can decide |
| **C** | **`strict-unvalidated+ratio`** | **C1 plus a compression-yield clause — the predeclared repair** |
| D | `+inner` | C plus inner-content validation — chosen post-hoc |

The null control is what makes the rest interpretable. Without it, "the repair
costs 120 false positives" has no scale. With it, the question becomes whether
120 is better than the 185 you get by deleting the mitigation outright, and
whether either is tolerable at all.

## 7.2 Attack closure

| Family | A | B | C1 | **C** | D |
|---|---|---|---|---|---|
| A1 header over ciphertext (21) | 7 | 21 | 21 | **21** | 21 |
| A2 standard-library container (3) | 0 | 3 | 0 | **3** | 3 |
| A3 incomplete container (2) | 1 | 2 | 2 | **2** | 2 |
| A4 intermittent in a valid container (3) | 0 | 3 | 0 | **3** | 3 |
| A7 forged inner content (3) | 0 | 3 | 0 | **3** | 1 |
| **total flagged of 34** | **10** | **34** | **25** | **34** | **32** |

**The repair closed the evaluated bypass.** Arm C flags every attack case.

Two rows carry more than the totals do. C1 — validator coverage alone — leaves
all three standard-library container witnesses benign, because a `gzip.compress`
stream genuinely *is* a valid gzip container and a validator correctly says so.
Only the compression-yield clause closes them, which is what D4 asks and what
makes C the repair rather than C1.

And A7 shows Arm D defeated: prepending a real JPEG marker chain gets past inner
validation and Arm D drops to 1 of 3. **A family list is not a proof of
closure**, and the arm chosen after its data was visible is the one the attack
families defeat. That is not a coincidence worth glossing over.

### 7.2.1 A1 — a header over ciphertext (21 cases)

The largest family and the simplest construction: take the magic bytes of a
format, put ciphertext behind them, write the file. No encoder, no library, no
knowledge of the format past its signature. One case per recognised format, plus
second cases for GIF (`GIF87a` and `GIF89a`) and MP3 (`ID3` and a bare frame
sync), which have two distinct signatures each.

Arm A flags **7 of 21**. The seven are exactly the six formats that have a
structural validator — `zip`, `gzip`, `png`, `jpeg`, `pdf`, `iso-bmff` — plus a
second `zip` case. The fourteen it misses are exactly the formats that do not:
`rar`, `7z`, `xz`, `bzip2`, `lz4`, `zstd`, `gif` twice, `mp3` twice, `ogg`,
`flac`, `riff`.

**The split is not approximate. It is the validator registry, read back.** Every
case with `validator_present: true` returns `container_status: forged` and is
flagged on `structural_mismatch`; every case with `validator_present: false`
returns `unvalidated`, is admitted by the exemption, and comes out
`benign_compressed` at 8.0 bits/byte. There is no third outcome and no
borderline case. This is the clearest single measurement in the thesis of what
§9.5's finding costs: the detector's coverage of this family is a function of
how many validators exist, and eleven of the seventeen recognised formats have
none.

One case is worth pulling out. `a1_01_zip.bin` carries `validator_present: true`
and is still missed by Arm A, because its status is `incomplete` rather than
`forged` — a real local header with ciphertext behind it and no central
directory reached within the bounded read. **A validator that can say "I did not
finish looking" gives the attacker a third state to aim at**, and legacy policy
treats that state the way it treats a valid container. Arms B, C1, C and D all
flag it; only Arm A does not.

### 7.2.2 A2 — a genuine container the standard library produced (3 cases)

```python
gzip.compress(ciphertext)
ZipFile(p, "w", ZIP_STORED).writestr("payload.bin", ciphertext)
ZipFile(p, "w", ZIP_DEFLATED).writestr("payload.bin", ciphertext)
```

**This is the family D4 exists to ask about, and the one that separates C1 from
C.** All three are `container_status: valid`, and they are valid because they
genuinely are what they claim: a real deflate stream with a real CRC-32, a real
local header with a real central directory and a real end-of-central-directory
record. Nothing is forged. Nothing is evaded.

Arm A flags none of the three. **Arm C1 — the core repair, strict handling of
unvalidated formats — also flags none of the three**, which is the single most
useful negative in the experiment: it shows that the intuitive fix (validate
harder) does not touch this family at all, because there is nothing to catch.
The validator is asked whether this is a real gzip container, it answers
correctly, and the answer is not evidence about the content.

What closes them is the compression-yield clause: a container that declares
compression and achieves none is carrying incompressible content. Arm C flags
all three; Arm B, which deletes the exemption outright, also flags all three at
the false-positive cost §7.3 records.

`a2_zip_deflated.zip` deserves its own line. Deflate ran over ciphertext and
achieved nothing — which is what deflate does to ciphertext. The attacker paid
CPU time for no size change and got the same exemption as `ZIP_STORED`. **The
attacker gives up nothing to get the exemption**, and in the STORED case gives
up not even the CPU.

### 7.2.3 A3 — an incomplete container (2 cases)

Two structures that begin correctly and stop: `a3_png_no_iend.png`, a real IHDR
with ciphertext where the IDAT data goes and no IEND chunk; and
`a3_zip_no_central_dir.zip`, a real local file header with ciphertext and no
central directory.

The PNG case comes back `forged` and is flagged by every arm including A. The
ZIP case comes back `incomplete` and is missed by Arm A, for the same reason
`a1_01_zip.bin` is. Arm D's verdict on it is `deferred` rather than
`suspected_encryption` — the refinement declines to decide — which counts as
flagged for the closure figure but is a weaker outcome than the other arms
produce, and is recorded here rather than folded into the total.

**Two cases is a small family and it is not a coverage claim.** It is here
because the `incomplete` state was found during construction and needed a case
of its own once found.

### 7.2.4 A4 — intermittent ciphertext inside a valid container (3 cases)

A `ZIP_STORED` archive of forty 4 KiB blocks, of which 25%, 50% and 75% are
ciphertext and the rest is compressible text. Whole-file entropy comes out 5.70,
6.81 and 7.61 bits/byte respectively — the first two **below the detector's own
7.5 threshold** and the third above it.

Arm A returns `benign` for the 25% and 50% cases: not merely exempted, but
genuinely under the static threshold, because the average of ciphertext and
prose is not ciphertext. It returns `benign_compressed` for the 75% case, which
is over the threshold and exempted.

Arms C and D flag all three, the 25% and 50% cases on `partial_entropy` — the
block-level signal — and the 75% case on `static_entropy`. C1 flags none.

**This family is the argument for a block-level signal existing at all**, and it
is also the family that §5.4's base64 finding defeats: `partial_entropy` has a
per-block threshold, and a transform that puts every block at 6.000 bits/byte
passes under it everywhere at once. The two results belong together — a signal
that catches a 25% mixture and misses a uniform 6.0 encoding is not measuring
what its name suggests.

### 7.2.5 A5 and A6 — the two controls (1 case each)

`a5_naked.bin` is ciphertext with no header at all; `a6_forged_zip.zip` is a ZIP
local-header signature with no ZIP structure behind it. Both are flagged by
every arm, A included, on `static_entropy` and `structural_mismatch`
respectively.

They are in the experiment to prove the detector is not simply broken. **A
family list on which every arm flags everything proves nothing; a family list on
which the controls fire in all five arms and the interesting families do not is
a measurement.** A6 in particular is the direct counterpart of A1's fourteen
misses: the same attack against a validated format fails, and the difference
between them is the registry.

### 7.2.6 A7 — forged inner content, and the family that defeats Arm D (3 cases)

Arm D adds an inner-content appeal to Arm C: if the bytes inside a
non-yielding container look like a genuine nested format, do not flag. It is a
post-hoc refinement — designed after Arm C's benign cost was visible — and A7
exists to price it.

- `a7_gzip_naive_magic.gz`: gzip of four JPEG magic bytes and ciphertext. **Arm
  D flags it**, because four bytes are not a marker chain.
- `a7_gzip_real_jpeg_head.gz`: gzip of a genuine JPEG through its SOS marker,
  with ciphertext where the scan data goes. **Arm D returns
  `benign_compressed`.**
- `a7_zip_real_jpeg_head.zip`: the same head, ciphertext, and a genuine EOI
  marker, deflated into a ZIP. **Arm D returns `benign_compressed`.**

Arm D flags 1 of 3 where Arms B and C flag 3 of 3. The cost of the refinement is
that the appeal is itself forgeable, and forging it costs the attacker one
`open("photo.jpg","rb").read(n)` against a file they already have.

**The arm that scores best on benign cost is the arm the attacks defeat, and it
is the arm that was designed after the benign data was visible.** §10.6 treats
this as a negative result in its own right rather than as a tuning note, because
the sequence — see the cost, add a clause, score better — is exactly the shape
that produces an over-fitted result, and the only reason it is visible here is
that A7 was built to look for it.

### 7.2.7 What the family table does not establish

Thirty-four cases across seven families, all built by the same author who built
the repair. §11.7 says what that costs. Three things in particular are not
established by this table:

1. **That the families are exhaustive.** A7 was added because the inner-content
   appeal suggested its own attack; nothing guarantees a further clause would
   not have its own A8. The right reading of "Arm C flags 34 of 34" is *the
   repair closed the evaluated bypass* — the Table 9.9 wording — and not that
   the bypass class is closed.
2. **That the per-family rates generalise.** A1 has 21 cases because there are
   21 signature variants to try, not because header-over-ciphertext is six times
   as important as standard-library containment. The totals are counts of
   constructions, not weights.
3. **That flagging is stopping.** Every figure here is a `classify` verdict.
   Chapter 8 measures what happens to that verdict downstream, and finds one
   integration row where the answer is not what the pipeline's own record
   suggests.

## 7.3 Benign cost

| Arm | False positives (275) | Rate |
|---|---|---|
| A | 0 | 0.0% |
| B | 185 | 67.3% |
| C1 | 90 | 32.7% |
| **C** | **120** | **43.6%** |
| D | 90 | 32.7% |

Per stratum, Arm C against the Arm A baseline [`reports/benign_tradeoff.json`]:

| Stratum | Files | Baseline FP | Arm C FP | Difference | 95% upper limit |
|---|---|---|---|---|---|
| unvalidated × compressible | 30 | 0 | 0 | 0.0 pp | 9.503 pp |
| **unvalidated × incompressible** | **90** | **0** | **90** | **100.0 pp** | **100.0 pp** |
| validated × compressible | 60 | 0 | 0 | 0.0 pp | 4.870 pp |
| validated × incompressible | 95 | 0 | 30 | 31.579 pp | 40.312 pp |
| **validated combined (Bound 1)** | **155** | **0** | **30** | **19.355 pp** | **25.323 pp** |
| corpus-wide | 275 | 0 | 120 | 43.636 pp | 48.771 pp |

**Bound 1 fails.** The predeclared tolerance is 2.00 pp at the one-sided 95%
upper limit; the measurement is **25.323 pp**, over by a factor of twelve. Exact
McNemar on the 30 discordant pairs rejects at p ≈ 9 × 10⁻¹⁰. The effect is not
noise, and no amount of additional corpus would rescue it.

Note the two zero rows. Both compressible strata cost nothing at all. The repair
is not indiscriminate — it is precise, and it is precisely wrong about
incompressible files, which is the interesting shape of the failure.

## 7.4 D5, and why it is not a tuning problem

**D5 fires at 100.0 pp against a 15.0 pp tolerance** on the unvalidated ×
incompressible stratum — 90 false positives on 90 files — **and the figure is
identical across arms B, C1, C and D**.

That last clause is the whole point. If 100 pp were a threshold set too
aggressively, a different threshold would move it. It does not move, because it
is not a threshold effect. Eleven registry formats have no structural validator.
The moment "no validator ran" stops counting as a pass, **every genuine file in
those eleven formats flags**, whichever repair variant is running.

**The cost is not tunable because it is not a parameter.** The correct fix is a
real structural validator for rar, 7z, xz, bzip2, lz4, zstd, gif, mp3, ogg, flac
and riff — which §9.13 places outside this project's scope, so it is named as the
fix and not attempted.

## 7.5 The one branch favourable to the project

**D3 does not fire.** The null control produces a 67.3% false-positive rate
against Table 5.9's 5% corpus-wide budget — over by a factor of thirteen.

D3 asks whether the exemption is worth governing at all: if deleting it were
cheap, the right answer would be to delete it and drop the whole question. It is
not cheap. The governance layer is doing work that deleting the mitigation cannot
do, and Arm B is what establishes it.

It is worth being explicit that this is the **only** decision rule whose branch
came out favourable to the project, and that it came out favourable because a
control was run specifically to give it the chance to come out either way.

## 7.6 Latency

Detection latency is unchanged by the repair. All five arms measure within noise
of one another, interleaved per repetition with rotation so no arm benefits from
cache warmth. Twenty repetitions of seven files gives 140 samples per arm
[`reports/three_arm_experiment.json`, `latency_ms`]:

| Arm | Median | IQR | p95 |
|---|---|---|---|
| A | 3.093 ms | 0.388 ms | 5.393 ms |
| B | 3.094 ms | 0.258 ms | 4.726 ms |
| C1 | 3.075 ms | 0.173 ms | 4.481 ms |
| C | 3.085 ms | 0.175 ms | 4.949 ms |
| D | 3.083 ms | 0.374 ms | 6.543 ms |

**Arm C is 0.008 ms from the baseline at the median, in a distribution whose
interquartile range is 0.388 ms.** The arms are indistinguishable, and the
sign of the difference is not meaningful.

Two things about these digits. They are **wall-clock on one host**, so they are
excluded from the artefact's stable digest and a reader reproducing this will get
different numbers — the finding is the *shape*, five arms within noise, not the
milliseconds. And they are in-process, so they are a floor rather than a
deployment figure; §9.3's concurrent measurement is the one to read for what the
deployed path costs.

The repair is rejected on false positives, not on speed, and this measurement
exists so that nobody has to wonder which.

## 7.7 The verdict

`CONTAINER_EXEMPTION_POLICY` defaults to **`legacy`** and the repair does not
ship.

The plan's own §9 reaches the same conclusion by a different route: the repair
"is accepted only if all required rows pass", and its validated-benign row fails.
Two documents, two criteria, one answer.

`services/monitor/tests/test_tc14_unvalidated_closure.py` and
`test_tc19_benign_bound.py` assert all of this as regressions — including that
the default is still `legacy` and that the bound is still missed — so a silent
change to either fails the suite. A negative result that nothing defends decays
into a footnote; this one is defended by 42 test cases.

---

# 8. Integration: does the decision reach the hops that act on it

## 8.1 The question

A governance decision that stops at the component that made it is not governance.
If the Monitor decides a suppression is inadmissible and attenuates an alert, the
ledger must record *why*, the response service must act on the attenuated verdict
rather than the original one, and recovery must not later report a restore as
verified on the strength of a record that was never checked.

## 8.2 One record, asserted by equality

`scripts/pipeline_governance.py` drives one suspicious event through Monitor →
ML → Ledger → Response → Recovery and asserts at every hop that the record is
**the same object's content**, not a lookalike with the same shape
[`reports/pipeline_governance.json`;
`services/gateway/tests/test_tc25_full_traverse.py`].

Equality rather than shape-matching is deliberate. A shape assertion passes when
a hop reconstructs a plausible record from partial data, which is exactly the
failure mode worth catching: a downstream service that rebuilds the adjudication
from what it happens to have is not carrying the decision, it is guessing at it.

**The ML hop deliberately does not receive the adjudication.** The model scores
bytes, not policy, and feeding it a governance verdict would leak the detector's
own conclusion into a feature the model is supposed to produce independently.
That absence is asserted by TC-25 so it stays a recorded decision rather than
becoming an unnoticed gap.

## 8.3 Five fields, thirty-six blocks

§9's row 10 requires every chained mitigation decision to carry the mitigation
identifier, the validation state, the capability levels, the policy version and
the reason.

| Field | Blocks carrying it |
|---|---|
| `mitigation_id` | 36/36 |
| `validation_state` | 36/36 |
| `capability_levels` | 36/36 |
| `policy_version` | 36/36 |
| `reason` | 36/36 |

**36 of 36 blocks, 5 of 5 fields**, measured per field by
`scripts/ledger_coverage.py` [`reports/ledger_coverage.json`,
`record_completeness`].

There are **three** block types that can hold an adjudication, not two, and the
third is where this row was quietly failing. `suppression_decision` carries a
cancelled decision and `file_event` carries an attenuated one; adding the two new
fields to those left **24 of 36** blocks complete. `response_action` chains the
attenuated record a second time, and it was the other twelve. A per-field count
found it; a per-record count would not have.

## 8.4 A conclusion the evidence does not support

Before this work, a container whose validator ran and could not finish — a ZIP
with no central directory, say — was treated the same as a container that
validated cleanly. The alert was cancelled and the record said `benign_compressed`,
which claims more than the evidence carries.

Under every policy that refuses INCOMPLETE as positive proof, such a file now
returns the named verdict **`deferred`**
[`services/monitor/tests/test_tc16_incomplete_deferred.py`]. `suspicious` stays
true and the signal is unchanged, so the alert still stands and
`admissibility.py` ranks it exactly as before. What changes is that the record
stops asserting a conclusion.

Two design choices in that are worth stating, because both were close calls:

**It is gated on INCOMPLETE, not on the tri-state's `None`.** UNVALIDATED is a
different answer — *no validator exists for this format* — and calling both
`deferred` would hide an eleven-format coverage gap behind a word that sounds
temporary.

**It is deliberately not extended to `legacy`.** The legacy policy exempts an
incomplete container on its header alone. That is the silent cancellation the row
forbids, it is what Arm A measured, and rewriting it now would change a baseline
after the fact.

## 8.5 The rest of the integration rows

| Row | Requirement | Measured |
|---|---|---|
| 8 | 13-family sweep, no regression | **13/13** within 2 s, all restores true, under the default policy *and* under Arm C |
| 9 | ML preservation | 48/48 ml-engine tests; the adjudication is withheld by design and recorded |
| 11 | Response preservation | attenuated population reaches `/response/trigger` **6/6**, record intact; isolation reports `enforced: false` explicitly with the rules it would have applied |
| 12 | Recovery preservation | **13/13** local restore round-trips; 5/5 injections, none reported as verified. **VSS-backed restore not measured** |
| 13 | Tamper handling | detected and named to the block; 32/32 tamper and chain tests |
| 14 | Safety | all restore round-trips true across both sweeps |

Row 12 is the only integration row still partial, and Chapter 11 says what it
would take to close.

## 8.6 The hop matrix, three populations by six hops

`scripts/pipeline_governance.py` drives real `handle_event`, the real pipeline
and a real `RecoveryManager`. **Only the network transport is replaced, and it
records rather than answers**, so every payload a service would have received is
captured and can be inspected for whether the governance record travelled with
it. The deferred population holds a genuine exclusive Win32 handle rather than a
simulated one.

Three populations of six events each — a *cancelled* decision (a hash-whitelist
suppression that was admitted), an *attenuated* one, and a *deferred* one — and
the payloads each produced:

| Hop | cancelled | attenuated | deferred |
|---|---|---|---|
| `monitor_event` | 6/6 | 6/6 | 0/6 |
| `ml_predict` | — | 0/6 | — |
| `ledger_file_event` | — | 6/6 | — |
| `ledger_suppression_decision` | **6/6** | — | — |
| `response_trigger` | — | 6/6 | — |
| `ledger_response_action` | — | 6/6 | — |

`n/m` is *payloads carrying an intact governance record* over *payloads sent*; a
dash means the hop did not occur for that population, which for most of these is
the correct behaviour rather than a gap.

**Read the rows, not the totals.** Three of them say something the summary
does not.

**`ml_predict` is 0 of 6 and that is correct.** The ML request carries the
feature vector and nothing else. The model scores bytes; handing it the
adjudication would let a suppression move a prediction, which is the failure
mode the separation exists to prevent. The report records this as *not carrying
the record* with a note saying why, rather than as a pass — because the honest
statement is that **the record does not literally traverse this hop**, and a
reader deserves to see the one hop where the answer is "by design" written as
such rather than folded into a green count.

**A cancelled decision produces no file event and no response trigger.** That is
what cancelling means: the alert is suppressed, so nothing downstream acts. What
it *does* produce is `ledger_suppression_decision`, 6 of 6 — **the suppression
itself is chained**. That row is finding S-11 closed: before this work a
cancelled suppression left no chained record at all, so the audit log recorded
the alerts that fired and was silent about the ones that were suppressed. An
audit log that only records what happened, and not what was decided not to
happen, is not an audit log of the decisions.

**The deferred population reaches no hop at all — 0 of 6 at `monitor_event`.**
The file is held under an exclusive Win32 handle, `open_for_read` exhausts its
40 ms retry budget, and the event is not classified. This is not a governance
failure and it is not a bug; it is the read-retry budget of §3.2 doing what it
is for. It is in the table because **a population that produces no payloads
would otherwise be invisible**, and the difference between "the record did not
travel" and "there was nothing to travel" is exactly the difference this chapter
exists to measure.

## 8.7 Recovery, the dashboard, and D6

Two hops sit outside the six-by-three grid.

**Recovery.** One payload, carrying the record intact, and carrying the incident
identifier the decision belongs to — so a restore can be attributed to the
adjudication that authorised it rather than merely coinciding with it. The
recovery itself returned `status: success` with one file restored.

**`integrity_verified` is false on that restore, and the reason is worth
stating.** The manager had no expected hash to compare against — `expected_hash`
is null — so it restored the file and declined to claim it verified the result.
That is the correct behaviour and it is also a limit: **the recovery hop proves
the record reaches recovery, not that recovery is correct.** §11.5 says what the
recovery claim rests on, which is the thirteen simulator round-trips and not
this hop.

**The dashboard.** `GOVERNANCE_OUTCOMES`, `governance_outcome` and
`governance_chip` are lifted from `services/dashboard/app.py` by AST and
executed, so what is measured is the deployed code rather than a description of
it. Three outcomes read back distinctly, three display labels are distinct,
three chips render, and `no_rule_applied` reads back as `None` rather than
collapsing into one of the three. One check is separate and deliberate:
`cancelled_is_not_read_from_suspicious` — the dashboard must derive "cancelled"
from the governance outcome and not from the suspicion flag, because those two
agree in the common case and diverge in exactly the case that matters.

**D6 does not fire.** All six gates pass: the adjudication reaches the chain for
a cancelled decision and for an attenuated one, travels to the Response service
and into its own chained entry, reaches recovery with the incident it answers,
and the dashboard tells the three outcomes apart.

The wording that follows is narrow and it is the wording used: **in the evaluated
URDS pipeline, the governance decision reaches the hops that act on it.** Not
that the pipeline is verified end to end — the transport is in-process (§11.3),
the ML hop does not receive the record by design, and one population never
produced a payload to begin with.


---

# 9. What this system does not stop

Eleven findings, each built and run [`docs/SECURITY_AUDIT.md`]. Nine are open.
Two were found and closed by this work.

| # | Finding | Attacker cost | Status |
|---|---|---|---|
| S-1 | `base64.b64encode` defeats all three entropy signals at once | one standard-library call, +33% size | **open** |
| S-2 | Eleven of seventeen registry formats have no structural validator | four bytes | **open**, §9.13 |
| S-3 | The chain does not detect a re-chained, truncated or appended ledger | database write access | **open by design**, §9.13 |
| S-4 | The container exemption is outside the governance layer entirely | four bytes | **open**, the subject of Chapter 7 |
| S-5 | Detection latency exceeds its budget at p99 under concurrency | none — a busy machine does it | **open**, measured |
| S-6 | The fan-out queue is unbounded; the Monitor outruns it 18.7:1 | write files quickly | **open**, measured |
| S-7 | `_SEEN_FILES` grows without bound | one distinct path at a time | **open**, measured, small constant |
| S-8 | Two deployed suppressions are not cost-justified on the plan's ladder | already available to the attacker | **open**, measured |
| S-9 | Snapshot-backed restoration is unverified | — | **not measured**, needs elevation |
| S-10 | A pasted container header defeated the detector entirely | four bytes | **closed** |
| S-11 | A cancelled suppression never reached the ledger | — | **closed** |

Three deserve their own treatment.

## 9.1 The ledger detects edits, not rewrites

`scripts/tamper_sweep.py` runs 28 cases — every tamper shape at every position,
applied through SQL directly to the database, then verified from a *fresh*
`HashChainLedger` so no in-memory state can hide the damage
[`reports/tamper_sweep.json`; `services/ledger/tests/test_tamper_sweep.py`].

**In-place tampering: 20 of 20 detected.** A column rewritten, an interior row's
payload swapped with another's, a hash altered — every shape at first, middle and
last position. This is the "injected ledger-tamper cases failing verification
100% of the time" that Table 9.8 requires, and it is met.

**Structural tampering: 0 of 8 detected, and none of them can be.**

| Shape | Position | What it is |
|---|---|---|
| `append_forged_block` | last | a block appended with a correctly computed hash |
| `delete_block` | last | the newest row deleted |
| `truncate_tail` | last | the last *k* rows removed |
| `rechain_from` | any | one block rewritten and every hash after it recomputed |

The chain is **unkeyed SHA-256 over public inputs**. Every input to every hash is
in the database, so anyone who can write the database can recompute exactly what
the verifier will recompute. There is no secret separating the attacker from the
verifier, and without one there is nothing to detect.

**"Tamper-evident" here means tamper-evident against an attacker who does not
recompute.** That is a real property and a useful one — it catches corruption,
accidental edits and an unsophisticated attacker — but it is not the property the
phrase usually implies, and the thesis states which.

Closing it needs a signing key the attacker cannot reach, or an external anchor.
§9.13 places blockchain anchoring out of scope, so it is named as the fix and not
attempted. The four undetected shapes are asserted **as undetected** in the
regression suite, so the boundary cannot move without a test failing.

## 9.2 The Monitor outruns its own audit trail

`scripts/load_test.py` produces events for 8 seconds and samples the fan-out
queue [`reports/load_test.json`]:

| | |
|---|---|
| Events produced in 8 s | 1,723 |
| Production rate | 215.4 / s |
| Peak `app._work` depth | **1,631** |
| Cleared by the worker | 92 |
| **Produce-to-drain ratio** | **18.7 : 1** |
| `queue.Queue` maxsize | **0 — unbounded** |
| Backlog grew monotonically | yes |
| Projected drain at measured latency | 97.9 s |

**The backlog grows fastest during exactly the burst it exists to record**, and
every queued item is a ledger write that has not happened. A ransomware event
storm is the scenario in which the audit trail is most valuable and the scenario
in which it lags furthest behind.

**Nothing was fixed.** Bounding the queue is the obvious move and the obvious
implementation is wrong: dropping on overflow discards the governance records
that `pipeline.log_governance_decision` exists to preserve, which converts a
latency problem into an evidence problem. The defensible shape is a bounded queue
whose overflow is *itself* recorded — a different change, needing its own design
and its own measurement, and this project measured rather than guessed.

Alongside it, `_SEEN_FILES` costs 214.3 bytes per distinct path and never
shrinks. The constant is small and the growth is unbounded; on a long-lived
monitor watching a large tree, that matters eventually.

## 9.3 The latency budget holds at p95 and misses at p99

| Measure | Value |
|---|---|
| Events | 1,200 at 16-way concurrency |
| Median | 61.279 ms |
| p95 | **94.650 ms** — within the 100 ms budget |
| p99 | **110.550 ms** — outside it |
| Max | 131.560 ms |
| Over budget | 36 of 1,200 |
| Single-file benchmark, p95 | 25.764 ms |

The single-file benchmark is 3.7× faster than the concurrent p95, which is the
ordinary shape of a contended measurement and is exactly why the concurrent one
was taken.

**The wording that follows from this is "within 100 ms at p95 under 16-way
concurrency", never "under 100 ms".** The second sentence is what a reader would
infer from the single-file benchmark alone, and it is not true of 36 events in
1,200.

The run completed 1,200 events in 4.767 s at 251.8 events/s with zero errors
[`reports/load_test.json`], so the excess is latency and not failure. The number
that matters operationally is 36: thirty-six events over budget on a fourteen-core
host running nothing else, and a ransomware run is by construction a burst of file
writes. **The attacker does not have to do anything to trigger this** - a busy
machine does it - which is why S-5's attacker cost is recorded as "none".

Two qualifications, both against the project's interest. The measurement is
in-process, so it excludes HTTP, serialisation and the fan-out §9.2 finds
unbounded; the deployed number is worse than this one, and this figure is a
floor rather than an estimate. And a p99 of 110.55 ms against a 100 ms budget is
a miss by 10.6%, which is a real result and not a catastrophe. It is reported as
measured rather than dramatised.

## 9.4 The two findings this work closed

**S-10 — a pasted container header defeated the detector entirely.** Writing four
bytes in front of ciphertext produced `benign_compressed` for eleven of seventeen
formats. Closed under Arm C, which flags 21 of 21 A1 witnesses — but Arm C does
not ship, so what is closed is the *evaluated* bypass under a policy that is not
the default. The honest status is that the repair exists, is tested, and is off.

**S-11 — a cancelled suppression never reached the ledger.** A decision to cancel
an alert produced no chained record. Closed: 36 of 36 blocks now carry all five
required fields, measured per field.

## 9.5 S-2: the registry is larger than the validator registry

`containers.identify_container` recognises **seventeen** formats. `_VALIDATORS`
holds structural validators for **six** of them.

| Recognised and validated (6) | Recognised, no validator (11) |
|---|---|
| `zip`, `gzip`, `png`, `jpeg`, `pdf`, `iso-bmff` | `rar`, `7z`, `xz`, `bzip2`, `lz4`, `zstd`, `gif`, `mp3`, `ogg`, `flac`, `riff` |

The gap is not a bug in either registry. Recognition needs a signature;
validation needs a parser. A signature is a constant and a parser is a project,
so the recognition table grew and the validator table did not — which is the
ordinary way this gap opens in any system that has both.

What makes it a security finding rather than a backlog item is what the
detector does with the difference. `validate_container` returns `None` for an
unrecognised-by-the-validator format, and the legacy exemption treats `None` the
way it treats `VALID`: it admits. **So the eleven formats with no validator are
eleven formats where four bytes of signature buy an exemption**, and §7.2.1
measures it exactly — fourteen of twenty-one A1 cases missed by Arm A, and the
fourteen are precisely the unvalidated ones.

Three things follow that are worth separating.

First, **the finding scales with recognition, not with validation.** Adding a
signature for a new format without adding its parser makes the system strictly
weaker than not recognising the format at all, because an unrecognised format
falls through to `static_entropy` and is flagged. This is a genuine perverse
incentive in the current design and it is not signposted anywhere in the code.

Second, **§9.13 puts writing the eleven validators out of scope**, and this
thesis does not write them. That is a scope decision and not a judgement that
they would not work; §12.3 lists it first under future work, with the estimate
that `bzip2`, `xz` and `gif` are each a bounded parser of a few dozen lines and
that `mp3`, `ogg` and `flac` are frame-walkers of similar size.

Third — and this is the part the calibration adds — **a validator would not close
A2.** §7.2.2 measures Arm C1, which is exactly "strict handling of unvalidated
formats", and it flags none of the three standard-library witnesses. Writing
eleven validators closes S-2 and leaves S-4 untouched. The two findings look
adjacent and are not.

## 9.6 S-7: `_SEEN_FILES` grows and nothing shrinks it

`_SEEN_FILES` answers one question — "is this the first time this path has been
seen?" — which gates one ledger baseline write per path per Monitor run. It is a
plain `set` and nothing removes from it.

Probing 20,000 synthetic paths [`reports/load_test.json`]:

| Quantity | Measured |
|---|---|
| entries probed | 20,000 |
| set container | 2,097,368 bytes |
| the strings themselves | 2,188,890 bytes |
| total | 4,286,258 bytes |
| **per path** | **214.3 bytes** |
| the running Monitor's set, at measurement | 2,923 entries |

**214 bytes per distinct path, unbounded.** A million distinct paths is roughly
204 MiB in one process; ten million is 2 GiB. Neither is an implausible number
for a file server, and the attacker's cost is "touch one distinct path at a
time", which is what encrypting a filesystem consists of.

This is the smallest of the eleven findings and it is included for a reason that
is methodological rather than operational. **It is a growth curve with a small
constant, and small constants are how unbounded growth stays invisible** — at
2,923 entries the set was 626 KB and nothing about the running system suggested
a problem. It was found by probing rather than by observing, and it would not
have been found by watching the service run.

The bound that would fix it is not free: evicting a path means the next write to
it is treated as a first sighting and writes a second baseline. The correct fix
is a bounded LRU with a documented eviction cost, and it is not written here.

## 9.7 S-8: two deployed suppressions are not cost-justified

Chapter 6 derives this in full; it appears in the findings table because it is a
security property and not only a methodological one.

The whitelist path rule and training mode both suppress alerts, both are
deployed, and both are keyed on something the attacker already controls — the
path a file is written to, and the events observed during a learning window.
On the code's four-point ladder each costs LOW to forge against NEGLIGIBLE to
avoid, and 1 > 0 admits them. On `NOVELTY_PROOF_PLAN.md` §5.2's five-level
ladder both cost **Level 0, direct attacker control**, the strict rule refuses
the tie, and both are attenuated rather than admitted.

**Which answer is right is a question about the ladder, not about the code**, and
§6.4 is about what that means for a governance layer whose output depends on a
scale nobody was asked to ratify. The security statement, independent of which
ladder wins, is this: **two suppressions that are on by default take their key
from attacker-supplied data**, and the only mitigation in the system that does
not — the hash whitelist, Level 4 — is the only one an attacker cannot arrange
to satisfy.

## 9.8 S-9: snapshot-backed restoration is not measured

`NOVELTY_PROOF_PLAN.md` §9 row 12 asks for snapshot-backed restoration.
`scripts/verify_vss.py --status-only` records what could be established
[`reports/vss_status.json`]:

| Field | Value |
|---|---|
| supported | true |
| platform | Windows 10.0.26200, client edition |
| backend | `wmi:Win32_ShadowCopy` |
| elevated | **false** |
| `list_snapshots` | refused — `VSSError` after 0.055 s |
| `create_snapshot` | refused — `SnapshotCreationError` |
| acceptance check run | **false** |
| blocker | elevation |

**Nothing here creates a snapshot or restores from one, and the report says so
in its own `what_this_does_not_show` field.** What is established is narrow and
worth stating precisely: the host reports VSS as supported, the code reaches the
VSS backend, and both operations refuse for one stated reason — the process is
not elevated. The gap in row 12 is therefore a shell privilege and not an
unmeasured capability, and it is the one acceptance row in the whole plan that
this thesis reports as **not measured** rather than as measured-and-failed.

§11.4 says what that costs the recovery claim. The short version: every restore
figure in this thesis comes from the file-copy path in
`services/response`, thirteen of thirteen simulator families round-trip through
it, and none of that is evidence about VSS.

---

# 10. Negative results

Plan §9.4 requires these collected in one place rather than distributed through the
chapters where they are least visible. This is the most useful chapter in the
thesis for anyone building something similar.

## 10.1 The repair does not ship

The central negative result. A repair was predeclared, built behind a policy
switch, and evaluated in five arms. It closes every attack family built for it
and its measured benign cost exceeds a bound declared before the corpus existed —
**25.323 pp against 2.00**, and **100.0 pp against 15.0** on the stratum where it
hurts most.

The temptation at that point is to move the threshold until the bound passes. The
bound was committed and tagged before the corpus was built precisely so that this
temptation would have to be acted on visibly. It was not acted on.
`CONTAINER_EXEMPTION_POLICY` still defaults to `legacy`, which is the pre-repair
behaviour, and 42 test cases assert that it does.

**What it cost to report this honestly:** the project's headline result is a
mechanism that was not fixed.

## 10.2 D1's answer reversed

Phase 5 answered D1 "no cells flip" and published it. The answer was correct on
the ladder Phase 5 used and wrong on the ladder the governing document makes
authoritative. Four cells flip; two deployed mitigations are not cost-justified.

This is a negative result about the project's own earlier reporting, and it is
recorded as one rather than quietly folded into a revision. Phase 5's completion
report retains its original figure with the date it was superseded — Appendix D.

## 10.3 The cost table was wrong in five of ten places, always in one direction

Five of the ten calibrated strategies came out cheaper than declared, and **not
one came out more expensive.** A cost table written by an author estimating
attacks they have not built is not merely noisy — it is biased high, and
consistently so.

The most expensive error was pricing `partial_entropy` avoidance at moderate when
`base64.b64encode` does it. The most consequential was pricing
`C_forge(ml_confidence_gate)` at high when holding a model's score below a
threshold turns out to be negligible.

## 10.4 The exemption bypasses governance, and nobody decided that

The container exemption never reaches `admissibility.adjudicate` — 0 of 12
adjudications where the comparable populations produce 12 of 12. The cause is not
a design position anyone took. It is an ordering: `handle_event` adjudicates a
verdict that is already suspicious, and the exemption's whole effect is to make
the verdict not suspicious first.

**A governance layer that is not on the path is not a governance layer.** No
review caught it, and no test failed, because nothing asserted that the layer was
reached.

## 10.5 Structural rewriting of the ledger is undetectable

0 of 8. Not "hard to detect": undetectable, by construction, for an unkeyed chain
over public inputs. The project's own earlier language described the ledger as
tamper-evident without qualification.

## 10.6 Arm D looks best and is the one the attacks defeat

Arm D removes the 30 validated-format false positives and would clear Bound 1.
It is not claimed, on two grounds: it was chosen after its own benign numbers
were visible, and attack family A7 defeats it 2 of 3 by prepending a real JPEG
marker chain.

**The variant that looks best on the benign corpus is the variant the attacks
beat.** That is the shape of a post-hoc choice, and it is why the conservative
reading was kept even after plan §7.1 turned out to have predeclared the variant.

## 10.7 The single-process test suite does not work

Running one pytest process over `services/` produces 19 failures and 113
collection errors. The five services use flat module names matching their
container layout — each has an `app.py`, two have a `main.py` — so one process
imports whichever module reached `sys.path` first and every later service tests
the wrong code.

Recorded because a reader who tries the obvious command will see a wall of red
and conclude the suite is broken. It is not; the command is.

## 10.8 What the reproducibility gate found in this project's own work

The Week 32 exit gate asks that an independent reader be able to reproduce every
headline figure from the repository and the appendix alone, and it says to
verify this **by actually re-running the appendix commands from a clean
checkout, not by inspection**. `scripts/verify_reproduction.py` does that: it
clones the repository at HEAD into a scratch directory, installs each service's
declared dependencies into a fresh virtual environment, rebuilds the corpus from
its seed, regenerates every artefact, compares every stable digest, re-checks
every claim, and runs all five test suites.

**It took six runs to pass.** Five of the six failed. One failed on a Windows
path-length obstacle that is not a defect in this repository; the other four
failed on **ten defects in this project's own work, every one of which meant a
reader could not have reproduced a figure this thesis quotes.**

### 10.8.1 Ten defects and one obstacle

**Run 1 — the scratch path.** `pip install` of scikit-learn failed with
`OSError: [Errno 2]` on a `.lib` file inside
`_pairwise_distances_reduction`: a Windows `MAX_PATH` overflow, because the
scratch directory was deep and the package's own paths are long. Not a defect in
the repository, but a real obstacle for a reader on Windows, and the appendix
now says to use a short scratch root.

**Run 2 — three defects.**

1. **`Pillow` was undeclared.** The corpus builder imports PIL. It was installed
   on the author's machine and declared in no requirements file, so a clean
   checkout fails the corpus rebuild — and every benign-cost figure is
   downstream of that rebuild.
2. **`capability_calibration.py` crashed on every clean checkout.** The
   `ml_confidence_gate` strategy returns a short record when the trained model is
   absent, and the summary builder indexed a key that record does not have.
   `models/` is gitignored, so this was the guaranteed path, not the rare one.
3. **"10 of 10 empirical" needs a gitignored model.** On a clean checkout it is 9
   of 10, with one level recorded unresolved under D2. The claim as originally
   worded was not reproducible by anyone but its author.

**Run 3 — three more.**

4. **`fpdf2` and `scipy` were undeclared.** scipy had been working only as a
   transitive dependency of scikit-learn, which is the kind of thing that holds
   until a version bump.
5. **`admission_recompute.py` raised `KeyError: 'cost_table_key'`** on the same
   short no-model record. The first fix had patched one consumer of it.
6. **Claim C-04's check was testing the wrong thing.** The claim is about the
   container exemption's measured cost; the check read the model-dependent
   coverage counter. It passed for two weeks because both were true. The check
   now reads `levels[0].measured_name`, and the coverage figure became C-15 with
   its own expectation.

**Run 4 — the one that mattered.**

7. **The appendix's own corpus command built the wrong corpus.**
   `build_benign_corpus.py` defaulted to `--per-cell 8`. The corpus every benign
   figure in this thesis is about has 275 files and was built with 15. **The
   appendix said `python scripts/build_benign_corpus.py`, that command ran
   without error, and it produced a 149-file corpus.** Downstream,
   `bound_2.stratum_files` came out 48 where the thesis says 90, and Bound 1 came
   out 27.1752 pp where the thesis says 25.3235 pp. Five monitor tests failed on
   the changed numbers, which is the system working — but `--verify` passed,
   because it read `per_cell` back from the manifest it had just overwritten.
8. **Three unpinned `gzip.compress` timestamps** in the attack builder, so three
   witness SHA-256s changed on every run and their recorded hashes could not be
   checked by anyone.
9. **Two fields declared volatile were never actually excluded.** The digest
   stripped declared names at the top level only, and `detection_seconds` and
   `collateral_events_flagged` live inside `results[i]`. **A declaration that does
   not take effect is worse than no declaration, because it reads as a decision
   that was made.**

**Run 5 — one left.**

10. **TC-22 failed on every clean checkout.** It asserted
    `monitor_floor_makes_gate_unreachable` on the ML gate's calibration record, a
    key that exists only when there is a model to measure against.

**Run 6 passed.** 27 stages, 0 failed; every deterministic artefact matched its
recorded digest, every claim re-checked, and 659 tests passed with 21 skipped and
none failed.

### 10.8.2 What the pattern is

Nine of the ten defects share a shape: **something was true on the
author's machine and was not true anywhere else.** A package installed years ago
for another project; an artefact that exists locally and is gitignored; a
default that had drifted away from the value the measured artefact was built
with; a timestamp that only varies if you run the thing twice.

None of these is a mistake of reasoning and none would have been caught by
review. Three appeared within ninety seconds of executing the appendix. The
corpus defect is the one to dwell on, because it is the case where **a document
that was accurate, a command that ran, and an exit status of zero together
produced the wrong number** — and the only thing that separated a reader from
quoting 27.1752 pp as this thesis's Bound 1 was that somebody ran it.

**An appendix that is written and not run is a description of a reproduction,
not a reproduction.** That is a finding about method, it applies to work far
outside this project, and it is the one result here that was not planned for.

### 10.8.3 What the gate still does not establish

It runs on one host, on Windows, on the author's machine. It does not establish
that the appendix works on Linux, that it works for someone who is not the
author, or that the two `--per-cell`-style defects were the last of their kind —
run 4 found one after three runs had passed the stages around it. And it does
not close §10.10: **no CI run has been observed**, so nothing has executed this
on a machine the author does not control.

## 10.9 The reproduction ring was not achieved

§9.15 sets the ring AS↔NI and SI↔SH, with the reproducing member recording their
result before seeing the original conclusion. **It did not happen.** Every
capability level was derived twice in opposite orders over the same recorded
facts — which is the protocol — but by one author in one session.

Every record carries `reproduction.independent_human_reviewer: false`. Nothing in
this repository claims independent human reproduction, and the Excellence-tier
criterion "all capability levels independently reproduced by a second member" is
**not met**.

## 10.10 No CI run has been observed

`.github/workflows/tests.yml` exists, defines a five-service matrix and an
acceptance-rows job, and **has never executed on a runner.** The Week 28 gate
asks for a green suite in CI from a clean checkout; the clean-checkout half is
met and measured, and the CI half is open. No badge is claimed.

---

# 11. Limitations

Required by §9.12 and deliberately long. Every limitation names what it would
take to remove.

## 11.1 The corpus is synthetic

275 procedurally generated files from seed `20260902`, stratified by validator
coverage and compressibility, byte-identically reproducible and hash-verified.
**It is not a sample of anyone's real filesystem.**

Every false-positive figure in this thesis — 0, 185, 90, 120, 90 — is a figure
about this corpus. Real filesystems differ in format mix, file size distribution
and how many files sit near the entropy ceiling for benign reasons. A corpus with
more compressible archives would make the repair look better; one with more media
files would make it look worse.

**To remove:** a real, consented filesystem sample, stratified the same way, with
the same per-file hashing so it can be re-run. That is a data-collection problem
with a privacy dimension, not an engineering one.

## 11.2 One reviewer, and the ring was not achieved

Covered in §10.9. The narrower statement: **the derivation protocol was followed
and the human independence was not.**

Two derivations in opposite decision orders catch a derivation error. They cannot
catch a wrong operational fact, because both derivations read the same recorded
facts. If a strategy's `format_specific_knowledge: false` is wrong, both
derivations are wrong together and both agree.

**To remove:** a second person builds the ten attacks independently and records
their levels before seeing these. It is a week of one other person's time.

## 11.3 In-process measurement

Every measurement in this thesis runs in a single Python process against imported
modules. **The Compose stack was not measured.** The network between containers,
container scheduling, a real filesystem under real load and the ledger's SQLite
under concurrent writers are all unmeasured.

The latency figures are therefore lower bounds on what a deployment would see,
and the queue-growth figure is a figure about one process's queue rather than
about a distributed backlog.

**To remove:** a running Docker daemon and a load generator outside it. The
`docker-compose.yml` exists and `docs/DEMONSTRATION_SCRIPT.md` has the runbook;
no recorded run had a daemon.

## 11.4 VSS-backed recovery is not measured

Local snapshot restore verifies 13 of 13. **Snapshot-backed restore through the
Volume Shadow Copy Service is not measured at all.**

The blocker is measured rather than asserted, which is the only improvement this
work made to that row: `reports/vss_status.json` records the host reporting VSS
`supported: true`, backend `wmi:Win32_ShadowCopy`, `elevated: false`, and both
`list_snapshots` and `create_snapshot` refusing with an explicit elevation error.
So the gap is a shell privilege, not a capability nobody exercised — and "not
measured" alone does not distinguish those two.

**To remove:** an Administrator shell on a Windows host. Ten minutes, and it is
the single cheapest open item in this thesis.

## 11.5 Monitor-scoped, where recovery is concerned

§9's closing note says that if any integration row is deferred, the final claim
must say "Monitor-scoped". Rows 9, 10, 11, 13 and 14 pass outright. Row 12 is
**partial, not deferred** — measured, with the missing half named and its blocker
recorded.

A reader taking the strictest reading should attach *local snapshots* to the
recovery claim specifically, rather than reducing the whole claim to Monitor
scope. The ML, ledger and response rows are no longer what holds it back.

## 11.6 One headline figure needs a gitignored artefact

"10 of 10 capability levels carry an empirical source trail" requires
`models/behavioral_model.pkl`. `models/` is gitignored — the file is a trained
model, and committing it would put a large binary in the repository whose
provenance is EMBER, which is not redistributable this way.

On a clean checkout the figure is **9 of 10, with `C_forge(ml_confidence_gate)`
recorded unresolved under D2.** That is D2 working as designed rather than a
failure, but a reader cannot reproduce the ten.

**To remove:** either commit the model, or make the strategy measurable against a
synthetic model shipped for the purpose. The second is better and was not done.

## 11.7 The attack families were built by the author of the repair

Seven families, 34 witnesses, all written by the same person who wrote the repair
they test. The repair closes all of them, which is a weaker statement than it
sounds.

Family A7 is the partial defence: it was built specifically to defeat Arm D and
does, 2 of 3. But a family built to defeat one arm by its author is still not an
adversary.

**To remove:** an independent red-team pass, or a public bounty on the deployed
policy. Neither was in scope.

## 11.8 A methodological result, not a better detector

Nothing here makes URDS detect more ransomware. The repair that would have closed
a bypass does not ship. **Ransomware detection improved generally is not
claimed**, no external-detector comparison was run, and nothing here is claimed
to generalise beyond URDS.

## 11.9 The P0 error

Phases 5 and 6 were carried out believing the governing method document did not
exist. It does. `docs/METHOD_DOCUMENT_STATUS.md` records the error, how it was
found and what it cost.

The largest single item is that D1 was answered on the wrong ladder and reversed
when asked again on the right one. Two smaller ones: plan §5.3's strict rule was
measured but not adopted until P6.8, and Arm D was described as post-hoc when
plan §7.1 had in fact predeclared the variant.

**The error is not presented as a happy accident.** It cost two phases of
misdirected work, and the reason the strongest result exists is that the error was
caught before submission rather than after.

## 11.10 89.1% of the studied commits are AI-assisted

82 of the 92 commits on the studied branch carry a `Co-Authored-By: Claude`
trailer. The figure is in `PROJECT_IMPLEMENTATION_RECORD.md` and is repeated here
because a limitations chapter that omitted it would be incomplete.

What mitigates it is the evidence discipline rather than any claim about the
assistant: every number in this thesis comes from a script a reader can run, and
`scripts/claim_matrix.py` re-checks every claim against its artefact. Assertion
is cheap regardless of who is asserting, which is why the project was built so
that assertion is not the currency.

---

# 12. Conclusion and future work

## 12.1 What was found

The project team designed and implemented a six-service ransomware detection and
recovery system. This work examined one mechanism inside it and found four things.

**In the reviewed URDS Monitor, the most-used evidence-cancelling path never
reaches the layer that exists to price evidence-cancelling paths.** Not by
decision — by ordering.

**Under the declared capability model, forging that path is negligible-cost**:
four bytes for eleven of seventeen formats, one standard-library call for the
rest. Ten strategies were built and run; five came out cheaper than declared and
none came out dearer. The cheapest defeats all three entropy signals at once with
`base64.b64encode`.

**A repair closes the evaluated bypass and is rejected on measured benign cost** —
25.323 pp against a predeclared 2.00, and 100.0 pp against 15.0 on the stratum
where eleven formats have no validator. It does not ship, and the reason it
cannot be tuned into shipping is that the cost is not a parameter.

**And the answer to the governance question depends on the ladder it is asked
on.** One decision rule, one set of recorded facts, two scales differing by one
rung, opposite answers.

## 12.2 What that is worth

The method is the contribution, in four parts:

1. **Pricing a false-positive mitigation against the signal it cancels**, with
   every price built and run rather than assigned.
2. **The two-ladder finding** — that a capability level quoted without its ladder
   is not a fact, demonstrated rather than argued.
3. **A repair reported as rejected**, with the bound predeclared and tagged
   before the corpus existed so that the rejection could not be negotiated.
4. **An audit trail carried to every hop that acts on it**, with a measured
   statement of what it is and is not evidence of — including that it does not
   detect a rewrite.

None of this makes a better ransomware detector, and that is not claimed.

## 12.3 Future work

In the order the evidence says they matter.

**Write the eleven validators.** rar, 7z, xz, bzip2, lz4, zstd, gif, mp3, ogg,
flac, riff. This is the single change that would make the repair shippable,
because it is the only thing that moves the 100 pp stratum. §9.13 put it out of
scope for this project; nothing puts it out of scope for the next.

**Measure a counter to the base64 attack before proposing one.** The obvious
detector — printable content that decodes to high entropy — must be measured
against PEM files, `.eml` attachments, JWTs, data URIs and embedded images before
it is a proposal rather than a guess. That measurement is a corpus problem and it
is tractable.

**Give the chain a secret or an anchor.** An HMAC with a key the monitor cannot
read, or periodic anchoring to an external append-only store. Either turns "does
not recompute" into a real adversary bound. §9.13 excluded blockchain anchoring
specifically; a signing key is not excluded and is simpler.

**Bound the queue, and record the overflow.** Not by dropping — by recording that
a drop occurred, which keeps the audit trail honest about its own gaps.

**Ask D1 on a third ladder.** The two-ladder finding invites the obvious
follow-up: is there a ladder on which the question is stable? If capability
levels are this sensitive to scale definition, a scale designed for stability —
rather than for description — would be worth having.

**Achieve the reproduction ring.** A second person, ten attacks, a week.

**Run the CI.** One pull request.

---

# Appendix A — Authorship record

The full record is `PROJECT_IMPLEMENTATION_RECORD.md`, generated from git by
`scripts/implementation_record.py`. Summarised:

| | Contributor | Commits on `HEAD` | Files first authored | Active |
|---|---|---|---|---|
| NI | nikhil-k3312 | 72 | 116 | 2026-08-05 → 2026-09-05 |
| SH | Shashank V S | 12 | 65 | 2026-02-01 → 2026-08-25 |
| AS | apekshashetty22 | 5 | 0 | 2026-07-19 → 2026-08-06 |
| SI | siddhi subhash gaikwad | 3 | 21 | 2026-08-06 |

92 commits on `HEAD`, 98 across all refs, 209 tracked files, four contributors,
every one verified against §9.15's `feature/<INITIALS>-<topic>` branch convention.

**The contribution is lopsided** — 72 of 92 commits by one contributor, all after
5 August 2026 — and **82 of 92 commits (89.1%) carry a `Co-Authored-By: Claude`
trailer.** Both figures are published rather than inferred. The ten without the
trailer are all five of AS's, four of SH's and one of NI's, which means the
monitor's entropy, magic-byte and watchdog primitives and the trained model are
hand-written and the measurement layer above them largely is not.

# Appendix B — Reproducibility

`docs/REPRODUCIBILITY_APPENDIX.md` carries the exact commands, the seeds and the
artefact hashes. `reports/reproduction_check.json` carries the result of running
them from a clean checkout, which is the Week 32 gate.

Two seeds: the corpus at `20260902`, and fixed per-family keystreams in the
simulator. Nothing that produces a recorded figure calls `os.urandom`.

Two digests per artefact: `sha256` over the committed bytes, and `stable_sha256`
over the JSON with volatile fields removed. The second is what a reproducer
compares, because no artefact in this repository is byte-identical across runs —
every report carries `generated_at`.

Three reproduction classes: `deterministic` (the digest must match),
`timing-dependent` (wall-clock, compare the shape) and `environment-dependent`
(depends on something the repository does not carry, with the tolerance naming
exactly which part). Ten of the twelve tracked artefacts are deterministic.

**The gate result, from the run of 5 September 2026 at commit `07dfdac`:**

| | |
|---|---|
| Stages | **27 run, 0 failed** |
| Corpus | 275 files rebuilt from seed, 270 of 270 rebuildable files byte-identical |
| Artefact digests | **every deterministic artefact matched its recorded digest** |
| Claims | **every claim in the matrix re-checked against the regenerated artefact** |
| Tests | **659 passed, 21 skipped, 0 failed** across gateway, ledger, monitor, ml-engine and response |
| Not installed | dashboard — no appendix command touches it, and the exclusion is recorded in the gate's own report |

The 21 skips are the 18 ml-engine tests and 1 monitor test that need the
gitignored model, and 2 response tests that need an elevated shell. Each names
its reason; §11.4 and §11.6 say what they cost.

**Six runs were needed to get there**, and §10.8 lists the ten defects the first
five found. Wall time is not a property of this repository: the same 27 stages
took 893 s and 7,496 s on two runs that shared the host with other work, and the
stage that dominated was different each time.

# Appendix C — Claim-to-artefact matrix

`docs/CLAIM_MATRIX.md`, checked by `scripts/claim_matrix.py` and re-checked by
TC-26 inside the monitor suite. Fourteen claims: twelve made, two recorded as
**not claimed**, nine carrying Table 9.9's mandatory wording.

Every claim carries a path into a report and the value expected there, so a claim
quoting a figure fails if the report stops holding it. The two not-claimed rows —
general detection improvement and patentability — are in the matrix carrying the
evidence they *would* have required, because a matrix listing only what is
claimed cannot show that a forbidden claim was avoided on purpose.

# Appendix D — Superseded figures, with dates

Retained per §9.12, as already done in `docs/PHASE1-4_COMPLETION_SUMMARY.md`. A
superseded figure is kept with the date it was superseded and the reason.

| Figure | Was | Now | Superseded | Why |
|---|---|---|---|---|
| D1's answer | 0 cells flip | 4 cells flip on the plan's ladder | 2026-09-04 | asked on the code's four-point ladder; plan §9.1 makes the plan's five-level ladder governing |
| `partial_entropy` avoidance | moderate | negligible | 2026-09-05 | `base64.b64encode` reaches exactly 6.000 bits/byte; the original reasoning is retained in the record under `superseded` |
| Admission flip count | 12 | 16 | 2026-09-05 | policies E and F added; the `partial_entropy` recalibration moved four more |
| Capability levels with an empirical trail | 9 of 10 | 10 of 10 | 2026-09-05 | `partial_entropy` was the one level derived from source; it is now built |
| Acceptance table | 10 of 14 met | 12 met, 1 partial, 1 failed | 2026-09-04 | rows 3 and 10 closed by P6.6 and P6.7 |
| Ledger record completeness | 24 of 36 blocks | 36 of 36 | 2026-09-04 | `response_action` was the third block type carrying an adjudication |
| Arm D's status | post-hoc | variant predeclared, choice post-hoc | 2026-09-04 | Plan §7.1 lists inner-content validation among five candidate variants. The conservative reading is kept |
| "Tamper-evident" | unqualified | against an attacker who does not recompute | 2026-09-05 | 0 of 8 structural cases detected |
| Latency | 25.764 ms p95 | 94.650 ms p95, 110.550 ms p99 under 16-way concurrency | 2026-09-05 | the first was a single-file benchmark |
| Test count, clean checkout | 639 passed | 659 passed | 2026-09-05 | TC-26 added 20 cases |

# Appendix E — Decision rules D1–D6

| Rule | Question | Answer | Evidence |
|---|---|---|---|
| **D1** | Do path-whitelist and training-mode admissions flip to attenuated under the calibrated rule? | **Fires on the plan's ladder, not on the code's.** 4 cells flip under policy F; 0 under the deployed table | `reports/admission_recompute.json`, policies A–F |
| **D2** | Does any capability level fail to reproduce? | **No.** 10 of 10 reproduce across opposite derivation orders; 0 unresolved. On a clean checkout, 9 of 10, with the tenth recorded unresolved as designed | `reports/capability_calibration.json` |
| **D3** | Is the null control's false-positive cost acceptable, making the mitigation not worth governing? | **Does not fire.** Arm B costs 67.3% against a 5% budget | `reports/three_arm_experiment.json`, `d3` |
| **D4** | Does validator coverage alone leave a standard-library container witness benign? | **Fires.** C1 flags 0 of 3; the compression-yield clause closes them | `reports/three_arm_experiment.json`, `d4` |
| **D5** | Do false positives in the unvalidated × incompressible stratum exceed tolerance? | **Fires hard.** 100.0 pp against 15.0, identical across arms B, C1, C and D | `reports/benign_tradeoff.json`, `d5` |
| **D6** | Is a decision recorded without reaching the ledger? | **Was firing, now closed.** 36 of 36 blocks carry all five fields | `reports/ledger_coverage.json` |

Four fire, one does not, one was closed. The one that does not fire is the one
favourable to the project.

# Appendix F — Test inventory

**659 passed, 20 skipped, 0 failed** from a clean checkout; 677 passed, 2 skipped
in a working tree that also has `models/`. The 18-test difference is ml-engine's
`skipif`-gated model tests.

| Service | Tests |
|---|---|
| monitor | 381 |
| response (incl. `recovery/`) | 95 + 2 skipped |
| gateway | 86 |
| ledger | 67 |
| ml-engine | 30 + 18 skipped |

Table 9.7's rows, added by this work:

| ID | What it holds | Cases |
|---|---|---|
| TC-14 | unvalidated-format closure, and that the default is still `legacy` | 24 |
| TC-15 | the integrity objective | 13 |
| TC-16 | INCOMPLETE yields `deferred` | 13 |
| TC-17 | a pasted header does not cancel an alert | 32 |
| TC-18 | the admission matrix, including the five ungoverned cells | 21 |
| TC-19 | the benign bound — asserted as **missed**, at 25.323 pp | 18 |
| TC-20 | corpus labels and byte-identical rebuild | 5 |
| TC-21 | per-kind accuracy; no class hidden under an aggregate | 6 |
| TC-22 | a confidence-gated suppression still produces a record | 10 |
| TC-23 | the chained record carries all five fields | 6 |
| TC-24 | three distinct recovery failure outcomes, none verified | 9 |
| TC-25 | full traverse, asserted by equality | 8 |
| TC-26 | every claim still matches its artefact | 20 |
| — | the tamper sweep, including 4 cases asserted **undetected** | 25 |

**Four test cases assert that something is not detected**, and three assert
results unfavourable to the project. A suite that only asserts the favourable
rows cannot show that the unfavourable ones were left standing.


# Appendix G — Glossary

| Term | Meaning here |
|---|---|
| **Adjudication** | the output of `admissibility.adjudicate`: admit a suppression, or attenuate it |
| **Arm** | one value of `CONTAINER_EXEMPTION_POLICY` under evaluation; A/B/C1/C/D |
| **Attenuated** | a suppression that was found inadmissible, so the alert stands with the reason recorded |
| **Avoidance cost** | what it costs an attacker to keep a detection signal from firing |
| **Cancelled** | a suppression that was admitted, so the alert is suppressed |
| **Capability level** | a rung on a ladder describing what an attacker must be able to do; **meaningless without naming the ladder** |
| **Container exemption** | the rule that a recognised container header cancels a high-entropy alert |
| **Deferred** | the verdict for a container whose validator ran and could not finish |
| **Forging cost** | what it costs an attacker to satisfy a suppression's condition |
| **Ladder** | a capability scale. Two are in play: `admissibility.py`'s four-point and plan §5.2's five-level |
| **Paired scoring** | every arm scores the same file from one read, so no arm can differ by a disk effect |
| **Stable digest** | SHA-256 over an artefact with volatile fields removed; what a reproducer compares |
| **Stratum** | one cell of the corpus: validator coverage × compressibility |
| **UNVALIDATED** | no validator exists for this format — distinct from INCOMPLETE, where one ran and could not finish |

---

# Appendix H — The full admission matrix, all 120 cells

Four suppressions × five signals × six policies. `adm` is *admitted*, which
cancels the alert; **`att`** is *attenuated*, which lets the alert stand with the
suppression's inadmissibility recorded; **`—` means the cost table has no entry
for that suppression at all**, so the governance layer returns no verdict rather
than a permissive one. Generated from `reports/admission_recompute.json` by
`scripts/admission_recompute.py`; nothing here is transcribed by hand.

| Policy | Rule | Costs | What it is |
|---|---|---|---|
| **A** | `>=` | declared | the behaviour before P6.8 |
| **B** | `>` | declared | rule change alone - DEPLOYED |
| **C** | `>=` | measured | calibration alone |
| **D** | `>` | measured | rule change and calibration |
| **E** | `>=` | plan | the plan's ladder alone |
| **F** | `>` | plan | the plan's ladder and the plan's rule |

Policy B is what the system deploys. Policy F is the plan's own combination —
its five-level ladder and its strict `>` rule — and §6.5 records that it is not
deployed.

## H.1 The grid

| Suppression | Signal | A | B | C | D | E | F |
|---|---|---|---|---|---|---|---|
| `hash` | `ransom_extension` | adm | adm | adm | adm | adm | adm |
| `hash` | `static_entropy` | adm | adm | adm | adm | adm | adm |
| `hash` | `structural_mismatch` | adm | adm | adm | adm | adm | adm |
| `hash` | `partial_entropy` | adm | adm | adm | adm | adm | adm |
| `hash` | `entropy_rise` | adm | adm | adm | adm | adm | adm |
| `path` | `ransom_extension` | adm | adm | adm | adm | adm | **att** |
| `path` | `static_entropy` | adm | adm | adm | adm | adm | **att** |
| `path` | `structural_mismatch` | **att** | **att** | adm | adm | **att** | **att** |
| `path` | `partial_entropy` | **att** | **att** | adm | adm | **att** | **att** |
| `path` | `entropy_rise` | **att** | **att** | adm | **att** | adm | **att** |
| `training_mode` | `ransom_extension` | adm | adm | adm | adm | adm | **att** |
| `training_mode` | `static_entropy` | adm | adm | adm | adm | adm | **att** |
| `training_mode` | `structural_mismatch` | **att** | **att** | adm | adm | **att** | **att** |
| `training_mode` | `partial_entropy` | **att** | **att** | adm | adm | **att** | **att** |
| `training_mode` | `entropy_rise` | **att** | **att** | adm | **att** | adm | **att** |
| `container` | `ransom_extension` | — | — | adm | **att** | adm | **att** |
| `container` | `static_entropy` | — | — | adm | **att** | adm | **att** |
| `container` | `structural_mismatch` | — | — | adm | **att** | **att** | **att** |
| `container` | `partial_entropy` | — | — | adm | **att** | **att** | **att** |
| `container` | `entropy_rise` | — | — | **att** | **att** | adm | **att** |

## H.2 The costs each policy reads

The grid is a function of two inputs: which cost table is consulted, and which
comparison rule breaks a tie. This table gives the inputs for the three distinct
cost sources — declared (policies A and B), measured (C and D) and the plan's
ladder (E and F). `—` again means no entry.

| Suppression | Signal | declared forge / avoid | measured forge / avoid | plan forge / avoid |
|---|---|---|---|---|
| `hash` | `ransom_extension` | high / negligible | high / negligible | secret/preimage / direct attacker control |
| `hash` | `static_entropy` | high / negligible | high / negligible | secret/preimage / direct attacker control |
| `hash` | `structural_mismatch` | high / moderate | high / negligible | secret/preimage / public primitive |
| `hash` | `partial_entropy` | high / moderate | high / negligible | secret/preimage / public primitive |
| `hash` | `entropy_rise` | high / moderate | high / low | secret/preimage / direct attacker control |
| `path` | `ransom_extension` | low / negligible | low / negligible | direct attacker control / direct attacker control |
| `path` | `static_entropy` | low / negligible | low / negligible | direct attacker control / direct attacker control |
| `path` | `structural_mismatch` | low / moderate | low / negligible | direct attacker control / public primitive |
| `path` | `partial_entropy` | low / moderate | low / negligible | direct attacker control / public primitive |
| `path` | `entropy_rise` | low / moderate | low / low | direct attacker control / direct attacker control |
| `training_mode` | `ransom_extension` | low / negligible | low / negligible | direct attacker control / direct attacker control |
| `training_mode` | `static_entropy` | low / negligible | low / negligible | direct attacker control / direct attacker control |
| `training_mode` | `structural_mismatch` | low / moderate | low / negligible | direct attacker control / public primitive |
| `training_mode` | `partial_entropy` | low / moderate | low / negligible | direct attacker control / public primitive |
| `training_mode` | `entropy_rise` | low / moderate | low / low | direct attacker control / direct attacker control |
| `container` | `ransom_extension` | — / negligible | negligible / negligible | direct attacker control / direct attacker control |
| `container` | `static_entropy` | — / negligible | negligible / negligible | direct attacker control / direct attacker control |
| `container` | `structural_mismatch` | — / moderate | negligible / negligible | direct attacker control / public primitive |
| `container` | `partial_entropy` | — / moderate | negligible / negligible | direct attacker control / public primitive |
| `container` | `entropy_rise` | — / moderate | negligible / low | direct attacker control / direct attacker control |

## H.3 Every flip, with what caused it

16 cells change outcome relative to policy A, and each is
attributed to the input that moved it. Cells where policy A has no verdict at
all are **not** counted as flips — a cell going from "no entry" to a verdict is
the cost table being extended, not a decision changing — which is why the
container rows appear nowhere below despite changing in the grid.

| Policy | Suppression | Signal | From | To | Attributed to |
|---|---|---|---|---|---|
| C | `path` | `structural_mismatch` | attenuated | **cancelled** | the P5.4 calibration alone |
| C | `path` | `partial_entropy` | attenuated | **cancelled** | the P5.4 calibration alone |
| C | `path` | `entropy_rise` | attenuated | **cancelled** | the P5.4 calibration alone |
| C | `training_mode` | `structural_mismatch` | attenuated | **cancelled** | the P5.4 calibration alone |
| C | `training_mode` | `partial_entropy` | attenuated | **cancelled** | the P5.4 calibration alone |
| C | `training_mode` | `entropy_rise` | attenuated | **cancelled** | the P5.4 calibration alone |
| D | `path` | `structural_mismatch` | attenuated | **cancelled** | the > rule and the calibration together |
| D | `path` | `partial_entropy` | attenuated | **cancelled** | the > rule and the calibration together |
| D | `training_mode` | `structural_mismatch` | attenuated | **cancelled** | the > rule and the calibration together |
| D | `training_mode` | `partial_entropy` | attenuated | **cancelled** | the > rule and the calibration together |
| E | `path` | `entropy_rise` | attenuated | **cancelled** | the plan's five-level ladder alone |
| E | `training_mode` | `entropy_rise` | attenuated | **cancelled** | the plan's five-level ladder alone |
| F | `path` | `ransom_extension` | cancelled | **attenuated** | the plan's ladder and the plan's strict rule |
| F | `path` | `static_entropy` | cancelled | **attenuated** | the plan's ladder and the plan's strict rule |
| F | `training_mode` | `ransom_extension` | cancelled | **attenuated** | the plan's ladder and the plan's strict rule |
| F | `training_mode` | `static_entropy` | cancelled | **attenuated** | the plan's ladder and the plan's strict rule |

## H.4 Four things the grid says that the totals do not

**The `hash` row never moves.** Five signals, six policies, thirty cells, all
admitted. A SHA-256 whitelist costs Level 4 on the plan's ladder and HIGH on the
code's, and no rule change or recalibration touches a suppression whose key the
attacker cannot produce. It is the only row stable under every input, and §5.6.8
is about why.

**The `container` row is empty under both declared-cost policies.** Ten cells,
no forgery cost, no verdict. This is S-4 rendered as a table: **the container
exemption is not in the cost table**, so the governance layer is not being
permissive about it — the layer is never asked. §3.4 traces the mechanism, which
is that `classify` returns `benign_compressed` before adjudication is reached,
and the ordering was not a decision anybody recorded making. The ten dashes are
the most direct evidence in this thesis that a governance layer can be complete,
correct and irrelevant at the same time.

**Policy C — recalibration with the permissive rule — admits more, not less.**
Six cells flip from attenuated to cancelled and none flips the other way.
Measuring the real costs made the suppressions look *better* justified than the
declared table did, because the declared table over-priced avoidance in five of
ten places (§5.7) and the comparison is a ratio, not an absolute. **A calibration
is not automatically a tightening**, and a reader who expects measurement to
produce strictness should read the C column before assuming it.

**Only policy F attenuates `path` and `training_mode` on the two cheap signals.**
Those four cells are D1's answer. They exist only where the plan's ladder and the
plan's strict rule are used *together*: policy E — the plan's ladder with the
permissive rule — leaves all four admitted, and policy B — the strict rule with
declared costs — leaves all four admitted too. §6.3 works through the single rung
that produces them, and §6.5 records that policy F is not deployed.

---

# Appendix I — The benign corpus, cell by cell

275 files, seed `20260902`, 15 per (format, construction) cell.
Generated from `reports/benign_corpus_manifest.json`; 270 of the 275 rebuild
byte-identically from the seed and the manifest records the SHA-256 of every
one. The other five carry repository provenance instead and are marked
`rebuildable: false`.

**Every file is produced by a real encoder for its format and is structurally
genuine.** The content is synthetic — generated images, prose and audio — and the
manifest does not claim these are files taken from anyone's disk. §11.1 is about
what that costs.

## I.1 The four strata

The axes are measured, not declared. *Validated* means
`containers._VALIDATORS` holds a structural validator for the detected format.
*Incompressible* means `detection.measure` reports whole-file entropy at or above
the detector's own 7.5 threshold — so a file lands in the incompressible column
because the detector thinks it is high-entropy, not because the author decided it
was.

| Stratum | Files | Arm A false positives |
|---|---|---|
| `unvalidated_x_compressible` | 30 | 0 |
| `unvalidated_x_incompressible` | 90 | 0 |
| `validated_x_compressible` | 60 | 0 |
| `validated_x_incompressible` | 95 | 0 |
| **total** | **275** | **0** |

**Arm A flags nothing on any of the 275.** That is the baseline every bound in
Chapter 7 is measured against, and it is why *c* = 0 in every cell and every
Clopper–Pearson limit is computed (§2.6).

## I.2 Every construction

Nineteen constructions across nine formats. The entropy range is the measured
minimum and maximum over the fifteen files in the cell, which is worth reading:
the strata are separated by a real gap, not by a threshold cutting through a
cluster.

| Stratum | Construction | Files | Entropy range |
|---|---|---|---|
| `unvalidated × compressible` | GIF of photographic content - dithered to 256 colours, high entropy | 15 | 7.32 – 7.33 |
| `unvalidated × compressible` | WAV of a pure tone - a real RIFF/WAVE header and PCM frames | 15 | 5.71 – 6.88 |
| `unvalidated × incompressible` | GIF of a flat-colour image - a real GIF89a with an LZW-coded image block | 15 | 7.93 – 7.97 |
| `unvalidated × incompressible` | WAV of white noise - a real RIFF whose samples look like ciphertext | 15 | 7.98 – 7.98 |
| `unvalidated × incompressible` | bzip2 of a JPEG - already-compressed input, so the output is flat | 15 | 7.99 – 7.99 |
| `unvalidated × incompressible` | bzip2 of prose - a real bzip2 stream over compressible input | 15 | 7.84 – 7.87 |
| `unvalidated × incompressible` | xz of a JPEG - already-compressed input | 15 | 7.99 – 7.99 |
| `unvalidated × incompressible` | xz of prose - a real LZMA2 stream over compressible input | 15 | 7.99 – 8.00 |
| `validated × compressible` | JPEG of a smooth gradient - a real JPEG that compresses hard | 15 | 6.88 – 7.14 |
| `validated × compressible` | PDF of prose - real indirect objects, a real xref and %%EOF | 15 | 6.96 – 7.15 |
| `validated × compressible` | PNG of a smooth gradient - a real IHDR, IDAT and IEND | 15 | 5.41 – 5.43 |
| `validated × compressible` | ZIP_STORED archive of prose - a real archive, low-entropy content | 15 | 4.13 – 4.14 |
| `validated × incompressible` | JPEG of photographic content - a real marker chain to SOS and EOI | 15 | 7.93 – 7.94 |
| `validated × incompressible` | PNG of photographic content - lossless over noise, so high entropy | 15 | 8.00 – 8.00 |
| `validated × incompressible` | ZIP_DEFLATED archive of a JPEG - a backup of an already-compressed file | 15 | 7.98 – 7.99 |
| `validated × incompressible` | ZIP_DEFLATED archive of prose - real deflate over compressible input | 15 | 7.98 – 7.99 |
| `validated × incompressible` | gzip of a JPEG - the shape a nightly backup of a photo directory has | 15 | 7.99 – 7.99 |
| `validated × incompressible` | gzip of prose - a real deflate stream over compressible input | 15 | 7.99 – 7.99 |
| `validated × incompressible` | produced by this project during Phases 1-4; not synthesised | 5 | 7.71 – 7.98 |

## I.3 Formats present, and formats absent

| Detected format | Files | Validator |
|---|---|---|
| `bzip2` | 30 | no |
| `gif` | 30 | no |
| `gzip` | 30 | yes |
| `jpeg` | 30 | yes |
| `pdf` | 16 | yes |
| `png` | 34 | yes |
| `riff` | 30 | no |
| `xz` | 30 | no |
| `zip` | 45 | yes |

**Nine of the seventeen recognised formats are represented, and the manifest
says so rather than implying coverage it does not have.** The eight absent
ones are absent for one reason each:

| Format | Why no file exists here |
|---|---|
| `iso-bmff` | no ffmpeg or MP4 muxer in this environment |
| `rar` | RAR is a proprietary format with no free encoder |
| `7z` | py7zr not installed |
| `lz4` | lz4 not installed |
| `zstd` | zstandard not installed |
| `mp3` | no LAME or MP3 encoder available |
| `ogg` | no Vorbis encoder available |
| `flac` | no FLAC encoder available |

The pattern is worth naming. **Every absent format is one with no free encoder
available in this environment, and six of the eight are also formats with no
structural validator.** So the stratum that costs the repair most — unvalidated ×
incompressible, where D5 fires at 100 pp — is represented by four formats
(`bzip2`, `xz`, `gif`, `riff`) rather than by the eleven that would be in it if
encoders existed. §11.1 records this as a limit on the benign-cost figures:
the direction of the bias is not known, and no claim is made that it is small.

## I.4 The five files that are not synthetic

Five files carry repository provenance instead of a seed: they were produced by
this project during Phases 1–4 and are included because a corpus of entirely
self-generated content is a corpus with one author's idea of what a file looks
like. They are marked `rebuildable: false`, they are excluded from the
byte-identity check (which is why it reports 270 of 270 rather than 275), and
they all fall in the validated × incompressible stratum.

| File | Bytes | Entropy | Detected format |
|---|---|---|---|
| `repo_confusion_matrix.png` | 21,040 | 7.85 | `png` |
| `repo_entropy_distribution.png` | 24,593 | 7.74 | `png` |
| `repo_shap_summary_plot.png` | 113,344 | 7.98 | `png` |
| `repo_class_balance_chart.png` | 16,196 | 7.71 | `png` |
| `repo_Phase1-4_Team_Explainer.pdf` | 127,561 | 7.87 | `pdf` |

**They are five files out of 275 and they are not a sample of real user data.**
Nothing in this thesis treats them as one. They are named here because the
byte-identity figure would otherwise read as a failure of five files rather than
as a deliberate exclusion of five.
