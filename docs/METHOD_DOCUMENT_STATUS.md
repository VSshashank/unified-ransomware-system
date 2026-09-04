# The governing method document — a wrong finding, and its correction

> ## CORRECTION, 3 September 2026
>
> **`docs/NOVELTY_PROOF_PLAN.md` exists.** It is on
> `origin/feat/admissibility-governance-novelty-v2`, added in commit `4e10adb`
> ("docs: add evidence-gated novelty proof plan"), and it is 382 lines carrying a
> 14-row acceptance table.
>
> **The finding recorded in this document on 2 September 2026 — that the file
> "does not exist and never has" — was wrong.** Phase 5 and Phase 6 were both
> carried out under that wrong finding. What each cost is set out below, and the
> Phase 6 report now maps every measurement onto the real acceptance table.
>
> The original text is preserved from §"What was searched" onward, unedited, so
> the mistake and its reasoning stay legible. It is wrong. Read this section
> first.

## How the search missed it

The command was:

```bash
git log --all --diff-filter=A --name-only | grep -i -E "novelty|proof"
```

`--all` means *every ref in this clone* — local branches, tags, and
remote-tracking refs under `refs/remotes/`. It does **not** mean every ref on the
server. The branch `feat/admissibility-governance-novelty-v2` existed on
`origin`, but it had never been fetched into this clone, so no ref pointed at it
and `--all` could not reach it. `git branch -a` had the same blind spot for the
same reason, and running it was what produced the false confidence that "9 local
and 11 remote branches" had been covered — eleven remote-tracking refs is not
eleven remote branches.

The discovery came from `git ls-remote --heads origin`, which asks the *server*
rather than the clone. It listed twelve branches, one more than `git branch -r`
knew about, and it was the missing one.

**The lesson, stated so it is not repeated:** a claim that something does not
exist anywhere must be made against the remote, not against the clone.
`git ls-remote` and `git fetch --all` come before `git log --all`, and the
reasoning in the original text below — *"`git log --all --diff-filter=A` lists
every path ever added anywhere in history"* — is false as written. It lists every
path ever added anywhere in **the history this clone has fetched**.

## What working under the wrong finding cost

The substitute acceptance layer was Chapter 9's Table 9.8 plus
`docs/PHASE5_PREDECLARED_BOUNDS.md`. That turned out to be close to the real plan
rather than at odds with it, so most of Phases 5 and 6 stands. The differences
that matter:

| # | The plan requires | What was done instead | Cost |
|---|---|---|---|
| 1 | §5.2 a **five-level** ladder: 0 direct control, 1 public primitive, 2 format-aware, 3 new engineering, 4 secret/preimage | P5.4 calibrated against `admissibility.py`'s four-point scale (NEGLIGIBLE/LOW/MODERATE/HIGH) | Levels are **not directly comparable**. The code's HIGH conflates the plan's 3 and 4. The plan puts a standard-library container at **Level 1**; P5.4 measured it NEGLIGIBLE, the plan's Level 0 |
| 2 | §5.3 the strict rule `admit only if C_forge > C_avoid`, because "equal capability does not demonstrate that the mitigation is harder to forge" | The deployed `>=` was left in place and `>` computed as Policies B and D of the recompute matrix | The rule change the plan **mandates** was measured but not adopted. `admissibility.py` is unchanged |
| 3 | §7.1 lists **inner-content/recursive validation as a predeclared candidate repair variant**, with "the final winner is selected only after calibration" | Arm D was built after Arm C's benign cost was seen and labelled post-hoc, with no predeclared criterion claimed for it | The caution was **stronger than the plan required**. The variant was predeclared; only the choice among variants came after calibration, which is what the plan asks for |
| 4 | §9 an INCOMPLETE container must yield `deferred` or `unverified` | Under the repair, INCOMPLETE yields `suspected_encryption` / `static_entropy` | The "no silent benign cancellation" half is met; the **named state is not**. §7.1's "explicit deferred state" variant was never built |
| 5 | §9 the ledger record must carry mitigation ID, validation state, capability levels, **policy version**, and reason | The `suppression_decision` block carries rule, signal, both costs and reason | **Validation state and policy version are missing** from the record |

**Update, 4 September 2026 — items 1, 2, 4 and 5 are closed.**

| # | Then | Now |
|---|---|---|
| 1 | levels derived on the code ladder only | P6.8 derives every strategy on both ladders, twice each, from the same recorded facts. All ten reproduce; both of §5.3's own calibration hypotheses hold. It changed D1's answer — see below |
| 2 | `>=` deployed, `>` computed | P6.8 adopts `>`. A no-op against the declared table (policy B ≡ policy A), and mandated, so it was adopted rather than argued about |
| 3 | Arm D labelled post-hoc, more cautiously than required | unchanged, deliberately. Arm D cannot ship either way and the conservative label costs nothing |
| 4 | INCOMPLETE yielded `suspected_encryption` | P6.7 gives it the named verdict `deferred` under every policy that refuses INCOMPLETE as proof. `legacy` is untouched, because that is Arm A |
| 5 | `validation_state` and `policy_version` absent | P6.6 carries both into all three block types that can hold an adjudication. 36/36 blocks now complete on all five required fields |

**Item 1 produced a result, not just a correction.** On the plan's five-level
ladder, `path` and `training_mode` forgery are Level 0 — §5.2 puts choosing a
path beside choosing bytes — and so are `ransom_extension` and `static_entropy`
avoidance. Four ties, and §5.3's strict rule breaks all four against the
suppression. **D1 fires.** Phase 5 reported that it did not, and that report was
correct about the four-point ladder it was measured on and wrong about the ladder
§9.1 makes governing. Policy F of `docs/ADMISSION_RECOMPUTE.md` is the
computation. It is not deployed, and why not is recorded there.

That is what the P0 error cost, stated as concretely as it can be: a primary
finding was answered on the wrong scale, and the answer reversed when it was
asked again on the right one.

## What was *not* affected

- Every measurement stands. Nothing was measured against a criterion invented
  after the fact, and the substitute bounds were committed at the Week 20 freeze
  before any Phase 6 number existed.
- The predeclared ≤2 pp non-inferiority bound is the plan's own figure —
  §10 gives `FPR(C) − FPR(A) ≤ 2 percentage points` and requires a one-sided 95%
  bound. That was arrived at independently from Table 9.8 and matches.
- §8.1's six required attack witnesses are all present in
  `reports/three_arm_experiment.json` as families A1–A7.
- §10's statistical design — paired fixtures across arms, discordant pairs,
  McNemar as a paired test only, ≥10 repetitions with median and IQR for
  timing — is what `scripts/benign_tradeoff.py` executes.

## Claim discipline, revised

The instruction in the original text — that no sentence may cite
`NOVELTY_PROOF_PLAN.md` as a source — **no longer applies**. The document exists
and is the governing method per §9.1. Where it and Chapter 9 disagree, the proof
plan governs the method and Chapter 9 governs the calendar.

---

---

# ORIGINAL TEXT, 2 SEPTEMBER 2026 — SUPERSEDED AND WRONG

*Preserved unedited below. Its central finding is false; see the correction
above.*

# The governing method document is missing — what Phase 5 does instead

**Item P0. Recorded 2 September 2026, before any Phase 5 measurement was taken.**

Chapter 9 §9.1 names `NOVELTY_PROOF_PLAN.md` as the governing method document:

> The governing method document is `NOVELTY_PROOF_PLAN.md`. This chapter is its
> schedule, ownership and acceptance layer: where the two disagree, the proof plan
> governs the method and this chapter governs the calendar.

It is also cited by §9.4.2, which makes the Week 24 exit gate *"every row of the
acceptance table in `NOVELTY_PROOF_PLAN.md` is measured and reported"*.

**The file does not exist and never has.**

## What was searched

| Where | Command | Result |
|---|---|---|
| Working tree | `ls`, `grep -ril NOVELTY_PROOF_PLAN .` | Only `docs/PHASE5-8_MASTER_PROMPT.md`, which is the prompt citing it |
| Every commit on every branch | `git log --all --diff-filter=A --name-only \| grep -i -E "novelty\|proof"` | No match — the file was never added in any commit |
| All 9 local and 11 remote branches | `git branch -a` enumerated, search above covers all of them | Absent |

`git log --all --diff-filter=A` lists every path ever *added* anywhere in history.
A file that was written and later deleted would still appear. Nothing does. This is
not a deleted file to recover; it is a document that was never written.

## What was considered as a substitute, and rejected

`docs/CAPABILITY_GOVERNED_EXCEPTIONS.md` is the nearest thing in the repository. It
is a 1,180-line design document covering the architecture (§3), the algorithm (§4),
the data contracts (§5), an implementation plan (§6), the container-exception
integration (§7) and a test plan (§8) whose §8.3 already sketches the three-arm
A/B/C comparison Phase 6 needs.

It is not the method document, for one decisive reason. Its own closing section says:

> The scale is a modelling choice, not a measurement, and a different analyst could
> defend different numbers.

Converting that modelling choice into a measurement is exactly what Phase 5 exists
to do. A document that declares the cost scale unmeasured cannot also be the
document that says what a measured level has to satisfy to be accepted. It seeds the
work; it cannot govern it.

## The decision taken

The user was asked, before any measurement ran, and directed that Phase 5 proceed
without the method document rather than have it authored in this session.

**Chapter 9's Table 9.8 acceptance benchmarks are therefore the operative acceptance
layer for Phase 5**, and Chapter 9's §9.7 decision rules D1–D6 are the operative
decision layer. Nothing in Phase 5 is measured against a criterion invented during
Phase 5.

## What this costs, stated rather than hidden

1. **The Week 24 gate is under-defined.** §9.4.2 makes it "every row of the
   acceptance table in `NOVELTY_PROOF_PLAN.md`". With no such table, Phase 6 would
   have to define its own pass condition — which is the failure mode §9.7 exists to
   prevent. *This session stops at the Week 20 gate, so the cost is deferred, not
   incurred.* It must be resolved before Phase 6 opens.

2. **Capability-level acceptance has no external definition.** §9.4.1 requires each
   level to have "a reproducible source trail confirmed by a second reviewer", and
   Table 9.8 requires 100% reproduction, but what *counts* as a level is defined only
   by `services/monitor/admissibility.py`'s four-point ordinal scale
   (NEGLIGIBLE / LOW / MODERATE / HIGH). Phase 5 therefore calibrates against that
   scale, and says so on every record it writes. The scale is the system's own, not
   an independent yardstick, and no claim in this work should be read as if it were.

3. **The non-inferiority bound (P5.6) has no prior definition to inherit.** It is
   predeclared in `docs/PHASE5_PREDECLARED_BOUNDS.md` from Table 9.8's stated
   ≤2-percentage-point figure, with the reasoning written down, and committed before
   Phase 6 opens — which satisfies §9.7's note on D5 on its own terms. But it is a
   bound this project chose, not one it was handed.

## What would resolve it

Either the original `NOVELTY_PROOF_PLAN.md` is located outside this repository and
restored, or it is authored deliberately — **before** Phase 6 opens and with the
Phase 5 measurements deliberately not consulted while its acceptance table is
written. Authoring it after the Phase 5 numbers are in hand would produce an
acceptance table fitted to results already obtained, which is the same defect
§9.4.1 forbids for the repair and the cost table.

## Claim discipline

Per Table 9.9, no sentence in the thesis, paper or defence may cite
`NOVELTY_PROOF_PLAN.md` as a source. Where the method needs a citation, the citation
is Chapter 9 §9.7 (decision rules), Table 9.8 (acceptance benchmarks) and
`services/monitor/admissibility.py` (the capability scale) — the three documents that
actually exist.
