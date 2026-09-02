# Mitigation-path inventory — every path that can cancel, attenuate or defer evidence

**Item P5.1 (AS). Chapter 9 §9.4.1, artefact register §9.8.**
Derived by reading the six services on branch `feat/admissibility-governance-novelty-v2`,
not by summarising `docs/CAPABILITY_GOVERNED_EXCEPTIONS.md` or
`docs/DETECTION_HARDENING.md`. Every line reference was resolved against the file
in this working tree; where the existing documents and the code disagree, the code
is recorded and the disagreement is called out.

## What counts as a path here

A path is in this inventory when it can change what evidence exists about a file
event. Three things it can do:

| Effect | Meaning |
|---|---|
| **cancel** | Evidence that would have existed does not, or reads as benign |
| **attenuate** | The alert stands but something about it is reduced or unrecorded |
| **defer** | No verdict is reached now; the question is postponed to a later event |

Two columns decide whether a path is *governed*:

- **→ adjudicate?** — does the decision pass through
  `admissibility.adjudicate()` (`services/monitor/admissibility.py:128`), the one
  place where a cancellation is priced against the evidence it cancels?
- **→ ledger?** — does the decision reach the hash chain, where an auditor can
  see it after the fact?

A path that is "no" in both columns can remove evidence with no record and no price.

---

## Summary

**34 call sites documented across the six services. 29 of them can cancel,
attenuate or defer evidence. 3 reach `adjudicate()`.**

| Service | Rows | Can cancel / attenuate / defer | → adjudicate | → ledger |
|---|---|---|---|---|
| Monitor | 21 | 19 | 3 | 3, and only when *attenuated* |
| ML Engine | 3 | 3 | 0 | 0 |
| Response | 4 | 2 | 0 | 2 |
| Ledger | 1 | 0 | — | n/a |
| Gateway | 3 | 3 | 0 | 1, best-effort |
| Dashboard | 2 | 2 | 0 | 0 |
| **Total** | **34** | **29** | **3** | **6** |

The five rows that are *not* evidence-cancelling are listed anyway, so the
inventory is complete rather than selective: **M-18** (an unreadable whitelist
file becomes an empty whitelist, which suppresses nothing), **M-21** (a validator
that raises returns FORGED — it fails closed), **D-01** (`verify_chain` reports
how far it got rather than certifying a short walk), **R-02** (a refused
termination is recorded with its reason and not counted as an action) and
**R-04** (an unverifiable restore reports `integrity_verified: false`).

The three governed paths are the whitelist hash rule, the whitelist path rule and
the training-mode ceiling — the three that Table 5.7 names as mitigations and that
the admissibility layer was written for. **Every other evidence-cancelling path in
the system is ungoverned**, including the one the Monitor uses most.

The `→ ledger` column is weaker than its count suggests. Of the six, three are the
governed rules and they reach the chain **only when the suppression was
outranked** (M-16); one is best-effort by design and fails open (G-02); one is
best-effort and fails open (R-03 affects R-02's record). No evidence-cancelling
decision reaches the ledger unconditionally.

---

## Monitor — `services/monitor/`

### The governed three

| # | Call site | Cancels | → adjudicate | → ledger |
|---|---|---|---|---|
| M-01 | `suppression.py:159` `Whitelist.match`, hash rule | any signal | **yes** (`app.py:425`) | only when attenuated — see M-16 |
| M-02 | `suppression.py:166` `Whitelist.match`, path rule | any signal | **yes** | only when attenuated |
| M-03 | `suppression.py:443` `TrainingMode.match` | any signal except `ransom_extension` and a FORGED container, which it refuses at `:426` and `:428` | **yes** | only when attenuated |

These three are the system working as designed: a rule matches, `adjudicate` prices
forging it against avoiding the signal, and the outcome — `cancelled` or
`attenuated` — is written onto the event with both costs
(`admissibility.py:150-165`).

### The adjudication itself

| # | Call site | What it decides | Note |
|---|---|---|---|
| M-04 | `admissibility.py:147` `admitted = forging >= avoiding` | whether a matched rule cancels or is attenuated | **`>=`, not `>`.** An equal-cost tie admits the suppression. This is the rule P5.5 recomputes the whole matrix under. |
| M-05 | `app.py:424` `if verdict["suspicious"]:` | whether `adjudicate` is called **at all** | A suppression that matches a verdict the detector already called benign is never adjudicated and never recorded. Combined with M-06 below, this is why the container exemption sits outside the governance layer entirely. |

### The container exemption — §9.3 finding 1

| # | Call site | Cancels | → adjudicate | → ledger |
|---|---|---|---|---|
| M-06 | `detection.py:702` `if high_entropy and container and container_valid is not False and not ransom_ext:` | `static_entropy` | **no** | **no** |
| M-07 | `containers.py:406` `return UNVALIDATED` — no validator for this format | feeds M-06 with `None` | no | no |
| M-08 | `containers.py:436` `return None` — `INCOMPLETE` and `UNREADABLE` both project to `None` | feeds M-06 with `None` | no | no |
| M-09 | `detection.py:690` `container_valid is not True` | `partial_entropy` — a structurally valid container cancels the intermittent-encryption signal | no | no |

M-06 is the single most consequential row in this table. `container_valid is not
False` is true for `True` **and** for `None`, and `None` is what
`validate_container` returns in three distinct situations that the detector cannot
tell apart:

1. the format has no structural validator (M-07) — 11 of the 16 formats in the
   registry;
2. the validator returned `INCOMPLETE`, i.e. the file is still being written (M-08);
3. the file could not be read at all — `UNREADABLE` (M-08).

The verdict text is honest about case 1 — `"a {container} header (this format has
no structural validator)"` at `detection.py:706` — but the *outcome* is identical
to case where the structure was checked and passed. "I could not check" and "I
checked and it passed" produce the same `benign_compressed`, the same
`suspicious: False`, the same `signal: None`, and, through M-05, the same absence
of any adjudication record.

**The 11 formats with no structural validator.** The registry
(`detection.py:128-150`) holds 20 signature entries over 16 unique format names;
`containers.py:_VALIDATORS` (`:378`) holds six validators, five of which correspond
to a registry name:

> validated — `zip`, `gzip`, `png`, `jpeg`, `pdf` (plus `iso-bmff`, reached through
> the `ftyp` branch at `detection.py:447` rather than the signature tuple)
>
> **unvalidated — `rar`, `7z`, `xz`, `bzip2`, `lz4`, `zstd`, `gif`, `mp3`, `ogg`,
> `flac`, `riff`**

Confirmed against the source in this tree, not carried from §9.3.

### Evidence dropped before classification

| # | Call site | Effect | → adjudicate | → ledger |
|---|---|---|---|---|
| M-10 | `app.py:343` `if not matches_patterns(path, _file_patterns):` | **cancel.** The event never exists — not classified, not buffered, not counted. Operator-controlled through `/monitor/start`'s `file_patterns`. | no | no |
| M-11 | `app.py:346-368` `deleted` short-circuit | **cancel.** Forces `suspicious: False`, `verdict: "deleted"`, no entropy reading. | no | no |
| M-12 | `app.py:349` `ENTROPY_HISTORY.forget(path)` | **cancel, forward in time.** Destroys the differential-entropy baseline for that path, so a file recreated there starts with no history and the `entropy_rise` signal cannot fire on it. | no | no |
| M-13 | `app.py:369` `if not os.path.isfile(path):` | cancel — no event | no | no |
| M-14 | `app.py:375` `except OSError: return None` on `getsize` | cancel — no event | no | no |
| M-15 | `detection.py:641` `if not readable:` | **cancel.** Entropy, structure and statistics are all unavailable; the verdict falls back to `unreadable` with `signal: None` unless a ransom extension is present. | only if a ransom extension made it suspicious | only if suspicious |

M-12 deserves a second look in Phase 6. It is defensible on its own terms — the
comment at `app.py:347` gives the reason, and it is a real one — but *delete then
recreate* is a write pattern an encryptor can choose, and this path is the one that
makes `entropy_rise` (priced MODERATE at `admissibility.py:88`) unavailable
afterwards. It is out of scope for the Week 20 freeze and is recorded here so it is
not lost.

### The fan-out gate — the largest audit gap found

| # | Call site | Effect | → adjudicate | → ledger |
|---|---|---|---|---|
| M-16 | `app.py:491` `if verdict["suspicious"] and suppression is None and PIPELINE_ENABLED:` | **cancel, at the audit layer.** | n/a | **no** |

`_record` (`app.py:520`) is an in-memory ring buffer. The *only* routes to the
ledger from the Monitor are `_work.put(("detection", …))` at `app.py:502` and
`_work.put(("baseline", …))` at `app.py:515`, both inside this branch or its
`elif`.

`suppression` is non-`None` exactly when `decision["admitted"]` is true
(`app.py:433-436`). So:

| Event | Pipeline runs? | Ledger record? |
|---|---|---|
| not suspicious | no | no |
| suspicious, suppression **attenuated** | **yes** | yes — `admissibility` travels in `event_data` (`pipeline.py:192`) |
| suspicious, suppression **cancelled** | **no** | **no** |

An attenuated suppression is chained with both costs. **A cancelled one is not
chained at all.** The record that an operator's rule was consulted, was found
expensive enough, and removed an alert exists only in `GET /monitor/events`, which
is a bounded in-memory buffer that does not survive a restart and is not
tamper-evident.

This is the gap TC-23 (Table 9.7) is written against — *"Every mitigation decision,
including attenuated and deferred ones, is chained"* — and it is a Phase 6/7 repair,
not a Phase 5 one. Recorded, not fixed.

### Deferral and best-effort paths

| # | Call site | Effect | → adjudicate | → ledger |
|---|---|---|---|---|
| M-17 | `detection.py:563` `EntropyHistory.observe` returns `None` on first sighting | **defer.** No delta exists, so `entropy_rise` cannot fire on the first event for a path. | no | no |
| M-18 | `suppression.py:118` `except (OSError, ValueError)` in `Whitelist.from_file` | An unreadable whitelist file becomes an empty whitelist. **Fails safe** — an empty whitelist suppresses nothing. Recorded for completeness. | n/a | no |
| M-19 | `app.py:547` `except Exception` in the worker drain | **defer, silently.** A fan-out that raises is logged and the event keeps whatever it had — no ledger block, no ML prediction, and nothing on the event saying the chain was attempted and failed. | no | no |
| M-20 | `pipeline.py:74-83` `_post` returns `None` on any HTTP error or timeout | **defer.** A ledger, ML engine or response service that is down produces a `logger.warning` and a missing stage. `result["stages"]` shows the absence, but only for a caller that reads it. | no | no |
| M-21 | `containers.py:416` `except (…): return FORGED` | **Not a cancellation** — a structure that cannot be parsed fails closed. Listed so the inventory is complete rather than selective. | n/a | n/a |

---

## ML Engine — `services/ml-engine/`

| # | Call site | Effect | → adjudicate | → ledger |
|---|---|---|---|---|
| L-01 | `app.py:152-160` `threat_level_from` | **attenuate.** Confidence maps to `critical`/`high`/`medium`/`low` at 0.9 / 0.7 / 0.4, and `prediction != "ransomware"` returns `low` at any confidence. | no | no |
| L-02 | `app.py:193` and `app.py:213` — model not loaded → HTTP 503 | **defer.** `pipeline._post` (M-20) turns it into `None`; the chain continues with no prediction. | no | no |
| L-03 | `app.py:233` `features_ignored` | **attenuate.** Features the caller sent that this model does not score. Reported in the response body rather than dropped silently — this is the A6 fix at commit `2378a42`. | no | no |

### §9.3 finding 3 does not hold as written — a correction

§9.3 states of the confidence gate: *"Below that line no response occurs, no
adjudication happens, and nothing records that an action was withheld."*

That is not what the current code does, and the reason is `pipeline.py:42-62`:

```python
def effective_threat_level(model_threat_level: str | None, suspicious: bool) -> str:
    monitor_threat_level = "high" if suspicious else "low"
    model_threat_level = model_threat_level or "low"
    return max(model_threat_level, monitor_threat_level, key=_rank)
```

The Monitor's own verdict is a **floor**, not a fallback. And `pipeline.run` is only
ever reached for a suspicious event (M-16). So inside `pipeline.run`,
`effective_threat_level` is always at least `"high"`, and the response gate at
`pipeline.py:212` (`ACTIONABLE_THREAT_LEVELS = {"high", "critical"}`) is
**unreachable in its withholding direction from this caller**.

The gate can still withhold in principle — `response/app.py:216` gates isolation on
the same set, and any future caller that does not floor the level would hit it —
but the specific failure §9.3 describes is not currently live. The measurement that
establishes this, rather than the reading, is item P5.4; this row records what the
source says so the two can be compared.

The real residual gap is narrower and is M-05 + M-16: an event the Monitor does
**not** call suspicious never enters the pipeline, so it is never scored by the
model at all. The confidence gate is not what suppresses it — the Monitor's own
container exemption (M-06) is.

---

## Response — `services/response/`

| # | Call site | Effect | → adjudicate | → ledger |
|---|---|---|---|---|
| R-01 | `app.py:216` `if payload.threat_level in {"high", "critical"}:` | **attenuate.** Below that, no network isolation, and `actions_taken` simply omits it — the omission is not itself an entry. | no | the trigger record is chained at `app.py:223`, but it lists only what happened |
| R-02 | `app.py:203-207` `except TerminationError` | **Recorded, not silent.** `details["terminate"] = {"status": "refused", "reason": …}` and `actions_taken` correctly does not claim the kill. | no | yes, inside the trigger record |
| R-03 | `app.py:107-121` `log_action` best-effort | **defer.** A response that happened with a ledger that was down returns `block_id: None` and the action is unchained. | no | **fails open** |
| R-04 | `recovery/recovery.py:210` `all_verified = bool(verify_integrity) and bool(results) and all(...)` | **Fails safe.** An unverifiable restore reports `integrity_verified: False` and status `partial`; `_recover_one:273` gives the reason. Listed because it is the one place in the system that already refuses to claim verification it did not do. | n/a | via `ledger_client` |

---

## Ledger — `services/ledger/`

| # | Call site | Effect |
|---|---|---|
| D-01 | `hash_chain.py:100` `verify_chain` stops at the first broken block | **Not a cancellation.** `blocks_checked` reports how far it got and `invalid_block_id` names the break, so a truncated walk is visible rather than reported as a clean chain. The fresh-connection read at `:126` is what makes it able to see an external edit at all. |

The ledger has no evidence-cancelling path. It is append-only and its verification
fails loudly. The gaps that concern the audit trail are all upstream — M-16, M-19,
M-20, R-03 and G-02 — and every one of them is a *write that never arrives*, not a
record the ledger discarded.

---

## Gateway — `services/gateway/`

| # | Call site | Effect | → adjudicate | → ledger |
|---|---|---|---|---|
| G-01 | `rate_limit.py:49` → HTTP 429 | **cancel.** A rate-limited `/analyze` never reaches the ML engine. The refusal is not written to the chain — only 401/403 are, through G-02. | no | no |
| G-02 | `main.py:81-116` `audit_access_denial`, with `except Exception` at `:115` | **defer.** TC-10's audit entry is best-effort by design: a ledger that is down turns an audited 401 into an unaudited one. The docstring says so and gives the reason. | no | best-effort |
| G-03 | `main.py:139-141` unhandled-exception handler → 500 | **cancel.** A 500 leaves no chain entry of any kind. | no | no |

---

## Dashboard — `services/dashboard/`

| # | Call site | Effect |
|---|---|---|
| B-01 | `app.py:222` `monitor_flagged = bool(latest_event.get("suspicious"))` | **cancel, at the display layer.** The banner reads one boolean. A **cancelled** event has `suspicious: False` and renders as "System Secure". |
| B-02 | (absence) — no reference to `admissibility`, `suppressed_by`, `outcome`, `attenuated` or `deferred` anywhere in the file | An **attenuated** event and a plain alert are pixel-identical on screen. The forgery/avoidance costs the admissibility layer computes are carried on the event and in the ledger and are shown to nobody. |

`grep -n "suppress\|admissib\|attenuat\|cancel\|defer" services/dashboard/app.py`
returns nothing. This is the §9.4.2 deliverable *"the dashboard surfaces
`cancelled`, `attenuated` and `deferred` distinctly"* (P6.4), recorded here as the
Phase 5 measurement of where it stands.

---

## What this inventory establishes for the Week 20 gate

1. **Three of twenty-eight paths are governed.** The admissibility layer covers
   exactly the mitigations Table 5.7 named. Every path that predates it — most of
   all the container exemption at `detection.py:702`, which is the Monitor's
   most-used suppression — cancels evidence without being priced.

2. **The governance layer's own decisions are half-recorded.** M-16: an attenuated
   suppression is chained, a cancelled one is not. The audit trail contains the
   decisions that changed nothing and omits the decisions that removed an alert.

3. **`container_valid is None` is doing three unrelated jobs.** M-07 and M-08 —
   *no validator*, *still being written*, and *unreadable* are one value to the
   detector, and all three produce `benign_compressed`. Separating them is what
   TC-15 and TC-16 will test.

4. **§9.3 finding 3 needs restating.** `pipeline.effective_threat_level` floors a
   Monitor-suspicious event at `high`, so the confidence gate cannot withhold a
   response on the only path that reaches it. The finding survives in a narrower
   form and is measured in P5.4.

5. **The equality case is unexamined.** M-04's `>=` admits a suppression whose
   forgery cost merely *ties* the signal's avoidance cost. Whether any live
   mitigation×signal pair sits on that tie, and what flips if it becomes `>`, is
   P5.5.

## Method

```bash
git rev-parse HEAD                       # the tree this was read against
grep -n "return None" services/monitor/*.py
grep -rn "suppress\|admissib\|attenuat\|cancel\|defer" services/dashboard/app.py
grep -n "adjudicate" services/monitor/app.py
```

Every `file:line` above was resolved with `grep -n` or `sed -n` against the working
tree at the commit recorded in `reports/phase5_baseline.json`. No line reference was
copied from `docs/CAPABILITY_GOVERNED_EXCEPTIONS.md`. Some of that document's own
citations have since drifted — its §4.5 points at `admissibility.py:80` for
`calculate_avoidance_capability`, and line 80 in this tree is the
`"structural_mismatch": MODERATE` entry of the `AVOIDANCE_COST` dict — which is why
this inventory was derived from the source rather than from it. Its §4.6 citation of
`admissibility.py:128` for `adjudicate` does still resolve.
