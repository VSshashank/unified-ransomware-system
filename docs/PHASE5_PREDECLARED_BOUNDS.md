# Predeclared bounds for Phase 6

**Item P5.6 (AS + NI). Chapter 9 §9.7, note on D5, and §9.4.2.**

> *"The numerical tolerance must be chosen and committed before Phase 6 begins.
> Choosing it after seeing the result is precisely what this section exists to
> prevent."* — §9.7, note on D5

Written and committed at the Week 20 gate, **before any repair exists and before
any Arm B or Arm C measurement has been taken**. The only Phase 6-relevant number
in hand at the time of writing is Arm A's baseline on the frozen corpus, which is
**0 false positives out of 149 files** (`reports/benign_corpus_manifest.json`,
tag `corpus-frozen-week19`).

Everything below is computed from the frozen corpus's composition and from
Table 9.8's stated targets. Nothing is chosen to make a result come out.

---

## Bound 1 — non-inferiority on validated formats

**Table 9.8:** *"False-positive difference, validated formats — ≤ 2 percentage
points, one-sided 95% bound."*

**Predeclared:** Arm C's false-positive rate on validated formats may exceed
Arm A's by **at most 2.00 percentage points**, judged by the **upper limit of a
one-sided 95% confidence interval** on the paired difference — not by the point
estimate. A point estimate of 0 with an upper bound of 8pp does not pass.

### The corpus cannot currently support this bound, and that is predeclared too

The frozen corpus holds **85 validated-format files** (53 incompressible + 32
compressible). With a paired design and Arm A at zero, every discordant pair is
an Arm-C-only false positive, so the difference is `b/n` and its one-sided 95%
upper limit is the Clopper–Pearson upper limit for `b` successes in `n` trials.

Even in the best possible case — **zero** new false positives — the bound is:

| validated files `n` | observed new FPs `b` | one-sided 95% upper limit |
|---|---|---|
| **85 (frozen corpus today)** | 0 | **3.46 pp** |
| 149 | 0 | 1.99 pp |
| 200 | 0 | 1.49 pp |

`n ≥ 149` validated files are required for a perfect result to clear 2.00 pp
(`ln 0.05 / ln 0.98 = 148.28`).

**So with 85 files the ≤2pp bound cannot be met even by a flawless repair.** This
is a property of the corpus, not of any repair, and it is being recorded now
rather than discovered in Week 23.

**Predeclared remedy, in order of preference:**

1. **Grow the validated stratum to ≥ 149 files before Arm C is measured.** The
   builder is seeded and reproducible, so raising `--per-cell` for the validated
   recipes and re-freezing is a mechanical change. This is the intended route.
2. If the corpus is not grown, Phase 6 reports the **achieved** bound and states
   plainly that Table 9.8's ≤2pp criterion was **not evaluable at the available
   sample size**. It is not reported as met, and it is not reported as failed.

Under no circumstance is the bound relaxed after the measurement, and under no
circumstance is a point estimate substituted for the interval.

---

## Bound 2 — the D5 tolerance on `unvalidated × incompressible`

**Table 9.8** deliberately gives no number here: *"Measured and reported; no
zero-cost assumption; D5 applies."* The number is therefore chosen here, and
derived rather than picked.

### Derivation

The repair Phase 6 selects will stop trusting headers for formats with no
structural validator. The files it will newly alert on are, by construction, the
`unvalidated × incompressible` stratum: genuine files in a format the system
cannot check, whose content legitimately looks like ciphertext — a bzip2 of a
JPEG, an xz of a JPEG, a dithered GIF, a WAV of white noise.

The project already binds itself to a corpus-wide false-positive budget:
**Table 5.9, False Positive Rate < 5%**. That budget is not superseded by
Phase 6 and is the right thing to derive from, because it is the number an
operator was already promised.

On the frozen corpus this stratum is **48 of 149 files = 32.21%**. For it to
consume the whole 5% corpus-wide budget on its own:

```
0.05 / 0.3221 = 15.52%
```

**Predeclared tolerance: 15.0 percentage points.** Rounded down from 15.52 for a
round number and a margin.

**The rule, stated composition-independently** — because the corpus may grow
before Phase 6 and the tolerance must not silently move with it:

> The `unvalidated × incompressible` false-positive rate may not be so high that
> this stratum alone would push the corpus-wide false-positive rate above the 5%
> of Table 5.9. On the corpus as frozen at `corpus-frozen-week19` that is
> **15.0 pp**. If the corpus composition changes, the rule is re-evaluated from
> the rule, and both the old and new figures are recorded.

### The tension in this number, stated now rather than later

15 pp is a *high* operational false-positive rate. One benign archive in seven
raising an alert is not a system an operator leaves switched on, and no reading
of this document should treat 15 pp as "acceptable" in an operational sense.

It is the number that follows from the budget the project already set, and it is
predeclared as the D5 **trigger**, not as a standard of quality. D5's remedy
applies to everything below it as much as above it: even a repair that comes in
well under tolerance ships behind an operator switch if the stratum cost is
non-zero, and the write-up says a real validator for those formats is the correct
long-term fix.

---

## The analysis, specified in advance

Fixed now so that the test cannot be selected after the numbers are seen.

- **Design:** paired. Arm A and Arm C score the *same* files from the frozen
  corpus. Arm B (exemption removed entirely) is scored on the same files and
  reported alongside as the null control.
- **Unit:** one file, one verdict. A file is a false positive when
  `classify()` returns `suspicious: true`.
- **Reported per stratum**, never pooled. §9.4.2's per-stratum requirement exists
  so a clean validated stratum cannot average away a costly unvalidated one.
- **Test on discordant pairs:** exact McNemar (binomial, one-sided). Concordant
  pairs carry no information about the difference and are excluded from the test
  while remaining in the denominator of the reported rate.
- **Interval:** Clopper–Pearson, one-sided, 95%, on the discordant count. The
  **upper limit** is what is compared against the bounds above.
- **No multiplicity adjustment across the four strata**, because each bound is a
  separate predeclared decision rather than a family of hypotheses about one
  effect. This choice is recorded here so it is not made later.
- **Arm C is not certified on the unvalidated-format witness alone** (D4). The
  standard-library valid container from `reports/recf_exemption_evidence.json`
  is a required test case.

---

## `cost-policy-v2` — proposed, not applied

`docs/ADMISSION_RECOMPUTE.md` records a defect the P5.4 calibration exposed:
under the cost model's comparison, **lowering what a signal costs to avoid makes
that signal easier to cancel**. Applying the measured costs to the deployed
policy would let a path whitelist cancel a structural-mismatch alert.

The cause is that one number is doing two jobs:

| Quantity | What it means | What P5.4 measured |
|---|---|---|
| avoidance cost | what an attacker who *wants* to evade this signal must spend | this |
| evidential weight | what the signal is worth *when it fires* | not this |

For `structural_mismatch` these point opposite ways. A file that trips it is one
whose author did not spend the single standard-library call that would have
avoided it; the signal is cheap to evade and, for exactly that reason, strong
evidence when it fires.

**Proposed for Phase 6, per D1's instruction that any refinement be "proposed,
justified and versioned as `cost-policy-v2` — never applied silently":**

> Separate the two quantities. A suppression is compared against the signal's
> *evidential weight*, not its avoidance cost. Avoidance cost is retained and
> reported, because it is what says which signals an attacker will route around
> first — it simply stops being the thing a suppression is measured against.

**Not implemented in Phase 5.** `services/monitor/admissibility.py` is unchanged
and every cost in it is unchanged. This is a proposal with a version name, which
is what D1 asks for.

---

## What is deliberately *not* predeclared

- **Which repair is selected.** §9.4.1 forbids choosing it before the cost table
  freezes. It is selected in Phase 6 from a row of the frozen table.
- **Whether the governance layer is required at all.** That is D3's question and
  it is answered by Arm B's measurement, not here.
- **Whether the repair ships on by default.** D5 decides that from the measured
  stratum cost against the tolerance above.
- **Any threshold for `validated × compressible` or `unvalidated × compressible`.**
  Table 9.8 sets no target for them; they are measured and reported.

---

## Provenance

| Input | Source |
|---|---|
| Corpus composition (149 files, 85 validated, 48 unvalidated × incompressible) | `reports/benign_corpus_manifest.json`, tag `corpus-frozen-week19` |
| Arm A baseline, 0/149 | same manifest, `summary.arm_a_baseline` |
| Measured capability costs | `reports/capability_calibration.json` (P5.4) |
| Admission flips | `reports/admission_recompute.json` (P5.5) |
| Corpus-wide FP budget < 5% | Table 5.9, reference document v1.6 |
| ≤2pp validated bound | Table 9.8, Chapter 9 |

Confidence limits computed with `scipy.stats.beta.ppf(0.95, b+1, n-b)`; the
required-`n` figure from `ln 0.05 / ln 0.98`.
