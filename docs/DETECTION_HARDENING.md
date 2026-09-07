# Detection hardening: five defects and what they had in common

This documents a pass over URDS that started from reading the system's own
source rather than from watching it fail, and found five defects that the
suite — 424 tests at the time, all passing — did not catch. Two were already
recorded in this repository's own reports as known limits. Three were not
recorded anywhere, and two of those turn the system's false-positive
mitigations into the evasion.

They share one root cause, and it is worth stating before the list because
every fix below is an instance of it:

> The system decided what to trust by **recency or presence**, where it should
> have decided by **how hard it would be for an attacker to fake**.

A magic byte is *present*, so the container exemption applied. The newest hash
on a path is *recent*, so recovery verified against it. The last five entropy
readings are *recent*, so they set the baseline. A learned ceiling *exists*, so
it suppressed. In each case the thing being trusted costs an attacker almost
nothing to produce, and in each case the system had no way to say so, because it
had no notion of cost at all.

| # | Defect | Was it known? | Status |
|---|---|---|---|
| D1 | Recovery verified a restored file against the **attacker's** hash | Reported | Fixed — selector, and a producer for the reference value |
| D2 | Training corpus contained **contradictory labels** | Reported | Fixed — corpus rebuilt |
| D3 | Training-mode ceiling could be **poisoned** by a created file | New | Fixed — dwell, structural class, and a cost bound |
| D4 | Differential-entropy baseline could be **flushed** by five writes | New | Fixed — session floor outside the window |
| D5 | `partial` and `spoofer` families undetected | Reported | Fixed — block profile, structural validation |

---

## D1 — The integrity check could only pass on a failed recovery

`services/response/recovery/recovery.py` restores a file from a snapshot and
then verifies it against "the last hash the ledger holds for this path".

`services/monitor/pipeline.py` reaches the ledger **only for events it has
already judged suspicious**. So on a path under attack, the newest hash in the
ledger is the hash of the file *as the attacker left it* — written once as
`file_event` and again as `response_action`. Checking a correctly restored file
against that hash inverts the test: it reports `integrity_verified: false` for
every successful recovery, and would report `true` only if recovery handed back
the ciphertext.

**Two halves, and only one of them was the fix.**

The selector was corrected first: `last_known_hash` now takes the most recent
hash from an allowlist of event types that describe a file in a state worth
restoring *to* — `file_baseline`, `file_recovered`, `snapshot_created` — rather
than the most recent hash of any kind. An allowlist and not a denylist, because
a denylist is one new event type away from reintroducing exactly this.

That made the check honest and left it **inert**: nothing in the running system
ever wrote any of those three event types for an ordinary file. Every real
recovery correctly reported that integrity could not be verified, which is a
true statement and a useless feature.

So the Monitor now records a baseline. The first time a path is seen and found
benign, `file_baseline` is written with its hash — once per path per monitor
run, off the detection path through the existing worker queue, and gated on the
*raw* verdict so a file an operator has whitelisted into silence still cannot
contribute one. `BASELINE_LOGGING_ENABLED` switches it off; the extra ledger
traffic is deviation V-5's cost and stays visible.

**Evidence.** `test_tc04_a_real_detect_encrypt_recover_cycle_verifies` in
`services/response/recovery/tests/test_integration.py` drives the whole loop
with nothing hand-written into the ledger — the Monitor sees a clean file, a
snapshot is taken, the file is encrypted, the Monitor detects it and writes the
ciphertext's hash as the newest one on the path, and recovery still verifies
against the baseline. Every other TC-04 test logs `file_baseline` itself, which
proved the check worked *given* a good hash and could not prove the system ever
produced one.

---

## D2 — The corpus contradicted itself, and the headline hid it

`src/train_behavioral_model.py` built its benign class like this:

```python
add(b"\x89PNG\r\n\x1a\n" + os.urandom(size), f"photo_{index}.png", 0)
```

and its malicious class like this:

```python
add(b"\x89PNG\r\n\x1a\n" + os.urandom(size), f"spoofed_{index}.png", 1)
```

The same expression, with opposite labels. Not a hard case — an **unlearnable**
one. No model could separate those two classes and none should have been able
to; there was no feature in the vector that distinguished them because there was
no difference to distinguish.

The aggregate accuracy was 88.4% and reported as a virtue: the docstring said an
earlier corpus had scored 1.000 and "measures nothing", so the lower number was
"the one that means something". It meant something, but not that.

Per-kind accuracy on the held-out set is where it shows. Rebuilding the previous
corpus and model from `git show HEAD:src/train_behavioral_model.py` reproduces
aggregate accuracy 0.880 / ROC AUC 0.959, and underneath it:

| Kind | Accuracy | Why |
|---|---|---|
| `spoofed` | **10.3%** | identical construction to `photo`/`archive`/`clip`, opposite label |
| `clip` | 80.6% | magic bytes + noise; indistinguishable from `spoofed` |
| `archive` | 84.8% | " |
| `photo` | 88.1% | " |
| everything else | 96.9–100% | genuinely different constructions |

One kind of fourteen scoring 10% is invisible in an average — it was two of
the twenty-two samples built per iteration — and it takes three more kinds down
with it.

**Those percentages move by several points per run**, which is a second finding:
the corpus was not reproducible, so neither were any of the figures quoted from
it. The committed numbers could not be re-derived, only re-rolled. Three separate
causes, and each had to be fixed for the claim to hold:

1. **`os.urandom`** for every random payload, so the corpus was different on
   every execution. The builders now take an `entropy` callable and the trainer
   passes one backed by a seeded `numpy.random.default_rng(42)`.
2. **`zipfile` stamps `time.localtime()`** and the host platform into every
   member it writes. Pinned to a fixed `ZipInfo` timestamp and `create_system`.
3. **`gzip.compress` writes the current time** into four bytes of its header.
   Pinned with `mtime=0`.

Two and three each perturb a handful of bytes in a 200 KB sample, which is
invisible in a file you are about to open and quite visible in aggregate: with
only the first fixed, two consecutive retrains still disagreed on ROC AUC in the
fifth decimal and shuffled the feature importances. With all three fixed, two
consecutive retrains produce byte-identical metrics — verified, not assumed.

The docstring was also wrong in three separate ways about what the corpus was.
It claimed "real archives, images, PDFs and documents" and "the same content
actually AES-encrypted". There is no AES anywhere — the malicious samples are
`os.urandom`; the malicious samples are not encrypted copies of the benign ones;
and several of the "images" were four magic bytes and noise.

**The fix is not to drop a class.** It is to make the benign files genuinely be
the format they claim, so there is something real to separate them by.
`scripts/synthetic_corpus.py` builds them: PNGs with a correct IHDR CRC and an
IDAT that inflates, JPEGs with a real JFIF marker chain, PDFs with a real
cross-reference table, MP4s whose box chain tiles the file exactly, real ZIP
central directories, real deflate streams. The forgeries are untouched. The pair
is the experiment, and `container_structurally_valid` is what reads it.

The docstring now says plainly that the corpus is **synthetic and procedurally
generated**, that nothing in it is a real photograph or a real ransomware
artefact, and why.

**The same defect was in the false-positive benchmark.** Seven of the forty
files in `_benign_corpus` were built the same way, so the graded 0/40 was
measured over files no user has ever had. Against a detector that checks
structure they are forgeries, and reporting 0/40 on them would have been
reporting a number about the wrong corpus. They are built properly now, and the
benchmark still reads 0/40 — which is the version of that number worth quoting.

`per_kind_accuracy` is produced on every training run rather than reconstructed
by hand afterwards, because it is the statistic that made the defect visible.

---

## D3 — A training-mode ceiling cost one write to move

`services/monitor/suppression.py` learns the highest entropy each extension
reaches during a training window, then stops alerting at or below it. Its
docstring said:

> The entropy ceiling is what keeps this from becoming a hole. […] Learning a
> workload therefore cannot teach the detector to ignore that workload being
> encrypted.

`observe()` refused any event carrying a differential-entropy rise, which is
what that claim rested on. But a file that has just been **created** has no
baseline, so `entropy_delta` is `None`, so `_rose()` is `False`, so there is
nothing to refuse. Anyone able to write into the watched tree while training was
learning could write one file at 7.99 bits/byte and lift the ceiling for that
extension to 7.99. Real encryption at 7.98 was then suppressed. Measured: one
poison write.

Three changes price it, and a fourth bounds what any residual is worth:

1. **Dwell.** A reading is recorded as a candidate immediately but only becomes
   a ceiling once its path has been under observation for
   `TRAINING_DWELL_SECONDS` (30 by default). A file created for the purpose has
   to survive the window instead of being written and spent.
2. **Structural validity.** A file whose declared container is forged never
   contributes and is never suppressed. Whatever it is, it is not an example of
   the format it claims, so it is not an example of anything.
3. **Structural class in the key.** Ceilings are keyed by
   `(extension, structural class)`, so a ceiling learned from real ZIP archives
   named `.docx` cannot be spent on a `.docx` that is raw ciphertext. That is
   the difference between learning "this workload produces high-entropy
   archives" and learning "ignore anything called .docx".
4. **A cost bound.** See below — a training-mode ceiling is priced LOW, so
   whatever it is poisoned to, it can only ever cancel a static-entropy verdict
   on a file with no measurement history. It cannot cancel an entropy rise, a
   forged container, or intermittent encryption.

None of the first three makes poisoning impossible. An attacker patient enough
to write early in a long window and wait still raises a ceiling. The fourth is
why that is survivable, and stating it that way is more useful than claiming a
close that is not there.

---

## D4 — The entropy floor could be flushed by five writes

`detection.EntropyHistory` kept `ENTROPY_HISTORY_WINDOW` readings per path and
took the minimum as the baseline a rise is measured against. Taking the minimum
rather than the previous reading was itself a fix for multi-pass encryptors —
the `staged` family — and it was the right one. It just left the window
flushable.

Five is the window size. Five writes at any entropy below `ENTROPY_RISE_FLOOR`
(7.0) do not alert on their own and push the document's original reading out of
the deque. The sixth write is the ciphertext: measured against the warm-up
writes the rise is about 1.5, under the 2.0 threshold, so differential entropy
says nothing — and a ZIP magic pasted over the ciphertext then collected the
container exemption. **Six writes, both of Table 5.7's built mitigations
defeated, zero alerts.**

The lowest substantive reading ever taken on a path is now kept alongside the
window and cannot be evicted from it. Every substantive reading updates it,
including — especially — readings below the rise floor, since those are exactly
what an attacker uses to flush.

The cost is a detector that grows more sensitive on a long-lived path: a file
that legitimately spends time at low entropy and later holds compressed content
reads as a rise. That is a real false-positive source. It is bounded the same
way everything else here is — the floor lives inside the per-path record, so the
4096-path eviction and `forget()` on delete both drop it, and a restart clears
it.

**Evidence.** `grinder` in `scripts/ransomware_simulator.py` is this attack, and
`test_grinder_cannot_flush_the_entropy_baseline` drives it write by write.
Asserted on the entropy delta rather than on `suspicious`, because structural
validation catches that file anyway — which is defence in depth working, and
also exactly how a regression in the floor would hide.

---

## D5 — Two families the sweep reported as undetected

`reports/simulator_families.json` recorded `partial` 0/8 and `spoofer` 0/8, and
`docs/APPROACH.md` §8 argued both were honest limits of whole-file entropy
rather than tuning left undone. That argument was half right.

**`spoofer`** writes a new `.zip` carrying a real ZIP magic over ciphertext and
deletes the original. With no prior reading on that path there is no rise, and
the container exemption explained the entropy away —
`"entropy 7.99 explained by zip container"`. The mitigation was the evasion.

`services/monitor/containers.py` asks the question the magic byte cannot: is the
rest of the file shaped like the format it claims? A ZIP records a central
directory whose offset must land on a real record; a PNG CRCs its image header
and ends with IEND; a JPEG chains length-prefixed marker segments to the start
of scan; a PDF numbers its objects and names its cross-reference offset; ISO
base media tiles its boxes exactly. The cost of borrowing the exemption goes
from four bytes to a working encoder.

The check has **three** outcomes, not two, and the third is what keeps it from
being a false-positive generator. A file that is still being written also fails
a structural check, for an entirely innocent reason — an archiver appending to a
500 MB ZIP has no central directory yet. So each validator separates *does the
leading structure parse* (is this the format at all) from *is the terminal
structure present* (is it finished):

| head | tail | result | effect |
|---|---|---|---|
| ok | ok | `VALID` | the exemption applies |
| ok | absent | `INCOMPLETE` | no verdict — judged again on the next write |
| bad | — | `FORGED` | evidence |

Measured over 5,600 truncated real files: none read as forged. Over 3,000
forgeries: all forged. Over 2,100 complete real files: all valid.

**`partial`** scrambles the leading quarter of each file, leaving whole-file
entropy around 5.2 against a 7.5 threshold. The objection to fixing it was that
per-block entropy also fires on the compressed blocks inside any `.docx` or PDF,
and would cost the 0 % false-positive rate.

The objection was correct and the conclusion did not follow. `.docx`, PDF, MP4
and ZIP all have that profile *and are all structurally valid containers*. So
the block rule is gated on the file not being one, and the false-positive cost
the objection predicted does not arrive: the benchmark still reads 0/40. The
gate is what makes the technique affordable, and without it the objection would
have been right.

`strider` was added because `partial` only touches the front of a file, and a
detector could pass it by looking at the first block alone without ever noticing
it had solved a narrower problem. `strider` encrypts 4 KB and skips 8 KB, to the
end of the file — which is what LockBit 3.0 and BlackCat actually do.

---

## The admissibility layer

The four fixes above are four instances of one idea, and `services/monitor/admissibility.py`
is the idea written down rather than re-derived:

> Every detection signal has an **avoidance cost** — what an attacker must spend
> to not trigger it. Every suppression has a **forgery cost** — what an attacker
> must spend to make it fire on a file they control. A suppression may cancel a
> detection only when forging the suppression costs at least as much as avoiding
> the detection.

| Detection signal | Avoidance cost | What avoiding it takes |
|---|---|---|
| `ransom_extension` | negligible | do not rename the file |
| `static_entropy` | negligible | write four magic bytes |
| `structural_mismatch` | moderate | emit a file that really is the format |
| `partial_entropy` | moderate | keep every 4 KB block under 7.9 |
| `entropy_rise` | moderate | a path never seen at lower entropy |

| Suppression | Forgery cost | What forging it takes |
|---|---|---|
| hash whitelist | high | a SHA-256 preimage |
| path whitelist | low | write into an approved directory |
| training-mode ceiling | low | get a file into the learned baseline |

Read against that table, the two rules this project had already derived by hand
are the two rows they have to be — a hash rule outranks everything, a path rule
yields to an entropy rise — and the two nobody had thought of fall out without
being thought of: a learned ceiling cannot cancel a forged container, and cannot
cancel intermittent encryption. Both are moderate to avoid; the ceiling is low
to forge.

Note the ordering is by **cost, not severity**. A known ransomware extension is
the loudest signal in the system and the cheapest to avoid, so it ranks lowest.
The static entropy threshold was — until structural validation existed —
avoidable for four bytes, which is why it is priced *negligible* and not *low*:
the exemption it bought was worth exactly nothing against an attacker who had
read the source.

A suppression that is outranked is **attenuated**, not discarded. The alert
stands, and the rule, both costs and the outcome are recorded on the event and
into the ledger. The previous implementation returned `None` in that case, which
on the event is indistinguishable from "no rule matched" — so an operator whose
whitelist was being overridden had no way to see it.

Unknown values fail closed in both directions: an unrecognised detection signal
is treated as the most expensive thing to avoid, and an unrecognised suppression
as the cheapest thing to forge. A new detection added without a cost entry keeps
its alert; a new suppression added without one suppresses nothing until someone
prices it.

---

## What the evidence says

All of the following is regenerated by the commands at the end of this document.

### Simulator families — `reports/simulator_families.json`

| | Before | After |
|---|---|---|
| Families | 10 | 13 |
| Detected | 8 | **13** |
| Detected within 2 s | 8 | **13** |
| Caught on every file | yes, of those detected | **yes, all 13** |
| `--restore` round-trips | 10/10 | **13/13** |

The three added families each attack something that did not exist before:
`strider` (strided intermittent encryption), `grinder` (window flush behind a
container header), `poisoner` (ceiling poisoning during a live training window).
Each family is asserted against the *evidence* that should catch it, so a
regression in one layer cannot hide behind another.

`poisoner` runs against a real training window opened with the production dwell.
`training_learned` in its result is `[]` — the ceiling the attacker tried to buy
does not exist.

### Benchmarks — `reports/as_benchmarks.json`

| Measurement | Before | After | Target |
|---|---|---|---|
| Detection latency p95 | 27.0 ms | **25.8 ms** | <100 ms |
| False positives | 0/40 † | **0/40** | <5% |
| Forged containers detected | not measured ‡ | **48/48** | — |
| True positives | 30/30 | **30/30** | — |
| CPU while monitoring | 1.35% of 14 cores | **1.02%** | <15% |
| Peak memory | 71.4 MB | **70.5 MB** | <500 MB |

† over a corpus in which seven of the forty files were forged containers
mislabelled as benign; see D2.
‡ it would have been 0/48, silently — which is the point of adding it. A
false-positive rate can always be driven to zero by detecting nothing, and this
is the number that says whether it was.

The latency figure is worth a note: structural validation adds a bounded tail
read, and block profiling adds per-block entropy. Neither shows, because the
tail read is skipped entirely for files that fit inside the leading sample, and
the block profile is derived from the per-block histograms the whole-file
histogram is summed from rather than from a second walk over the bytes.

### Behavioural model — `models/behavioral_model_metrics.json`

| | Before | After |
|---|---|---|
| Accuracy | 0.8843 (0.880 on re-run) | 0.9954 |
| ROC AUC | 0.9585 (0.959 on re-run) | 0.9999 |
| Features | 7 | 11 |
| Worst kind | `spoofed` 10.3% | `partial` 96.0% |
| Reproducible | no — `os.urandom` corpus | yes — seeded corpus |

**This is the number to be most careful with.** It is an in-distribution split
of a corpus this repository generates itself. It moved because the corpus
stopped contradicting itself, not because the model learned anything new about
ransomware, and a corpus fix does not earn a generalisation claim. The held-out
evidence for this model's problem is the simulator sweep, whose files are
produced by a separate program by a separate mechanism.

The top feature is `container_structurally_valid` at 0.38, followed by
`chi_square_uniformity` at 0.19 and the block-entropy scalars.

### Suite

424 tests before, **467** after (465 passing, 2 skipped) across five services.
The two skips predate this work and are correct: `psutil.terminate()` maps to
`TerminateProcess` on Windows, which no process can ignore, so the
SIGTERM-escalation tests assert a POSIX guarantee with no Windows equivalent.

---

## What is still open

* **Only six formats have structural validators** — ZIP, GZIP, PNG, JPEG, PDF,
  ISO base media. A `Rar!`, `7z`, `BZh`, XZ, zstd or lz4 header over ciphertext
  still buys the container exemption on its magic bytes alone. The training
  corpus contains real bzip2 and XZ streams with **no** forged counterparts,
  because nothing in the feature vector distinguishes them and labelling them
  apart would manufacture a result.
* **GZIP has no terminal check.** Its CRC-32 trailer can only be verified by
  inflating the whole member, so a truncated GZIP reads as valid.
* **A JPEG truncated before its start-of-scan marker** — the first few hundred
  bytes of a write — reads as forged rather than incomplete.
* **A patient attacker can still poison a training ceiling** by writing early in
  a long window and waiting out the dwell. What that buys is bounded by the
  admissibility layer, not eliminated.
* **The entropy floor makes long-lived paths more sensitive** over time. Bounded
  by path eviction and cleared on restart.
* **`_SEEN_FILES` is unbounded** — a slow leak on a long-lived watch. `EVENTS`
  is bounded; this is not. Untouched here; it wants its own change.
* **`models/io_behavior_model.pkl` is trained and served by nothing.** It has
  its own independent `FEATURE_NAMES` and the ML engine does not load it. A
  trained model nothing serves belongs in the limitations chapter.

---

## Reproducing all of it

```bash
for svc in gateway ledger monitor ml-engine response; do (cd services/$svc && python -m pytest -q); done
```

```bash
python src/train_behavioral_model.py
```

```bash
URDS_WRITE_REPORTS=1 python scripts/simulator_sweep.py --files 8 --settle 2.0
```

```bash
cd services/monitor && URDS_WRITE_REPORTS=1 python -m pytest -m benchmark -q -s
```

`URDS_WRITE_REPORTS=1` is required to write anything into `reports/`. Without
it every benchmark still measures and still asserts; what the flag gates is
overwriting committed evidence, so a plain `pytest -q` cannot silently move a
figure the write-up cites.
