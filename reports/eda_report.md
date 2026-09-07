# EDA report - EMBER, CLEAR and RanSAP

Table 5.4, Weeks 1-4: *"Dataset acquisition (EMBER, CLEAR, RanSAP), exploratory
data analysis, feature understanding"*, deliverable *"EDA report"*, success
criterion *"Dataset characteristics documented"*.

Generated 2026-08-12T16:51:50.403017Z by `src/eda_datasets.py`. Every number below
is measured from the files in `data/`.

## Summary

| Dataset | Unit of a row | Rows | Labels | Role in the project |
|---|---|---|---|---|
| EMBER | one PE file | 50,000 | 25,000 benign / 25,000 malicious | Training input - static-PE classifier |
| CLEAR | one I/O operation | 1,000 | 447 benign / 553 ransomware | Training input - I/O behaviour classifier |
| RanSAP | one I/O operation | 668,881 | by trace (ransomware vs benign run) | Training input - I/O behaviour classifier |

## EMBER

- Path: `data/ember_subset/ember_50k.parquet`
- 50,000 samples, 2,381 features each
- Class balance: 25,000 benign / 25,000 malicious (ratio 1.0)
- Unique SHA-256 values: 50,000 (no duplicate samples)
- Feature families: EMBER v2 static feature vector: byte histogram, byte-entropy histogram, string statistics, general file info, PE header, section table, imports, exports and data directories

The corpus is exactly balanced, which is the measurement that decides the
SMOTE question in `docs/APPROACH.md` §8.

## CLEAR

- Path: `data/clear_io/wannacry_io_sample.csv`
- 1,000 I/O operations across 6 process/label combinations
- Class balance: 447 benign / 553 ransomware operations

Operations by process:

| Process (label) | Operations |
|---|---|
| `sample_BlackMatter_e4fd.bin (label 1)` | 409 |
| `MRT.exe (label 0)` | 194 |
| `System (label 1)` | 144 |
| `SearchFilterHost.exe (label 0)` | 143 |
| `System (label 0)` | 101 |
| `SearchIndexer.exe (label 0)` | 9 |

Access-pattern counters, mean per operation. These are CLEAR's behavioural
fingerprint: write-after-read, read-after-read, read-after-write,
write-after-write.

| Label | WAR | RAR | RAW | WAW |
|---|---|---|---|---|
| 0 (benign) | 0.1074 | 9.4206 | 1.0201 | 2.613 |
| 1 (ransomware) | 0.0 | 0.0 | 0.0018 | 14.3363 |

The separation is stark and is the reason CLEAR is worth training on:
benign processes re-read what they have read (high RAR), ransomware
overwrites what it has written and never reads it back (high WAW, RAR at
zero). That is the encrypt-in-place signature expressed in I/O terms.

*Rows are individual I/O operations from one instrumented run, not per-file samples. There is no key on which a CLEAR row could be joined to an EMBER row, so the two corpora train two models rather than one merged feature matrix.*

## RanSAP

| Trace | Operations | Duration (s) | Mean size | 4KB share |
|---|---|---|---|---|
| ransomware_write | 454,596 | 93 | 4,096 | 99.99% |
| ransomware_read | 95,689 | 95 | 3,708 | 83.92% |
| benign_write | 47,403 | 222 | 4,090 | 99.81% |
| benign_read | 71,193 | 192 | 4,039 | 97.57% |

### Write entropy - the mean is the wrong statistic

RanSAP normalises entropy to 0-1 rather than bits/byte. Read straight,
the numbers say ransomware writes are *less* random than Firefox's,
which is the opposite of the premise the whole detector rests on. The
distribution shape explains it:

| Trace | Mean | Median | p95 | Max | Share > 0.9 | Share < 0.05 |
|---|---|---|---|---|---|---|
| ransomware_write | 0.1918 | 0.0 | 0.9943 | 0.9996 | 9.76% | 68.62% |
| benign_write | 0.3716 | 0.4333 | 0.6372 | 0.996 | 2.68% | 22.70% |

The ransomware trace is **bimodal**. Roughly two thirds of its writes sit
at effectively zero entropy - zero-fill over the originals it is
destroying, plus filesystem metadata - and the remainder sit at the
ceiling, which is the ciphertext. Averaging those two modes together
produces a number that describes neither.

The benign trace is unimodal around its median and its 95th percentile
never approaches the ceiling the ransomware trace reaches in bulk.

So the separating statistic is the **shape of the upper tail**, not the
centre. That is what `src/train_io_behavior_model.py` scores: it windows
the trace and takes the high-entropy share of each window, rather than a
single per-operation reading. A per-operation threshold on this data
would be close to useless in both directions.

*RanSAP write traces carry per-block entropy measured by its own collector, which is the only real (non-synthetic) encryption entropy in the repository. Read traces carry no entropy column.*

## What each dataset is used for, and why

The three corpora do not share a unit of observation. An EMBER row is a PE
file; a CLEAR row and a RanSAP row are each a single I/O operation from an
instrumented run. There is no key on which they could be joined, so merging
them into one feature matrix is not possible without inventing a
correspondence that does not exist.

They therefore train two models, both of which serve:

1. **Static-PE classifier** (`models/xgboost_model.pkl`) - EMBER only. Scores an
   executable before it runs.
2. **I/O behaviour classifier** (`models/io_behavior_model.pkl`) - CLEAR and
   RanSAP, windowed into per-process bursts. Scores what a process is *doing*
   to the file system, which is the signal a packed or previously unseen
   binary cannot hide.

A third model, the file-content behavioural classifier
(`models/behavioral_model.pkl`), is trained on a generated corpus because no
public dataset carries the raw bytes of encrypted user documents alongside
their benign originals. That is stated in `docs/APPROACH.md` §8.
