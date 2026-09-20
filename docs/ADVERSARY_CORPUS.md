# The adversary corpus

**Phase 5 of the URDS build plan: prove it against an adversary you did not
write.** Dated 20 September 2026, branch `fix/evidence-integrity`.

Everything measured here was done by software this project did not write.
There is no encryptor in this repository and there is not going to be one: an
attack written by the same hand that measures the response is not evidence, it
is a demonstration. The two scripts are deliberately split —
`scripts/adversary_runner.py` starts other people's binaries and measures
nothing; `scripts/adversary_corpus.py` measures and encrypts nothing — and a
test asserts that neither of them imports a crypto library.

| | |
|---|---|
| attack corpus | `scripts/adversary_corpus.py` → `reports/phase5_attack_corpus.json` |
| benign corpus | `scripts/benign_soak.py` → `reports/phase5_benign_soak.json` |
| the harness's own gates | `agent/tests/test_phase5.py` |
| claims | `scripts/claim_matrix.py` rows C-19 and C-20 |

---

## 1. What the attack corpus is

Six arms. Each is a command line handed to a binary from somewhere else, and
they differ in the shape of the **process**, which is what decides whether a
response can reach the attacker at all.

| arm | tool | process shape |
|---|---|---|
| `openssl-loop` | OpenSSL (Git for Windows) | one short-lived process per file, original unlinked |
| `openssl-inplace` | OpenSSL | one process per file whose **stdout is the file it is reading**, opened `r+b` — the open-existing-and-write-over case |
| `gpg-loop` | GnuPG | one short-lived process per file, original unlinked |
| `sevenzip-archive` | 7-Zip | one long-lived process, everything into one encrypted archive, originals unlinked by `-sdel` |
| `sevenzip-root` | 7-Zip | the same, pointed at the protected root, so it meets the decoys |
| `atomic-t1486` | Red Canary's Atomic Red Team, T1486-8 | one long-lived PowerShell host, one short-lived `gpg.exe` per file beneath it |

`nextron-quickbuck` (NextronSystems' `ransomware-simulator`) is implemented and
is not in the host run: it is reserved for the clean virtual machine.

### The technique named by number

The build plan names **T1486**. Red Canary publishes ten atomics for it, four
of them for Windows, and only one can be run inside a protected path. The other
three are excluded by the blast-radius rule and not by preference —
`docs/LIMITATIONS.md` §16 has the table and the reasons, the short version
being that two of them hardcode paths outside every protected path and the
third encrypts a whole volume with DiskCryptor.

The one that runs, **T1486-8 "Data Encrypted with GPG4Win"**, is invoked
through `Invoke-AtomicTest` against Red Canary's own YAML rather than
transcribed into PowerShell here. Its executor ignores its own
`GPG_Exe_Location` input argument and hardcodes GPG4Win's path; that is a
defect in the atomic, worked around rather than patched, because a patched
atomic is no longer the published one.

---

## 2. How attribution is graded

Against an answer key written by the side that **launched** the encryptors,
never against the agent's own record. `adversary_runner.py` appends one line
per process it starts, with the PID the operating system returned, and fsyncs
it. The measuring script reads that file and grades every `file_event` block in
the hash chain against it.

Three things about the key are not obvious and each of them was a bug first:

* **It holds the process tree, not just the child.** The Atomic Red Team arm
  starts `powershell.exe`, which starts `cmd.exe`, which starts `gpg.exe`, and
  gpg is the one whose handle the bytes go through. A key holding only the
  PowerShell host would score every correctly-named `gpg.exe` as a
  *mis-attribution* — manufacturing the one number this branch exists to keep
  at zero.
* **It records launches, not distinct PIDs.** Windows recycled enough PIDs
  inside one 200-file loop that 200 launches produced 180 distinct numbers.
  Keyed by PID the key is twenty launches short of what happened.
* **A PID observed as suspended is checked against its creation time.** See
  `docs/CORRECTIONS.md` correction 13: an earlier run of this harness reported
  a time-to-suspend of 12.3 seconds from a PID the agent had never touched.

---

## 3. The attack corpus — measured

Six arms, 200 files each (245 for the root-scope arm), agent running, elevated
[`reports/phase5_attack_corpus.json`]:

| arm | detected | events | CERTAIN | mis-attributed | suspended | FEBR |
|---|---|---|---|---|---|---|
| `openssl-loop` | yes | 400 | 19 | **0** | no | 182 |
| `openssl-inplace` | yes | 296 | 216 | **0** | no | 200 |
| `gpg-loop` | yes | 493 | 0 | **0** | no | 200 |
| `sevenzip-archive` | **no** | 0 | 0 | **0** | no | 200 |
| `sevenzip-root` | yes | 16 | 20 | **0** | no | 245 |
| `atomic-t1486` | **no** | 0 | 0 | **0** | no | 200 |

```
mis-attributions across every arm            0   (the plan requires 0)
files restored and verified              1,227 / 1,227
restore failures                             0
chain valid                               true   over 288,355 blocks
a third-party encryptor suspended within
  20 files and 2 s                       FALSE   ← the plan's bound, not met
```

### The bound that is not met

**No arm was suspended.** `docs/LIMITATIONS.md` §4 is why, and it is a property
of the corpus rather than of the response: an encryptor that is a new process
per file lives about 65 ms, and the audit record naming it is delivered
600–1010 ms later. The response is correct and it is late, every time. The two
long-lived arms — 7-Zip and the Atomic Red Team PowerShell host — were not
detected at all, for the two separate reasons below, so there was nothing to
suspend either.

### Two arms produced no events, and both reasons are measured

**`sevenzip-archive`** archives 200 files into one encrypted `.7z` and deletes
the originals. The output is a *structurally valid* container, which the
detector deliberately treats as benign, and the deletions carry no content to
measure. `docs/LIMITATIONS.md` §14.

**`atomic-t1486`** is the more interesting one, because it is somebody else's
attack run unmodified and it is invisible by arithmetic:

```
block 287959  document_0000.csv       entropy 4.73  size 9814  benign
block 288156  document_0000.csv.gpg   entropy 6.52  size  123  benign
```

The atomic overwrites its target with a fixed 37-byte string and GPG-encrypts
that, so its ciphertext is 123 bytes. Shannon entropy over 256 symbols is
bounded by `log2(N)`, and 200 measured draws of `os.urandom` do not reach 7.5
bits per byte until **356 bytes**. Across all 199 `.gpg` files this arm
produced, entropy ran 6.02–6.67. Not one of them could have crossed the
threshold at any quality of encryption. `docs/LIMITATIONS.md` §22.

### An unexpected result: the detector blocks the attacker's delete

`openssl-loop` left 18 of 200 originals in place, and the runner now records
why:

```
unlink refused for 18 originals
[WinError 32] The process cannot access the file because it is being
used by another process
```

The detector opens every file it judges, to read its entropy. Windows will not
unlink a file another process has open. So the detection path, which cannot
suspend this encryptor, incidentally prevented 9 per cent of its deletions —
and the same mechanism is the most likely explanation for `git gc` failing 247
of 272 runs in the benign corpus. It is accidental, it is unmeasured as a
mitigation, and it is a cost on the benign side at the same rate.

---

## 4. The benign corpus — measured

Nine third-party workloads looping inside the protected path for 60.2 minutes
with the agent running [`reports/phase5_benign_soak.json`]:

```
workload runs                          3,385  over 519 cycles
suspensions of this run's processes        6  = 5.98 per hour
  all six                            git.exe
  all six                            resumed, none terminated
suspensions of anything else               0
file events flagged                    3,204  = 3,194 per hour
chain valid                             true  over 184,841 blocks
```

**The build plan asks for zero suspensions and six is not zero: this item is
not met.** What the six are made of is in `docs/LIMITATIONS.md` §19 — one tool,
`git`, during the workload that writes hundreds of small high-entropy files in
a burst, and every one of them resumed rather than killed.

The larger number is the more interesting one. 3,204 alerts against 6
suspensions is a ratio of 534 to 1, and the reasons read literally:

```
entropy 7.94 >= 7.5; no recognised container header   ← makecab output
entropy 7.9x >= 7.5; no recognised container header   ← .git/objects/*
```

Git's loose objects are raw zlib streams; cabinet files are a format the
registry has no validator for. Under every content-only predicate this system
has, both are the same shape as ciphertext. That is the separability result of
`docs/THESIS.md` §7.8 arriving from the benign side — Chapter 7 reached it from
a constructed corpus, this reached it by pointing ordinary tools at a directory
for an hour and counting.

Six members of the plan's benign corpus are not installable on this host and
are named in the artefact with reasons. `npm-install` failed all 519 attempts
and measured nothing. The rate is therefore a **lower bound**.

---

## 5. What the harness had to learn first

Five of the six defects this phase found are in the measuring script, not the
system, and two of them were found only because a result looked wrong rather
than because anything went red. They are worth reading before any number
below.

| # | what it published | what was true |
|---|---|---|
| 13 | `tts_s 12.307` for `openssl-loop` | Windows had recycled a 65 ms process's PID; the agent never touched it |
| 14 | `gpg-loop` FEBR 200, TTS null | it suspended the 104th of 200 writers and the chain said so |
| 15 | `removed <workdir>` | 139 MB of a git clone was still in the protected path |
| 16 | five arms `detected=False`, 0 events | the agent wrote 1,208 `suspected_encryption` blocks for three of them, after the harness had looked |
| 17 | **five mis-attributions** | the agent had correctly named `makecab.exe` and `git.exe` for a *different* workload's files, still in its queue |

16 is the one to understand. The harness verified the entire hash chain once
per arm — 285,632 blocks, a full table scan, against a ledger deliberately not
in WAL mode — so its own reads held a lock the agent's appends queued behind.
**The measuring script starved the thing it was measuring and then published
the starvation as a detection failure.** Each arm now verifies only its own
window, the whole-chain walk happens once per run, and after each arm a
sentinel file is written into the protected path and waited for: the agent
processes its queue in order, so the sentinel's block arriving means everything
before it has been dealt with. An arm whose sentinel never arrives is out of
bounds, because a chain read before its writer finished is not evidence about
the writer.

---

## 6. What the harness does not let itself do

The four gates that stop a result being better than it earned, each in
`agent/tests/test_phase5.py`:

1. **An arm nobody detected cannot pass.** FEBR and TTS have bounds that only
   apply once something has been suspended, so an arm the agent never noticed
   exceeds neither and reads `ok`. The first version of this script had exactly
   that: 7-Zip archived the protected root, deleted twenty decoys, and the arm
   was reported as within bounds.
2. **A missing tool is a failed arm, not a skipped one** — including a missing
   *atomic*, which matters because that arm launches PowerShell and PowerShell
   is on every Windows host.
3. **FEBR is a number when nothing was suspended.** `null` reads as no damage;
   it means the attacker got everything.
4. **The attack is not in the file that measures it**, asserted by parsing both
   scripts' imports.

---

## 7. Where to look next

* `docs/CORRECTIONS.md` 11–17 — the seven defects this phase found, five of
  them in the harness rather than the system.
* `docs/LIMITATIONS.md` §14–§21 — what this phase established that the system
  does not stop, including the valid-container case, the false-positive rate,
  and the fact that verifying the chain can stop the chain being written.
* `docs/THESIS.md` §7.8 — the separability result the benign corpus
  corroborates.
