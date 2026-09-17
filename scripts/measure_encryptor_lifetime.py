"""How long does a third-party encryptor actually exist, and when does it unlink?

The response cannot suspend a process that has exited. Attribution arrives with
the audit record, and `scripts/measure_attribution_lag.py` measured that record
at 600-1010 ms after the write. So the question that decides whether a given
encryptor shape is reachable at all is not how good the detector is - it is how
long the process lives.

This measures that, for the two shapes the Phase 3 acceptance runs, with
nothing else involved. It writes into a temporary directory outside any
protected path, so the agent is not running against it and the numbers are the
tools' own.

    python scripts/measure_encryptor_lifetime.py
    URDS_WRITE_REPORTS=1 python scripts/measure_encryptor_lifetime.py

Writes reports/encryptor_lifetime.json only when URDS_WRITE_REPORTS=1.

Why it exists
-------------

`reports/agent_phase3_acceptance.json` previously explained arm A1's escape by
saying that 7-Zip's `-sdel` "unlinks the originals only after the archive
completes, so all 520 deletions land in the process's final moments". That was
not measured. It was inferred from an acceptance harness that sampled the file
count only when the set of live PIDs changed - and arm A1 is a single process,
so after the first sample there was never another one until the run ended. One
sample at the start and one at the end look exactly like "nothing happened
until the end".

What it found
-------------

7-Zip archives and unlinks five hundred 100 KB documents in **230-383 ms**
across runs, at 124-200 MB/s, with the first unlink about 130 ms in. The
spread is disk cache state; the category below it does not move. So `-sdel` does
delete during the run rather than only at the end - and it barely matters which,
because the entire process is over in a quarter of the time it takes for the
audit record naming it to arrive.

That is the whole reason arm A1 is not suspended, and it is a different reason
from the one that was published. The container-separability result (§6 of
LIMITATIONS.md) is real, but it is not what saves A1: in the acceptance the
decoy tripwire *did* fire, the agent *did* attribute the deletions to `7z.exe`
with `CERTAIN` confidence, and the response was refused only because the PID no
longer existed. A perfect verdict on the archive's contents would have changed
nothing.

The same measurement is the reason a benign arm has to be given real work. A
7-Zip archive that finishes in 130 ms "completes untouched" whatever the
detector thinks of it, so an arm that short is not evidence of specificity.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Where the acceptance finds them. Overridable so this runs on another host.
SEVEN_ZIP = Path(os.getenv("URDS_SEVEN_ZIP", r"C:\Program Files\7-Zip\7z.exe"))
OPENSSL = Path(os.getenv(
    "URDS_OPENSSL", r"C:\Program Files\Git\mingw64\bin\openssl.exe"))

CORPUS = int(os.getenv("URDS_LIFETIME_CORPUS", "500"))
DOC = (b"Quarterly report section 0. " * 3400) + b"\n" * 64

#: From reports/attribution_delivery_lag.json, the same host.
DELIVERY_LAG_MEDIAN_MS = 601.0
DELIVERY_LAG_CEILING_MS = 1011.3


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True,
                              text=True, check=False).stdout.strip()
    except OSError:
        return ""


def _present(root: Path) -> int:
    try:
        return sum(1 for entry in os.scandir(root)
                   if entry.is_file() and entry.name.startswith("doc_"))
    except OSError:
        return 0


def _make_corpus(root: Path) -> int:
    for index in range(CORPUS):
        (root / f"doc_{index:04d}.docx").write_bytes(DOC)
    return CORPUS * len(DOC)


def _reachability(lifetime_ms: float) -> str:
    """One of three words, so the claim matrix can assert an outcome.

    The underlying figure is a timing and moves by tens of milliseconds between
    runs; the category does not, because each arm sits nowhere near a boundary.
    Asserting the category is asserting the finding rather than the sample.
    """
    if lifetime_ms < DELIVERY_LAG_MEDIAN_MS:
        return "unreachable"
    if lifetime_ms < DELIVERY_LAG_CEILING_MS:
        return "marginal"
    return "reachable"


def _verdict(lifetime_ms: float) -> str:
    return {
        "unreachable": "unreachable: the process is gone before the median "
                       "audit record arrives, so no response gated on "
                       "attribution can act on it",
        "marginal": "marginal: reachable only when the flush happens to land "
                    "early in the process's life",
        "reachable": "reachable: the process outlives the delivery ceiling, so "
                     "a response has a window in which to act",
    }[_reachability(lifetime_ms)]


def measure_seven_zip() -> dict | None:
    """One process, many files. Sampled continuously, which is the point."""
    if not SEVEN_ZIP.is_file():
        return {"tool": str(SEVEN_ZIP), "not_run": "7-Zip is not installed here"}

    raw = tempfile.mkdtemp(prefix="urds-lifetime-7z-")
    root = Path(raw)
    archive = Path(raw + ".7z")
    try:
        total_bytes = _make_corpus(root)
        samples: list[tuple[float, int]] = []
        started = time.perf_counter()
        proc = subprocess.Popen(
            [str(SEVEN_ZIP), "a", "-purds-lifetime", "-mhe=on", "-mx=0",
             "-sdel", str(archive), str(root) + r"\*"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # No sleep in this loop. The entire question is what happens inside the
        # first few hundred milliseconds, and a poll interval of even 50 ms - the
        # acceptance harness's - is a quarter of the process's life.
        while proc.poll() is None:
            samples.append(((time.perf_counter() - started) * 1000.0,
                            _present(root)))
        lifetime_ms = (time.perf_counter() - started) * 1000.0
        samples.append((lifetime_ms, _present(root)))

        unlinked = [(at, CORPUS - n) for at, n in samples if n < CORPUS]
        first = unlinked[0][0] if unlinked else None
        half = next((at for at, n in unlinked if n >= CORPUS // 2), None)
        return {
            "tool": str(SEVEN_ZIP),
            "shape": "one process, many files (7z a -p -mhe=on -mx=0 -sdel)",
            "corpus_files": CORPUS,
            "corpus_bytes": total_bytes,
            "exit_code": proc.returncode,
            "process_lifetime_ms": round(lifetime_ms, 1),
            "throughput_mb_per_s": round(total_bytes / 1e6 / (lifetime_ms / 1000), 1),
            "first_unlink_ms": None if first is None else round(first, 1),
            "half_unlinked_ms": None if half is None else round(half, 1),
            "first_unlink_as_fraction_of_life": (
                None if first is None else round(first / lifetime_ms, 3)),
            "samples": len(samples),
            "sdel_unlinks_during_the_run": bool(
                first is not None and first < lifetime_ms * 0.9),
            "reachability": _reachability(lifetime_ms),
            "reachable_by_an_attribution_gated_response": _verdict(lifetime_ms),
        }
    finally:
        shutil.rmtree(raw, ignore_errors=True)
        archive.unlink(missing_ok=True)


#: The acceptance arm runs 500 files. Two hundred here is a compromise between
#: representing that and not spending a minute spawning processes - and it has
#: to be enough of them, because at forty the campaign measured 1002 ms against
#: a 1011 ms ceiling and reported itself "marginal", which is a fact about the
#: sample rather than about the attack.
OPENSSL_CAMPAIGN_FILES = int(os.getenv("URDS_OPENSSL_CAMPAIGN_FILES", "200"))


def measure_openssl_loop(files: int = OPENSSL_CAMPAIGN_FILES) -> dict | None:
    """One process per file. Each child's own lifetime is what matters here.

    The campaign's driver is long-lived and is what the agent actually names -
    through the deletions, not the writes. What this measures is the other half
    of that asymmetry: how long the process that writes each ciphertext exists.
    """
    if not OPENSSL.is_file():
        return {"tool": str(OPENSSL), "not_run": "OpenSSL is not installed here"}

    raw = tempfile.mkdtemp(prefix="urds-lifetime-ssl-")
    root = Path(raw)
    try:
        for index in range(files):
            (root / f"doc_{index:04d}.docx").write_bytes(DOC)
        lifetimes = []
        campaign_started = time.perf_counter()
        for index in range(files):
            source = root / f"doc_{index:04d}.docx"
            started = time.perf_counter()
            subprocess.run(
                [str(OPENSSL), "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
                 "-in", str(source), "-out", str(source) + ".enc",
                 "-pass", "pass:urds-lifetime"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            lifetimes.append((time.perf_counter() - started) * 1000.0)
            source.unlink(missing_ok=True)
        campaign_ms = (time.perf_counter() - campaign_started) * 1000.0
        return {
            "tool": str(OPENSSL),
            "shape": "one process per file (openssl enc -aes-256-cbc)",
            "files": files,
            "files_in_the_acceptance_arm": 500,
            "writer_lifetime_ms_median": round(statistics.median(lifetimes), 1),
            "writer_lifetime_ms_max": round(max(lifetimes), 1),
            "campaign_lifetime_ms": round(campaign_ms, 1),
            "files_per_second": round(files / (campaign_ms / 1000), 1),
            "writer_reachability": _reachability(statistics.median(lifetimes)),
            "campaign_reachability": _reachability(campaign_ms),
            "writer_reachable": _verdict(statistics.median(lifetimes)),
            "campaign_reachable": _verdict(campaign_ms),
            "why_this_one_is_suspended":
                "The writer is unreachable and the campaign is not. The driver "
                "unlinks each original, so DELETE auditing names a process that "
                "is still alive; the openssl that produced the ciphertext is "
                "long gone. That asymmetry is the entire reason this arm is "
                "suspended and the 7-Zip arm is not.",
        }
    finally:
        shutil.rmtree(raw, ignore_errors=True)


def main() -> int:
    seven = measure_seven_zip()
    ssl = measure_openssl_loop()

    report = {
        "schema": "urds.encryptor_lifetime/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "_what_this_measures":
            "How long each acceptance attack arm's process exists, measured "
            "outside any protected path with the agent not involved. A "
            "response that has to wait for an audit record cannot act on a "
            "process that has already exited, so this is what decides whether "
            "an arm is reachable at all - before any question about detection.",
        "delivery_lag_median_ms": DELIVERY_LAG_MEDIAN_MS,
        "delivery_lag_ceiling_ms": DELIVERY_LAG_CEILING_MS,
        "delivery_lag_source": "reports/attribution_delivery_lag.json",
        "seven_zip": seven,
        "openssl_loop": ssl,
        "finding":
            "7-Zip archives and unlinks the whole corpus in about a fifth of a "
            "second, which is a quarter of the time its own audit record takes "
            "to arrive. It is unreachable by any response gated on attribution, "
            "and that is a fact about process lifetime rather than about "
            "detection: in the acceptance the decoy tripwire fired, the agent "
            "attributed the deletions to 7z.exe with CERTAIN confidence, and "
            "the response was refused because the PID no longer existed.",
        "consequence":
            "Two things follow. An attack arm shorter than the delivery lag "
            "measures the floor and not the agent. And a *benign* arm shorter "
            "than the delivery lag completes untouched whatever the detector "
            "decided, so it is not evidence of specificity and must not be "
            "reported as if it were.",
        "corrects":
            "reports/agent_phase3_acceptance.json previously stated that 7-Zip's "
            "-sdel unlinks only after the archive completes. It does not: the "
            "first unlink lands about 130 ms in, roughly half way through the "
            "run. That claim came from an acceptance harness that sampled the "
            "file count only when the set of live PIDs changed, and this arm is "
            "one process. See docs/CORRECTIONS.md.",
    }

    print(json.dumps(report, indent=2))
    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    out = REPO_ROOT / "reports" / "encryptor_lifetime.json"
    with out.open("w", encoding="utf-8", newline="") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
