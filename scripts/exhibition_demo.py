"""Guided exhibition demo: the whole URDS story, start to end, in one command.

    .venv\\Scripts\\python.exe scripts\\exhibition_demo.py              presenter mode (Enter = next)
    .venv\\Scripts\\python.exe scripts\\exhibition_demo.py --auto --loop  unattended kiosk loop
    .venv\\Scripts\\python.exe scripts\\exhibition_demo.py --steps 2,6    only some steps
    .venv\\Scripts\\python.exe scripts\\exhibition_demo.py --reset        clean up between visitors

(or scripts\\exhibition_demo.ps1 with the same arguments)

Every step tells the audience in plain words what is about to happen, does it
against the running stack, and reports what the system did. The console at
http://localhost:8501 shows the same activity as it happens: the Overview
follows each detection, the Ledger page holds every block it writes.

Steps
  1  Normal work is left alone          text, CSV and a real ZIP - no alarm (TC-03)
  2  A disguised encrypted file          ZIP header over ciphertext - caught (TC-02)
  3  Live attack, attacker stopped       scripts/attack_chain_demo.py (TC-01/07/09)
  4  Ransomware simulator vs URDS        20 documents, how many were lost, then undo
  5  Recovery from a shadow copy         real Windows VSS restore, hash-verified (TC-04)
  6  Tamper-evident evidence log         edit the database, the chain breaks (TC-05)
  7  Only authorised access              401 without a token, 200 with (TC-10)
  8  The numbers                         model and benchmark figures from reports/

Why this script never writes a suspicious file itself: the Monitor names the
process that wrote an encrypted-looking file and the Response service kills
it. Every suspicious write is therefore made by a short-lived child process,
exactly as scripts/attack_chain_demo.py does, so the demo is never its own
victim.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[1]
RUN = REPO / "run"
WATCH = REPO / "watched_files"
STAGE = WATCH / "exhibition"
SIM_DIR = STAGE / "office_documents"
RECOVERY_DIR = STAGE / "recovery"
BOOTSTRAP_SECRET = os.getenv("DEV_TOKEN_BOOTSTRAP_SECRET", "dev-bootstrap-change-me")
IS_WINDOWS = platform.system() == "Windows"

sys.path.insert(0, str(REPO / "scripts"))

# --------------------------------------------------------------------------- the story

STEPS = [
    {
        "n": 1,
        "key": "normal",
        "title": "Normal work is left alone",
        "story": "Every time a file changes, URDS measures how random its bytes look (entropy, 0-8) "
                 "and checks that its inner structure matches its type. Everyday files - and even ZIP "
                 "archives, which look very random - pass without raising an alarm.",
        "watch": "The pipeline turns green at the Monitor and stops there: no AI call, no alarm.",
    },
    {
        "n": 2,
        "key": "disguised",
        "title": "A disguised encrypted file is caught",
        "story": "Ransomware often hides encrypted data behind a familiar header. This file claims to "
                 "be a ZIP archive, but its structure is fake. URDS spots the forgery, the AI model "
                 "confirms it, and the evidence is sealed into the ledger.",
        "watch": "The pipeline turns red: Monitor -> AI verdict -> ledger block -> response.",
    },
    {
        "n": 3,
        "key": "attack",
        "title": "Live attack: the attacker process is stopped",
        "story": "A separate 'attacker' program encrypts a file and keeps running, like real ransomware. "
                 "URDS detects it, uses the Windows security log to identify exactly which process did "
                 "it, and terminates that process - in well under two seconds.",
        "watch": "The Response stage shows the attacker's process ID being terminated.",
    },
    {
        "n": 4,
        "key": "simulator",
        "title": "Ransomware simulator vs URDS",
        "story": "A harmless ransomware simulator starts encrypting 20 office documents one by one. "
                 "Watch how many it manages to lock before URDS stops it - then every file is put back.",
        "watch": "The document grid: red = encrypted, green = safe. Count the red ones.",
    },
    {
        "n": 5,
        "key": "recovery",
        "title": "Files restored from a Windows shadow copy",
        "story": "Stopping an attack is half the job. URDS takes a Windows Volume Shadow Copy, the file "
                 "is then encrypted, and URDS restores it from the snapshot - checking the restored "
                 "file's fingerprint (SHA-256) against the one recorded in the ledger.",
        "watch": "The Recovery stage turns green with 'hash verified'.",
    },
    {
        "n": 6,
        "key": "tamper",
        "title": "Tamper-evident evidence log",
        "story": "Every alert is sealed into a hash chain: each record carries the fingerprint of the "
                 "one before it. An attacker who edits a record in the database breaks the chain, and "
                 "URDS names the exact record that was changed.",
        "watch": "The ledger seal turns red and names the tampered block, then goes green again.",
    },
    {
        "n": 7,
        "key": "auth",
        "title": "Only authorised users can use the system",
        "story": "Every API call goes through a gateway that demands a signed token. Requests without "
                 "one are refused - and the refusal itself is written to the ledger.",
        "watch": "401 (refused) without a token, 200 (allowed) with one.",
    },
    {
        "n": 8,
        "key": "numbers",
        "title": "The numbers behind it",
        "story": "How good is it? Model accuracy and system benchmarks, measured and recorded in the "
                 "project reports.",
        "watch": "Precision, recall, F1, detection latency, kill time, CPU and memory.",
    },
]
TOTAL = len(STEPS)

# --------------------------------------------------------------------------- console

if IS_WINDOWS:
    os.system("")  # turns on ANSI colour handling in the Windows console
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "b": "\033[94m", "m": "\033[95m",
     "c": "\033[96m", "w": "\033[97m", "d": "\033[2m", "B": "\033[1m", "0": "\033[0m"}


def col(text: str, *codes: str) -> str:
    return "".join(C[c] for c in codes) + str(text) + C["0"]


def say(text: str = "") -> None:
    print(text, flush=True)


def good(text: str) -> None:
    say(f"   {col('✔', 'g', 'B')} {text}")


def bad(text: str) -> None:
    say(f"   {col('✘', 'r', 'B')} {text}")


def note(text: str) -> None:
    say(f"   {col('•', 'c')} {text}")


def warn(text: str) -> None:
    say(f"   {col('!', 'y', 'B')} {col(text, 'y')}")


def wrap(text: str, width: int = 86, indent: str = "   ") -> str:
    words, lines, line = text.split(), [], ""
    for word in words:
        if len(line) + len(word) + 1 > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        lines.append(line)
    return "\n".join(indent + item for item in lines)


def banner(step: dict) -> None:
    bar = "═" * 90
    say()
    say(col(bar, "b"))
    say(col(f"  STEP {step['n']} of {TOTAL}  ·  {step['title'].upper()}", "w", "B"))
    say(col(bar, "b"))
    say(wrap(step["story"]))
    say(col(f"\n   👀 On the screen: {step['watch']}", "y"))
    say()


# --------------------------------------------------------------------------- shared state

class State:
    """What this run did, step by step; printed as the summary at the end."""

    def __init__(self) -> None:
        self.data: dict = {
            "steps": [{"n": s["n"], "title": s["title"], "status": "pending"} for s in STEPS],
            "results": {},
            "simulator": None,
            "recovery": None,
            "tamper": None,
        }

    def set(self, **fields) -> None:
        self.data.update(fields)

    def step(self, n: int, status: str) -> None:
        for s in self.data["steps"]:
            if s["n"] == n:
                s["status"] = status

    def result(self, key: str, value) -> None:
        self.data["results"][key] = value


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- helpers

def entropy_of(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


WRITER = (
    "import sys, base64, pathlib\n"
    "p = pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True, exist_ok=True)\n"
    "p.write_bytes(base64.b64decode(sys.stdin.buffer.read()))\n"
)


def write_via_child(path: Path, data: bytes) -> None:
    """Write from a throwaway process, so a kill aimed at the writer never hits this script."""
    subprocess.run([sys.executable, "-c", WRITER, str(path)], input=base64.b64encode(data),
                   check=True, timeout=60, capture_output=True)


def plain_verdict(event: dict) -> tuple[str, str]:
    """(colour, words) a visitor understands."""
    verdict = str(event.get("verdict") or "")
    if verdict == "benign_compressed":
        return "g", "real compressed file - safe"
    if verdict == "benign":
        return "g", "normal file - safe"
    if verdict == "deleted":
        return "d", "file removed"
    if event.get("suspicious"):
        return "r", "looks ENCRYPTED - ransomware suspected"
    return "g", verdict or "safe"


def same_file(event_path: str | None, target: Path) -> bool:
    """The Monitor normalises paths its own way; compare the last two components, case-insensitively."""
    if not event_path:
        return False
    tail = lambda p: [x.lower() for x in Path(str(p).replace("\\", "/")).parts[-2:]]
    return tail(event_path) == tail(target)


class Stack:
    """Thin client over the gateway (and two services the gateway does not proxy)."""

    def __init__(self, args) -> None:
        self.gw = args.gateway.rstrip("/")
        self.monitor = args.monitor.rstrip("/")
        self.response = args.response.rstrip("/")
        self.dashboard = args.dashboard.rstrip("/")
        self.http = httpx.Client(timeout=15.0)
        self.token: str | None = None

    @property
    def auth(self) -> dict:
        if self.token is None:
            r = self.http.post(f"{self.gw}/auth/token", headers={"X-Bootstrap-Secret": BOOTSTRAP_SECRET},
                               json={"sub": "exhibition", "role": "admin", "tier": "enterprise"})
            r.raise_for_status()
            self.token = r.json()["access_token"]
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, path: str, **params):
        r = self.http.get(f"{self.gw}{path}", params=params or None, headers=self.auth)
        if r.status_code == 401:  # token expired during a long exhibition day
            self.token = None
            r = self.http.get(f"{self.gw}{path}", params=params or None, headers=self.auth)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, body: dict):
        r = self.http.post(f"{self.gw}{path}", json=body, headers=self.auth)
        r.raise_for_status()
        return r.json()

    def events(self, limit: int = 200) -> list[dict]:
        return self.get("/monitor/events", limit=limit).get("events", [])

    def event_ids(self) -> set:
        return {e.get("event_id") for e in self.events()}

    def wait_event(self, target: Path, before: set, timeout: float = 12.0, need_pipeline: bool = False,
                   need_closed: bool = False) -> dict | None:
        """Newest new event for `target`; optionally wait for the ML/ledger/response fan-out."""
        deadline = time.time() + timeout
        found = None
        while time.time() < deadline:
            try:
                for e in self.events():
                    if e.get("event_id") in before or not same_file(e.get("file_path"), target):
                        continue
                    if e.get("verdict") == "deleted":
                        continue
                    found = e
                    if need_pipeline and e.get("suspicious") and not e.get("pipeline"):
                        break
                    if need_closed and e.get("attribution_pending"):
                        break
                    return e
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        return found


# --------------------------------------------------------------------------- pause control

class Pacer:
    def __init__(self, auto: bool, pause: float) -> None:
        self.auto = auto
        self.pause = pause

    def wait(self, prompt: str = "Press Enter to continue", seconds: float | None = None) -> str:
        if self.auto:
            time.sleep(self.pause if seconds is None else seconds)
            return ""
        try:
            return input(col(f"\n   ▶ {prompt} (s = skip, q = quit) ", "m", "B")).strip().lower()
        except EOFError:
            return ""


class Quit(Exception):
    pass


# --------------------------------------------------------------------------- preflight

def preflight(stack: Stack, state: State, args) -> bool:
    say(col("\n  URDS · Unified Ransomware Detection System · exhibition walkthrough", "w", "B"))
    say(col("  Checking that every part of the system is running ...\n", "d"))
    state.set(phase="preflight", current=None, message="Checking the system is ready")
    ok = True
    try:
        health = stack.http.get(f"{stack.gw}/health", timeout=10).json()
    except httpx.HTTPError as exc:
        bad(f"API gateway not reachable at {stack.gw} ({exc})")
        warn("Start the stack:  powershell -ExecutionPolicy Bypass -File scripts\\start_stack.ps1")
        return False
    names = {"gateway": "API gateway", "monitor": "File monitor", "ml_engine": "AI model service",
             "ledger": "Evidence ledger", "response": "Response engine"}
    for key, label in names.items():
        status = (health.get("services", {}).get(key) or {}).get("status")
        if status == "healthy":
            good(f"{label:20} running")
        else:
            bad(f"{label:20} {status or 'not reachable'}")
            ok = False
    try:
        stack.http.get(f"{stack.dashboard}/_stcore/health", timeout=5).raise_for_status()
        good(f"{'Dashboard':20} running  ->  {stack.dashboard}")
    except httpx.HTTPError:
        warn("Dashboard not reachable on :8501")
    try:
        ml = stack.http.get(args.ml.rstrip("/") + "/health", timeout=5).json()
        if ml.get("behavioral_model_loaded"):
            good(f"{'AI model':20} loaded")
        else:
            bad("AI model not loaded - run: .venv\\Scripts\\python.exe src\\train_behavioral_model.py, then restart")
            ok = False
    except httpx.HTTPError:
        pass
    if not ok:
        return False

    STAGE.mkdir(parents=True, exist_ok=True)
    status = stack.get("/monitor/status")
    watching = status.get("status") == "active" and os.path.normcase(str(status.get("watch_path") or "")) in {
        os.path.normcase(str(WATCH)), os.path.normcase(str(WATCH.resolve()))}
    if not watching:
        r = stack.post("/monitor/start", {"watch_path": str(WATCH), "recursive": True, "file_patterns": []})
        note(f"started the Monitor on {r.get('watch_path')}")
    good(f"{'Watching':20} {WATCH}")

    try:
        attribution = stack.http.get(f"{stack.monitor}/monitor/attribution", timeout=5).json()
    except httpx.HTTPError:
        attribution = {}
    state.set(attribution=bool(attribution.get("available")))
    if attribution.get("available"):
        good(f"{'Attacker tracking':20} LIVE ({attribution.get('source')}) - attackers will be stopped")
    else:
        warn(f"Attacker tracking is OFF ({attribution.get('error') or 'unknown'}).")
        warn("Detection, AI and the ledger still work, but no process will be killed.")
        warn("Fix: elevated PowerShell + scripts\\setup_vm.ps1 -SkipInstall -NoStart, then restart the stack.")
    return True


# --------------------------------------------------------------------------- steps

def step_normal(stack: Stack, state: State, pacer: Pacer, args) -> None:
    import synthetic_corpus

    files = [
        (STAGE / "meeting_notes.txt",
         ("Minutes of the project meeting. Action items: finish the report, review the budget.\n" * 60).encode()),
        (STAGE / "budget_2026.csv",
         ("month,income,expenses\n" + "".join(f"{m},{1000 + m * 37},{800 + m * 21}\n" for m in range(1, 400))).encode()),
        (STAGE / "quarterly_report.zip", synthetic_corpus.build_zip(200_000)),
    ]
    before = stack.event_ids()
    rows = []
    for path, data in files:
        state.set(focus_file=str(path), message=f"Saving {path.name}")
        note(f"saving {col(path.name, 'w', 'B')}  ({len(data):,} bytes, entropy {entropy_of(data):.2f} / 8)")
        write_via_child(path, data)
        event = stack.wait_event(path, before)
        rows.append((path, event))
    say()
    say(col(f"   {'FILE':26}{'ENTROPY':>9}   SYSTEM DECISION", "d"))
    all_safe = True
    for path, event in rows:
        if not event:
            say(f"   {path.name:26}{'?':>9}   {col('no event seen (is the Monitor watching?)', 'y')}")
            all_safe = False
            continue
        colour, words = plain_verdict(event)
        all_safe &= not event.get("suspicious")
        say(f"   {path.name:26}{event.get('entropy', 0):>9}   {col(words, colour, 'B')}")
    say()
    zip_event = rows[-1][1] or {}
    if zip_event and not zip_event.get("suspicious"):
        good("The ZIP's entropy is almost 8.0 - as random as encrypted data - yet it was NOT flagged,")
        say("     because URDS checked its structure and found a genuine archive. (TC-03)")
    state.result("normal_files_safe", all_safe)


def step_disguised(stack: Stack, state: State, pacer: Pacer, args) -> None:
    path = STAGE / "invoice_march.zip"
    data = b"PK\x03\x04" + os.urandom(200_000)
    before = stack.event_ids()
    state.set(focus_file=str(path), message="Writing a fake ZIP full of encrypted bytes")
    note(f"writing {col(path.name, 'w', 'B')} - starts with the ZIP signature 'PK', the rest is ciphertext")
    write_via_child(path, data)
    event = stack.wait_event(path, before, timeout=20, need_pipeline=True)
    say()
    if not event:
        bad("no event seen for the file")
        state.result("disguised_caught", False)
        return
    colour, words = plain_verdict(event)
    say(f"   Monitor     : entropy {event.get('entropy')} -> {col(words, colour, 'B')}")
    if event.get("reason"):
        say(col(f"                 why: {event.get('reason')}", "d"))
    if event.get("prediction"):
        say(f"   AI model    : {col(str(event.get('prediction')).upper(), 'r' if event.get('prediction') == 'ransomware' else 'g', 'B')}"
            f" (threat level {event.get('threat_level')})")
    if event.get("block_id"):
        say(f"   Ledger      : evidence sealed in block #{event.get('block_id')}")
    stages = (event.get("pipeline") or {}).get("stages", [])
    if "response_triggered" in stages:
        say("   Response    : engaged (alert raised, writer process looked up)")
    caught = bool(event.get("suspicious"))
    say()
    (good if caught else bad)("Disguised ciphertext detected (TC-02)" if caught else "Not detected")
    state.result("disguised_caught", caught)


def step_attack(stack: Stack, state: State, pacer: Pacer, args) -> None:
    out = RUN / "exhibition_attack_chain.txt"
    results_path = out.with_name(out.stem + "_results.json")
    results_path.unlink(missing_ok=True)
    state.set(focus_file=None, message="Attacker program running ...")
    note("launching the attacker and following it through every service (about 20 seconds) ...")
    cmd = [sys.executable, "-u", str(REPO / "scripts" / "attack_chain_demo.py"),
           "--gateway", stack.gw, "--monitor", stack.monitor, "--response", stack.response,
           "--dashboard", stack.dashboard,
           "--watch-host", str(WATCH), "--watch-container", str(WATCH), "--out", str(out)]
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", env=env, cwd=str(REPO))
    labels = {
        "0.": "checking services", "1.": "monitor ready", "2.": "control: a normal archive",
        "3.": "ATTACK: attacker encrypts a file", "4.": "monitor detection", "5.": "AI -> ledger -> response",
        "6.": "ledger evidence", "7.": "response: stopping the attacker", "8.": "dashboard freshness",
        "9.": "API security",
    }
    for line in proc.stdout:
        line = line.rstrip()
        if args.verbose:
            say(col("     " + line, "d"))
        elif line.startswith("--- ") and line[4:6] in labels:
            say(col(f"     … {labels[line[4:6]]}", "d"))
            state.set(message=labels[line[4:6]].capitalize())
        elif "victim file" in line or "writer pid" in line or "writer gone" in line or "attributed" in line:
            say(col("       " + line.strip(), "c"))
    proc.wait()
    results = {}
    if results_path.exists():
        results = json.loads(results_path.read_text(encoding="utf-8"))
    say()
    checks = [
        ("tc03_no_false_positive", "A normal archive was not flagged"),
        ("tc01_detected", "The attacker's encryption was detected"),
        ("detection_latency_under_100ms", "Detected in under 100 milliseconds"),
        ("tc06_ml_classified", "The AI model classified it as ransomware"),
        ("ledger_logged", "The evidence was sealed in the ledger"),
        ("response_triggered", "The response engine was engaged"),
        ("tc07_process_terminated", "The attacker process was identified and TERMINATED"),
        ("kill_time_under_2s", "...within 2 seconds of its write"),
        ("tc09_dashboard_within_1s", "The dashboard showed it within 1 second"),
        ("tc10_auth_rejects", "Requests without a valid token were refused"),
    ]
    for key, label in checks:
        value = results.get(key)
        if value is True:
            good(label)
        elif value is None:
            warn(f"{label}: not checked here (attacker tracking is off)")
        else:
            bad(label)
    note(f"full transcript: {out}")
    state.result("attack", {k: results.get(k) for k, _ in checks})
    if not results:
        warn("attack_chain_demo.py produced no results - run it with --verbose to see why")


def _sim_files(target: Path) -> list[Path]:
    """The simulator's documents: everything but its hidden manifest and journal."""
    if not target.exists():
        return []
    return [p for p in sorted(target.iterdir())
            if p.is_file() and not p.name.startswith(".") and p.name != "journal.json"]


def _doc_grid(target: Path, encrypted_names: set) -> list[dict]:
    # Judged by what the simulator reported, not by entropy: a decoy .jpg is
    # legitimately high-entropy and would be miscounted as encrypted.
    return [{"name": p.name, "status": "encrypted" if p.name in encrypted_names else "safe"}
            for p in _sim_files(target)]


def restore_simulator(target: Path) -> None:
    if (target).exists():
        subprocess.run([sys.executable, str(REPO / "scripts" / "ransomware_simulator.py"),
                        "--target-dir", str(target), "--restore"], capture_output=True, text=True, timeout=120)


def step_simulator(stack: Stack, state: State, pacer: Pacer, args) -> None:
    total = args.files
    if SIM_DIR.exists():
        restore_simulator(SIM_DIR)
        shutil.rmtree(SIM_DIR, ignore_errors=True)
    cmd = [sys.executable, "-u", str(REPO / "scripts" / "ransomware_simulator.py"),
           "--target-dir", str(SIM_DIR), "--family", args.family, "--files", str(total)]
    if args.delay_ms is not None:
        cmd += ["--delay-ms", str(args.delay_ms)]
    state.set(focus_file=None, message="Simulator is encrypting documents ...",
              simulator={"family": args.family, "total": total, "encrypted": 0, "stopped": None,
                         "restored": False, "docs": []})
    note(f"simulator family '{args.family}' - creating {total} office documents, then encrypting them")
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", cwd=str(REPO),
                            env={**os.environ, "PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"})
    encrypted, names, finished = 0, set(), False
    for line in proc.stdout:
        line = line.rstrip()
        if line.startswith("ENCRYPTED"):
            parts = line.split(maxsplit=2)
            encrypted = int(parts[1])
            names.add(parts[2] if len(parts) > 2 else "")
            say(f"   {col('🔒 encrypted', 'r', 'B')} {encrypted:>2}/{total}  {parts[2] if len(parts) > 2 else ''}")
            state.set(simulator={**state.data["simulator"], "encrypted": encrypted,
                                 "docs": _doc_grid(SIM_DIR, names)})
        elif line.startswith("finished:"):
            finished = True
        elif line.startswith("created"):
            say(col(f"   {line}", "d"))
            state.set(simulator={**state.data["simulator"], "docs": _doc_grid(SIM_DIR, names)})
        elif line.startswith("refusing") or "Traceback" in line:
            say(col(f"   {line}", "y"))
    proc.wait()
    elapsed = time.time() - started
    stopped = not finished
    time.sleep(1.0)
    docs = _doc_grid(SIM_DIR, names)
    locked = sum(1 for d in docs if d["status"] == "encrypted")
    say()
    if stopped:
        good(f"URDS STOPPED the simulator after {elapsed:.1f}s.")
        good(f"{col(str(total - locked), 'g', 'B')} of {total} documents are untouched; {col(str(locked), 'r', 'B')} were encrypted before the kill.")
    else:
        warn(f"The simulator finished all {encrypted} files - it was not stopped.")
        warn("Attacker tracking must be LIVE for URDS to kill it (see the preflight check).")
    state.set(simulator={**state.data["simulator"], "encrypted": locked, "stopped": stopped, "docs": docs},
              message=f"{locked} of {total} documents encrypted - simulator {'stopped by URDS' if stopped else 'not stopped'}")
    state.result("simulator_stopped", stopped)

    answer = pacer.wait("Press Enter to undo the damage and restore every document", seconds=max(4.0, pacer.pause))
    if answer == "q":
        raise Quit
    restore_simulator(SIM_DIR)
    time.sleep(0.5)
    files = _sim_files(SIM_DIR)
    docs = [{"name": p.name, "status": "restored"} for p in files]
    still_locked = [p.name for p in files if p.name in names or p.suffix in {".locked", ".enc"}]
    if still_locked:
        warn(f"{len(still_locked)} file(s) still look encrypted: {still_locked[:3]}")
    else:
        good("every document restored and readable again")
    state.set(simulator={**state.data["simulator"], "restored": not still_locked, "docs": docs},
              message="All documents restored")


def step_recovery(stack: Stack, state: State, pacer: Pacer, args) -> None:
    if args.skip_vss or not IS_WINDOWS:
        why = "skipped with --skip-vss" if args.skip_vss else "Windows Volume Shadow Copy needs Windows"
        warn(f"Recovery step {why}.")
        state.set(recovery={"status": "skipped", "reason": why})
        state.result("recovery_verified", None)
        return
    sys.path.insert(0, str(REPO / "services" / "response"))
    try:
        from recovery.ledger_client import LedgerClient
        from recovery.vss_manager import VSSManager
    except Exception as exc:
        bad(f"cannot load the recovery module: {exc}")
        state.set(recovery={"status": "failed", "reason": str(exc)})
        return

    RECOVERY_DIR.mkdir(parents=True, exist_ok=True)
    doc = RECOVERY_DIR / "thesis_chapter1.txt"
    original = ("Chapter 1 - Introduction.\nThis is the original, irreplaceable thesis text.\n" * 80).encode()
    doc.write_bytes(original)  # plain text: harmless to write from here
    clean_hash = sha256(original)
    first_line = original.decode().splitlines()[0]
    state.set(focus_file=str(doc), recovery={"status": "baseline", "file": doc.name, "before": first_line},
              message="Recording the clean file's fingerprint")
    note(f"created {col(doc.name, 'w', 'B')}: \"{first_line}\"")
    stack.post("/ledger/log", {"event_type": "file_baseline",
                               "event_data": {"file_path": str(doc), "file_hash": clean_hash,
                                              "entropy": round(entropy_of(original), 3)}})
    note(f"fingerprint recorded in the ledger: sha256 {clean_hash[:16]}…")

    volume = os.path.splitdrive(str(REPO))[0] + "\\"
    note(f"taking a Windows shadow copy of {volume} (a few seconds) ...")
    state.set(recovery={**state.data["recovery"], "status": "snapshotting"}, message="Taking a shadow copy")
    manager = VSSManager(ledger_client=LedgerClient(base_url=args.ledger), default_volume=volume)
    started = time.perf_counter()
    try:
        snapshot_id = manager.create_snapshot(volume)
    except Exception as exc:
        bad(f"shadow copy failed: {exc}")
        warn("VSS is unavailable on this host; say so and move on (detection is unaffected).")
        state.set(recovery={"status": "failed", "reason": f"shadow copy failed: {exc}"})
        state.result("recovery_verified", False)
        return
    good(f"shadow copy {snapshot_id} created in {time.perf_counter() - started:.1f}s")

    if pacer.wait("Press Enter to let 'ransomware' encrypt the file", seconds=2) == "q":
        raise Quit
    before = stack.event_ids()
    write_via_child(doc, os.urandom(len(original)))
    damaged = doc.read_bytes()
    bad(f"file encrypted: entropy {entropy_of(damaged):.2f}, first bytes {damaged[:12].hex(' ')} …")
    state.set(recovery={**state.data["recovery"], "status": "encrypted", "snapshot_id": snapshot_id,
                        "during": damaged[:24].hex(" ")}, message="The file has been encrypted")
    event = stack.wait_event(doc, before, timeout=10)
    if event and event.get("suspicious"):
        good("URDS detected the encryption")

    if pacer.wait("Press Enter to restore the file from the shadow copy", seconds=3) == "q":
        raise Quit
    try:
        r = stack.http.post(f"{stack.response}/response/recover", timeout=120,
                            json={"snapshot_id": snapshot_id, "files": [str(doc)], "verify_integrity": True})
        result = r.json()
    except httpx.HTTPError as exc:
        result = {"status": "failed", "error": str(exc)}
    restored = doc.read_bytes()
    verified = bool(result.get("integrity_verified")) and sha256(restored) == clean_hash
    if verified:
        good(f"restored: \"{restored.decode(errors='replace').splitlines()[0]}\"")
        good("restored file's SHA-256 matches the fingerprint in the ledger - integrity VERIFIED (TC-04)")
    else:
        bad(f"restore did not verify: {json.dumps(result)[:300]}")
    state.set(recovery={**state.data["recovery"], "status": "restored" if verified else "failed",
                        "after": restored.decode(errors="replace").splitlines()[0] if verified else None,
                        "verified": verified},
              message="File restored and verified" if verified else "Restore failed")
    state.result("recovery_verified", verified)


def step_tamper(stack: Stack, state: State, pacer: Pacer, args) -> None:
    verify = stack.get("/ledger/verify")
    good(f"chain verified: {verify.get('blocks_checked')} blocks, all links intact "
         f"({verify.get('verification_time_ms')} ms)")
    state.set(focus_file=None, tamper={"state": "valid", "blocks": verify.get("blocks_checked")},
              message="Ledger chain intact")
    db = Path(args.ledger_db)
    if not db.exists():
        warn(f"ledger database not found at {db}; pass --ledger-db to show the tamper half")
        state.result("tamper_detected", None)
        return
    block = stack.post("/ledger/log", {"event_type": "file_event", "event_data": {
        "file_path": str(STAGE / "invoice_march.zip"), "verdict": "suspected_encryption",
        "entropy": 7.999, "note": "exhibition record - the 'attacker' will try to hide this"}})
    block_id = block["block_id"]
    note(f"an alert is sealed in block #{block_id}: entropy 7.999, verdict suspected_encryption")
    if pacer.wait(f"Press Enter: the attacker edits block #{block_id} directly in the database", seconds=2) == "q":
        raise Quit
    conn = sqlite3.connect(str(db), timeout=10)
    original = conn.execute("SELECT event_data FROM blocks WHERE id = ?", (block_id,)).fetchone()[0]
    try:
        forged = json.dumps({"file_path": str(STAGE / "invoice_march.zip"), "verdict": "benign", "entropy": 1.1},
                            sort_keys=True, separators=(",", ":"))
        conn.execute("UPDATE blocks SET event_data = ? WHERE id = ?", (forged, block_id))
        conn.commit()
        bad(f"block #{block_id} rewritten: verdict 'benign', entropy 1.1 - hiding the attack")
        tampered = stack.get("/ledger/verify")
        detected = tampered.get("valid") is False and tampered.get("invalid_block_id") == block_id
        state.set(tamper={"state": "tampered", "block": block_id, "detected": detected},
                  message=f"Ledger TAMPERED at block #{block_id}")
        if detected:
            good(f"URDS: chain BROKEN at block #{tampered.get('invalid_block_id')} - the forgery is exposed (TC-05)")
        else:
            bad(f"verify returned {tampered}")
        state.result("tamper_detected", detected)
        pacer.wait("Press Enter to put the original record back", seconds=max(5.0, pacer.pause))
    finally:
        conn.execute("UPDATE blocks SET event_data = ? WHERE id = ?", (original, block_id))
        conn.commit()
        conn.close()
    again = stack.get("/ledger/verify")
    (good if again.get("valid") else bad)(f"original restored - chain valid again: {again.get('valid')}")
    state.set(tamper={"state": "valid" if again.get("valid") else "tampered", "block": block_id,
                      "detected": state.data["tamper"].get("detected"), "restored": bool(again.get("valid"))},
              message="Ledger chain intact again")
    say(col("     Honest limit: an attacker who recomputes every later hash is not caught by this check.", "d"))


def step_auth(stack: Stack, state: State, pacer: Pacer, args) -> None:
    state.set(focus_file=None, message="Testing API access control")
    url = f"{stack.gw}/ledger/entries"
    no = stack.http.get(url)
    forged = stack.http.get(url, headers={"Authorization": "Bearer not-a-real-token"})
    yes = stack.http.get(url, headers=stack.auth)
    show = lambda code: col(str(code), "g" if code == 200 else "r", "B")
    say(f"   no token        -> HTTP {show(no.status_code)}  {'refused' if no.status_code == 401 else ''}")
    say(f"   forged token    -> HTTP {show(forged.status_code)}  {'refused' if forged.status_code == 401 else ''}")
    say(f"   valid token     -> HTTP {show(yes.status_code)}  {'allowed' if yes.status_code == 200 else ''}")
    ok = no.status_code == 401 and forged.status_code == 401 and yes.status_code == 200
    time.sleep(0.5)
    try:
        blocks = stack.get("/ledger/blocks", event_type="auth_failure", newest_first="true", limit=1).get("blocks", [])
        if blocks:
            good(f"the refusal was itself recorded in ledger block #{blocks[0]['block_id']} (TC-10)")
    except httpx.HTTPError:
        pass
    state.result("auth_enforced", ok)
    state.set(auth={"no_token": no.status_code, "forged": forged.status_code, "valid": yes.status_code})


def step_numbers(stack: Stack, state: State, pacer: Pacer, args) -> None:
    def load(name: str) -> dict:
        try:
            return json.loads((REPO / "reports" / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    m = load("model_metrics.json")
    b = load("as_benchmarks.json")
    pct = lambda v: f"{v * 100:.1f}%" if isinstance(v, (int, float)) else "n/a"
    numbers = {
        "Precision": pct(m.get("precision")),
        "Recall": pct(m.get("recall")),
        "F1 score": pct(m.get("f1_score")),
        "Detection latency (mean)": f"{(b.get('detection_latency_ms') or {}).get('mean', 'n/a')} ms  (target < 100 ms)",
        "Process kill time": f"{(b.get('process_kill_time_s') or {}).get('measured', 'n/a')} s  (target < 2 s)",
        "False-positive rate": pct((b.get("false_positive_rate") or {}).get("rate")),
        "CPU use": f"{(b.get('cpu_percent') or {}).get('percent_of_total_cpu', 'n/a')}%  (target < 15%)",
        "Memory growth": f"{(b.get('memory_mb') or {}).get('growth_mb', 'n/a')} MB  (target < 500 MB)",
    }
    for label, value in numbers.items():
        say(f"   {label:28} {col(value, 'w', 'B')}")
    say(col("\n     Source: reports/model_metrics.json, reports/as_benchmarks.json, docs/test_cases.md", "d"))
    state.set(numbers=numbers, focus_file=None, message="Results")


RUNNERS = {
    "normal": step_normal, "disguised": step_disguised, "attack": step_attack, "simulator": step_simulator,
    "recovery": step_recovery, "tamper": step_tamper, "auth": step_auth, "numbers": step_numbers,
}


# --------------------------------------------------------------------------- reset

def reset(stack: Stack | None) -> None:
    say(col("Resetting the exhibition area ...", "c"))
    # Any folder the simulator worked in (ours, or watched_files\tc01 from the
    # manual commands) is restored first: its originals live outside the folder.
    for manifest in WATCH.rglob(".simulator_manifest.json"):
        restore_simulator(manifest.parent)
    for leftover in WATCH.iterdir() if WATCH.exists() else []:
        if leftover.is_dir():
            shutil.rmtree(leftover, ignore_errors=True)
        else:
            leftover.unlink(missing_ok=True)
    if stack is not None:
        try:
            stack.http.put(f"{stack.monitor}/monitor/whitelist", json={"paths": [], "hashes": []}, timeout=5)
        except httpx.HTTPError:
            pass
    good("watched_files cleaned, simulator files restored, whitelist emptied")


# --------------------------------------------------------------------------- main

def run_once(stack: Stack, args, selected: list[dict], pacer: Pacer) -> bool:
    state = State()
    if not preflight(stack, state, args):
        state.set(phase="error", message="The system is not ready - see the console")
        return False
    if pacer.wait("Ready. Press Enter to start the story", seconds=2) == "q":
        return True
    for step in STEPS:
        if step not in selected:
            state.step(step["n"], "skipped")
    for step in selected:
        banner(step)
        state.step(step["n"], "running")
        state.set(current=step["n"], phase="running", title=step["title"], story=step["story"],
                  watch=step["watch"], message="")
        answer = pacer.wait("Press Enter to run this step", seconds=3)
        if answer == "q":
            raise Quit
        if answer == "s":
            state.step(step["n"], "skipped")
            continue
        try:
            RUNNERS[step["key"]](stack, state, pacer, args)
            state.step(step["n"], "done")
        except Quit:
            raise
        except Exception as exc:  # one broken step must not end the show
            bad(f"this step hit an error: {exc}")
            state.step(step["n"], "error")
            state.set(message=f"Step error: {exc}")
        state.set(phase="waiting")
        if step is not selected[-1] and pacer.wait("Press Enter for the next step") == "q":
            raise Quit
    say(col("\n  SUMMARY", "w", "B"))
    marks = {"done": col("done", "g"), "error": col("error", "r"), "skipped": col("skipped", "d"),
             "pending": col("not run", "d"), "running": col("stopped", "y")}
    for s in state.data["steps"]:
        say(f"   {s['n']}. {s['title']:44} {marks.get(s['status'], s['status'])}")
    say(col("\n  ✔ Demo complete. Thank you!\n", "g", "B"))
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--steps", help="comma-separated step numbers, e.g. 1,2,6 (default: all)")
    parser.add_argument("--auto", action="store_true", help="no key presses; pause --pause seconds between steps")
    parser.add_argument("--pause", type=float, default=8.0, help="seconds between steps in --auto mode")
    parser.add_argument("--loop", action="store_true", help="with --auto: repeat forever (kiosk mode), resetting between runs")
    parser.add_argument("--reset", action="store_true", help="clean up the exhibition area and exit")
    parser.add_argument("--family", default="locker", help="simulator family for step 4 (locker, slowburn, silent, ...)")
    parser.add_argument("--files", type=int, default=20, help="documents the simulator creates in step 4")
    parser.add_argument("--delay-ms", type=int, default=400, help="simulator pause between files; lower = faster attack")
    parser.add_argument("--skip-vss", action="store_true", help="skip the shadow-copy recovery step")
    parser.add_argument("--verbose", action="store_true", help="show the full attack_chain_demo.py transcript")
    parser.add_argument("--gateway", default="http://127.0.0.1:8000")
    parser.add_argument("--monitor", default="http://127.0.0.1:8001")
    parser.add_argument("--ml", default="http://127.0.0.1:8002")
    parser.add_argument("--ledger", default="http://127.0.0.1:8003")
    parser.add_argument("--response", default="http://127.0.0.1:8004")
    parser.add_argument("--dashboard", default="http://127.0.0.1:8501")
    parser.add_argument("--ledger-db", default=os.getenv("LEDGER_DB_PATH", str(RUN / "data" / "ledger.db")))
    args = parser.parse_args()

    stack = Stack(args)
    if args.reset:
        reset(stack)
        return 0

    selected = STEPS
    if args.steps:
        wanted = {int(x) for x in args.steps.replace(" ", "").split(",") if x}
        selected = [s for s in STEPS if s["n"] in wanted]
    pacer = Pacer(args.auto, args.pause)
    try:
        while True:
            ok = run_once(stack, args, selected, pacer)
            if not (args.auto and args.loop and ok):
                return 0 if ok else 1
            time.sleep(args.pause * 2)
            reset(stack)
    except (Quit, KeyboardInterrupt):
        say(col("\n  stopped. Run with --reset to clean up.", "y"))
        if SIM_DIR.exists():
            restore_simulator(SIM_DIR)
        return 0


if __name__ == "__main__":
    sys.exit(main())
