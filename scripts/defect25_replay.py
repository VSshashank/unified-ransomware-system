"""Replay the 2026-10-05 elevated run's notification shape through handle_event.

usage: python scripts/defect25_replay.py <monitor_dir> <out.json>

Shape source: run2's real ledger (C:\\URDS-latest-run\\20261005_203206\\run2\\data\\ledger.db).
Per suspicious path: the sequence of watchdog notifications that each produced a
file_event block (event_type, offset from the first by the escalation block's
observed_at, the PIDs that block's closing answer listed). Replayed in order
through the real handle_event -> correlation lanes -> _correlate path, with a
fake kernel-grade source (1500 ms horizon, records delivered 300 ms late), ML,
ledger and Response stubbed in-process. The Response stub writes its own
response_action blocks like services/response/app.py does (one per trigger, one
per terminate, refusing a PID it already killed).
Gaps over 300 ms are capped at 300 ms (anything past the coalescing window is
equivalent); inter-file spacing is 15 ms. The file gets new random bytes
wherever the run's notification hashed differently from the one before it, so
the 15 multi-notification files whose content changed in the run change here.
Each PID a notification's closing answer listed gets one audit record, at that
notification's write. The probe reports a PID alive until the Response stub has
killed it.
Reads only the run's ledger (read-only) and a temp dir; writes OUT and nothing else.
"""

import collections
import json
import os
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

MONITOR = sys.argv[1]
OUT = sys.argv[2]
sys.path.insert(0, MONITOR)
os.environ["PIPELINE_ENABLED"] = "true"
os.environ["BASELINE_LOGGING_ENABLED"] = "false"

RUN = r"C:\URDS-latest-run\20261005_203206\run2\data\ledger.db"


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s else None


def shape():
    conn = sqlite3.connect("file:" + RUN + "?mode=ro", uri=True)
    rows = conn.execute("SELECT id, event_type, event_data FROM blocks ORDER BY id").fetchall()
    esc = {}
    for _, et, raw in rows:
        if et == "attribution_escalation":
            d = json.loads(raw)
            esc[d["incident_id"]] = d
    files = collections.OrderedDict()
    for _, et, raw in rows:
        if et != "file_event":
            continue
        d = json.loads(raw)
        e = esc.get(d.get("incident_id"), {})
        files.setdefault(d["file_path"], []).append({
            "type": d.get("event_type"),
            "renamed_from": d.get("renamed_from"),
            "obs": ts(e.get("observed_at")),
            "pids": list(e.get("attribution_candidates") or []),
            "hash": d.get("file_hash"),
        })
    return files


import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import AttributionSource, Attributor, ProcessFacts, WriteLog  # noqa: E402


class LaggingKernelSource(AttributionSource):
    name = "replay-lagging-4663"
    kernel_grade = True
    delivery_horizon_ms = 1500.0

    def start(self):
        self.available = True
        return True

    def deliver(self, path, pid, image, written_at, lag_ms=300):
        t = threading.Timer(lag_ms / 1000.0, lambda: self.log.record(path, pid, image, written_at=written_at))
        t.daemon = True
        t.start()


class Downstream:
    def __init__(self):
        self.lock = threading.Lock()
        self.ledger = []
        self.dead = set()
        self.terminate_requests = []

    def log(self, event_type, data):
        with self.lock:
            self.ledger.append({"event_type": event_type, "event_data": data})
            return {"block_id": len(self.ledger)}

    def __call__(self, client, base_url, path, payload, *a, **k):
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            return self.log(payload["event_type"], payload["event_data"])
        if path == "/response/trigger":
            kill = payload["action_required"] == "terminate_process"
            self.log("response_action", {"action": "trigger", "incident_id": payload["incident_id"],
                                         "process_id": payload["process_id"] if kill else None,
                                         "attribution_confidence": payload["attribution_confidence"]})
            return {"status": "success", "actions_taken": ["network_isolation_planned", "admin_notified"]}
        if path == "/response/terminate":
            pid = payload["process_id"]
            with self.lock:
                self.terminate_requests.append(payload)
                refused = pid in self.dead
                self.dead.add(pid)
            self.log("response_action", {"action": "terminate", "incident_id": payload["incident_id"],
                                         "process_id": pid, "attribution_confidence": payload["attribution_confidence"],
                                         "outcome": "refused" if refused else "terminated"})
            return None if refused else {"status": "terminated", "process_id": pid}
        return {}


def main():
    files = shape()
    log = WriteLog()
    source = LaggingKernelSource(log)
    source.start()
    downstream = Downstream()
    long_ago = time.time() - 600
    at = Attributor(log=log, source=source,
                    probe=lambda pid: None if pid in downstream.dead else
                    ProcessFacts(pid=pid, image=rf"C:\sim\writer_{pid}.exe", created_at=long_ago))
    pipeline._post = downstream
    monitor_app.attributor = at
    monitor_app.PIPELINE_ENABLED = True
    monitor_app.BASELINE_LOGGING_ENABLED = False
    monitor_app.EVENTS = collections.deque(maxlen=100000)
    monitor_app._ensure_worker()
    monitor_app._lanes.start()

    root = Path(tempfile.mkdtemp(prefix="replay_f6_"))
    path_map = {}
    notifications = 0
    for index, (orig, seq) in enumerate(files.items()):
        folder = root / f"f{index:03d}"
        folder.mkdir()
        target = folder / Path(orig.replace("\\", "/")).name
        path_map[str(monitor_app.normalise_path(str(target)))] = orig
        seen = set()
        prev_obs = None
        prev_hash = None
        for n in seq:
            if prev_obs is not None and n["obs"] and prev_obs:
                time.sleep(min(0.3, max(0.0, n["obs"] - prev_obs)))
            prev_obs = n["obs"] or prev_obs
            written_at = time.time()
            renamed_from = None
            if n["type"] == "renamed":
                src = folder / ("src_" + target.name)
                src.write_bytes(os.urandom(48 * 1024))
                os.replace(src, target)
                renamed_from = str(src)
                rec_path = str(src)
            else:
                # New bytes where the run's notification read new bytes.
                if not target.exists() or n["hash"] != prev_hash:
                    target.write_bytes(os.urandom(48 * 1024))
                rec_path = str(target)
            prev_hash = n["hash"]
            for pid in n["pids"]:
                if pid not in seen:
                    seen.add(pid)
                    source.deliver(rec_path, pid, rf"C:\sim\writer_{pid}.exe", written_at)
            notifications += 1
            monitor_app.handle_event(str(target), n["type"], renamed_from=renamed_from, lanes=monitor_app._lanes)
        time.sleep(0.015)

    monitor_app._lanes.stop(timeout=30)
    time.sleep(2.5)  # past the last horizon
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and monitor_app._pending is not None and monitor_app._pending.depth():
        time.sleep(0.1)
    monitor_app._escalations.join()
    monitor_app._work.join()
    time.sleep(0.5)
    monitor_app._work.join()

    events = [e for e in monitor_app.EVENTS if e.get("suspicious")]
    by_path = collections.defaultdict(list)
    for e in events:
        by_path[e["file_path"]].append(e)
    writes = downstream.ledger
    fe_incidents = collections.defaultdict(set)
    for w in writes:
        d = w["event_data"]
        if w["event_type"] == "file_event":
            fe_incidents[d["file_path"]].add(d["incident_id"])
    inc_to_path = {i: p for p, s in fe_incidents.items() for i in s}
    blocks_per_path = collections.Counter()
    for w in writes:
        d = w["event_data"]
        p = d.get("file_path") or inc_to_path.get(d.get("incident_id"))
        if p in fe_incidents:
            blocks_per_path[p] += 1
    inc_counts = [len(s) for s in fe_incidents.values()]
    types = collections.Counter(w["event_type"] for w in writes)
    refused = sum(1 for w in writes if w["event_data"].get("outcome") == "refused")
    escal = collections.Counter(w["event_data"].get("result") for w in writes if w["event_type"] == "attribution_escalation")
    result = {
        "monitor_dir": MONITOR,
        "notifications_replayed": notifications,
        "suspicious_events_in_monitor_events": len(events),
        "events_joined_to_an_open_incident": sum(1 for e in events if e.get("coalesced_into")),
        "events_still_pending": sum(1 for e in events if e.get("attribution_pending")),
        "distinct_suspicious_files": len(by_path),
        "files_with_a_file_event": len(fe_incidents),
        "incidents_per_suspicious_file": {
            "mean": round(statistics.mean(inc_counts), 3), "median": statistics.median(inc_counts),
            "max": max(inc_counts), "distribution": dict(sorted(collections.Counter(inc_counts).items()))},
        "file_event_blocks": types.get("file_event", 0),
        "ledger_blocks_total": len(writes),
        "ledger_blocks_per_suspicious_file": round(sum(blocks_per_path.values()) / len(fe_incidents), 3),
        "block_types": dict(types),
        "terminate_requests": len(downstream.terminate_requests),
        "terminate_refused": refused,
        "escalation_results": dict(escal),
        "pending_stats": monitor_app._pending.stats() if monitor_app._pending else None,
    }
    print(json.dumps(result, indent=1))
    Path(OUT).write_text(json.dumps(result, indent=1))


main()
sys.stdout.flush()
os._exit(0)
