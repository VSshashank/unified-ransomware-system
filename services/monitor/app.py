import os
import math
from collections import Counter
from datetime import datetime, timezone
from random import choice, randint, uniform
from time import time
from uuid import uuid4

from fastapi import FastAPI
from pydantic import BaseModel, Field


# PLACEHOLDER STUB: AS owns the real Monitor service logic.
# This stub exists so SH can test gateway/dashboard integration end-to-end.

app = FastAPI(title="URDS Monitor Stub", version="0.1.0")
STARTED_AT = time()
RUNNING = True
EVENTS = []


class MonitorStartRequest(BaseModel):
    watch_path: str
    recursive: bool = True
    file_patterns: list[str] = Field(default_factory=list)


class FeatureRequest(BaseModel):
    path: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as file:
            data = file.read()

        if len(data) == 0:
            return 0.0

        counter = Counter(data)

        entropy = 0.0

        for count in counter.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return round(entropy, 2)

    except Exception as e:
        print(f"Entropy Error: {e}")
        return 0.0
    
def make_event(path: str | None = None) -> dict:
    event_type = choice(["created", "modified", "renamed", "encrypted"])
    suffix = choice(["doc", "pdf", "jpg", "xlsx"])
    event = {
        "event_id": f"evt_{uuid4().hex[:10]}",
        "file_path": path or f"/watch/capstone_file_{randint(1, 200)}.{suffix}",
        "event_type": event_type,
        "entropy": round(uniform(3.2, 8.1), 2),
        "timestamp": utc_now(),
        "process_id": randint(1000, 9999),
        "user": choice(["admin", "student", "analyst"]),
    }
    EVENTS.append(event)
    del EVENTS[:-50]
    return event


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "monitor", "placeholder": True}


@app.post("/monitor/start")
def start_monitoring(payload: MonitorStartRequest) -> dict:
    global RUNNING, STARTED_AT
    RUNNING = True
    STARTED_AT = time()
    make_event(payload.watch_path)
    return {
        "status": "monitoring",
        "monitor_id": f"mon_{uuid4().hex[:6]}",
        "start_time": utc_now(),
    }


@app.post("/monitor/stop")
def stop_monitoring() -> dict:
    global RUNNING
    RUNNING = False
    return {"status": "stopped", "stop_time": utc_now()}


@app.get("/monitor/status")
def monitor_status() -> dict:
    if RUNNING and (not EVENTS or time() % 2 < 1):
        make_event()
    return {
        "status": "active" if RUNNING else "stopped",
        "files_monitored": 1523 + len(EVENTS),
        "events_captured": len(EVENTS),
        "uptime_seconds": int(time() - STARTED_AT),
    }


@app.get("/monitor/events")
def monitor_events(limit: int = 20) -> dict:
    if RUNNING:
        make_event()
    return {"events": list(reversed(EVENTS[-limit:]))}


@app.post("/features")
def extract_features(payload: FeatureRequest) -> dict:
    event = make_event(payload.path)
    # AS Module: Calculate real Shannon entropy
    entropy = calculate_entropy(payload.path)
    return {
        "shannon_entropy": entropy,
        "file_size": os.path.getsize(payload.path),
        "magic_bytes": choice(["4D5A", "25504446", "FFD8FFE0"]),
        "modification_rate": round(min(1.0, entropy / 8.2), 2),
        "pe_imports_count": randint(5, 80),
        "api_calls": ["CreateFile", "WriteFile", "CryptEncrypt"] if entropy > 7 else ["CreateFile", "ReadFile"],
    }
