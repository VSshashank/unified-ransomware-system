"""Exhibition Story - the projector view of a live URDS demo.

http://localhost:8501/Exhibition_Story

Built for a jury standing three metres from a screen: big type, one idea per
panel, plain words instead of field names. It follows scripts/exhibition_demo.py
through run/exhibition_state.json (which step is running, what to look at) and
draws the live system from the gateway: the newest file event walked through
the six stages, the ledger's hash chain, the simulator's documents.

Works without the demo script too: with no state file it simply shows the
newest event, so files dropped into watched_files by hand light it up as well.
"""

import html
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import streamlit as st
from jose import jwt

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000").rstrip("/")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
REPO_ROOT = Path(__file__).resolve().parents[3]
STATE_PATH = Path(os.getenv("URDS_EXHIBITION_STATE", str(REPO_ROOT / "run" / "exhibition_state.json")))

STEP_TITLES = [
    "Normal work", "Disguised file", "Live attack", "Simulator",
    "Recovery", "Tamper-proof log", "Access control", "Results",
]

# Colours: one meaning each, the same everywhere on the page.
SAFE, THREAT, INFO, IDLE, SEAL, WARN = "#22c55e", "#ef4444", "#38bdf8", "#475569", "#a78bfa", "#f59e0b"


def token() -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": "exhibition-page", "role": "admin", "tier": "enterprise",
         "iat": int(now.timestamp()), "exp": int((now + timedelta(hours=2)).timestamp())},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )


def gateway(path: str, auth: str, **params) -> dict:
    response = requests.get(f"{GATEWAY_URL}{path}", params=params or None,
                            headers={"Authorization": f"Bearer {auth}"}, timeout=3)
    response.raise_for_status()
    return response.json()


def read_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def file_name(path) -> str:
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1]


def same_file(a, b) -> bool:
    tail = lambda p: [x.lower() for x in str(p or "").replace("\\", "/").split("/")[-2:]]
    return bool(a) and bool(b) and tail(a) == tail(b)


def visible(events: list) -> list:
    """Events a visitor should see: no deletions, no tool bookkeeping (dotfiles, the simulator's journal)."""
    return [e for e in events
            if e.get("verdict") != "deleted"
            and not file_name(e.get("file_path")).startswith(".")
            and file_name(e.get("file_path")) != "journal.json"]


def focus_event(events: list, state: dict) -> dict:
    live = visible(events)
    wanted = state.get("focus_file")
    if wanted:
        for event in live:
            if same_file(event.get("file_path"), wanted):
                return event
    if state.get("current") == 4:
        # During the simulator the story is the encrypted documents, not the decoys being created.
        threats = [e for e in live if e.get("suspicious")]
        if threats:
            return threats[0]
    return live[0] if live else {}


def describe(event: dict) -> tuple[str, str]:
    """(colour, plain words) for a Monitor verdict."""
    verdict = str(event.get("verdict") or "")
    if verdict == "benign_compressed":
        return SAFE, "Real compressed file - safe"
    if verdict == "benign":
        return SAFE, "Normal file - safe"
    if event.get("suspicious"):
        return THREAT, "Looks encrypted - ransomware suspected"
    return SAFE, verdict.replace("_", " ").capitalize() or "Safe"


def stages(event: dict, state: dict) -> list[dict]:
    """The six boxes of the pipeline, each with a colour, a headline and a detail line."""
    if not event:
        waiting = {"color": IDLE, "value": "Waiting", "detail": "no file activity yet"}
        return [dict(waiting, name=n, icon=i) for n, i in (
            ("File changed", "📄"), ("Monitor", "🔎"), ("AI model", "🧠"),
            ("Evidence ledger", "🔗"), ("Response", "🛡️"), ("Recovery", "♻️"))]

    suspicious = bool(event.get("suspicious"))
    colour, words = describe(event)
    pipe = (event.get("pipeline") or {}).get("stages", [])
    out = [{
        "name": "File changed", "icon": "📄", "color": INFO,
        "value": esc(file_name(event.get("file_path"))),
        "detail": f"{esc(event.get('event_type', 'modified'))} · {int(event.get('file_size') or 0):,} bytes",
    }]

    entropy = event.get("entropy")
    structure = event.get("container_valid")
    structure_text = {True: "structure valid", False: "structure FORGED", None: "no container"}.get(structure, "")
    out.append({
        "name": "Monitor", "icon": "🔎", "color": colour, "value": words,
        "detail": f"randomness {entropy} / 8 · {structure_text}",
    })

    prediction = event.get("prediction")
    if not suspicious:
        out.append({"name": "AI model", "icon": "🧠", "color": IDLE, "value": "Not needed",
                    "detail": "only suspicious files go to the AI"})
    elif prediction:
        out.append({"name": "AI model", "icon": "🧠", "color": THREAT if prediction == "ransomware" else SAFE,
                    "value": esc(str(prediction).capitalize()),
                    "detail": f"threat level {esc(event.get('threat_level') or '-')}"})
    else:
        out.append({"name": "AI model", "icon": "🧠", "color": WARN, "value": "Analysing…", "detail": ""})

    block = event.get("block_id")
    if not suspicious:
        out.append({"name": "Evidence ledger", "icon": "🔗", "color": IDLE, "value": "Nothing to record",
                    "detail": "no alert, no evidence needed"})
    elif block:
        out.append({"name": "Evidence ledger", "icon": "🔗", "color": SEAL, "value": f"Sealed in block #{esc(block)}",
                    "detail": "hash-chained, tamper-evident"})
    else:
        out.append({"name": "Evidence ledger", "icon": "🔗", "color": WARN, "value": "Recording…", "detail": ""})

    escalation = event.get("attribution_escalation") or {}
    pid = event.get("process_id")
    image = file_name(event.get("process_image")) or "process"
    if not suspicious:
        out.append({"name": "Response", "icon": "🛡️", "color": IDLE, "value": "No action", "detail": "nothing to stop"})
    elif escalation.get("result") == "terminated":
        out.append({"name": "Response", "icon": "🛡️", "color": SAFE, "value": "Attacker STOPPED",
                    "detail": f"terminated {esc(image)} (PID {esc(pid)})"})
    elif event.get("attribution_pending"):
        out.append({"name": "Response", "icon": "🛡️", "color": WARN, "value": "Identifying attacker…",
                    "detail": "reading the Windows security log"})
    elif "response_triggered" in pipe:
        detail = f"result: {esc(escalation.get('result'))}" if escalation.get("result") else "alert raised"
        if pid and event.get("attribution_confidence") == "certain":
            detail = f"attacker identified: {esc(image)} (PID {esc(pid)})"
        out.append({"name": "Response", "icon": "🛡️", "color": WARN, "value": "Engaged", "detail": detail})
    else:
        out.append({"name": "Response", "icon": "🛡️", "color": WARN, "value": "Starting…", "detail": ""})

    recovery = state.get("recovery") or {}
    rstatus = recovery.get("status")
    if rstatus == "restored":
        out.append({"name": "Recovery", "icon": "♻️", "color": SAFE, "value": "Restored", "detail": "hash verified ✔"})
    elif rstatus in {"snapshotting", "baseline", "encrypted"}:
        out.append({"name": "Recovery", "icon": "♻️", "color": INFO, "value": "Shadow copy ready",
                    "detail": "Windows VSS snapshot"})
    else:
        out.append({"name": "Recovery", "icon": "♻️", "color": IDLE, "value": "Standing by",
                    "detail": "snapshots every 6 hours"})
    return out


def pipeline_html(boxes: list[dict]) -> str:
    cells = []
    for i, box in enumerate(boxes):
        lit = box["color"] != IDLE
        cells.append(
            f'<div class="node" style="border-color:{box["color"]};'
            f'box-shadow:0 0 {"28px" if lit else "0"} {box["color"]}55;opacity:{1 if lit else .55}">'
            f'<div class="node-icon">{box["icon"]}</div>'
            f'<div class="node-step">{i + 1}. {esc(box["name"])}</div>'
            f'<div class="node-value" style="color:{box["color"]}">{box["value"]}</div>'
            f'<div class="node-detail">{box["detail"]}</div></div>'
        )
        if i < len(boxes) - 1:
            cells.append('<div class="arrow">➜</div>')
    return f'<div class="pipeline">{"".join(cells)}</div>'


def tracker_html(state: dict) -> str:
    statuses = {s["n"]: s["status"] for s in state.get("steps", [])}
    chips = []
    for n, title in enumerate(STEP_TITLES, start=1):
        status = statuses.get(n, "pending")
        colour = {"done": SAFE, "running": INFO, "error": THREAT, "skipped": IDLE}.get(status, IDLE)
        mark = {"done": "✔", "running": "●", "error": "✘", "skipped": "–"}.get(status, str(n))
        style = f"background:{colour};color:#0b1120" if status in {"done", "running"} else f"border-color:{colour}"
        chips.append(f'<div class="chip {status}" style="{style}"><b>{mark}</b> {esc(title)}</div>')
    return f'<div class="tracker">{"".join(chips)}</div>'


def chain_html(blocks: list[dict], tamper: dict) -> str:
    broken = tamper.get("block") if tamper.get("state") == "tampered" else None
    cells = []
    for block in reversed(blocks):
        bid = block.get("block_id")
        bad = broken is not None and bid is not None and int(bid) >= int(broken)
        colour = THREAT if bad else SEAL
        label = "TAMPERED" if bid == broken else ("link broken" if bad else esc(block.get("event_type", "")))
        cells.append(
            f'<div class="block" style="border-color:{colour}">'
            f'<div class="block-id" style="color:{colour}">#{esc(bid)}</div>'
            f'<div class="block-type">{label}</div>'
            f'<div class="block-hash">prev {esc(str(block.get("previous_hash", ""))[:8])}…</div>'
            f'<div class="block-hash">hash {esc(str(block.get("current_hash", ""))[:8])}…</div></div>'
        )
        cells.append(f'<div class="link" style="color:{THREAT if bad else SEAL}">⛓</div>')
    return f'<div class="chain">{"".join(cells[:-1])}</div>' if cells else ""


def docs_html(sim: dict) -> str:
    tiles = []
    for doc in sim.get("docs", []):
        status = doc.get("status")
        colour = {"encrypted": THREAT, "restored": INFO}.get(status, SAFE)
        icon = {"encrypted": "🔒", "restored": "♻️"}.get(status, "📄")
        tiles.append(f'<div class="doc" style="border-color:{colour};color:{colour}">{icon}'
                     f'<span>{esc(doc.get("name", "").replace("quarterly_report_", ""))[:22]}</span></div>')
    return f'<div class="docs">{"".join(tiles)}</div>'


def feed_html(events: list) -> str:
    rows = []
    for event in visible(events)[:8]:
        colour, words = describe(event)
        extra = ""
        if event.get("block_id"):
            extra += f" · ledger #{esc(event['block_id'])}"
        if (event.get("attribution_escalation") or {}).get("result") == "terminated":
            extra += f" · attacker PID {esc(event.get('process_id'))} terminated"
        when = str(event.get("timestamp", ""))[11:19]
        rows.append(f'<div class="feed-row"><span class="dot" style="background:{colour}"></span>'
                    f'<span class="when">{esc(when)}</span><b>{esc(file_name(event.get("file_path")))}</b>'
                    f'<span class="why">{esc(words)}{extra}</span></div>')
    return "".join(rows) or '<div class="feed-row">No file activity yet.</div>'


def tile(label: str, value, colour: str = "#e2e8f0") -> str:
    return (f'<div class="tile"><div class="tile-value" style="color:{colour}">{esc(value)}</div>'
            f'<div class="tile-label">{esc(label)}</div></div>')


CSS = """
<style>
  .stApp { background: #0b1120; }
  [data-testid="stSidebar"], [data-testid="stHeader"] { display: none; }
  /* The page reruns every second; Streamlit greys out "stale" elements while it
     does, which on a projector reads as flicker. */
  .stale-element, [data-stale="true"] { opacity: 1 !important; transition: none !important; }
  .block-container { padding-top: 1.2rem; max-width: 1800px; }
  h1, h2, h3, p, div, span { color: #e2e8f0; }
  .headline { display:flex; justify-content:space-between; align-items:center; gap: 16px; flex-wrap: wrap; }
  .headline h1 { font-size: 40px; margin: 0; }
  .pill { font-size: 26px; font-weight: 800; padding: 10px 26px; border-radius: 999px; color: #0b1120; }
  .tracker { display:flex; gap:10px; margin: 14px 0 18px; flex-wrap: wrap; }
  .chip { border: 2px solid; border-radius: 999px; padding: 6px 16px; font-size: 17px; color:#cbd5e1; }
  .chip.running { animation: pulse 1.2s infinite; }
  @keyframes pulse { 50% { opacity: .55; } }
  .story { background:#111a2e; border-left: 8px solid #38bdf8; border-radius: 12px; padding: 18px 24px; margin-bottom: 18px; }
  .story-title { font-size: 34px; font-weight: 800; }
  .story-text { font-size: 22px; line-height: 1.45; color:#cbd5e1; margin-top: 6px; }
  .story-watch { font-size: 20px; color: #fbbf24; margin-top: 10px; }
  .story-msg { font-size: 18px; color: #94a3b8; margin-top: 6px; }
  .pipeline { display:flex; align-items:stretch; gap: 8px; margin: 8px 0 22px; }
  .node { flex:1; border: 3px solid; border-radius: 16px; padding: 10px 10px; background:#0f172a; text-align:center; min-width: 0; }
  .node-icon { font-size: 32px; }
  .node-step { font-size: 15px; text-transform: uppercase; letter-spacing: .06em; color:#94a3b8; margin-top: 4px; }
  .node-value { font-size: 22px; font-weight: 800; margin-top: 6px; overflow-wrap: anywhere; }
  .node-detail { font-size: 15px; color:#94a3b8; margin-top: 6px; overflow-wrap: anywhere; }
  .arrow { align-self:center; font-size: 30px; color:#475569; }
  .tiles { display:flex; gap: 12px; margin: 18px 0; flex-wrap: wrap; }
  .tile { flex:1; min-width: 150px; background:#0f172a; border:1px solid #1e293b; border-radius: 14px; padding: 12px 16px; }
  .tile-value { font-size: 34px; font-weight: 800; }
  .tile-label { font-size: 15px; color:#94a3b8; text-transform: uppercase; letter-spacing: .05em; }
  .panel-title { font-size: 22px; font-weight: 700; margin: 8px 0 10px; color:#e2e8f0; }
  .chain { display:flex; align-items:center; gap: 6px; flex-wrap: wrap; min-width: 0; }
  .block { border: 3px solid; border-radius: 12px; padding: 10px 14px; background:#0f172a; min-width: 120px; }
  .block-id { font-size: 22px; font-weight: 800; }
  .block-type { font-size: 14px; color:#cbd5e1; }
  .block-hash { font-family: monospace; font-size: 13px; color:#64748b; }
  .link { font-size: 26px; }
  .docs { display:grid; grid-template-columns: repeat(auto-fill, minmax(64px, 1fr)); gap: 8px; }
  .doc { border: 3px solid; border-radius: 10px; padding: 8px 4px; text-align:center; font-size: 26px; background:#0f172a; min-width: 0; overflow: hidden; }
  .doc span { display:block; font-size: 11px; color:#94a3b8; overflow:hidden; white-space:nowrap; text-overflow: ellipsis; }
  .feed-row { display:flex; align-items:center; gap: 12px; padding: 7px 0; border-bottom: 1px solid #1e293b; font-size: 18px; }
  .dot { width: 14px; height: 14px; border-radius: 50%; flex: none; }
  .when { color:#64748b; font-family: monospace; }
  .why { color:#94a3b8; }
  .compare { display:flex; gap: 14px; }
  .compare > div { flex:1; background:#0f172a; border: 3px solid; border-radius: 14px; padding: 12px 16px; font-size: 18px; }
  .compare b { font-size: 20px; }
  .mono { font-family: monospace; font-size: 15px; color:#cbd5e1; overflow-wrap:anywhere; }
  @media (max-width: 900px) {
    .pipeline { flex-direction: column; } .arrow { transform: rotate(90deg); }
     .compare { flex-direction: column; }
  }
</style>
"""

st.set_page_config(page_title="URDS Exhibition", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
st.markdown(CSS, unsafe_allow_html=True)


@st.fragment(run_every="1s")
def story() -> None:
    state = read_state()
    auth = token()
    try:
        events = gateway("/monitor/events", auth, limit=40).get("events", [])
        monitor = gateway("/monitor/status", auth)
        verify = gateway("/ledger/verify", auth)
        blocks = gateway("/ledger/blocks", auth, limit=6, newest_first="true").get("blocks", [])
    except Exception as exc:
        st.error(f"The URDS services are not reachable ({exc}). Start them with scripts\\start_stack.ps1.")
        return

    event = focus_event(events, state)
    tamper = state.get("tamper") or {}
    chain_ok = bool(verify.get("valid"))
    threat = bool(event.get("suspicious")) or not chain_ok
    pill_colour, pill_text = (THREAT, "THREAT DETECTED") if threat else (SAFE, "SYSTEM SECURE")
    if not chain_ok:
        pill_text = "LEDGER TAMPERED"

    st.markdown(
        f'<div class="headline"><h1>🛡️ How URDS stops ransomware — live</h1>'
        f'<div class="pill" style="background:{pill_colour}">{pill_text}</div></div>'
        + tracker_html(state),
        unsafe_allow_html=True,
    )

    current = state.get("current")
    if current:
        st.markdown(
            f'<div class="story"><div class="story-title">Step {esc(current)} of {len(STEP_TITLES)} · '
            f'{esc(state.get("title"))}</div><div class="story-text">{esc(state.get("story"))}</div>'
            f'<div class="story-watch">👀 {esc(state.get("watch"))}</div>'
            f'<div class="story-msg">{esc(state.get("message"))}</div></div>',
            unsafe_allow_html=True,
        )
    else:
        intro = state.get("message") or "Every file change is checked in milliseconds. Drop a file into watched_files to see it."
        st.markdown(
            '<div class="story"><div class="story-title">Unified Ransomware Detection System</div>'
            '<div class="story-text">Detect the encryption &nbsp;→&nbsp; confirm with AI &nbsp;→&nbsp; seal the evidence '
            '&nbsp;→&nbsp; stop the attacker &nbsp;→&nbsp; restore the files.</div>'
            f'<div class="story-msg">{esc(intro)}</div></div>',
            unsafe_allow_html=True,
        )

    def draw_pipeline() -> None:
        st.markdown('<div class="panel-title">The detection pipeline · newest file</div>'
                    + pipeline_html(stages(event, state)), unsafe_allow_html=True)

    # Steps 4-8 are about their own panel (documents, recovery, chain, access,
    # numbers); it goes first so it is on the projector's first screen.
    panel_first = current in (4, 5, 6, 7, 8)
    if not panel_first:
        draw_pipeline()

    left, right = st.columns([1.35, 1])
    with left:
        sim = state.get("simulator")
        recovery = state.get("recovery")
        if current == 4 and sim:
            stopped_text = {True: "stopped by URDS", False: "NOT stopped", None: "running…"}[sim.get("stopped")]
            st.markdown(
                f'<div class="panel-title">Ransomware simulator ({esc(sim.get("family"))}) · '
                f'{esc(sim.get("encrypted", 0))} of {esc(sim.get("total"))} documents encrypted · {stopped_text}'
                f'{" · all restored ♻️" if sim.get("restored") else ""}</div>' + docs_html(sim),
                unsafe_allow_html=True,
            )
        elif current == 5 and recovery:
            status = recovery.get("status")
            after = recovery.get("after") or ("…" if status != "failed" else esc(recovery.get("reason")))
            st.markdown(
                '<div class="panel-title">Recovery from a Windows shadow copy</div><div class="compare">'
                f'<div style="border-color:{SAFE}"><b>Before</b><div class="mono">{esc(recovery.get("before") or "…")}</div></div>'
                f'<div style="border-color:{THREAT}"><b>Encrypted</b><div class="mono">{esc(recovery.get("during") or "…")}</div></div>'
                f'<div style="border-color:{SAFE if status == "restored" else IDLE}"><b>Restored</b>'
                f'<div class="mono">{esc(after)}</div>'
                f'{"<div>SHA-256 matches the ledger ✔</div>" if recovery.get("verified") else ""}</div></div>',
                unsafe_allow_html=True,
            )
        elif current == 7 and state.get("auth"):
            a = state["auth"]
            code = lambda c: f'<b style="color:{SAFE if c == 200 else THREAT}">HTTP {esc(c)}</b>'
            st.markdown(
                '<div class="panel-title">Access control at the API gateway</div><div class="compare">'
                f'<div style="border-color:{THREAT}">No token<br>{code(a.get("no_token"))} refused</div>'
                f'<div style="border-color:{THREAT}">Forged token<br>{code(a.get("forged"))} refused</div>'
                f'<div style="border-color:{SAFE}">Valid token<br>{code(a.get("valid"))} allowed</div></div>',
                unsafe_allow_html=True,
            )
        elif current == 8 and state.get("numbers"):
            st.markdown('<div class="panel-title">Measured results</div><div class="tiles">'
                        + "".join(tile(k, v, "#e2e8f0") for k, v in state["numbers"].items()) + "</div>",
                        unsafe_allow_html=True)
        elif current == 6:
            st.markdown('<div class="panel-title">Evidence ledger · each block carries the fingerprint of the one before it</div>'
                        + chain_html(blocks, tamper if not chain_ok else {}), unsafe_allow_html=True)
        else:
            st.markdown('<div class="panel-title">What the system just saw</div>' + feed_html(events),
                        unsafe_allow_html=True)
    with right:
        if current == 6:
            st.markdown('<div class="panel-title">What the system just saw</div>' + feed_html(events[:5]),
                        unsafe_allow_html=True)
        else:
            st.markdown('<div class="panel-title">Evidence ledger · each block locks the one before it</div>'
                        + chain_html(blocks[:3], tamper if not chain_ok else {}), unsafe_allow_html=True)
        if not chain_ok:
            st.markdown(f'<div class="story" style="border-left-color:{THREAT};margin-top:14px">'
                        f'<div class="story-title" style="color:{THREAT}">Tampering detected at block '
                        f'#{esc(verify.get("invalid_block_id"))}</div><div class="story-text">The record was '
                        'edited directly in the database. Its fingerprint no longer matches the chain.</div></div>',
                        unsafe_allow_html=True)

    if panel_first:
        draw_pipeline()

    alerts = sum(1 for e in events if e.get("suspicious"))
    stopped = sum(1 for e in events if (e.get("attribution_escalation") or {}).get("result") == "terminated")
    st.markdown(
        '<div class="tiles">'
        + tile("Files checked", f"{monitor.get('files_monitored', 0):,}", INFO)
        + tile("Alerts raised", alerts, THREAT if alerts else SAFE)
        + tile("Attackers stopped", stopped, SAFE if stopped else "#e2e8f0")
        + tile("Evidence blocks", verify.get("blocks_checked", "-"), SEAL)
        + tile("Ledger seal", "INTACT ✔" if chain_ok else f"BROKEN at #{verify.get('invalid_block_id')}",
               SAFE if chain_ok else THREAT)
        + tile("Attacker tracking", "LIVE" if monitor.get("attribution_available") else "OFF",
               SAFE if monitor.get("attribution_available") else WARN)
        + "</div>",
        unsafe_allow_html=True,
    )


story()
