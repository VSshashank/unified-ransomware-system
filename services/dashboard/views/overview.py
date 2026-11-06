"""Overview: health, counters, the latest detection end to end, recent activity."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
import requests  # noqa: E402
import streamlit as st  # noqa: E402

import urds_ui as ui  # noqa: E402

ui.apply_style()

SERVICES = [("gateway", "Gateway"), ("monitor", "Monitor"), ("ml_engine", "ML engine"),
            ("ledger", "Ledger"), ("response", "Response")]


def track(event: dict, prediction: dict | None) -> str:
    """Detected -> Classified -> Recorded -> Responded for one event."""
    stages = (event.get("pipeline") or {}).get("stages", [])
    suspicious = bool(event.get("suspicious"))
    latency = event.get("detection_latency_ms")
    label = (prediction or {}).get("prediction") or event.get("prediction")
    steps = [
        ("Detected", f"{ui.verdict_text(event)}" + (f" · {latency} ms" if latency is not None else ""),
         ui.TONES[ui.verdict_tone(event)]),
        ("Classified", (str(label).capitalize() if label else "-") +
         (f" · {ui.pct((prediction or {}).get('confidence'))}" if prediction else ""),
         ui.RED if label == "ransomware" else ui.GREEN if label else ui.LINE),
        ("Recorded", f"Block #{event['block_id']}" if event.get("block_id") else ("-" if not suspicious else "Pending"),
         ui.ACCENT if event.get("block_id") else ui.LINE),
        ("Responded", ui.response_result(event),
         ui.GREEN if ui.response_result(event) == "Terminated" else ui.AMBER if "response_triggered" in stages else ui.LINE),
    ]
    cells = "".join(
        f'<div class="u-step{" on" if colour != ui.LINE else ""}" style="--c:{colour}">'
        f'<div class="u-step-name">{name}</div><div class="u-step-value">{ui.esc(value)}</div></div>'
        for name, value, colour in steps
    )
    return f'<div class="u-track">{cells}</div>'


# The live panels are one fragment on a timer, not the whole page on
# st_autorefresh. A full-page rerun cancels the run in progress, and a run had
# to finish inside the interval to draw anything: on the Windows test VM a run
# took longer than 1 s while the gateway was slow, so every run was cut off
# after the title and the page never showed data (defect 13). A fragment's
# timed rerun waits for the run in progress, and a pending one is not queued
# twice, so a slow run is late rather than lost.
@st.fragment(run_every=ui.REFRESH_INTERVAL)
def live_view() -> None:
    token = ui.make_dashboard_token()
    try:
        health = requests.get(f"{ui.GATEWAY_URL}/health", timeout=3).json()
        monitor = ui.gateway_get("/monitor/status", token)
        events = ui.gateway_get("/monitor/events", token, {"limit": 100}).get("events", [])
        verify = ui.gateway_get("/ledger/verify", token)
        blocks = ui.gateway_get("/ledger/entries", token, {"limit": 8}).get("entries", [])
    except Exception as exc:
        ui.page_header("Overview")
        st.error(f"Gateway data unavailable: {exc}")
        return

    events = [e for e in events if e.get("verdict") != "deleted"]
    alerts = [e for e in events if e.get("suspicious")]
    focus = alerts[0] if alerts else (events[0] if events else {})
    prediction = None
    if focus:
        try:
            prediction = ui.gateway_post("/predict", token, ui.prediction_request(focus))
        except Exception:
            prediction = None
    is_threat, level = ui.system_decision(focus, prediction)

    running = monitor.get("status") == "active"
    attribution = monitor.get("attribution_available")
    ui.page_header("Overview", "".join([
        f'<span>Monitor <b>{"active" if running else "stopped"}</b></span>',
        f'<span>Watching <b>{ui.esc(monitor.get("watch_path") or "-")}</b></span>',
        f'<span>Attribution <b>{ui.esc(monitor.get("attribution_source") or "-") if attribution else "unavailable"}</b></span>',
        f'<span>Uptime <b>{int(monitor.get("uptime_seconds") or 0) // 60} min</b></span>',
    ]))

    st.markdown(
        '<div class="u-panel" style="display:flex;gap:28px;flex-wrap:wrap;padding:10px 16px">'
        + "".join(
            ui.chip(label, "green" if ui.service_status(health, key) == "healthy" else "red")
            for key, label in SERVICES
        )
        + "</div>",
        unsafe_allow_html=True,
    )
    st.write("")

    terminated = sum(1 for e in events if ui.response_result(e) == "Terminated")
    chain_ok = bool(verify.get("valid"))
    ui.stat_row([
        ui.stat("Files watched", f"{monitor.get('files_monitored', 0):,}"),
        ui.stat("Events captured", f"{monitor.get('events_captured', 0):,}"),
        ui.stat("Alerts", len(alerts), "in the last 100 events", "red" if alerts else "ink"),
        ui.stat("Processes terminated", terminated, "in the last 100 events"),
        ui.stat("Ledger blocks", f"{verify.get('blocks_checked', 0):,}",
                f"verified in {verify.get('verification_time_ms', '-')} ms"),
        ui.stat("Chain integrity", "Valid" if chain_ok else "Broken",
                "" if chain_ok else f"first bad block #{verify.get('invalid_block_id')}",
                "green" if chain_ok else "red"),
    ])

    left, right = st.columns([1.15, 1], gap="medium")
    with left:
        ui.section("Latest alert" if alerts else "Latest event",
                   ui.clock(focus.get("timestamp")) if focus else "")
        if focus:
            process = ui.file_name(focus.get("process_image")) or "-"
            st.markdown(
                '<div class="u-panel">'
                f'<div class="u-title"><b>{ui.esc(focus.get("file_path"))}</b>'
                f'{ui.chip(level.capitalize() if is_threat else "No threat", "red" if is_threat else "green")}</div>'
                + ui.kv_grid([
                    ("Event", ui.esc(focus.get("event_type"))),
                    ("Entropy", f'{ui.esc(focus.get("entropy"))} / 8'),
                    ("Container", ui.esc({True: "valid", False: "forged", None: "none"}.get(focus.get("container_valid"), "-"))
                     + (f' ({ui.esc(focus.get("container_format"))})' if focus.get("container_format") else "")),
                    ("Reason", ui.esc(focus.get("reason") or "-")),
                    ("Process", f'{ui.esc(process)} · PID {ui.esc(focus.get("process_id"))} · '
                                f'{ui.esc(focus.get("attribution_confidence"))}' if focus.get("process_id")
                     else "Not identified"),
                    ("SHA-256", ui.mono(ui.short_hash(focus.get("file_hash")))),
                    ("Governance", ui.esc(ui.governance_label(focus))),
                ])
                + track(focus, prediction)
                + "</div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown('<div class="u-panel u-empty">No file events yet.</div>', unsafe_allow_html=True)

    with right:
        ui.section("Entropy", f"last {len(events)} events · threshold {ui.ENTROPY_THRESHOLD}")
        if events:
            frame = pd.DataFrame(events).sort_values("timestamp")
            frame["when"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
            colours = [ui.RED if s else ui.MUTED for s in frame.get("suspicious", [False] * len(frame))]
            fig = go.Figure()
            fig.add_hline(y=ui.ENTROPY_THRESHOLD, line=dict(color=ui.RED, width=1, dash="dot"))
            fig.add_trace(go.Scatter(
                x=frame["when"], y=frame["entropy"], mode="markers",
                marker=dict(size=7, color=colours, line=dict(width=0)),
                text=[ui.file_name(p) for p in frame["file_path"]],
                hovertemplate="%{text}<br>entropy %{y}<extra></extra>",
            ))
            fig.update_yaxes(range=[0, 8.3])
            st.plotly_chart(ui.plot_layout(fig, 292), width="stretch", theme=None)
        else:
            st.markdown('<div class="u-panel u-empty">No file events yet.</div>', unsafe_allow_html=True)

    left, right = st.columns([1.6, 1], gap="medium")
    with left:
        ui.section("Recent events", f"{len(events)} shown")
        if events:
            table = pd.DataFrame([
                {
                    "Time": ui.clock(e.get("timestamp")),
                    "File": ui.file_name(e.get("file_path")),
                    "Event": str(e.get("event_type") or ""),
                    "Entropy": e.get("entropy"),
                    "Verdict": ui.verdict_text(e),
                    "Governance": ui.governance_label(e),
                    "Response": ui.response_result(e),
                    "PID": str(e.get("process_id") or ""),
                }
                for e in events[:25]
            ])
            st.dataframe(table, width="stretch", hide_index=True, height=360)
        else:
            st.markdown('<div class="u-panel u-empty">No file events yet.</div>', unsafe_allow_html=True)

    with right:
        ui.section("Latest ledger blocks")
        if blocks:
            table = pd.DataFrame([
                {
                    "Block": str(b.get("block_id")),
                    "Time": ui.clock(b.get("timestamp")),
                    "Type": str(b.get("event_type") or ""),
                    "Hash": ui.short_hash(b.get("current_hash")),
                }
                for b in blocks
            ])
            st.dataframe(table, width="stretch", hide_index=True, height=360)
        else:
            st.markdown('<div class="u-panel u-empty">The ledger is empty.</div>', unsafe_allow_html=True)


live_view()
