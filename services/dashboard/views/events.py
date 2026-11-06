"""Events: every file event the Monitor reports, filtered, with one event in full."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

import urds_ui as ui  # noqa: E402

ui.apply_style()

token = ui.make_dashboard_token()
try:
    monitor = ui.gateway_get("/monitor/status", token)
    events = ui.gateway_get("/monitor/events", token, {"limit": 500}).get("events", [])
except Exception as exc:
    ui.page_header("Events")
    st.error(f"Gateway data unavailable: {exc}")
    st.stop()

alerts = sum(1 for e in events if e.get("suspicious"))
ui.page_header("Events", "".join([
    f'<span>Held by the Monitor <b>{len(events):,}</b></span>',
    f'<span>Alerts <b>{alerts:,}</b></span>',
    f'<span>Captured since start <b>{monitor.get("events_captured", 0):,}</b></span>',
]))

c1, c2, c3, c4 = st.columns([1.3, 1.6, 2, 0.6])
show = c1.segmented_control("Show", ["All", "Alerts", "Benign", "Governed", "Deleted"], default="All", key="ev_show")
verdicts = sorted({ui.verdict_text(e) for e in events})
picked = c2.multiselect("Verdict", verdicts, key="ev_verdict")
query = c3.text_input("File path contains", key="ev_query")
if c4.button("Refresh", width="stretch"):
    st.rerun()

rows = [e for e in events if e.get("verdict") != "deleted"]
if show == "Deleted":
    rows = [e for e in events if e.get("verdict") == "deleted"]
elif show == "Alerts":
    rows = [e for e in rows if e.get("suspicious")]
elif show == "Benign":
    rows = [e for e in rows if not e.get("suspicious") and not ui.governance_outcome(e)]
elif show == "Governed":
    rows = [e for e in rows if ui.governance_outcome(e)]
if picked:
    rows = [e for e in rows if ui.verdict_text(e) in picked]
if query.strip():
    rows = [e for e in rows if query.strip().lower() in str(e.get("file_path", "")).lower()]

table = pd.DataFrame([
    {
        "Time": ui.stamp(e.get("timestamp")),
        "File": ui.file_name(e.get("file_path")),
        "Folder": str(e.get("file_path") or "").replace("\\", "/").rsplit("/", 1)[0],
        "Event": str(e.get("event_type") or ""),
        "Size": int(e.get("file_size") or 0),
        "Entropy": e.get("entropy"),
        "Verdict": ui.verdict_text(e),
        "Model": str(e.get("prediction") or ""),
        "Block": str(e.get("block_id") or ""),
        "Governance": ui.governance_label(e),
        "Response": ui.response_result(e),
        "PID": str(e.get("process_id") or ""),
        "Latency ms": e.get("detection_latency_ms"),
    }
    for e in rows
], columns=["Time", "File", "Folder", "Event", "Size", "Entropy", "Verdict", "Model", "Block", "Governance",
            "Response", "PID", "Latency ms"])

ui.section("File events", f"{len(rows):,} of {len(events):,}")
selection = st.dataframe(
    table, width="stretch", hide_index=True, height=440, on_select="rerun",
    selection_mode="single-row", key="events_table",
    column_config={"Size": st.column_config.NumberColumn("Size", format="%d B")},
)
chosen = (selection.selection.rows if selection is not None and hasattr(selection, "selection") else []) or []
alert_rows = [e for e in rows if e.get("suspicious")]
event = rows[chosen[0]] if chosen and chosen[0] < len(rows) else (alert_rows or rows or [None])[0]

ui.section("Event detail", ui.esc(event.get("event_id")) if event else "")
if not event:
    st.markdown('<div class="u-panel u-empty">No events match.</div>', unsafe_allow_html=True)
    st.stop()

left, right = st.columns([1.2, 1], gap="medium")
with left:
    st.markdown(
        '<div class="u-panel">'
        f'<div class="u-title"><b>{ui.esc(event.get("file_path"))}</b>'
        f'{ui.chip(ui.verdict_text(event), ui.verdict_tone(event))}</div>'
        + ui.kv_grid([
            ("Time", ui.esc(ui.stamp(event.get("timestamp")))),
            ("Event", ui.esc(event.get("event_type"))),
            ("Size", f'{int(event.get("file_size") or 0):,} bytes'),
            ("Entropy", f'{ui.esc(event.get("entropy"))} / 8'),
            ("Magic bytes", ui.mono(event.get("magic_bytes") or "-")),
            ("Container", ui.esc({True: "valid", False: "forged", None: "none"}.get(event.get("container_valid"), "-"))
             + (f' ({ui.esc(event.get("container_format"))})' if event.get("container_format") else "")),
            ("Signal", ui.esc(event.get("signal") or "-")),
            ("Reason", ui.esc(event.get("reason") or "-")),
            ("SHA-256", ui.mono(event.get("file_hash") or "-")),
            ("Detection", f'{ui.esc(event.get("detection_latency_ms", "-"))} ms'),
        ])
        + "</div>",
        unsafe_allow_html=True,
    )
with right:
    escalation = event.get("attribution_escalation") or {}
    stages = (event.get("pipeline") or {}).get("stages", [])
    st.markdown(
        '<div class="u-panel">'
        '<div class="u-title"><b>Pipeline and response</b></div>'
        + ui.kv_grid([
            ("Stages", ui.esc(", ".join(stages) or "-")),
            ("Model", ui.esc(event.get("prediction") or "-")
             + (f' · {ui.esc(event.get("threat_level"))}' if event.get("threat_level") else "")),
            ("Ledger block", ui.esc(event.get("block_id") or "-")),
            ("Incident", ui.mono(event.get("incident_id")) if event.get("incident_id") else "-"),
            ("Process", ui.esc(ui.file_name(event.get("process_image")) or "-")),
            ("PID", ui.esc(event.get("process_id") or "-")),
            ("Attribution", ui.esc(event.get("attribution_confidence") or "-")),
            ("Attribution source", ui.esc(event.get("attribution_source") or "-")),
            ("Response", ui.esc(ui.response_result(event))),
            ("First answer", ui.esc(escalation.get("initial_attribution_confidence") or "-")),
            ("Audit", ui.esc(escalation.get("audit_miss") or "-")),
        ])
        + "</div>",
        unsafe_allow_html=True,
    )
    # The adjudication, in full, when a rule was involved. Both costs are
    # shown because the outcome is a comparison between them and an operator
    # who can only see the verdict cannot tell whether their rule won on
    # merit or on a tie.
    adjudication = event.get("admissibility")
    if isinstance(adjudication, dict):
        st.dataframe(
            ui.field_table([
                ("Outcome", adjudication.get("outcome")),
                ("Rule", adjudication.get("rule")),
                ("Matched value", adjudication.get("value")),
                ("Signal it would cancel", adjudication.get("signal")),
                ("Cost to forge the rule", adjudication.get("forgery_cost")),
                ("Cost to avoid the signal", adjudication.get("avoidance_cost")),
                ("Why", adjudication.get("reason")),
            ]),
            width="stretch", hide_index=True,
        )

with st.expander("Raw event"):
    st.json(event)
