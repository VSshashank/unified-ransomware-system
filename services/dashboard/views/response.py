"""Response: monitoring control, attribution, actions taken, leases, recovery, whitelist."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import requests  # noqa: E402
import streamlit as st  # noqa: E402

import urds_ui as ui  # noqa: E402

ui.apply_style()

RECOVERY_TYPES = ("snapshot_created", "file_recovered", "recovery_completed", "recovery_failed")

token = ui.make_dashboard_token()
try:
    monitor = ui.gateway_get("/monitor/status", token)
    actions = ui.gateway_get("/ledger/blocks", token,
                             {"event_type": "response_action", "newest_first": "true", "limit": 200})
except Exception as exc:
    ui.page_header("Response")
    st.error(f"Gateway data unavailable: {exc}")
    st.stop()

attribution = ui.monitor_get("/monitor/attribution")
whitelist = ui.monitor_get("/monitor/whitelist")
try:
    leases = ui.gateway_get("/response/leases", token)
except Exception:
    leases = None

running = monitor.get("status") == "active"
ui.page_header("Response", "".join([
    f'<span>Monitor <b>{"active" if running else "stopped"}</b></span>',
    f'<span>Response actions recorded <b>{actions.get("total", 0):,}</b></span>',
]))

# --------------------------------------------------------------------------- monitor

ui.section("Monitoring")
left, right = st.columns([1.1, 1], gap="medium")
with left:
    st.markdown(
        '<div class="u-panel">'
        f'<div class="u-title"><b>File monitor</b>{ui.chip("Active" if running else "Stopped", "green" if running else "amber")}</div>'
        + ui.kv_grid([
            ("Watch path", ui.mono(monitor.get("watch_path") or "-")),
            ("Monitor id", ui.esc(monitor.get("monitor_id") or "-")),
            ("Backend", ui.esc(monitor.get("observer_backend") or "-")),
            ("Files seen", f'{monitor.get("files_monitored", 0):,}'),
            ("Events captured", f'{monitor.get("events_captured", 0):,}'),
            ("Uptime", f'{int(monitor.get("uptime_seconds") or 0) // 60} min'),
            ("Training mode", ui.esc(monitor.get("training_mode") or "-")),
            ("File patterns", ui.esc(", ".join(monitor.get("file_patterns") or []) or "all files")),
        ])
        + "</div>",
        unsafe_allow_html=True,
    )
    with st.form("monitor_control", border=False):
        path = st.text_input("Watch path", value=monitor.get("watch_path") or "")
        b1, b2, _ = st.columns([1, 1, 2])
        start = b1.form_submit_button("Start monitoring", type="primary", width="stretch")
        stop = b2.form_submit_button("Stop monitoring", width="stretch")
    if start:
        try:
            ui.gateway_post("/monitor/start", token, {"watch_path": path, "recursive": True, "file_patterns": []}, 15)
            st.rerun()
        except requests.HTTPError as exc:
            st.error(f"Start failed: {exc.response.text[:300]}")
        except Exception as exc:
            st.error(f"Start failed: {exc}")
    if stop:
        try:
            ui.gateway_post("/monitor/stop", token, {}, 15)
            st.rerun()
        except Exception as exc:
            st.error(f"Stop failed: {exc}")

with right:
    if attribution is None:
        st.markdown('<div class="u-panel"><div class="u-title"><b>Process attribution</b>'
                    f'{ui.chip("Unreachable", "muted")}</div>'
                    f'<div class="u-empty">Monitor not reachable at {ui.esc(ui.MONITOR_URL)}.</div></div>',
                    unsafe_allow_html=True)
    else:
        live = bool(attribution.get("available"))
        pending = attribution.get("pending") or {}
        suspend = attribution.get("suspend_first") or {}
        st.markdown(
            '<div class="u-panel">'
            f'<div class="u-title"><b>Process attribution</b>{ui.chip("Live" if live else "Unavailable", "green" if live else "amber")}</div>'
            + ui.kv_grid([
                ("Source", ui.esc(attribution.get("source") or "-")),
                ("Error", ui.esc(attribution.get("error") or "none")),
                ("Kernel grade", ui.esc(attribution.get("kernel_grade"))),
                ("Delivery horizon", f'{ui.esc(attribution.get("delivery_horizon_ms", "-"))} ms'),
                ("Writes recorded", f'{attribution.get("writes_recorded", 0):,}'),
                ("Writes buffered", f'{attribution.get("writes_buffered", 0):,}'),
                ("Writes evicted", f'{attribution.get("writes_evicted", 0):,}'),
                ("Open questions", ui.esc(pending.get("open", 0))),
                ("Suspend first", ui.esc("on" if suspend.get("enabled") else "off")),
            ])
            + "</div>",
            unsafe_allow_html=True,
        )

# --------------------------------------------------------------------------- actions

ui.section("Response actions", f'{actions.get("total", 0):,} recorded in the ledger')
action_rows = []
for block in actions.get("blocks", []):
    data = block.get("event_data") or {}
    outcome = data.get("outcome", data.get("actions_taken"))
    action_rows.append({
        "Block": str(block.get("block_id")),
        "Time": ui.stamp(block.get("timestamp")),
        "Action": str(data.get("action") or "-"),
        "Target PID": str(data.get("pid") or data.get("process_id") or ""),
        "Process": ui.file_name(data.get("process_name") or data.get("process_image")) or "",
        "File": ui.file_name(data.get("file_path")),
        "Outcome": ", ".join(map(str, outcome)) if isinstance(outcome, list) else str(outcome or data.get("status") or "-"),
    })
if action_rows:
    st.dataframe(pd.DataFrame(action_rows), width="stretch", hide_index=True, height=320)
else:
    st.markdown('<div class="u-panel u-empty">No response actions recorded.</div>', unsafe_allow_html=True)

left, right = st.columns(2, gap="medium")
with left:
    lease_list = leases.get("leases", leases) if isinstance(leases, dict) else leases
    ui.section("Suspension leases", f"{len(lease_list)} active" if isinstance(lease_list, list) else "")
    if isinstance(lease_list, list) and lease_list:
        st.dataframe(pd.DataFrame([{k: str(v) for k, v in lease.items()} for lease in lease_list]),
                     width="stretch", hide_index=True)
    elif leases is None:
        st.markdown('<div class="u-panel u-empty">Response service not reachable.</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="u-panel u-empty">No processes are suspended.</div>', unsafe_allow_html=True)

with right:
    ui.section("Recovery")
    recovery = []
    for kind in RECOVERY_TYPES:
        try:
            recovery += ui.gateway_get("/ledger/blocks", token,
                                       {"event_type": kind, "newest_first": "true", "limit": 50}).get("blocks", [])
        except Exception:
            pass
    recovery.sort(key=lambda b: b.get("block_id", 0), reverse=True)
    if recovery:
        st.dataframe(pd.DataFrame([
            {
                "Block": str(b.get("block_id")),
                "Time": ui.stamp(b.get("timestamp")),
                "Type": str(b.get("event_type")),
                "Snapshot": str((b.get("event_data") or {}).get("snapshot_id") or ""),
                "File": ui.file_name((b.get("event_data") or {}).get("file_path")),
                "Result": str((b.get("event_data") or {}).get("status")
                              or (b.get("event_data") or {}).get("integrity_verified", "")),
            }
            for b in recovery[:50]
        ]), width="stretch", hide_index=True)
    else:
        st.markdown('<div class="u-panel u-empty">No snapshots or restores recorded.</div>', unsafe_allow_html=True)

# --------------------------------------------------------------------------- whitelist

ui.section("Whitelist", f'{whitelist.get("entries", 0)} entries' if whitelist else "")
if whitelist is None:
    st.markdown(f'<div class="u-panel u-empty">Monitor not reachable at {ui.esc(ui.MONITOR_URL)}.</div>',
                unsafe_allow_html=True)
else:
    rules = whitelist.get("whitelist") or {}
    entries = [{"Kind": "Path", "Value": str(p)} for p in rules.get("paths", [])] + \
              [{"Kind": "Hash", "Value": str(h)} for h in rules.get("hashes", [])]
    if entries:
        st.dataframe(pd.DataFrame(entries), width="stretch", hide_index=True)
        if st.button("Clear whitelist"):
            requests.put(f"{ui.MONITOR_URL}/monitor/whitelist", json={"paths": [], "hashes": []}, timeout=5)
            st.rerun()
    else:
        st.markdown('<div class="u-panel u-empty">No whitelist rules.</div>', unsafe_allow_html=True)
