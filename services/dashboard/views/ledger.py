"""Ledger: the whole hash chain - integrity, every block, one block in full, export."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

import urds_ui as ui  # noqa: E402

ui.apply_style()

# Every event type a service writes (services/monitor/pipeline.py, services/
# response/app.py and recovery/, services/gateway/main.py). Types seen on the
# current page are added to the filter too, so a new one is never hidden.
EVENT_TYPES = [
    "file_event", "response_action", "attribution_escalation", "suppression_decision", "file_baseline",
    "snapshot_created", "file_recovered", "recovery_completed", "recovery_failed", "analysis", "auth_failure",
]
EXPORT_PAGE = 500


def subject(block: dict) -> str:
    data = block.get("event_data") or {}
    for key in ("file_path", "path", "target_path"):
        if data.get(key):
            return ui.file_name(data[key])
    for key in ("snapshot_id", "process_name", "pid", "process_id", "path_requested", "client"):
        if data.get(key) not in (None, ""):
            return f"{key.replace('_', ' ')} {data[key]}"
    return "-"


def detail(block: dict) -> str:
    data = block.get("event_data") or {}
    for key in ("verdict", "action", "result", "outcome", "status", "reason", "code"):
        value = data.get(key)
        if value not in (None, "", [], {}):
            return ", ".join(map(str, value)) if isinstance(value, list) else str(value)
    return "-"


def link_status(blocks: list[dict]) -> dict:
    """block_id -> Linked / Broken / '' using the neighbours on this page."""
    by_id = {b["block_id"]: b for b in blocks if b.get("block_id") is not None}
    status = {}
    for block_id, block in by_id.items():
        before = by_id.get(block_id - 1)
        if before is None:
            status[block_id] = ""
        else:
            status[block_id] = "Linked" if block.get("previous_hash") == before.get("current_hash") else "Broken"
    return status


def fetch(token: str, offset: int, limit: int, event_type: str | None, file_path: str | None,
          newest_first: bool) -> dict:
    params = {"offset": offset, "limit": limit, "newest_first": str(newest_first).lower()}
    if event_type:
        params["event_type"] = event_type
    if file_path:
        params["file_path"] = file_path
    return ui.gateway_get("/ledger/blocks", token, params)


def block_by_id(token: str, block_id: int, first_id: int) -> dict | None:
    """One block. Ids are sequential, so its offset is its distance from the first."""
    if block_id < first_id:
        return None
    page = ui.gateway_get("/ledger/blocks", token, {"offset": block_id - first_id, "limit": 1})
    blocks = page.get("blocks", [])
    return blocks[0] if blocks and blocks[0].get("block_id") == block_id else None


def full_export(token: str) -> list[dict]:
    out, offset = [], 0
    while True:
        page = ui.gateway_get("/ledger/blocks", token, {"offset": offset, "limit": EXPORT_PAGE})
        out.extend(page.get("blocks", []))
        offset += EXPORT_PAGE
        if offset >= page.get("total", 0) or not page.get("blocks"):
            return out


token = ui.make_dashboard_token()
try:
    verify = ui.gateway_get("/ledger/verify", token)
    first = ui.gateway_get("/ledger/blocks", token, {"offset": 0, "limit": 1}).get("blocks", [])
    last = ui.gateway_get("/ledger/blocks", token, {"offset": 0, "limit": 1, "newest_first": "true"}).get("blocks", [])
except Exception as exc:
    ui.page_header("Ledger")
    st.error(f"Gateway data unavailable: {exc}")
    st.stop()

chain_ok = bool(verify.get("valid"))
total_blocks = int(verify.get("blocks_checked") or 0)
first_id = first[0]["block_id"] if first else 1
last_id = last[0]["block_id"] if last else 0

ui.page_header("Ledger", "".join([
    f'<span>Blocks <b>{total_blocks:,}</b></span>',
    f'<span>Chain <b>{"valid" if chain_ok else "broken"}</b></span>',
    f'<span>Last block <b>{ui.stamp(last[0]["timestamp"]) if last else "-"}</b></span>',
]))

ui.stat_row([
    ui.stat("Chain integrity", "Valid" if chain_ok else "Broken",
            "every block's hash and link checked" if chain_ok else f"first bad block #{verify.get('invalid_block_id')}",
            "green" if chain_ok else "red"),
    ui.stat("Blocks", f"{total_blocks:,}", f"#{first_id} to #{last_id}" if last else ""),
    ui.stat("Verification time", f"{verify.get('verification_time_ms', '-')} ms", "full chain"),
    ui.stat("Latest block", f"#{last_id}" if last else "-", ui.esc(last[0]["event_type"]) if last else ""),
])
if not chain_ok and verify.get("invalid_block_id") is not None:
    st.session_state.setdefault("inspect_id", int(verify["invalid_block_id"]))

# --------------------------------------------------------------------------- browse

ui.section("Blocks")
f1, f2, f3, f4 = st.columns([1.2, 2, 1.2, 0.8])
event_type = f1.selectbox("Event type", ["All types"] + EVENT_TYPES, key="lf_type")
file_filter = f2.text_input("File path", key="lf_path", placeholder="C:\\urds\\watched_files\\report.docx")
order = f3.segmented_control("Order", ["Newest first", "Oldest first"], default="Newest first", key="lf_order")
page_size = f4.selectbox("Rows", [25, 50, 100, 200], index=1, key="lf_size")

type_value = None if event_type == "All types" else event_type
newest_first = order != "Oldest first"
try:
    probe = fetch(token, 0, 1, type_value, file_filter.strip() or None, newest_first)
except Exception as exc:
    st.error(f"Ledger query failed: {exc}")
    st.stop()
matching = int(probe.get("total") or 0)
pages = max(1, -(-matching // page_size))

p1, p2 = st.columns([1, 5])
page_no = p1.number_input(f"Page of {pages}", min_value=1, max_value=pages, value=1, step=1, key="lf_page")
page = fetch(token, (page_no - 1) * page_size, page_size, type_value, file_filter.strip() or None, newest_first)
blocks = page.get("blocks", [])
start = (page_no - 1) * page_size + 1 if blocks else 0
p2.markdown(f'<div class="u-meta" style="padding-top:34px">Showing {start:,}-{start + len(blocks) - 1:,} '
            f'of {matching:,} matching blocks</div>', unsafe_allow_html=True)

links = link_status(blocks)
broken_id = verify.get("invalid_block_id")
table = pd.DataFrame([
    {
        "Block": int(b["block_id"]),
        "Time": ui.stamp(b.get("timestamp")),
        "Type": str(b.get("event_type") or ""),
        "Subject": subject(b),
        "Detail": detail(b),
        "Previous hash": ui.short_hash(b.get("previous_hash")),
        "Hash": ui.short_hash(b.get("current_hash")),
        "Link": "Invalid" if broken_id is not None and b["block_id"] == broken_id else links.get(b["block_id"], ""),
    }
    for b in blocks
], columns=["Block", "Time", "Type", "Subject", "Detail", "Previous hash", "Hash", "Link"])

selection = st.dataframe(
    table, width="stretch", hide_index=True, height=min(38 + 35 * max(len(table), 1), 640),
    on_select="rerun", selection_mode="single-row", key="ledger_table",
    column_config={"Block": st.column_config.NumberColumn("Block", format="%d", width="small")},
)
rows = (selection.selection.rows if selection is not None and hasattr(selection, "selection") else []) or []
if rows and rows[0] < len(blocks):
    st.session_state["inspect_id"] = int(blocks[rows[0]]["block_id"])

e1, e2, _ = st.columns([1, 1, 3])
e1.download_button("Download page as CSV", table.to_csv(index=False).encode("utf-8"),
                   file_name=f"urds-ledger-page-{page_no}.csv", mime="text/csv", width="stretch")
if e2.button("Export full ledger", width="stretch"):
    st.session_state["ledger_export"] = json.dumps(full_export(token), indent=1, default=str)
if st.session_state.get("ledger_export"):
    e2.download_button("Save JSON", st.session_state["ledger_export"].encode("utf-8"),
                       file_name="urds-ledger.json", mime="application/json", width="stretch")

# --------------------------------------------------------------------------- inspect

ui.section("Block inspector")
default_id = int(st.session_state.get("inspect_id") or last_id or first_id)
i1, i2, i3, _ = st.columns([1, 0.6, 0.6, 3])
inspect_id = i1.number_input("Block", min_value=int(first_id), max_value=max(int(last_id), int(first_id)),
                             value=min(max(default_id, int(first_id)), max(int(last_id), int(first_id))), step=1)
if i2.button("Previous", width="stretch", disabled=inspect_id <= first_id):
    st.session_state["inspect_id"] = inspect_id - 1
    st.rerun()
if i3.button("Next", width="stretch", disabled=inspect_id >= last_id):
    st.session_state["inspect_id"] = inspect_id + 1
    st.rerun()
st.session_state["inspect_id"] = int(inspect_id)

block = block_by_id(token, int(inspect_id), int(first_id)) if total_blocks else None
if block is None:
    st.markdown('<div class="u-panel u-empty">No block with that number.</div>', unsafe_allow_html=True)
else:
    before = block_by_id(token, block["block_id"] - 1, int(first_id))
    if before is None:
        link = ui.chip("Genesis", "muted")
    elif before.get("current_hash") == block.get("previous_hash"):
        link = ui.chip(f"Linked to #{before['block_id']}", "green")
    else:
        link = ui.chip(f"Does not match #{before['block_id']}", "red")
    integrity = (ui.chip("Fails verification", "red") if broken_id is not None and block["block_id"] >= broken_id
                 else ui.chip("Verified", "green"))
    left, right = st.columns([1.1, 1], gap="medium")
    with left:
        st.markdown(
            '<div class="u-panel">'
            f'<div class="u-title"><b>Block #{block["block_id"]} · {ui.esc(block.get("event_type"))}</b>'
            f'<span style="display:flex;gap:16px">{link}{integrity}</span></div>'
            + ui.kv_grid([
                ("Timestamp", ui.esc(ui.stamp(block.get("timestamp")))),
                ("Event type", ui.esc(block.get("event_type"))),
                ("Previous hash", ui.mono(block.get("previous_hash"))),
                ("Hash", ui.mono(block.get("current_hash"))),
                ("Anchor", ui.esc(block.get("blockchain_anchor") or "none")),
            ])
            + "</div>",
            unsafe_allow_html=True,
        )
    with right:
        st.json(block.get("event_data") or {}, expanded=True)
