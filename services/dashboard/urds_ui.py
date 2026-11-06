"""Shared plumbing for the URDS console: gateway access, formatting, styling.

Every page imports this module. Nothing here draws on its own; the pages decide
what to show. Design rules the style follows, so later edits keep one system:

  * the interface is neutral (slate ink on near-white); colour is used only for
    state - red for a detection or a broken chain, amber for a pending or
    attenuated decision, green for healthy/verified, teal for the one accent;
  * one radius (4px), one hairline, one card recipe, no shadows or gradients;
  * sentence case, 13px/500 labels, mono for paths, hashes and ids.
"""

from __future__ import annotations

import html
import os
from datetime import datetime, timedelta, timezone

import pandas as pd
import requests
import streamlit as st
from jose import jwt

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000").rstrip("/")
# The Monitor's own status routes (attribution, whitelist) are not proxied by
# the gateway. The console reads them directly when it can reach the Monitor.
MONITOR_URL = os.getenv("MONITOR_URL", "http://localhost:8001").rstrip("/")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
# How often the live panels refresh: the "1s auto-refresh" the README states.
REFRESH_INTERVAL = "1s"
ENTROPY_THRESHOLD = 7.5

# Palette: "Frost and slate" from the taste-skill library, with state colours
# tuned to the same ink.
INK, MUTED, LINE, CARD, BG, ALT = "#1f3038", "#5d6b72", "#dde3e6", "#ffffff", "#f7f9fa", "#eef2f4"
ACCENT, RED, AMBER, GREEN = "#0d7480", "#b42318", "#b54708", "#067647"


# --------------------------------------------------------------------------- gateway

def make_dashboard_token() -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "dashboard",
        "role": "admin",
        "tier": "enterprise",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=2)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def gateway_get(path: str, token: str, params: dict | None = None) -> dict:
    response = requests.get(
        f"{GATEWAY_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        timeout=3,
    )
    response.raise_for_status()
    return response.json()


def gateway_post(path: str, token: str, payload: dict, timeout: float = 5) -> dict:
    response = requests.post(
        f"{GATEWAY_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def monitor_get(path: str) -> dict | None:
    """A Monitor route the gateway does not proxy; None when it cannot be reached."""
    try:
        response = requests.get(f"{MONITOR_URL}{path}", timeout=2)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


# --------------------------------------------------------------------------- formatting

def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def pct(value: float | int | None) -> str:
    if value is None:
        return "N/A"
    return f"{float(value) * 100:.1f}%"


def field_table(rows: list[tuple[str, object]]) -> pd.DataFrame:
    """A two-column Field / Value table, with every value as text.

    The values are of mixed types: a path, an entropy, a PID, a boolean. pyarrow
    cannot hold those in one column, so every refresh Streamlit caught an
    ArrowTypeError for each such table, logged it, and converted the column
    itself (reports/VM_TEST_REPORT_2026-10-04.md, "After the test"). Missing
    values read "N/A", as elsewhere on this page.
    """
    return pd.DataFrame([{"Field": field, "Value": "N/A" if value is None else str(value)} for field, value in rows])


def short_hash(value: str | None) -> str:
    if not value:
        return "N/A"
    return f"{value[:10]}...{value[-6:]}" if len(value) > 18 else value


def status_label(raw_status: str | None) -> str:
    if not raw_status:
        return "Unknown"
    return raw_status.replace("_", " ").capitalize()


def file_name(path) -> str:
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1]


def clock(timestamp) -> str:
    """HH:MM:SS from an ISO timestamp, or the raw value when it is not one."""
    text = str(timestamp or "")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
    except ValueError:
        return text[11:19] or text


def stamp(timestamp) -> str:
    text = str(timestamp or "")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text


# --------------------------------------------------------------------------- domain

# The three outcomes an operator rule can have.
# P5.1 found this vocabulary absent from the dashboard entirely: an alert that a
# whitelist had cancelled and an alert that was never raised looked identical
# here, which is the one distinction the governance layer exists to make.
#
#   cancelled   a rule matched and was expensive enough to fake that it was
#               allowed to remove the alert. The detection happened.
#   attenuated  a rule matched and was outranked. The alert stands, and the
#               operator should see that their rule was consulted and lost.
#   deferred    no verdict was reached now - an unreadable file, a first
#               sighting with no entropy history. Not a benign finding.
GOVERNANCE_OUTCOMES = {
    "cancelled": ("Cancelled", AMBER, "an operator rule removed this alert"),
    "attenuated": ("Attenuated", AMBER, "a rule matched and was outranked; the alert stands"),
    "deferred": ("Deferred", MUTED, "no verdict was reached on this event"),
}


def governance_outcome(event: dict) -> str | None:
    """`cancelled`, `attenuated`, `deferred`, or None when no rule was involved.

    Read from the adjudication record the Monitor puts on the event, never
    inferred from `suspicious` - a cancelled alert and a benign file both report
    `suspicious: false`, and telling them apart from that field is exactly the
    mistake this function exists to stop.
    """
    adjudication = event.get("admissibility")
    if isinstance(adjudication, dict) and adjudication.get("outcome"):
        return adjudication["outcome"]
    if event.get("verdict") in {"unreadable", "deferred"}:
        return "deferred"
    return None


def governance_label(event: dict) -> str:
    return GOVERNANCE_OUTCOMES.get(governance_outcome(event), ("-",))[0]


def verdict_text(event: dict) -> str:
    verdict = str(event.get("verdict") or "")
    return {
        "benign": "Benign",
        "benign_compressed": "Benign (valid container)",
        "suspected_encryption": "Suspected encryption",
        "deleted": "Deleted",
    }.get(verdict, verdict.replace("_", " ").capitalize() or "-")


def verdict_tone(event: dict) -> str:
    if event.get("suspicious"):
        return "red"
    if governance_outcome(event) in {"cancelled", "attenuated"}:
        return "amber"
    if event.get("verdict") == "deleted":
        return "muted"
    return "green"


def response_result(event: dict) -> str:
    """What the Response engine did for this event, in one phrase."""
    escalation = event.get("attribution_escalation") or {}
    if escalation.get("result"):
        return str(escalation["result"]).replace("_", " ").capitalize()
    if event.get("attribution_pending"):
        return "Attribution pending"
    stages = (event.get("pipeline") or {}).get("stages", [])
    if "response_triggered" in stages:
        return "Triggered"
    return "-" if not event.get("suspicious") else "Not dispatched"


def service_status(health: dict, name: str) -> str:
    return health.get("services", {}).get(name, {}).get("status", "unknown")


# Keys that are not health detail. Everything else a service reports about
# itself is shown, so the table stays truthful as services add fields.
_HEALTH_METADATA_KEYS = {"status", "service"}


def health_detail(service_data: dict) -> str:
    """What a service reports about itself, beyond up/down.

    This column used to read `service_data.get("placeholder", name != "gateway")`.
    No backend /health returns a `placeholder` key, so the default always won and
    the dashboard labelled monitor, ml_engine, ledger and response as
    placeholders on every load. The services do report real detail; this shows
    that instead.
    """
    details = [
        f"{key.replace('_', ' ')}: {value}"
        for key, value in service_data.items()
        if key not in _HEALTH_METADATA_KEYS
    ]
    return " | ".join(details) if details else "-"


def prediction_request(event: dict) -> dict:
    """The /predict body for a Monitor event, from what the Monitor measured.

    These used to be the reference document's illustrative constants, which
    meant the model was scoring a file that did not exist: magic_bytes pinned
    to 4D5A held has_container_header - the model's highest-importance feature
    - at 0 for everything, so a ZIP the Monitor had correctly cleared as
    benign_compressed could still be rendered as a threat.
    """
    entropy = event.get("entropy") or 0
    return {
        "features": {
            "shannon_entropy": entropy,
            "file_size": event.get("file_size", 0),
            "magic_bytes": event.get("magic_bytes", "UNKNOWN"),
            # /8.0 to match the Monitor's own normalisation in extract_features.
            "modification_rate": round(min(1.0, entropy / 8.0), 2),
            "container_format": event.get("container_format"),
            # Tri-state and passed through as one: an event that predates the
            # field arrives as null - "not checked" - rather than as False, which
            # is the model's highest-importance column saying the container was
            # examined and found forged.
            "container_valid": event.get("container_valid"),
            "ransom_extension": event.get("ransom_extension", False),
            # The measured statistics, forwarded rather than left to be
            # interpolated: measured and estimated byte statistics diverge most
            # on exactly the compressed-versus-encrypted case.
            **{
                key: event[key]
                for key in (
                    "printable_ratio",
                    "byte_value_std",
                    "chi_square_uniformity",
                    "entropy_max_block",
                    "entropy_block_spread",
                    "high_entropy_block_fraction",
                )
                if key in event
            },
            # Required by the FeatureSet contract, and PE-only.
            "pe_imports_count": 0,
            "api_calls": [],
        }
    }


THREAT_LEVEL_ORDER = ("low", "medium", "high", "critical")


def system_decision(event: dict, prediction: dict | None) -> tuple[bool, str]:
    """(is_threat, threat_level) as the system decided it.

    The Monitor's verdict and the model's score together - the same rule
    services/monitor/pipeline.py applies when it decides whether to fire a
    response. Showing only the model score made the status disagree with the
    system standing behind it: the behavioural classifier is not confident on
    ciphertext under about 40KB, so a small file encrypted in place read
    "secure" while the Monitor had already flagged it and Response had acted.
    """
    model_label = (prediction or {}).get("prediction", "benign")
    model_level = (prediction or {}).get("threat_level", "low")
    flagged = bool(event.get("suspicious"))
    level = max(
        model_level,
        "high" if flagged else "low",
        key=lambda value: THREAT_LEVEL_ORDER.index(value) if value in THREAT_LEVEL_ORDER else 0,
    )
    return model_label == "ransomware" or flagged, level


# --------------------------------------------------------------------------- drawing

TONES = {"red": RED, "amber": AMBER, "green": GREEN, "accent": ACCENT, "muted": MUTED, "ink": INK}


def chip(text: str, tone: str = "muted") -> str:
    colour = TONES.get(tone, MUTED)
    return f'<span class="u-chip" style="--c:{colour}"><i></i>{esc(text)}</span>'


def stat(label: str, value, sub: str = "", tone: str = "ink") -> str:
    colour = TONES.get(tone, INK)
    sub_html = f'<div class="u-stat-sub">{sub}</div>' if sub else ""
    return (f'<div class="u-stat"><div class="u-stat-label">{esc(label)}</div>'
            f'<div class="u-stat-value" style="color:{colour}">{esc(value)}</div>{sub_html}</div>')


def stat_row(items: list[str]) -> None:
    st.markdown(f'<div class="u-stats">{"".join(items)}</div>', unsafe_allow_html=True)


def page_header(title: str, meta: str = "") -> None:
    st.markdown(
        f'<div class="u-head"><h1>{esc(title)}</h1><div class="u-meta">{meta}</div></div>',
        unsafe_allow_html=True,
    )


def section(title: str, aside: str = "") -> None:
    st.markdown(f'<div class="u-section"><h3>{esc(title)}</h3><span>{aside}</span></div>',
                unsafe_allow_html=True)


def kv_grid(rows: list[tuple[str, str]]) -> str:
    """Label / value pairs as a definition grid; values are HTML (already escaped)."""
    cells = "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in rows)
    return f'<dl class="u-kv">{cells}</dl>'


def mono(value) -> str:
    return f'<code class="u-mono">{esc(value)}</code>'


def plot_layout(fig, height: int = 280):
    fig.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=8, b=8),
        paper_bgcolor=CARD,
        plot_bgcolor=CARD,
        font=dict(family="IBM Plex Sans, sans-serif", size=12, color=MUTED),
        showlegend=False,
        hoverlabel=dict(bgcolor=CARD, font_color=INK, bordercolor=LINE),
    )
    fig.update_xaxes(showgrid=False, linecolor=LINE, ticks="outside", tickcolor=LINE, title=None)
    fig.update_yaxes(gridcolor="#edf1f3", zeroline=False, linecolor=LINE, title=None)
    return fig


CSS = f"""
<style>
  .block-container {{ padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1480px; }}
  [data-testid="stHeader"] {{ background: transparent; }}
  /* The live panels rerun every second; Streamlit greys out "stale" elements
     while a run is in flight, which reads as flicker. */
  .stale-element, [data-stale="true"] {{ opacity: 1 !important; transition: none !important; }}
  h1, h2, h3 {{ letter-spacing: -0.01em; }}
  .u-head {{ display: flex; align-items: baseline; justify-content: space-between; gap: 16px;
            flex-wrap: wrap; border-bottom: 1px solid {LINE}; padding-bottom: 12px; margin-bottom: 20px; }}
  .u-head h1 {{ font-size: 22px; font-weight: 600; margin: 0; padding: 0; color: {INK}; }}
  .u-meta {{ display: flex; gap: 16px; flex-wrap: wrap; font-size: 13px; color: {MUTED}; }}
  .u-meta b {{ color: {INK}; font-weight: 500; }}
  .u-section {{ display: flex; align-items: baseline; justify-content: space-between; gap: 12px;
               margin: 24px 0 8px; }}
  .u-section h3 {{ font-size: 15px; font-weight: 600; margin: 0; padding: 0; color: {INK}; }}
  .u-section span {{ font-size: 13px; color: {MUTED}; }}
  .u-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
             border: 1px solid {LINE}; border-radius: 4px; background: {CARD}; overflow: hidden; }}
  .u-stat {{ padding: 14px 16px; border-right: 1px solid {LINE}; min-width: 0; }}
  .u-stat:last-child {{ border-right: 0; }}
  .u-stat-label {{ font-size: 13px; font-weight: 500; color: {MUTED}; }}
  .u-stat-value {{ font-size: 24px; font-weight: 500; margin-top: 4px; font-variant-numeric: tabular-nums;
                  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .u-stat-sub {{ font-size: 13px; color: {MUTED}; margin-top: 2px; white-space: nowrap; overflow: hidden;
                text-overflow: ellipsis; }}
  .u-chip {{ display: inline-flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 500;
            color: {INK}; white-space: nowrap; }}
  .u-chip i {{ width: 8px; height: 8px; border-radius: 50%; background: var(--c); display: inline-block; }}
  .u-panel {{ border: 1px solid {LINE}; border-radius: 4px; background: {CARD}; padding: 16px 18px; }}
  .u-panel + .u-panel {{ margin-top: 12px; }}
  .u-title {{ display: flex; justify-content: space-between; align-items: center; gap: 12px;
             margin-bottom: 12px; }}
  .u-title b {{ font-size: 15px; font-weight: 600; color: {INK}; overflow-wrap: anywhere; }}
  .u-kv {{ display: grid; grid-template-columns: max-content 1fr; gap: 6px 20px; margin: 0; font-size: 14px; }}
  .u-kv dt {{ color: {MUTED}; font-weight: 500; font-size: 13px; padding-top: 1px; }}
  .u-kv dd {{ margin: 0; color: {INK}; overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }}
  .u-mono {{ font-family: 'IBM Plex Mono', ui-monospace, monospace; font-size: 12.5px; color: {INK};
            background: {ALT}; padding: 1px 5px; border-radius: 3px; overflow-wrap: anywhere; }}
  .u-track {{ display: grid; grid-template-columns: repeat(4, 1fr); border: 1px solid {LINE};
             border-radius: 4px; overflow: hidden; margin-top: 14px; }}
  .u-step {{ padding: 10px 12px; border-right: 1px solid {LINE}; background: {CARD}; min-width: 0; }}
  .u-step:last-child {{ border-right: 0; }}
  .u-step-name {{ font-size: 13px; color: {MUTED}; font-weight: 500; }}
  .u-step-value {{ font-size: 14px; color: {INK}; margin-top: 2px; overflow-wrap: anywhere; }}
  .u-step.on {{ box-shadow: inset 0 3px 0 var(--c); }}
  .u-empty {{ color: {MUTED}; font-size: 14px; padding: 8px 0; }}
  [data-testid="stSidebarNav"] a span {{ font-size: 14px; }}
  .u-brand {{ font-size: 15px; font-weight: 600; color: {INK}; padding: 0 0 4px 2px; }}
  .u-brand span {{ display: block; font-size: 13px; font-weight: 400; color: {MUTED}; }}
  @media (max-width: 760px) {{
    .u-track {{ grid-template-columns: 1fr 1fr; }}
    .u-stat {{ border-right: 0; border-bottom: 1px solid {LINE}; }}
  }}
</style>
"""


def apply_style() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
