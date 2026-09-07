import os
from datetime import datetime, timedelta, timezone

from collections import Counter

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from jose import jwt
from streamlit_autorefresh import st_autorefresh


GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000").rstrip("/")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


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


def gateway_post(path: str, token: str, payload: dict) -> dict:
    response = requests.post(
        f"{GATEWAY_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def pct(value: float | int | None) -> str:
    if value is None:
        return "N/A"
    return f"{float(value) * 100:.0f}%"


def short_hash(value: str | None) -> str:
    if not value:
        return "N/A"
    return f"{value[:10]}...{value[-6:]}" if len(value) > 18 else value


def status_label(raw_status: str | None) -> str:
    if not raw_status:
        return "Unknown"
    return raw_status.replace("_", " ").title()


# The three outcomes an operator rule can have, and how each reads on screen.
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
    "cancelled": ("Cancelled", "#f59e0b", "an operator rule removed this alert"),
    "attenuated": ("Attenuated", "#38bdf8", "a rule matched and was outranked; the alert stands"),
    "deferred": ("Deferred", "#a78bfa", "no verdict was reached on this event"),
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


def governance_chip(outcome: str | None) -> str:
    if outcome not in GOVERNANCE_OUTCOMES:
        return ""
    label, colour, _ = GOVERNANCE_OUTCOMES[outcome]
    return (
        f'<span style="background:{colour}22;color:{colour};border:1px solid {colour}66;'
        f'border-radius:6px;padding:2px 8px;font-size:0.78rem;font-weight:600;">'
        f"{label}</span>"
    )


def service_status(health: dict, name: str) -> str:
    return health.get("services", {}).get(name, {}).get("status", "unknown")


st.set_page_config(page_title="URDS Dashboard", page_icon="URDS", layout="wide")
st_autorefresh(interval=1000, key="urds_refresh")

st.markdown(
    """
    <style>
      .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
      div[data-testid="stMetric"] {
        background: #050816;
        border: 1px solid #243047;
        border-radius: 8px;
        padding: 14px 16px;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.14);
      }
      div[data-testid="stMetric"] * { color: #f8fafc !important; }
      div[data-testid="stMetric"] label,
      div[data-testid="stMetricLabel"] p {
        color: #cbd5e1 !important;
        font-weight: 600;
      }
      div[data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-weight: 800;
      }
      .status-banner {
        border-radius: 8px;
        padding: 18px 22px;
        border: 1px solid rgba(0,0,0,0.08);
        margin: 12px 0 18px 0;
      }
      .status-title {
        font-size: 24px;
        font-weight: 700;
        margin-bottom: 6px;
      }
      .status-line {
        font-size: 15px;
        line-height: 1.45;
      }
      .flow-row {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 10px;
        margin: 8px 0 16px 0;
      }
      .flow-step {
        border: 1px solid #243047;
        border-radius: 8px;
        padding: 12px 14px;
        background: #050816;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.14);
      }
      .flow-name { font-size: 13px; color: #cbd5e1; margin-bottom: 4px; }
      .flow-value { font-size: 16px; font-weight: 700; color: #ffffff; }
      .section-note { color: #606b78; font-size: 14px; margin-top: -6px; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("URDS Operations Dashboard")
st.caption("Live integration view for the API Gateway, ransomware prediction, ledger logging, and service health.")

token = make_dashboard_token()

try:
    health = requests.get(f"{GATEWAY_URL}/health", timeout=3).json()
    monitor = gateway_get("/monitor/status", token)
    events_payload = gateway_get("/monitor/events", token, {"limit": 30})
    metrics = gateway_get("/model/metrics", token)
    ledger_payload = gateway_get("/ledger/entries", token, {"limit": 10})
except Exception as exc:
    st.error(f"Gateway data unavailable: {exc}")
    st.stop()

events = events_payload.get("events", [])
ledger_entries = ledger_payload.get("entries", [])
latest_event = events[0] if events else {}
latest_block = ledger_entries[0] if ledger_entries else {}

latest_prediction = None
if latest_event:
    # Every value here is read off the event the Monitor actually measured.
    # These used to be the reference document's illustrative constants, which
    # meant the banner was scoring a file that did not exist: magic_bytes pinned
    # to 4D5A held has_container_header - the model's highest-importance feature
    # - at 0 for everything, so a ZIP the Monitor had correctly cleared as
    # benign_compressed could still be rendered as a threat.
    entropy = latest_event.get("entropy") or 0
    feature_payload = {
        "features": {
            "shannon_entropy": entropy,
            "file_size": latest_event.get("file_size", 0),
            "magic_bytes": latest_event.get("magic_bytes", "UNKNOWN"),
            # /8.0 to match the Monitor's own normalisation in extract_features.
            "modification_rate": round(min(1.0, entropy / 8.0), 2),
            "container_format": latest_event.get("container_format"),
            # Tri-state and passed through as one. `.get` with no default so an
            # event that predates the field arrives as null - "not checked" -
            # rather than as False, which is the model's highest-importance
            # column saying the container was examined and found forged.
            "container_valid": latest_event.get("container_valid"),
            "ransom_extension": latest_event.get("ransom_extension", False),
            # The measured statistics, forwarded rather than left to be
            # interpolated. Omitting them makes features_to_vector estimate them
            # from entropy, which is what rendered a legitimate ZIP as a threat:
            # measured and estimated byte statistics diverge most on exactly the
            # compressed-versus-encrypted case the banner exists to tell apart.
            # The block scalars are here for the same reason - interpolation
            # assumes a uniform file, which is precisely what a partially
            # encrypted one is not.
            **{
                key: latest_event[key]
                for key in (
                    "printable_ratio",
                    "byte_value_std",
                    "chi_square_uniformity",
                    "entropy_max_block",
                    "entropy_block_spread",
                    "high_entropy_block_fraction",
                )
                if key in latest_event
            },
            # Required by the FeatureSet contract, and PE-only. A file event
            # carries no PE parse, so these report nothing rather than inventing
            # a count - the same convention extract_features uses for a .docx.
            "pe_imports_count": 0,
            "api_calls": [],
        }
    }
    try:
        latest_prediction = gateway_post("/predict", token, feature_payload)
    except Exception:
        latest_prediction = None

THREAT_LEVEL_ORDER = ("low", "medium", "high", "critical")

prediction = (latest_prediction or {}).get("prediction", "benign")
confidence = (latest_prediction or {}).get("confidence")
model_threat_level = (latest_prediction or {}).get("threat_level", "low")

# The banner reports what the *system* decided, which is the Monitor's verdict
# and the model's score together - the same rule services/monitor/pipeline.py
# applies when it decides whether to fire a response. Showing only the model
# score made the banner disagree with the system standing behind it: the
# behavioural classifier is not confident on ciphertext under about 40KB, so a
# small file encrypted in place read "System Secure" on screen while the
# Monitor had already flagged it and the Response engine had acted on it.
monitor_flagged = bool(latest_event.get("suspicious"))
# A cancelled alert reads `suspicious: false`, so the banner would call it
# "System Secure" and say nothing about the detection an operator rule removed.
# The outcome is read from the adjudication record instead.
latest_outcome = governance_outcome(latest_event)
is_threat = prediction == "ransomware" or monitor_flagged
threat_level = max(
    model_threat_level,
    "high" if monitor_flagged else "low",
    key=lambda level: THREAT_LEVEL_ORDER.index(level) if level in THREAT_LEVEL_ORDER else 0,
)

banner_color = "#fff1f2" if is_threat else "#ecfdf3"
border_color = "#fda4af" if is_threat else "#86efac"
text_color = "#9f1239" if is_threat else "#166534"
banner_text = "Threat Detected" if is_threat else "System Secure"
latest_path = latest_event.get("file_path", "Waiting for file event")
latest_entropy = latest_event.get("entropy", 0)
event_type = latest_event.get("event_type", "none")

st.markdown(
    f"""
    <div class="status-banner" style="background:{banner_color}; color:{text_color}; border-color:{border_color};">
      <div class="status-title">{banner_text}</div>
      <div class="status-line">
        Latest event: <strong>{event_type}</strong> on <strong>{latest_path}</strong><br>
        Monitor verdict: <strong>{status_label(latest_event.get("verdict"))}</strong> |
        Governance: <strong>{GOVERNANCE_OUTCOMES.get(latest_outcome, ("None applied",))[0]}</strong> |
        Model decision: <strong>{prediction}</strong> | Threat level: <strong>{threat_level.upper()}</strong> |
        Confidence: <strong>{pct(confidence)}</strong> | Entropy: <strong>{latest_entropy}</strong>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.subheader("End-to-End Pipeline")
st.markdown(
    f"""
    <div class="flow-row">
      <div class="flow-step">
        <div class="flow-name">1. Monitor</div>
        <div class="flow-value">{status_label(service_status(health, "monitor"))}</div>
      </div>
      <div class="flow-step">
        <div class="flow-name">2. ML Engine</div>
        <div class="flow-value">{prediction.title()} ({pct(confidence)})</div>
      </div>
      <div class="flow-step">
        <div class="flow-name">3. Ledger</div>
        <div class="flow-value">Block #{latest_block.get("block_id", "N/A")}</div>
      </div>
      <div class="flow-step">
        <div class="flow-name">4. Response</div>
        <div class="flow-value">{status_label(service_status(health, "response"))}</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

overview_cols = st.columns(5)
overview_cols[0].metric("Gateway", status_label(health.get("status")))
overview_cols[1].metric("Monitor", status_label(monitor.get("status")))
overview_cols[2].metric("Files Watched", f"{monitor.get('files_monitored', 0):,}")
overview_cols[3].metric("Events Captured", f"{monitor.get('events_captured', 0):,}")
overview_cols[4].metric("Uptime", f"{monitor.get('uptime_seconds', 0)} sec")

summary_left, summary_right = st.columns([1.2, 1])

with summary_left:
    st.subheader("Current Event Under Review")
    if latest_event:
        event_summary = pd.DataFrame(
            [
                {"Field": "File path", "Value": latest_event.get("file_path")},
                {"Field": "Event type", "Value": latest_event.get("event_type")},
                {"Field": "Entropy", "Value": latest_event.get("entropy")},
                {"Field": "Process ID", "Value": latest_event.get("process_id")},
                {"Field": "User", "Value": latest_event.get("user")},
                {"Field": "Timestamp", "Value": latest_event.get("timestamp")},
            ]
        )
        st.dataframe(event_summary, use_container_width=True, hide_index=True)

        # The adjudication, in full, when a rule was involved. Both costs are
        # shown because the outcome is a comparison between them and an operator
        # who can only see the verdict cannot tell whether their rule won on
        # merit or on a tie.
        adjudication = latest_event.get("admissibility")
        if latest_outcome:
            label, colour, meaning = GOVERNANCE_OUTCOMES[latest_outcome]
            st.markdown(
                f"{governance_chip(latest_outcome)} &nbsp;<span style='opacity:0.8'>{meaning}</span>",
                unsafe_allow_html=True,
            )
        if isinstance(adjudication, dict):
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Field": "Rule", "Value": adjudication.get("rule")},
                        {"Field": "Matched value", "Value": adjudication.get("value")},
                        {"Field": "Signal it would cancel", "Value": adjudication.get("signal")},
                        {"Field": "Cost to forge the rule", "Value": adjudication.get("forgery_cost")},
                        {"Field": "Cost to avoid the signal", "Value": adjudication.get("avoidance_cost")},
                        {"Field": "Outcome", "Value": adjudication.get("outcome")},
                        {"Field": "Why", "Value": adjudication.get("reason")},
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.info("Waiting for the monitor service to report a file event.")

with summary_right:
    st.subheader("Model Decision")
    decision_cols = st.columns(2)
    decision_cols[0].metric("Prediction", prediction.title())
    decision_cols[1].metric("Confidence", pct(confidence))
    st.metric("Threat Level", threat_level.upper())
    if latest_prediction:
        importance = latest_prediction.get("features_importance", {})
        importance_df = pd.DataFrame(
            [{"Signal": key.replace("_", " ").title(), "Importance": value} for key, value in importance.items()]
        )
        fig_importance = px.bar(
            importance_df,
            x="Importance",
            y="Signal",
            orientation="h",
            range_x=[0, 0.5],
            title="Signals Driving the Decision",
        )
        fig_importance.update_layout(height=240, margin=dict(l=10, r=10, t=45, b=10))
        st.plotly_chart(fig_importance, use_container_width=True)

chart_col, ledger_col = st.columns([1.5, 1])

with chart_col:
    st.subheader("Entropy Trend")
    if events:
        event_df = pd.DataFrame(events)
        chart_df = event_df.sort_values("timestamp")
        fig = px.line(chart_df, x="timestamp", y="entropy", markers=True)
        fig.add_trace(
            go.Scatter(
                x=chart_df["timestamp"],
                y=[7.5] * len(chart_df),
                mode="lines",
                name="High-risk threshold",
                line=dict(color="#dc2626", dash="dash"),
            )
        )
        fig.update_layout(
            height=360,
            margin=dict(l=10, r=10, t=20, b=10),
            yaxis_title="Entropy",
            xaxis_title="Event time",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Waiting for monitor events.")

with ledger_col:
    st.subheader("Ledger Evidence")
    if latest_block:
        ledger_summary = pd.DataFrame(
            [
                {"Field": "Latest block", "Value": latest_block.get("block_id")},
                {"Field": "Current hash", "Value": short_hash(latest_block.get("current_hash"))},
                {"Field": "Previous hash", "Value": short_hash(latest_block.get("previous_hash"))},
                {"Field": "Tamper proof", "Value": latest_block.get("tamper_proof")},
                {"Field": "Timestamp", "Value": latest_block.get("timestamp")},
            ]
        )
        st.dataframe(ledger_summary, use_container_width=True, hide_index=True)
    else:
        st.info("No ledger entries yet.")

st.subheader("Service Health")

# Keys that are not health detail. Everything else a service reports about
# itself is shown, so the table stays truthful as services add fields.
_HEALTH_METADATA_KEYS = {"status", "service"}


def health_detail(service_data: dict) -> str:
    """What a service reports about itself, beyond up/down.

    This column used to read `service_data.get("placeholder", name != "gateway")`.
    No backend /health returns a `placeholder` key, so the default always won and
    the dashboard labelled monitor, ml_engine, ledger and response as
    placeholders on every load - contradicting the README, and on screen during
    the demo. The services do report real detail; this shows that instead.
    """
    details = [
        f"{key.replace('_', ' ')}: {value}"
        for key, value in service_data.items()
        if key not in _HEALTH_METADATA_KEYS
    ]
    return " | ".join(details) if details else "-"


health_rows = []
for service_name in ["gateway", "monitor", "ml_engine", "ledger", "response"]:
    service_data = health.get("services", {}).get(service_name, {"status": health.get("status") if service_name == "gateway" else "unknown"})
    health_rows.append(
        {
            "Service": service_name.replace("_", " ").title(),
            "Status": status_label(service_data.get("status")),
            "Reported": health_detail(service_data),
        }
    )
st.dataframe(pd.DataFrame(health_rows), use_container_width=True, hide_index=True)

details_left, details_right = st.columns([1.4, 1])

with details_left:
    st.subheader("Recent File Events")
    if events:
        table_df = pd.DataFrame(events).rename(
            columns={
                "timestamp": "Timestamp",
                "event_type": "Event",
                "file_path": "File",
                "entropy": "Entropy",
                "process_id": "Process ID",
                "user": "User",
            }
        )
        # One column per row saying which of the three outcomes applied. Without
        # it a cancelled detection is indistinguishable from a file that was
        # never suspicious, which is the row an auditor most needs to find.
        table_df["Governance"] = [
            GOVERNANCE_OUTCOMES.get(governance_outcome(event), ("-",))[0] for event in events
        ]
        st.dataframe(
            table_df[
                ["Timestamp", "Event", "File", "Entropy", "Governance", "Process ID", "User"]
            ],
            use_container_width=True,
            hide_index=True,
        )
        counts = Counter(
            governance_outcome(event) for event in events if governance_outcome(event)
        )
        if counts:
            st.caption(
                "Governance outcomes in view: "
                + ", ".join(
                    f"{GOVERNANCE_OUTCOMES[key][0]} {value}"
                    for key, value in counts.items()
                    if key in GOVERNANCE_OUTCOMES
                )
            )
    else:
        st.info("No events reported yet.")

with details_right:
    st.subheader("Model Quality")
    quality_df = pd.DataFrame(
        [
            {"Metric": "Accuracy", "Value": pct(metrics.get("accuracy"))},
            {"Metric": "Precision", "Value": pct(metrics.get("precision"))},
            {"Metric": "Recall", "Value": pct(metrics.get("recall"))},
            {"Metric": "F1 Score", "Value": pct(metrics.get("f1_score"))},
            {"Metric": "ROC AUC", "Value": pct(metrics.get("roc_auc"))},
            {"Metric": "Last trained", "Value": metrics.get("last_trained", "unknown")},
        ]
    )
    st.dataframe(quality_df, use_container_width=True, hide_index=True)
