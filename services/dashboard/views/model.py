"""Model: the classifier's measured quality, and scoring a file on demand."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
import requests  # noqa: E402
import streamlit as st  # noqa: E402

import urds_ui as ui  # noqa: E402

ui.apply_style()

token = ui.make_dashboard_token()
try:
    metrics = ui.gateway_get("/model/metrics", token)
except Exception as exc:
    ui.page_header("Model")
    st.error(f"Gateway data unavailable: {exc}")
    st.stop()

models = metrics.get("models") or {}
ui.page_header("Model", "".join([
    f'<span>Version <b>{ui.esc(metrics.get("model_version") or "-")}</b></span>',
    f'<span>Last trained <b>{ui.esc(ui.stamp(metrics.get("last_trained")) or "unknown")}</b></span>',
    f'<span>Models loaded <b>{sum(1 for m in models.values() if m.get("loaded"))} of {len(models)}</b></span>',
]))

ui.stat_row([
    ui.stat("Accuracy", ui.pct(metrics.get("accuracy"))),
    ui.stat("Precision", ui.pct(metrics.get("precision"))),
    ui.stat("Recall", ui.pct(metrics.get("recall"))),
    ui.stat("F1 score", ui.pct(metrics.get("f1_score"))),
    ui.stat("ROC AUC", ui.pct(metrics.get("roc_auc"))),
])

ui.section("Models")
if models:
    def count(value):
        return len(value) if isinstance(value, (list, dict)) else value

    st.dataframe(pd.DataFrame([
        {
            "Model": name.replace("_", " "),
            "Loaded": "Yes" if m.get("loaded") else "No",
            "Accuracy": ui.pct(m.get("accuracy")),
            "Precision": ui.pct(m.get("precision")),
            "Recall": ui.pct(m.get("recall")),
            "F1": ui.pct(m.get("f1_score")),
            "ROC AUC": ui.pct(m.get("roc_auc")),
            "Test samples": str(m.get("test_samples") or "-"),
            "Features": str(count(m.get("features") or m.get("feature_names")) or "-"),
            "Dataset": str(m.get("dataset") or "-"),
            "Trained": ui.stamp(m.get("trained_at")) or "-",
        }
        for name, m in models.items()
    ]), width="stretch", hide_index=True)
else:
    st.markdown('<div class="u-panel u-empty">The ML engine reports no per-model metrics.</div>',
                unsafe_allow_html=True)

ui.section("Score a file")
with st.form("analyze", border=False):
    c1, c2 = st.columns([4, 1])
    path = c1.text_input("File path", placeholder="C:\\urds\\watched_files\\report.docx",
                         label_visibility="collapsed")
    submitted = c2.form_submit_button("Score file", type="primary", width="stretch")
if submitted and path.strip():
    try:
        result = ui.gateway_post("/analyze", token, {"file_path": path.strip()}, timeout=30)
    except requests.HTTPError as exc:
        st.error(f"Scoring failed: {exc.response.text[:400]}")
        result = None
    except Exception as exc:
        st.error(f"Scoring failed: {exc}")
        result = None
    if result:
        label = str(result.get("prediction", "-"))
        left, right = st.columns([1, 1.3], gap="medium")
        with left:
            st.markdown(
                '<div class="u-panel">'
                f'<div class="u-title"><b>{ui.esc(ui.file_name(path))}</b>'
                f'{ui.chip(label.capitalize(), "red" if label == "ransomware" else "green")}</div>'
                + ui.kv_grid([
                    ("Confidence", ui.pct(result.get("confidence"))),
                    ("Threat level", ui.esc(result.get("threat_level") or "-")),
                    ("Model", ui.esc(result.get("model_used") or result.get("model") or "-")),
                    ("Inference", f'{ui.esc(result.get("inference_time_ms", "-"))} ms'),
                    ("Logged", "analysis block written to the ledger"),
                ])
                + "</div>",
                unsafe_allow_html=True,
            )
        with right:
            importance = result.get("features_importance") or {}
            if importance:
                frame = pd.DataFrame(sorted(importance.items(), key=lambda kv: kv[1])[-10:],
                                     columns=["feature", "weight"])
                fig = go.Figure(go.Bar(x=frame["weight"], y=[f.replace("_", " ") for f in frame["feature"]],
                                       orientation="h", marker_color=ui.ACCENT))
                st.plotly_chart(ui.plot_layout(fig, 300), width="stretch", theme=None)
