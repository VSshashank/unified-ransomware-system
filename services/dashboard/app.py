"""URDS console - the operator dashboard.

    streamlit run app.py

Five pages over the API gateway: Overview, Events, Ledger, Response, Model.
Each page is a script under views/; shared plumbing is in urds_ui.py.
"""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

import urds_ui as ui  # noqa: E402

st.set_page_config(page_title="URDS console", page_icon=":material/shield:", layout="wide")
ui.apply_style()

with st.sidebar:
    st.markdown('<div class="u-brand">URDS<span>Ransomware detection and response</span></div>',
                unsafe_allow_html=True)

VIEWS = Path(__file__).resolve().parent / "views"
navigation = st.navigation(
    [
        st.Page(VIEWS / "overview.py", title="Overview", icon=":material/monitoring:", default=True),
        st.Page(VIEWS / "events.py", title="Events", icon=":material/list_alt:"),
        st.Page(VIEWS / "ledger.py", title="Ledger", icon=":material/link:"),
        st.Page(VIEWS / "response.py", title="Response", icon=":material/shield:"),
        st.Page(VIEWS / "model.py", title="Model", icon=":material/query_stats:"),
    ]
)
navigation.run()
