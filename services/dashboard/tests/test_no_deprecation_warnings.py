"""The dashboard no longer trips Streamlit's `use_container_width` warning.

While open, the dashboard logged that deprecation about seven times per refresh
(69,510 lines in 35 minutes on the Windows test VM). The supported spelling is
`width="stretch"`; the pinned streamlit==1.51.0 accepts it on `st.dataframe` and
`st.plotly_chart`. These tests count the deprecation records Streamlit logs while
the real script runs against test_render.py's stubbed gateway, and check that no
table or chart lost its full-width layout in the swap.

Streamlit's `deprecation_util` logger does not propagate, so caplog cannot see it;
a handler is attached to that logger directly.
"""

import logging

import pytest
from streamlit.delta_generator import DeltaGenerator

from test_render import APP, EVENT, GATEWAY, gateway, run_dashboard  # noqa: F401

DEPRECATED = "use_container_width"
ADJUDICATED = dict(EVENT, admissibility={
    "rule": "path", "value": r"C:\watch\*", "signal": "static_entropy", "forgery_cost": "low",
    "avoidance_cost": "negligible", "outcome": "attenuated", "reason": "test", "admitted": False,
})


class Collector(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def deprecations():
    collector = Collector()
    logger = logging.getLogger("streamlit.deprecation_util")
    logger.addHandler(collector)
    yield [collector.messages]
    logger.removeHandler(collector)


def test_one_refresh_logs_no_use_container_width_warning(gateway, deprecations, monkeypatch):
    # The adjudicated event draws every table, so every call site runs.
    monkeypatch.setitem(GATEWAY, "/monitor/events", {"events": [ADJUDICATED]})
    run_dashboard()
    seen = [m for m in deprecations[0] if DEPRECATED in m]
    assert seen == [], f"{len(seen)} deprecation warnings in one refresh"


def test_the_source_has_no_use_container_width_left():
    assert DEPRECATED not in APP.read_text(encoding="utf-8")


def test_every_table_and_chart_still_stretches(gateway, monkeypatch):
    monkeypatch.setitem(GATEWAY, "/monitor/events", {"events": [ADJUDICATED]})
    drawn = []
    real = DeltaGenerator._enqueue

    def spy(self, delta_type, element_proto, add_rows_metadata=None, layout_config=None):
        if delta_type in ("arrow_data_frame", "plotly_chart"):
            drawn.append((delta_type, getattr(layout_config, "width", None)))
        return real(self, delta_type, element_proto, add_rows_metadata, layout_config)

    monkeypatch.setattr(DeltaGenerator, "_enqueue", spy)
    run_dashboard()

    kinds = {kind for kind, _ in drawn}
    assert kinds == {"arrow_data_frame", "plotly_chart"}, kinds
    assert len(drawn) >= 8, drawn
    assert all(width == "stretch" for _, width in drawn), drawn
