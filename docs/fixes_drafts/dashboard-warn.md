## 27. The dashboard logged Streamlit's `use_container_width` deprecation on every refresh

Found in the 2026-10-05 VM run: the open dashboard's log held 69,510 lines in 35
minutes, almost all this warning.

**Measured:** eight `st.dataframe` / `st.plotly_chart` calls in
`services/dashboard/app.py` passed `use_container_width=True`. Streamlit 1.51.0
logs "Please replace `use_container_width` with `width`" for each one it draws,
on every refresh. With the adjudicated event (which draws every table) one
refresh logged **8** of them.

**Checked, not assumed:** the pinned `streamlit==1.51.0` accepts
`width="stretch"` on both calls (`inspect.signature` shows `width: Width =
'stretch'`; the deprecation text in `elements/arrow.py` names it as the
replacement for `use_container_width=True`).

**What changed:** the eight `use_container_width=True` became `width="stretch"`.
Same layout, no deprecation. Nothing else in `app.py` moved; `field_table()`
(defect 19) is untouched.

**Tests:** `services/dashboard/tests/test_no_deprecation_warnings.py`, +3; the
dashboard suite goes from 4 to 7 passed, run 3 times.
- A handler on Streamlit's non-propagating `streamlit.deprecation_util` logger
  counts the warnings in one refresh, and the source is checked for the old
  name. **Both fail on `dc089ff`** ("8 deprecation warnings in one refresh").
- A spy on `DeltaGenerator._enqueue` asserts every drawn table and chart still
  has a `stretch` width (>= 8 of them). This one passes on base too: it guards
  the swap, it does not prove the fix.
- The four existing `test_render.py` tests pass unchanged.

**Check on Windows:** with the dashboard open for a few refreshes, its log has
no "use_container_width" line.

**Not changed:** the Streamlit pin; the refresh interval; any panel.
