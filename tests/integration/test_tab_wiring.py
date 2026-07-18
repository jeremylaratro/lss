"""Integration tests: the extracted tabs are wired into the running app.

These construct a REAL Tk root (via a display; skipped if none is available)
and a real ``SecurityControlPanel``. They exist because the rest of the suite
mocks Tk entirely and never instantiates the running app, so nothing else would
catch a regression in the monolith<->extracted-tab wiring (the whole point of
retiring the dead-code fork). Run under a headless display with ``xvfb-run``.
"""
import tkinter as tk

import pytest

from ids_suite.ui.tabs import AlertsTab, TrafficTab, DNSTab, QuarantineTab


@pytest.fixture
def app():
    """A fully constructed SecurityControlPanel on a hidden real Tk root."""
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available for Tk")
    root.withdraw()

    from ids_suite.ui.main_window import SecurityControlPanel

    panel = SecurityControlPanel(root)
    # Auto-refresh scheduled root.after callbacks never fire without mainloop,
    # but pin _update_eve_buffer to a no-op so injected buffers stay stable.
    panel._update_eve_buffer = lambda: None
    yield panel
    try:
        root.destroy()
    except Exception:
        pass


@pytest.mark.integration
class TestTabWiring:
    def test_extracted_tabs_are_instantiated(self, app):
        """The four create_*_tab builders now instantiate the extracted classes."""
        assert isinstance(app.alerts_tab, AlertsTab)
        assert isinstance(app.traffic_tab, TrafficTab)
        assert isinstance(app.dns_tab, DNSTab)
        assert isinstance(app.quarantine_tab, QuarantineTab)

    def test_all_seventeen_tabs_present_in_order(self, app):
        """Tab order must be preserved (auto-refresh dispatch keys off indices)."""
        labels = [app.notebook.tab(i, "text")
                  for i in range(app.notebook.index("end"))]
        assert len(labels) == 17
        # index -> substring the auto-refresh dispatcher relies on
        assert "Alerts" in labels[1]
        assert "Traffic" in labels[2]
        assert "DNS" in labels[4]
        assert "Quar" in labels[6]

    def test_refresh_shims_delegate_without_error(self, app):
        for fn in (app.refresh_alerts, app.refresh_traffic,
                   app.refresh_dns, app.refresh_quarantine):
            fn()  # must not raise

    def test_kept_shared_helpers_survive(self, app):
        """Helpers used by other tabs / the Intel tab must not be deleted."""
        for name in ("lookup_virustotal", "lookup_otx",
                     "_show_threat_intel_result", "copy_to_clipboard"):
            assert callable(getattr(app, name))

    def test_global_search_hook_delegates(self, app):
        app.filter_alerts_treeview("anything")  # must not raise
        app._update_filter_count()

    def test_auto_refresh_dispatch_per_tab(self, app):
        """_apply_refresh_ui refreshes the active tab keyed by notebook index."""
        for idx in (1, 2, 4, 6):
            app.notebook.select(idx)
            app._apply_refresh_ui()  # must not raise for any wired tab


def _alert_event(i):
    ts = f"2026-07-17T12:{i // 60:02d}:{i % 60:02d}.000000-0400"
    return {
        "timestamp": ts,
        "data": {
            "event_type": "alert",
            "timestamp": ts,
            "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
            "src_port": 1234, "dest_port": 80,
            "alert": {
                "severity": 3,  # low -> no threat-intel auto-lookup threads
                "signature": f"SIG-{i:03d}",
                "category": "Test",
            },
        },
    }


@pytest.mark.integration
class TestAlertsSliceRegression:
    """Guards the HIGH-4 fix ported into AlertsTab: keep the NEWEST 200 alerts."""

    def test_keeps_newest_200_not_oldest(self, app):
        app.alerts_tab.historical_mode = False
        # 250 distinct-signature alerts, ascending timestamps (SIG-249 newest)
        app.eve_event_buffer = [_alert_event(i) for i in range(250)]

        app.alerts_tab.refresh()

        tree = app.alerts_tab.alerts_tree
        rows = tree.get_children()
        assert len(rows) == 200

        sigs = {tree.item(r, "values")[2] for r in rows}
        assert "SIG-249" in sigs   # newest kept
        assert "SIG-050" in sigs   # boundary of newest-200 kept
        assert "SIG-049" not in sigs  # older dropped
        assert "SIG-000" not in sigs  # oldest dropped

    def test_refresh_is_idempotent(self, app):
        app.alerts_tab.historical_mode = False
        app.eve_event_buffer = [_alert_event(i) for i in range(10)]
        app.alerts_tab.refresh()
        n1 = len(app.alerts_tab.alerts_tree.get_children())
        app.alerts_tab.refresh()  # unchanged data -> early return, stable view
        n2 = len(app.alerts_tab.alerts_tree.get_children())
        assert n1 == n2 == 10
