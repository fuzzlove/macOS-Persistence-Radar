from __future__ import annotations


def test_gui_module_imports_without_root() -> None:
    import persistence_radar.gui.app as app

    assert app.RadarWindow is not None


def test_app_icon_loads() -> None:
    from PySide6.QtWidgets import QApplication

    from persistence_radar.gui.icons import app_icon

    app = QApplication.instance() or QApplication([])
    assert not app_icon().isNull()


def test_reset_filters_reveals_hidden_inventory(monkeypatch) -> None:
    from PySide6.QtWidgets import QApplication

    from persistence_radar.core.models import Finding, Severity
    from persistence_radar.gui.app import RadarWindow

    app = QApplication.instance() or QApplication([])
    window = RadarWindow()
    window.inventory_items = [
        Finding(id="one", title="Normal item", severity=Severity.INFO, category="LaunchAgent", path="/tmp/a")
    ]
    window.update_all_views()
    window.inventory_filter_bar.search.setText("does-not-match")
    assert window.filtered_inventory == []
    window.inventory_filter_bar.reset()
    window.apply_inventory_filters()
    assert len(window.filtered_inventory) == 1
    window.close()


def test_findings_sort_click_cycle_and_multicolumn() -> None:
    from PySide6.QtWidgets import QApplication

    from persistence_radar.gui.app import RadarWindow

    app = QApplication.instance() or QApplication([])
    window = RadarWindow()
    severity_section = 0
    first_seen_section = 6

    window.handle_sort("findings", severity_section)
    assert window.findings_sort == [("severity", True)]
    window.handle_sort("findings", severity_section)
    assert window.findings_sort == [("severity", False)]
    window.handle_sort("findings", severity_section)
    assert window.findings_sort == [("severity", False), ("risk_score", False), ("new", False)]

    window.findings_sort = [("severity", False)]
    window.findings_sort.append(("first_seen", True))
    assert window.findings_sort == [("severity", False), ("first_seen", True)]
    assert first_seen_section == 6
    window.close()
