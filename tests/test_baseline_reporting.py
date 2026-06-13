from __future__ import annotations

from pathlib import Path
import json

from persistence_radar.core.baseline import compare_findings
from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.reporting import export_html, export_json, export_markdown
from persistence_radar.core.scan import doctor


def finding(item_id: str, path: str, command: str = "/usr/bin/true") -> Finding:
    return Finding(
        id=item_id,
        title=f"Finding {item_id}",
        severity=Severity.LOW,
        category="LaunchAgent",
        path=path,
        command=command,
    )


def test_baseline_diff_added_removed_modified() -> None:
    old = [finding("same", "/a", "old"), finding("removed", "/removed")]
    new = [finding("same", "/a", "new"), finding("added", "/added")]

    diff = compare_findings(old, new)

    assert [item.id for item in diff.added] == ["added"]
    assert [item.id for item in diff.removed] == ["removed"]
    assert [(old_item.id, new_item.id) for old_item, new_item in diff.modified] == [("same", "same")]


def test_export_valid_json_and_html(tmp_path: Path) -> None:
    findings = [finding("one", "/Library/LaunchAgents/example.plist")]
    json_path = export_json(findings, tmp_path / "report.json")
    html_path = export_html(findings, tmp_path / "report.html")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["app_version"]
    assert payload["scan_metadata"]["scanner_version"]
    assert payload["inventory_items"][0]["id"] == "one"
    assert payload["warnings"] == []
    assert payload["errors"] == []
    assert payload["metadata"]["scanner_version"]
    assert payload["summary"]["total_findings"] == 1
    assert payload["findings"][0]["id"] == "one"
    html = html_path.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "macOS Persistence Radar Report" in html
    assert "Executive Summary" in html
    assert "MITRE ATT&amp;CK Coverage" in html


def test_export_markdown_has_client_sections(tmp_path: Path) -> None:
    findings = [finding("one", "/Library/LaunchAgents/example.plist")]
    md_path = export_markdown(findings, tmp_path / "report.md")
    markdown = md_path.read_text(encoding="utf-8")

    assert "## Executive Summary" in markdown
    assert "## Severity Counts" in markdown
    assert "## Remediation Checklist" in markdown
    assert "## Finding Appendix" in markdown


def test_doctor_release_diagnostics(tmp_path: Path) -> None:
    diagnostics = doctor(root=str(tmp_path))

    assert diagnostics["app_version"]
    assert diagnostics["python_version"]
    assert diagnostics["macos_version"] is not None
    assert diagnostics["current_user"]
    assert diagnostics["app_path"]
    assert diagnostics["database_path"]
    assert diagnostics["log_path"]
    assert diagnostics["full_disk_access_likely"] in {"yes", "unknown"}
    assert diagnostics["scanner_modules_enabled"] > 0
    assert diagnostics["last_scan_status"] == "unknown"
