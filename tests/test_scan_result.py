from __future__ import annotations

from pathlib import Path
import shutil
import sys

from persistence_radar.core.scan import run_scan
from persistence_radar.scanners.launchd import scan_launchd

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _install_fixture(root: Path, fixture: str, name: str) -> None:
    destination = root / "Users" / "alice" / "Library" / "LaunchAgents"
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / fixture, destination / name)


def test_fixture_launch_agent_appears_in_inventory(tmp_path: Path) -> None:
    _install_fixture(tmp_path, "launch_agent_run_at_load.plist", "com.example.audit.agent.plist")

    result = run_scan(root=str(tmp_path))

    assert len(result.inventory_items) == 1
    assert result.inventory_items[0].title == "LaunchAgent: com.example.audit.agent"
    assert result.inventory_items[0].severity == "INFO"
    assert result.findings == []
    assert result.scanner_counts["LaunchAgents found"] == 1


def test_curl_bash_fixture_appears_as_finding(tmp_path: Path) -> None:
    _install_fixture(tmp_path, "launch_agent_curl_bash.plist", "com.apple.software.update.helper.plist")

    result = run_scan(root=str(tmp_path))

    assert len(result.inventory_items) == 1
    assert len(result.findings) == 1
    assert "curl" in result.findings[0].command


def test_parse_error_still_creates_inventory_item(tmp_path: Path) -> None:
    destination = tmp_path / "Library" / "LaunchDaemons"
    destination.mkdir(parents=True)
    (destination / "broken.plist").write_text("not a plist", encoding="utf-8")

    items = scan_launchd(root=str(tmp_path))

    assert len(items) == 1
    assert items[0].raw_evidence["parse_error"]


def test_scanner_exception_is_reported(monkeypatch, tmp_path: Path) -> None:
    import persistence_radar.core.scan as scan_module

    def broken(root: str = "/"):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "persistence_radar.scanners.SCANNERS",
        (("Broken", broken),),
    )

    result = run_scan(root=str(tmp_path))

    assert result.errors
    assert "Broken" in result.errors[0]


def test_system_launchdaemons_produce_inventory_on_macos() -> None:
    if sys.platform != "darwin" or not Path("/System/Library/LaunchDaemons").is_dir():
        return

    items = scan_launchd(root="/")
    system_daemons = [item for item in items if item.category == "LaunchDaemon" and item.path.startswith("/System/Library/LaunchDaemons/")]

    assert system_daemons
