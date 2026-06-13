from __future__ import annotations

from pathlib import Path
import shutil

from persistence_radar.core.scan import run_scan
from persistence_radar.scanners.browser_extensions import scan_browser_extensions
from persistence_radar.scanners.native_messaging import scan_native_messaging
from persistence_radar.scanners.path_hijack import scan_path_hijack
from persistence_radar.scanners.shell_startup import scan_shell_startup

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_shell_profile_curl_bash_and_path_hijack(tmp_path: Path) -> None:
    profile = tmp_path / "Users" / "alice" / ".zshrc"
    profile.parent.mkdir(parents=True)
    shutil.copy(FIXTURES / "shell_profile_curl_bash", profile)

    shell_items = scan_shell_startup(root=str(tmp_path))
    path_items = scan_path_hijack(root=str(tmp_path))

    assert any("curl" in item.command for item in shell_items)
    assert path_items


def test_browser_extension_native_messaging_permission(tmp_path: Path) -> None:
    manifest = tmp_path / "Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abc/1.0.0/manifest.json"
    manifest.parent.mkdir(parents=True)
    shutil.copy(FIXTURES / "browser_extension_manifest.json", manifest)

    items = scan_browser_extensions(root=str(tmp_path))

    assert items
    assert items[0].category == "Browser Extension"
    assert "nativeMessaging" in items[0].raw_evidence["permissions"]


def test_native_messaging_host_user_writable_binary(tmp_path: Path) -> None:
    manifest = tmp_path / "Users/alice/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.example.nativehost.json"
    manifest.parent.mkdir(parents=True)
    shutil.copy(FIXTURES / "native_messaging_host.json", manifest)

    items = scan_native_messaging(root=str(tmp_path))

    assert items
    assert items[0].category == "Native Messaging Host"
    assert items[0].severity in {"MEDIUM", "HIGH", "CRITICAL"}


def test_scan_result_includes_coverage_and_chains(tmp_path: Path) -> None:
    helper = tmp_path / "Library" / "PrivilegedHelperTools" / "com.example.Helper"
    helper.parent.mkdir(parents=True)
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    daemon = tmp_path / "Library" / "LaunchDaemons" / "com.example.Helper.plist"
    daemon.parent.mkdir(parents=True)
    daemon.write_text(
        """<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.example.Helper</string><key>ProgramArguments</key><array><string>/Library/PrivilegedHelperTools/com.example.Helper</string></array></dict></plist>""",
        encoding="utf-8",
    )

    result = run_scan(root=str(tmp_path))

    assert "native_messaging" in result.coverage
    assert result.scanner_counts["Privileged helpers found"] >= 1
