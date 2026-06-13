from __future__ import annotations

from pathlib import Path
import shutil

from persistence_radar.core.models import Severity
from persistence_radar.scanners.launchd import scan_launchd


FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _install_fixture(root: Path, fixture: str, name: str) -> None:
    destination = root / "Users" / "alice" / "Library" / "LaunchAgents"
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / fixture, destination / name)


def test_detects_sample_launch_agent_with_run_at_load(tmp_path: Path) -> None:
    _install_fixture(tmp_path, "launch_agent_run_at_load.plist", "com.example.audit.agent.plist")

    findings = scan_launchd(root=str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "LaunchAgent"
    assert finding.mitre_technique_id == "T1543.001"
    assert finding.raw_evidence["plist"]["RunAtLoad"] is True
    assert "launchd" in finding.explanation


def test_detects_suspicious_program_arguments_using_curl_and_bash(tmp_path: Path) -> None:
    _install_fixture(tmp_path, "launch_agent_curl_bash.plist", "com.apple.software.update.helper.plist")

    finding = scan_launchd(root=str(tmp_path))[0]

    assert "curl" in finding.command
    assert "bash" in finding.command
    assert finding.severity in {Severity.HIGH, Severity.CRITICAL}
    assert finding.mitre_technique_id == "T1543.001"


def test_unknown_or_unsigned_signing_status_is_graceful(tmp_path: Path) -> None:
    _install_fixture(tmp_path, "launch_agent_run_at_load.plist", "com.example.audit.agent.plist")

    finding = scan_launchd(root=str(tmp_path))[0]

    assert finding.code_signature_status in {"valid", "invalid", "unsigned", "unknown", "missing", "system-protected", "not-checked"}
