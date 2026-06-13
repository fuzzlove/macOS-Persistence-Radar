from __future__ import annotations

from pathlib import Path

from persistence_radar.core.mitre import technique
from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.scoring import command_has_suspicious_token, score_finding
from persistence_radar.scanners.common import root_join, stat_metadata, user_home_paths

SHELL_FILES = (".zshrc", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile")
SYSTEM_SHELL_FILES = ("/etc/zshrc", "/etc/bashrc", "/etc/profile")


def _make_finding(path: Path, display_path: str, user_context: str) -> Finding:
    owner, permissions = stat_metadata(path)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        content = ""
    indicators = (
        "curl | sh",
        "curl | bash",
        "wget",
        "osascript",
        "base64",
        "python -c",
        "perl -e",
        "ruby -e",
        " nc ",
        "ncat",
        "socat",
        "chmod +x",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    )
    suspicious_lines = [
        line.strip()
        for line in content.splitlines()
        if command_has_suspicious_token(line) or any(indicator.lower() in line.lower() for indicator in indicators) or line.strip().startswith("PATH=")
    ]
    evidence = {"path": display_path, "command": "\n".join(suspicious_lines), "executable_path": ""}
    severity, reasons = score_finding(evidence)
    path_hijack = any(line.strip().startswith("PATH=") and ("/tmp" in line or "/Users/Shared" in line or ":." in line) for line in content.splitlines())
    dyld = "DYLD_INSERT_LIBRARIES" in content or "DYLD_LIBRARY_PATH" in content
    if not suspicious_lines:
        severity = Severity.INFO
    elif path_hijack or dyld:
        severity = Severity.HIGH
    mitre_id, mitre_name = technique("startup_script")
    return Finding(
        id=f"shell:{display_path}",
        title=f"Shell startup file: {display_path}",
        severity=severity,
        category="Shell Startup",
        mitre_technique_id=mitre_id,
        mitre_technique_name=mitre_name,
        path=display_path,
        command="\n".join(suspicious_lines),
        user_context=user_context,
        owner=owner,
        permissions=permissions,
        explanation="Shell startup files can execute commands during interactive login shells."
        + (f" Risk factors: {'; '.join(reasons)}." if reasons else ""),
        recommendation="Review unexpected commands, especially downloaders, interpreters, and remote URLs.",
        raw_evidence={"suspicious_lines": suspicious_lines, "path_hijack_indicator": path_hijack, "dyld_indicator": dyld, "size": len(content)},
    )


def scan_shell_startup(root: str = "/") -> list[Finding]:
    findings: list[Finding] = []
    for item in SYSTEM_SHELL_FILES:
        path = root_join(root, item)
        if path.exists():
            findings.append(_make_finding(path, item, "system"))
    for home in user_home_paths(root):
        for name in SHELL_FILES:
            path = home / name
            if path.exists():
                display = "/" + str(path.relative_to(root)).lstrip("/") if root != "/" else str(path)
                findings.append(_make_finding(path, display, home.name))
    return findings
