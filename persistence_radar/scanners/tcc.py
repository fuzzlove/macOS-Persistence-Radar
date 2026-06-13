from __future__ import annotations

from persistence_radar.core.models import Finding, Severity
from persistence_radar.scanners.common import root_join, stat_metadata, user_home_paths


def scan_tcc(root: str = "/") -> list[Finding]:
    paths = [root_join(root, "/Library/Application Support/com.apple.TCC/TCC.db")]
    for home in user_home_paths(root):
        paths.append(home / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db")
    findings = []
    for path in paths:
        if path.exists():
            owner, permissions = stat_metadata(path)
            display = str(path) if root == "/" else "/" + str(path.relative_to(root)).lstrip("/")
            findings.append(
                Finding(
                    id=f"tcc:{display}",
                    title=f"TCC privacy database: {display}",
                    severity=Severity.INFO,
                    category="TCC",
                    path=display,
                    owner=owner,
                    permissions=permissions,
                    explanation="TCC databases record privacy grants; readable indicators can reveal unusual application permissions.",
                    recommendation="Review high-risk grants such as Full Disk Access, Accessibility, Screen Recording, and Automation.",
                    raw_evidence={"readable": path.is_file()},
                )
            )
    return findings
