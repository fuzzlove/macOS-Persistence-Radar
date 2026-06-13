from __future__ import annotations

from pathlib import Path

from persistence_radar.core.mitre import technique
from persistence_radar.core.models import Finding, Severity
from persistence_radar.scanners.common import root_join, stat_metadata, user_home_paths

LOGIN_ITEM_HINTS = (
    "/Library/Application Support/com.apple.backgroundtaskmanagementagent",
    "/Library/LaunchAgents",
)


def scan_login_items(root: str = "/") -> list[Finding]:
    findings: list[Finding] = []
    mitre_id, mitre_name = technique("login_item")
    for hint in LOGIN_ITEM_HINTS:
        path = root_join(root, hint)
        if path.exists():
            owner, permissions = stat_metadata(path)
            findings.append(
                Finding(
                    id=f"login-item-source:{hint}",
                    title=f"Login/background item source: {hint}",
                    severity=Severity.INFO,
                    category="Login Items",
                    mitre_technique_id=mitre_id,
                    mitre_technique_name=mitre_name,
                    path=hint,
                    owner=owner,
                    permissions=permissions,
                    explanation="Login Items and Background Items can launch applications or helpers at user login.",
                    recommendation="Use System Settings and BTM records to verify approved background items.",
                    raw_evidence={"source_exists": True},
                )
            )
    mitre_id, mitre_name = technique("reopened_application")
    pref_paths = [Path.home() / "Library/Preferences/com.apple.loginwindow.plist"] if root == "/" else []
    pref_paths.extend(home / "Library/Preferences/com.apple.loginwindow.plist" for home in user_home_paths(root))
    for prefs in pref_paths:
        if prefs.is_file():
            owner, permissions = stat_metadata(prefs)
            findings.append(
                Finding(
                    id=f"reopened-apps:{prefs}",
                    title="Re-opened applications/session restore preference",
                    severity=Severity.INFO,
                    category="Re-opened Applications",
                    mitre_technique_id=mitre_id,
                    mitre_technique_name=mitre_name,
                    path=str(prefs),
                    owner=owner,
                    permissions=permissions,
                    explanation="macOS can restore applications and windows across login sessions. Attackers may abuse reopened applications for persistence in some workflows.",
                    recommendation="Review session restore behavior when investigating user-level persistence.",
                    raw_evidence={"preference_exists": True},
                )
            )
    return findings
