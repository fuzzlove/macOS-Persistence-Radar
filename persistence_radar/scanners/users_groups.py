from __future__ import annotations

from persistence_radar.core.models import Finding, Severity
from persistence_radar.scanners.common import root_join, stat_metadata

ACCOUNT_FILES = ("/etc/passwd", "/etc/group", "/var/db/dslocal/nodes/Default/users", "/var/db/dslocal/nodes/Default/groups")


def scan_users_groups(root: str = "/") -> list[Finding]:
    findings = []
    for configured in ACCOUNT_FILES:
        path = root_join(root, configured)
        if path.exists():
            owner, permissions = stat_metadata(path)
            findings.append(
                Finding(
                    id=f"account-source:{configured}",
                    title=f"User/group data source: {configured}",
                    severity=Severity.INFO,
                    category="Users and Groups",
                    path=configured,
                    owner=owner,
                    permissions=permissions,
                    explanation="Unexpected local users, groups, or admin membership changes can support persistence.",
                    recommendation="Compare account state with an approved inventory or baseline.",
                    raw_evidence={"source_exists": True},
                )
            )
    return findings
