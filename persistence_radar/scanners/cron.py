from __future__ import annotations

from pathlib import Path
import time

from persistence_radar.core.mitre import technique
from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.scoring import command_has_suspicious_token, is_world_writable
from persistence_radar.scanners.common import root_join, stat_metadata

CRON_PATHS = ("/etc/crontab", "/usr/lib/cron/tabs", "/var/at/jobs", "/etc/periodic", "/Library/Scripts")


def scan_cron(root: str = "/") -> list[Finding]:
    findings: list[Finding] = []
    mitre_id, mitre_name = technique("command_interpreter")
    for configured in CRON_PATHS:
        path = root_join(root, configured)
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            try:
                candidates = sorted(path.iterdir())
            except PermissionError:
                owner, permissions = stat_metadata(path)
                findings.append(
                    Finding(
                        id=f"cron-permission:{configured}",
                        title=f"Scheduled job directory not readable: {configured}",
                    severity=Severity.INFO,
                        category="Cron/At",
                        mitre_technique_id=mitre_id,
                        mitre_technique_name=mitre_name,
                        path=configured,
                        owner=owner,
                        permissions=permissions,
                        explanation="This scheduled job directory exists but is not readable without additional privileges.",
                        recommendation="Run with appropriate authorization if cron or at job inspection is required.",
                        raw_evidence={"permission_error": True},
                    )
                )
                continue
        else:
            candidates = []
        for item in candidates:
            if not item.is_file():
                continue
            owner, permissions = stat_metadata(item)
            try:
                content = item.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            suspicious = [line.strip() for line in content.splitlines() if command_has_suspicious_token(line)]
            encoded = any(token in content.lower() for token in ("base64", "-enc", "frombase64string"))
            hidden = item.name.startswith(".")
            writable = is_world_writable(item)
            try:
                recent = time.time() - item.stat().st_mtime < 14 * 24 * 3600
            except OSError:
                recent = False
            severity = Severity.HIGH if suspicious or encoded else Severity.MEDIUM if hidden or writable or recent else Severity.INFO
            findings.append(
                Finding(
                    id=f"cron:{item}",
                    title=f"Scheduled job: {item.name}",
                    severity=severity,
                    category="Cron/At",
                    mitre_technique_id=mitre_id,
                    mitre_technique_name=mitre_name,
                    path=str(item),
                    command="\n".join(suspicious),
                    owner=owner,
                    permissions=permissions,
                    explanation="Cron and at jobs can run commands persistently on a schedule.",
                    recommendation="Confirm each scheduled command is expected and owned by an authorized administrator.",
                    raw_evidence={"suspicious_lines": suspicious, "encoded_command_indicator": encoded, "hidden_script": hidden, "world_writable": writable, "recently_modified": recent},
                )
            )
    return findings
