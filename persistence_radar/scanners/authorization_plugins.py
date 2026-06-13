from __future__ import annotations

from pathlib import Path
import time

from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.signing import code_signature_status
from persistence_radar.scanners.common import display_path, root_join, stat_metadata


def scan_authorization_plugins(root: str = "/") -> list[Finding]:
    findings = []
    now = time.time()
    for configured in ("/Library/Security/SecurityAgentPlugins", "/System/Library/Security/SecurityAgentPlugins"):
        base = root_join(root, configured)
        if not base.is_dir():
            continue
        for plugin in sorted(base.iterdir()):
            owner, permissions = stat_metadata(plugin)
            signature = "system-protected" if configured.startswith("/System/") else code_signature_status(plugin)
            recent = False
            try:
                recent = now - plugin.stat().st_mtime < 14 * 24 * 3600
            except OSError:
                pass
            broad_write = "w" in permissions[-3:]
            non_apple = not configured.startswith("/System/")
            severity = Severity.HIGH if non_apple and (signature in {"unsigned", "invalid"} or broad_write) else Severity.MEDIUM if non_apple or recent else Severity.INFO
            findings.append(
                Finding(
                    id=f"auth-plugin:{display_path(root, plugin)}",
                    title=f"Authorization plugin: {plugin.name}",
                    severity=severity,
                    category="Authorization Plugin",
                    path=display_path(root, plugin),
                    executable_path=display_path(root, plugin),
                    owner=owner,
                    permissions=permissions,
                    code_signature_status=signature,
                    explanation="Authorization plugins are high-interest DFIR artifacts because they can participate in authentication and authorization workflows.",
                    recommendation="Confirm non-Apple authorization plugins are expected, signed, and owned by trusted software.",
                    raw_evidence={"recently_modified": recent, "broad_write_permissions": broad_write, "non_apple_location": non_apple},
                )
            )
    return findings
