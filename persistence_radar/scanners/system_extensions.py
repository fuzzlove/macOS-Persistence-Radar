from __future__ import annotations

import re
import subprocess

from persistence_radar.core.models import Finding, Severity


def scan_system_extensions(root: str = "/") -> list[Finding]:
    if root != "/":
        return []
    try:
        result = subprocess.run(["systemextensionsctl", "list"], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"systemextensionsctl list failed: {exc}") from exc
    output = result.stdout + result.stderr
    findings = []
    for line in output.splitlines():
        if not line.strip() or "teamID" in line:
            continue
        team_match = re.search(r"\(([A-Z0-9]{10})\)", line)
        bundle_match = re.search(r"([A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)", line)
        team_id = team_match.group(1) if team_match else ""
        bundle_id = bundle_match.group(1) if bundle_match else line.strip()
        extension_type = "Endpoint Security" if "endpoint" in line.lower() else "Network Extension" if any(word in line.lower() for word in ("network", "filter", "dns", "vpn")) else "System Extension"
        severity = Severity.MEDIUM if any(word in line.lower() for word in ("activated", "enabled", "filter", "endpoint", "vpn", "dns")) and not team_id else Severity.INFO
        findings.append(
            Finding(
                id=f"system-extension:{bundle_id}:{team_id}",
                title=f"{extension_type}: {bundle_id}",
                severity=severity,
                category="System Extension",
                path="systemextensionsctl list",
                user_context=team_id,
                explanation="System, Endpoint Security, and Network extensions can provide persistent security, filtering, DNS, or VPN capabilities.",
                recommendation="Verify Team ID, bundle ID, activation state, and business purpose.",
                raw_evidence={"line": line, "team_id": team_id, "bundle_id": bundle_id, "extension_type": extension_type},
            )
        )
    return findings
