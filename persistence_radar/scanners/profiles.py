from __future__ import annotations

from persistence_radar.core.models import Finding, Severity
from persistence_radar.scanners.common import root_join, stat_metadata
import subprocess

PROFILE_PATHS = ("/Library/Managed Preferences", "/var/db/ConfigurationProfiles")


def scan_profiles(root: str = "/") -> list[Finding]:
    findings: list[Finding] = []
    for configured in PROFILE_PATHS:
        path = root_join(root, configured)
        if path.exists():
            owner, permissions = stat_metadata(path)
            findings.append(
                Finding(
                    id=f"profile-source:{configured}",
                    title=f"Configuration profile store: {configured}",
                    severity=Severity.INFO,
                    category="Configuration Profile",
                    path=configured,
                    owner=owner,
                    permissions=permissions,
                    explanation="Configuration profiles and managed preferences can enforce persistent system and security settings.",
                    recommendation="Verify profiles are installed by approved MDM or administrators.",
                    raw_evidence={"source_exists": True},
                )
            )
    if root == "/":
        try:
            result = subprocess.run(["profiles", "list"], capture_output=True, text=True, timeout=15, check=False)
            output = result.stdout + result.stderr
            indicators = [word for word in ("LoginItems", "Proxy", "VPN", "Root", "Certificate", "SystemExtension", "WebClip", "ContentFilter", "Privacy", "TCC") if word.lower() in output.lower()]
            if output.strip():
                findings.append(
                    Finding(
                        id="profiles-command:list",
                        title="Configuration profiles command inventory",
                        severity=Severity.MEDIUM if any(word in indicators for word in ("Proxy", "VPN", "Root", "Certificate", "ContentFilter", "SystemExtension")) else Severity.INFO,
                        category="Configuration Profile",
                        path="profiles list",
                        explanation="Installed configuration profiles can enforce login items, proxies, VPN, certificates, content filters, system extensions, web clips, and privacy permissions.",
                        recommendation="Verify profile organizations and payloads are expected for this Mac.",
                        raw_evidence={"command": "profiles list", "indicators": indicators, "output_excerpt": output[:4000]},
                    )
                )
        except (OSError, subprocess.SubprocessError) as exc:
            findings.append(
                Finding(
                    id="profiles-command:error",
                    title="Configuration profile enumeration failed",
                    severity=Severity.INFO,
                    category="Configuration Profile",
                    path="profiles list",
                    explanation=f"The read-only profiles command could not be completed: {exc}",
                    recommendation="Run doctor diagnostics or grant appropriate local permissions if profile visibility is required.",
                    raw_evidence={"error": str(exc)},
                )
            )
    return findings
