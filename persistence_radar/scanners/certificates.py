from __future__ import annotations

import re
import subprocess

from persistence_radar.core.models import Finding, Severity

SUSPICIOUS_CERT_RE = re.compile(r"(proxy|intercept|mitm|vpn|filter|monitor|root)", re.IGNORECASE)


def scan_certificates(root: str = "/") -> list[Finding]:
    if root != "/":
        return []
    findings = []
    for keychain in ("login.keychain-db", "/Library/Keychains/System.keychain"):
        try:
            result = subprocess.run(["security", "find-certificate", "-a", "-p", keychain], capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"security find-certificate failed for {keychain}: {exc}") from exc
        certs = result.stdout.count("BEGIN CERTIFICATE")
        if certs:
            suspicious = bool(SUSPICIOUS_CERT_RE.search(result.stdout))
            findings.append(
                Finding(
                    id=f"certificates:{keychain}",
                    title=f"Certificate trust inventory: {keychain}",
                    severity=Severity.MEDIUM if suspicious else Severity.INFO,
                    category="Certificate Trust",
                    path=keychain,
                    explanation="Trusted root certificates can enable traffic inspection when paired with proxy or content-filter configuration.",
                    recommendation="Review non-Apple or recently added trusted roots and confirm they belong to approved software or MDM.",
                    raw_evidence={"certificate_count": certs, "suspicious_name_indicator": suspicious},
                )
            )
    return findings
