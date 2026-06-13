from __future__ import annotations

from pathlib import Path
import json

from persistence_radar.core.hashing import sha256_file
from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.scoring import path_is_suspicious
from persistence_radar.core.signing import code_signature_status
from persistence_radar.scanners.common import display_path, root_join, stat_metadata, user_home_paths

BROWSER_HOST_DIRS = (
    "Library/Application Support/Google/Chrome/NativeMessagingHosts",
    "Library/Application Support/Chromium/NativeMessagingHosts",
    "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
    "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
    "Library/Application Support/Mozilla/NativeMessagingHosts",
)
SYSTEM_HOST_DIRS = (
    "/Library/Google/Chrome/NativeMessagingHosts",
    "/Library/Application Support/Google/Chrome/NativeMessagingHosts",
    "/Library/Application Support/Chromium/NativeMessagingHosts",
    "/Library/Application Support/Microsoft Edge/NativeMessagingHosts",
    "/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
    "/Library/Application Support/Mozilla/NativeMessagingHosts",
)


def scan_native_messaging(root: str = "/") -> list[Finding]:
    bases = [root_join(root, path) for path in SYSTEM_HOST_DIRS]
    for home in user_home_paths(root):
        bases.extend(home / path for path in BROWSER_HOST_DIRS)
    findings = []
    for base in bases:
        if not base.is_dir():
            continue
        for manifest in sorted(base.glob("*.json")):
            try:
                data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                data = {"parse_error": str(exc)}
            executable = str(data.get("path", ""))
            origins = data.get("allowed_origins") or data.get("allowed_extensions") or []
            missing = bool(executable) and not Path(executable).exists()
            broad = any("*" in str(origin) or origin in {"chrome-extension://*/", "*"} for origin in origins)
            suspicious_path = path_is_suspicious(executable)
            signature = code_signature_status(executable) if executable and Path(executable).exists() else "missing" if missing else "unknown"
            severity = Severity.HIGH if missing or suspicious_path or broad or signature in {"unsigned", "invalid"} else Severity.INFO
            owner, permissions = stat_metadata(manifest)
            findings.append(
                Finding(
                    id=f"native-host:{display_path(root, manifest)}",
                    title=f"Native messaging host: {data.get('name', manifest.stem)}",
                    severity=severity,
                    category="Native Messaging Host",
                    path=display_path(root, manifest),
                    executable_path=executable,
                    owner=owner,
                    permissions=permissions,
                    sha256=sha256_file(executable),
                    code_signature_status=signature,
                    explanation="Browser native messaging hosts bridge browser extensions to local executables. Broad origins or user-writable executables increase persistence and abuse risk.",
                    recommendation="Verify the host executable, allowed extension origins, signature, and owning application.",
                    raw_evidence={"manifest": data, "allowed_origins": origins, "missing_executable": missing, "broad_origins": broad, "risk_factors": [x for x, y in {"missing executable": missing, "broad origins": broad, "suspicious executable path": suspicious_path}.items() if y]},
                )
            )
    return findings
