from __future__ import annotations

from pathlib import Path
import json

from persistence_radar.core.models import Finding, Severity
from persistence_radar.scanners.common import stat_metadata, user_home_paths

BROWSER_EXTENSION_GLOBS = (
    "Library/Application Support/Google/Chrome/*/Extensions/*",
    "Library/Application Support/Chromium/*/Extensions/*",
    "Library/Application Support/Microsoft Edge/*/Extensions/*",
    "Library/Application Support/BraveSoftware/Brave-Browser/*/Extensions/*",
    "Library/Safari/Extensions/*",
    "Library/Application Support/Firefox/Profiles/*/extensions/*",
)


def scan_browser_extensions(root: str = "/") -> list[Finding]:
    findings: list[Finding] = []
    for home in user_home_paths(root):
        for pattern in BROWSER_EXTENSION_GLOBS:
            for item in sorted(home.glob(pattern)):
                owner, permissions = stat_metadata(item)
                display = str(item) if root == "/" else "/" + str(item.relative_to(root)).lstrip("/")
                manifest_path = next(iter(sorted(item.glob("*/manifest.json"))), item / "manifest.json") if item.is_dir() else item
                manifest = {}
                if manifest_path.is_file():
                    try:
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
                    except Exception as exc:
                        manifest = {"parse_error": str(exc)}
                permissions_list = manifest.get("permissions", []) + manifest.get("host_permissions", [])
                risky = {"<all_urls>", "all_urls", "webRequest", "webRequestBlocking", "proxy", "cookies", "tabs", "downloads", "nativeMessaging", "management"}
                risky_permissions = sorted({str(permission) for permission in permissions_list if str(permission) in risky or str(permission) == "<all_urls>"})
                local_unpacked = "Extensions" not in display or manifest.get("update_url", "") == ""
                severity = Severity.HIGH if "nativeMessaging" in risky_permissions and ("<all_urls>" in risky_permissions or "proxy" in risky_permissions) else Severity.MEDIUM if risky_permissions else Severity.INFO
                findings.append(
                    Finding(
                        id=f"browser-extension:{display}",
                        title=f"Browser extension: {manifest.get('name', item.name)}",
                        severity=severity,
                        category="Browser Extension",
                        path=display,
                        user_context=home.name,
                        owner=owner,
                        permissions=permissions,
                        explanation="Browser extensions can persist in user profiles and affect browser behavior. High-risk permissions can expose browsing data or bridge to native messaging hosts.",
                        recommendation="Review extension ID, publisher, permissions, and whether the user approved it.",
                        raw_evidence={"browser_path": display, "extension_id": item.name, "name": manifest.get("name", ""), "version": manifest.get("version", ""), "permissions": permissions_list, "high_risk_permissions": risky_permissions, "local_or_unpacked_indicator": local_unpacked},
                    )
                )
    return findings
