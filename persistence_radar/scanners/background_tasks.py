from __future__ import annotations

from pathlib import Path
import json
import plistlib

from persistence_radar.core.mitre import technique
from persistence_radar.core.models import Finding, Severity
from persistence_radar.scanners.common import display_path, root_join, stat_metadata, user_home_paths


def _records(base: Path) -> list[Path]:
    if not base.is_dir():
        return []
    return [item for item in base.rglob("*") if item.is_file() and item.suffix.lower() in {".plist", ".json", ".btm"}]


def _parse(path: Path) -> dict:
    try:
        if path.suffix.lower() == ".json":
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
        with path.open("rb") as handle:
            data = plistlib.load(handle)
            return data if isinstance(data, dict) else {"value": data}
    except Exception as exc:
        return {"parse_error": str(exc)}


def scan_background_tasks(root: str = "/") -> list[Finding]:
    mitre_id, mitre_name = technique("login_item")
    bases = [root_join(root, "/Library/Application Support/com.apple.backgroundtaskmanagement")]
    bases.extend(home / "Library" / "Application Support" / "com.apple.backgroundtaskmanagement" for home in user_home_paths(root))
    findings = []
    for base in bases:
        for record in _records(base):
            raw = _parse(record)
            text = str(raw)
            parent_app = raw.get("parentApp") or raw.get("app") or raw.get("bundlePath") or ""
            missing_parent = bool(parent_app) and not Path(str(parent_app)).exists()
            severity = Severity.MEDIUM if missing_parent else Severity.INFO
            owner, permissions = stat_metadata(record)
            findings.append(
                Finding(
                    id=f"btm:{display_path(root, record)}",
                    title=f"Background task record: {record.name}",
                    severity=severity,
                    category="Background Task",
                    mitre_technique_id=mitre_id,
                    mitre_technique_name=mitre_name,
                    path=display_path(root, record),
                    executable_path=str(parent_app),
                    owner=owner,
                    permissions=permissions,
                    explanation="Background Task Management and SMAppService records can represent login/background items. Service Management login items may be less visible to users."
                    + (" The parent app referenced by this record appears to be missing." if missing_parent else ""),
                    recommendation="Verify the owning app is installed, expected, and approved by the user or administrator.",
                    raw_evidence={"record": raw, "parent_app_missing": missing_parent, "contains_allowed": "allowed" in text.lower()},
                )
            )
    return findings
