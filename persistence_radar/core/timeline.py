from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json

from persistence_radar.core.baseline import BaselineDiff
from persistence_radar.core.models import Finding


@dataclass(slots=True)
class TimelineEvent:
    event_id: str
    timestamp: str
    event_type: str
    item_id: str
    title: str
    severity: str
    mechanism: str
    path: str = ""
    executable_path: str = ""
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "item_id": self.item_id,
            "title": self.title,
            "severity": self.severity,
            "mechanism": self.mechanism,
            "path": self.path,
            "executable_path": self.executable_path,
            "summary": self.summary,
            "details": self.details,
        }


def _iso_from_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0).isoformat()


def enrich_file_times(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        candidates = [finding.path, finding.executable_path]
        for candidate in candidates:
            if not candidate:
                continue
            try:
                info = Path(candidate).stat()
            except OSError:
                continue
            finding.modified_time = finding.modified_time or _iso_from_epoch(info.st_mtime)
            creation = getattr(info, "st_birthtime", None)
            if creation:
                finding.created_time = finding.created_time or _iso_from_epoch(creation)
            break
    return findings


def _event_time(finding: Finding, fallback: str = "") -> str:
    return finding.modified_time or finding.created_time or finding.last_seen or finding.first_seen or fallback


def _change_details(old: Finding, new: Finding) -> dict[str, Any]:
    changes = {}
    for field in ("sha256", "code_signature_status", "notarization_status", "command", "executable_path", "permissions", "owner", "modified_time"):
        before = getattr(old, field)
        after = getattr(new, field)
        if before != after:
            changes[field] = {"before": before, "after": after}
    return changes


def events_for_inventory(findings: list[Finding]) -> list[TimelineEvent]:
    events = []
    for finding in findings:
        events.append(
            TimelineEvent(
                event_id=f"observed:{finding.id}",
                timestamp=_event_time(finding),
                event_type="observed",
                item_id=finding.id,
                title=finding.title,
                severity=str(finding.severity),
                mechanism=finding.category,
                path=finding.path,
                executable_path=finding.executable_path,
                summary="Persistence item observed in current scan.",
                details={
                    "first_seen": finding.first_seen,
                    "last_seen": finding.last_seen,
                    "created_time": finding.created_time,
                    "modified_time": finding.modified_time,
                },
            )
        )
    return sorted(events, key=lambda event: event.timestamp, reverse=True)


def events_from_diff(diff: BaselineDiff, compared_at: str | None = None) -> list[TimelineEvent]:
    compared_at = compared_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    events: list[TimelineEvent] = []
    for finding in diff.added:
        events.append(
            TimelineEvent(
                event_id=f"new:{finding.id}",
                timestamp=_event_time(finding, compared_at),
                event_type="new persistence",
                item_id=finding.id,
                title=finding.title,
                severity=str(finding.severity),
                mechanism=finding.category,
                path=finding.path,
                executable_path=finding.executable_path,
                summary="New persistence item compared with selected baseline.",
                details={"first_seen": finding.first_seen, "created_time": finding.created_time, "modified_time": finding.modified_time},
            )
        )
    for finding in diff.removed:
        events.append(
            TimelineEvent(
                event_id=f"removed:{finding.id}",
                timestamp=compared_at,
                event_type="removed persistence",
                item_id=finding.id,
                title=finding.title,
                severity=str(finding.severity),
                mechanism=finding.category,
                path=finding.path,
                executable_path=finding.executable_path,
                summary="Persistence item was present in baseline but absent from current scan.",
                details={"last_seen": finding.last_seen, "sha256": finding.sha256},
            )
        )
    for old, new in diff.modified:
        changes = _change_details(old, new)
        event_types = ["modified persistence"]
        if "sha256" in changes:
            event_types.append("hash change")
        if "code_signature_status" in changes or "notarization_status" in changes:
            event_types.append("signature change")
        events.append(
            TimelineEvent(
                event_id=f"modified:{new.id}",
                timestamp=_event_time(new, compared_at),
                event_type=", ".join(event_types),
                item_id=new.id,
                title=new.title,
                severity=str(new.severity),
                mechanism=new.category,
                path=new.path,
                executable_path=new.executable_path,
                summary="Persistence item changed compared with selected baseline.",
                details={"changes": changes},
            )
        )
    return sorted(events, key=lambda event: event.timestamp, reverse=True)


def export_timeline(events: list[TimelineEvent], fmt: str, destination: str | Path) -> Path:
    path = Path(destination)
    if fmt == "json":
        path.write_text(json.dumps([event.to_dict() for event in events], indent=2, sort_keys=True), encoding="utf-8")
    elif fmt in {"md", "markdown"}:
        lines = ["# macOS Persistence Radar Timeline", ""]
        for event in events:
            lines.append(f"- `{event.timestamp}` **{event.event_type}** {event.title} ({event.mechanism}, {event.severity}) - `{event.path}`")
        path.write_text("\n".join(lines), encoding="utf-8")
    elif fmt == "html":
        rows = "".join(
            f"<tr><td>{event.timestamp}</td><td>{event.event_type}</td><td>{event.severity}</td><td>{event.mechanism}</td><td>{event.title}</td><td><code>{event.path}</code></td><td>{event.summary}</td></tr>"
            for event in events
        )
        path.write_text(
            "<!doctype html><html><head><meta charset='utf-8'><title>Persistence Timeline</title>"
            "<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:32px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #d8dee8;padding:8px;text-align:left;vertical-align:top}th{background:#f2f5f9}code{white-space:pre-wrap}</style>"
            "</head><body><h1>macOS Persistence Radar Timeline</h1><table><thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>Mechanism</th><th>Item</th><th>Path</th><th>Summary</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></body></html>",
            encoding="utf-8",
        )
    else:
        raise ValueError(f"unsupported timeline export format: {fmt}")
    return path
