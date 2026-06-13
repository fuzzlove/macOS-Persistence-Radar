from __future__ import annotations

import json
from pathlib import Path

from persistence_radar.core.baseline import compare_findings
from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.posture import calculate_posture
from persistence_radar.core.timeline import events_from_diff, export_timeline


def item(item_id: str, severity: Severity = Severity.INFO, sha256: str = "a") -> Finding:
    return Finding(
        id=item_id,
        title=f"Item {item_id}",
        severity=severity,
        category="LaunchAgent",
        path=f"/tmp/{item_id}.plist",
        sha256=sha256,
        code_signature_status="valid",
    )


def test_timeline_detects_new_removed_modified_hash_and_signature(tmp_path: Path) -> None:
    old = [item("same", sha256="old"), item("removed")]
    new = [item("same", sha256="new"), item("added", Severity.HIGH)]
    new[0].code_signature_status = "unsigned"

    events = events_from_diff(compare_findings(old, new))
    event_types = " ".join(event.event_type for event in events)

    assert "new persistence" in event_types
    assert "removed persistence" in event_types
    assert "modified persistence" in event_types
    assert "hash change" in event_types
    assert "signature change" in event_types

    out = export_timeline(events, "json", tmp_path / "timeline.json")
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload[0]["event_type"]


def test_security_posture_score_drops_for_risky_items() -> None:
    risky = item("bad", Severity.CRITICAL)
    risky.raw_evidence["trust"] = {"classification": "Suspicious"}
    risky.raw_evidence["malware_artifact_matches"] = [{"family": "Test"}]

    posture = calculate_posture([risky])

    assert posture["score"] < 100
    assert posture["grade"] in {"Good", "Needs Review", "High Risk"}
