from __future__ import annotations

import json
from pathlib import Path

from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.reporting import export_json
from persistence_radar.core.trust import apply_trust, evaluate_trust


def test_apple_system_item_scores_legitimate() -> None:
    finding = Finding(
        id="apple",
        title="LaunchDaemon: com.apple.test",
        severity=Severity.INFO,
        category="LaunchDaemon",
        path="/System/Library/LaunchDaemons/com.apple.test.plist",
        executable_path="/usr/bin/true",
        code_signature_status="system-protected",
        notarization_status="not-checked",
        raw_evidence={"label": "com.apple.test"},
    )

    trust = evaluate_trust(finding)

    assert trust.score >= 70
    assert trust.classification == "Legitimate"
    assert trust.positive_indicators


def test_hidden_unsigned_item_scores_suspicious() -> None:
    finding = Finding(
        id="bad",
        title="LaunchAgent: com.apple.update",
        severity=Severity.HIGH,
        category="LaunchAgent",
        path="/Users/alice/Library/LaunchAgents/com.apple.update.plist",
        executable_path="/Users/Shared/.cache/update",
        code_signature_status="unsigned",
        raw_evidence={"label": "com.apple.update"},
    )

    trust = evaluate_trust(finding, baseline_ids=set())

    assert trust.score <= 44
    assert trust.classification == "Suspicious"
    assert trust.negative_indicators


def test_trust_is_added_to_report_json(tmp_path: Path) -> None:
    finding = Finding(
        id="unknown",
        title="Browser extension",
        severity=Severity.INFO,
        category="Browser Extension",
        path="/Users/alice/Library/Application Support/Browser/Extensions/abc",
    )
    apply_trust([finding])

    report = export_json([finding], tmp_path / "report.json")
    payload = json.loads(report.read_text(encoding="utf-8"))

    trust = payload["findings"][0]["raw_evidence"]["trust"]
    assert "score" in trust
    assert trust["classification"] in {"Legitimate", "Unknown", "Suspicious"}
