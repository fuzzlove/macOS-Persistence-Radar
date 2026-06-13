from __future__ import annotations

from dataclasses import dataclass

from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.table_sorting import chain_severity, severity_rank, sort_items


def make_item(severity: Severity, title: str = "") -> Finding:
    return Finding(id=title or str(severity), title=title or str(severity), severity=severity, category="Test")


def test_severity_descending_security_order() -> None:
    items = [
        make_item(Severity.INFO),
        make_item(Severity.CRITICAL),
        make_item(Severity.LOW),
        make_item(Severity.HIGH),
        make_item(Severity.MEDIUM),
    ]

    sorted_items = sort_items(items, [("severity", False)], {"severity": lambda item: severity_rank(str(item.severity))})

    assert [str(item.severity) for item in sorted_items] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_severity_ascending_security_order() -> None:
    items = [
        make_item(Severity.INFO),
        make_item(Severity.CRITICAL),
        make_item(Severity.LOW),
        make_item(Severity.HIGH),
        make_item(Severity.MEDIUM),
    ]

    sorted_items = sort_items(items, [("severity", True)], {"severity": lambda item: severity_rank(str(item.severity))})

    assert [str(item.severity) for item in sorted_items] == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_multi_column_sort_preserves_primary_then_secondary() -> None:
    items = [
        make_item(Severity.HIGH, "b"),
        make_item(Severity.CRITICAL, "z"),
        make_item(Severity.HIGH, "a"),
    ]
    key_map = {
        "severity": lambda item: severity_rank(str(item.severity)),
        "title": lambda item: item.title,
    }

    sorted_items = sort_items(items, [("severity", False), ("title", True)], key_map)

    assert [(str(item.severity), item.title) for item in sorted_items] == [
        ("CRITICAL", "z"),
        ("HIGH", "a"),
        ("HIGH", "b"),
    ]


@dataclass
class Chain:
    risk_score: int


def test_chain_severity_from_risk_score() -> None:
    assert chain_severity(Chain(90)) == "CRITICAL"
    assert chain_severity(Chain(55)) == "HIGH"
    assert chain_severity(Chain(30)) == "MEDIUM"
    assert chain_severity(Chain(10)) == "LOW"
    assert chain_severity(Chain(0)) == "INFO"
