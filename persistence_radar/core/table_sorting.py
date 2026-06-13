from __future__ import annotations

from typing import Any, Callable

SEVERITY_RANK = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


def severity_rank(value: str) -> int:
    return SEVERITY_RANK.get(str(value), 0)


def reputation_score(item: Any) -> int:
    return int(((getattr(item, "raw_evidence", {}) or {}).get("trust", {}) or {}).get("score", 0))


def risk_score(item: Any) -> int:
    base = severity_rank(str(getattr(item, "severity", ""))) * 20
    raw = getattr(item, "raw_evidence", {}) or {}
    factors = raw.get("risk_factors") or []
    if "Risk factors:" in getattr(item, "explanation", ""):
        base += 5
    return base + min(20, len(factors) * 4)


def team_id(item: Any) -> str:
    raw = getattr(item, "raw_evidence", {}) or {}
    return str(raw.get("team_id") or raw.get("TeamIdentifier") or "")


def chain_severity(chain: Any) -> str:
    score = int(getattr(chain, "risk_score", 0))
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def sort_items(items: list[Any], sort_state: list[tuple[str, bool]], key_map: dict[str, Callable[[Any], Any]]) -> list[Any]:
    sorted_items = list(items)
    for key, ascending in reversed(sort_state):
        getter = key_map[key]
        sorted_items.sort(key=getter, reverse=not ascending)
    return sorted_items
