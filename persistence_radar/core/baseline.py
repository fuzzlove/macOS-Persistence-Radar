from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from persistence_radar.core.models import Finding


@dataclass(frozen=True)
class BaselineDiff:
    added: list[Finding]
    removed: list[Finding]
    modified: list[tuple[Finding, Finding]]


def finding_fingerprint(finding: Finding) -> str:
    payload = json.dumps(finding.fingerprint_payload(), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compare_findings(baseline: list[Finding], current: list[Finding]) -> BaselineDiff:
    baseline_by_id = {item.id: item for item in baseline}
    current_by_id = {item.id: item for item in current}

    baseline_ids = set(baseline_by_id)
    current_ids = set(current_by_id)

    added = [current_by_id[item_id] for item_id in sorted(current_ids - baseline_ids)]
    removed = [baseline_by_id[item_id] for item_id in sorted(baseline_ids - current_ids)]
    modified: list[tuple[Finding, Finding]] = []

    for item_id in sorted(baseline_by_id.keys() & current_by_id.keys()):
        old = baseline_by_id[item_id]
        new = current_by_id[item_id]
        if finding_fingerprint(old) != finding_fingerprint(new):
            modified.append((old, new))

    return BaselineDiff(added=added, removed=removed, modified=modified)
