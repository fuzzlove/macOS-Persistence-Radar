from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
import json


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    path: str = ""
    executable_path: str = ""
    command: str = ""
    user_context: str = ""
    owner: str = ""
    permissions: str = ""
    sha256: str = ""
    code_signature_status: str = "unknown"
    notarization_status: str = "unknown"
    created_time: str = ""
    modified_time: str = ""
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    explanation: str = ""
    recommendation: str = ""
    raw_evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": str(self.severity),
            "category": self.category,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "path": self.path,
            "executable_path": self.executable_path,
            "command": self.command,
            "user_context": self.user_context,
            "owner": self.owner,
            "permissions": self.permissions,
            "sha256": self.sha256,
            "code_signature_status": self.code_signature_status,
            "notarization_status": self.notarization_status,
            "created_time": self.created_time,
            "modified_time": self.modified_time,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "raw_evidence": self.raw_evidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        payload = dict(data)
        payload["severity"] = Severity(payload.get("severity", "LOW"))
        if isinstance(payload.get("raw_evidence"), str):
            payload["raw_evidence"] = json.loads(payload["raw_evidence"])
        return cls(**payload)

    def fingerprint_payload(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": str(self.severity),
            "category": self.category,
            "mitre_technique_id": self.mitre_technique_id,
            "path": self.path,
            "executable_path": self.executable_path,
            "command": self.command,
            "owner": self.owner,
            "permissions": self.permissions,
            "sha256": self.sha256,
            "code_signature_status": self.code_signature_status,
            "created_time": self.created_time,
            "modified_time": self.modified_time,
            "raw_evidence": self.raw_evidence,
        }


@dataclass(slots=True)
class PersistenceItem:
    item_id: str
    category: str
    mechanism: str
    severity: Severity = Severity.INFO
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    source_path: str = ""
    config_path: str = ""
    executable_path: str = ""
    command: str = ""
    parent_app: str = ""
    bundle_id: str = ""
    team_id: str = ""
    signing_status: str = "unknown"
    sha256: str = ""
    owner: str = ""
    group: str = ""
    permissions: str = ""
    created_time: str = ""
    modified_time: str = ""
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    risk_factors: list[str] = field(default_factory=list)
    linked_items: list[str] = field(default_factory=list)
    raw_evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "category": self.category,
            "mechanism": self.mechanism,
            "severity": str(self.severity),
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "source_path": self.source_path,
            "config_path": self.config_path,
            "executable_path": self.executable_path,
            "command": self.command,
            "parent_app": self.parent_app,
            "bundle_id": self.bundle_id,
            "team_id": self.team_id,
            "signing_status": self.signing_status,
            "sha256": self.sha256,
            "owner": self.owner,
            "group": self.group,
            "permissions": self.permissions,
            "created_time": self.created_time,
            "modified_time": self.modified_time,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "risk_factors": self.risk_factors,
            "linked_items": self.linked_items,
            "raw_evidence": self.raw_evidence,
        }

    @classmethod
    def from_finding(cls, finding: Finding) -> "PersistenceItem":
        raw = finding.raw_evidence or {}
        return cls(
            item_id=finding.id,
            category=finding.category,
            mechanism=finding.category,
            severity=finding.severity,
            mitre_technique_id=finding.mitre_technique_id,
            mitre_technique_name=finding.mitre_technique_name,
            source_path=finding.path,
            config_path=finding.path,
            executable_path=finding.executable_path,
            command=finding.command,
            signing_status=finding.code_signature_status,
            sha256=finding.sha256,
            owner=finding.owner,
            permissions=finding.permissions,
            first_seen=finding.first_seen,
            last_seen=finding.last_seen,
            risk_factors=raw.get("risk_factors", []),
            linked_items=raw.get("linked_items", []),
            raw_evidence=raw,
        )


@dataclass(slots=True)
class PersistenceChain:
    chain_id: str
    title: str
    item_ids: list[str]
    relationship: str
    mitre_technique_id: str = ""
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "item_ids": self.item_ids,
            "relationship": self.relationship,
            "mitre_technique_id": self.mitre_technique_id,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
        }
