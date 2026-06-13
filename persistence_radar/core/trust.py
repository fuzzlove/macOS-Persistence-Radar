from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import plistlib
import re

from persistence_radar.core.models import Finding
from persistence_radar.core.scoring import is_world_writable, path_is_suspicious

KNOWN_VENDOR_PREFIXES = (
    "com.apple.",
    "com.google.",
    "com.microsoft.",
    "com.adobe.",
    "com.dropbox.",
    "com.zoom.",
    "com.slack.",
    "com.cisco.",
    "com.jamf.",
    "com.cloudflare.",
    "org.mozilla.",
)

APPLE_CONTROLLED_PREFIXES = (
    "/System/",
    "/usr/bin/",
    "/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/Library/Apple/",
)


@dataclass(slots=True)
class ReputationResult:
    score: int
    confidence: str
    classification: str
    why: str
    positive_indicators: list[str] = field(default_factory=list)
    negative_indicators: list[str] = field(default_factory=list)
    neutral_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "confidence": self.confidence,
            "classification": self.classification,
            "why": self.why,
            "positive_indicators": self.positive_indicators,
            "negative_indicators": self.negative_indicators,
            "neutral_indicators": self.neutral_indicators,
        }


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _file_age_days(path: str) -> int | None:
    if not path:
        return None
    try:
        stat = Path(path).stat()
    except OSError:
        return None
    modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - modified).days)


def _label_or_bundle(finding: Finding) -> str:
    raw = finding.raw_evidence or {}
    label = raw.get("label") or raw.get("bundle_id") or raw.get("extension_id") or ""
    if label:
        return str(label)
    plist = raw.get("plist")
    if isinstance(plist, dict):
        return str(plist.get("Label", ""))
    return finding.title


def _bundle_id_from_app(path: str) -> str:
    if not path or ".app/" not in path and not path.endswith(".app"):
        return ""
    app_part = path.split(".app/", 1)[0] + ".app"
    plist = Path(app_part) / "Contents" / "Info.plist"
    if not plist.is_file():
        return ""
    try:
        with plist.open("rb") as handle:
            data = plistlib.load(handle)
        return str(data.get("CFBundleIdentifier", ""))
    except Exception:
        return ""


def _known_vendor(label: str, team_id: str) -> bool:
    if label.startswith(KNOWN_VENDOR_PREFIXES):
        return True
    return team_id in {
        "APPLE",
        "EQHXZ8M8AV",  # Google LLC
        "UBF8T346G9",  # Microsoft Corporation
        "JQ525L2MZD",  # Adobe Inc.
    }


def evaluate_trust(finding: Finding, baseline_ids: set[str] | None = None) -> ReputationResult:
    raw = finding.raw_evidence or {}
    label = _label_or_bundle(finding)
    executable = finding.executable_path or ""
    path = finding.path or ""
    signing = finding.code_signature_status or "unknown"
    notarization = finding.notarization_status or "unknown"
    team_id = str(raw.get("team_id") or raw.get("TeamIdentifier") or "")
    parent_app = str(raw.get("parent_app") or raw.get("parentApp") or raw.get("app") or "")
    bundle_id = str(raw.get("bundle_id") or raw.get("bundleID") or _bundle_id_from_app(executable))

    score = 50
    positives: list[str] = []
    negatives: list[str] = []
    neutral: list[str] = []

    apple_signed = signing == "system-protected" or executable.startswith(APPLE_CONTROLLED_PREFIXES) or path.startswith("/System/")
    if apple_signed:
        score += 25
        positives.append("Apple-controlled or system-protected location/signing")
    elif signing == "valid":
        score += 14
        positives.append("Code signature is valid")
    elif signing in {"unsigned", "invalid", "missing"}:
        score -= 28
        negatives.append(f"Code signature status is {signing}")
    else:
        neutral.append(f"Code signature status is {signing}")

    if notarization.startswith("accepted"):
        score += 10
        positives.append("Executable is accepted/notarized by local assessment")
    elif notarization in {"rejected"}:
        score -= 15
        negatives.append("Executable failed local notarization/Gatekeeper assessment")
    else:
        neutral.append(f"Notarization status is {notarization}")

    if team_id:
        score += 7
        positives.append(f"Team ID is present: {team_id}")
    else:
        score -= 4
        negatives.append("No Team ID was observed")

    if _known_vendor(label, team_id):
        score += 10
        positives.append("Identifier matches a known vendor pattern")

    installed_app_exists = bool(parent_app) and Path(parent_app).exists()
    if installed_app_exists:
        score += 8
        positives.append("Referenced parent application exists")
    elif parent_app:
        score -= 12
        negatives.append("Referenced parent application is missing")

    age_days = _file_age_days(executable) or _file_age_days(path)
    if age_days is None:
        neutral.append("File age could not be determined")
    elif age_days >= 30:
        score += 6
        positives.append(f"File has existed for at least {age_days} days")
    elif age_days <= 3:
        score -= 8
        negatives.append(f"File appears recently modified ({age_days} days)")
    else:
        neutral.append(f"File age is {age_days} days")

    first_seen = _parse_time(finding.first_seen)
    if first_seen:
        first_seen_days = max(0, (datetime.now(timezone.utc) - first_seen).days)
        if first_seen_days >= 30:
            score += 5
            positives.append("Item has baseline/history age greater than 30 days")
        elif first_seen_days <= 3:
            neutral.append("Item was first seen recently")

    if baseline_ids is not None:
        if finding.id in baseline_ids:
            score += 8
            positives.append("Item was present in selected baseline history")
        else:
            score -= 12
            negatives.append("Item is new relative to selected baseline")

    if path_is_suspicious(executable) or path_is_suspicious(path):
        score -= 18
        negatives.append("Executable or config path is hidden, temporary, shared, or otherwise user-controlled")

    for candidate in (executable, path):
        if candidate and is_world_writable(candidate):
            score -= 18
            negatives.append(f"World-writable path: {candidate}")
            break

    if finding.owner == "root" and executable:
        try:
            if Path(executable).exists() and Path(executable).stat().st_uid != 0:
                score -= 14
                negatives.append("Root-owned persistence references a non-root-owned executable")
        except OSError:
            pass

    apple_like = bool(re.match(r"^com\.apple\.", label))
    if apple_like and not (path.startswith("/System/") or executable.startswith(APPLE_CONTROLLED_PREFIXES)):
        score -= 20
        negatives.append("Apple-like identifier is outside Apple-controlled paths")

    if bundle_id and label and bundle_id not in label and label not in bundle_id:
        score -= 6
        negatives.append("Bundle identifier and persistence label do not appear consistent")
    elif bundle_id:
        score += 4
        positives.append("Bundle identifier is present and broadly consistent")
    else:
        neutral.append("Bundle identifier was not available")

    score = max(0, min(100, score))
    evidence_points = len(positives) + len(negatives)
    if evidence_points >= 7:
        confidence = "High"
    elif evidence_points >= 4:
        confidence = "Medium"
    else:
        confidence = "Low"

    if score >= 75 and not negatives:
        classification = "Legitimate"
    elif score >= 70 and len(negatives) <= 1:
        classification = "Legitimate"
    elif score <= 44 or len(negatives) >= 4:
        classification = "Suspicious"
    else:
        classification = "Unknown"

    why = (
        f"Reputation score {score}/100 classified as {classification} with {confidence.lower()} confidence. "
        "This is an explanatory trust assessment only; it does not whitelist or suppress the item."
    )
    return ReputationResult(score, confidence, classification, why, positives, negatives, neutral)


def apply_trust(findings: list[Finding], baseline_ids: set[str] | None = None) -> list[Finding]:
    for finding in findings:
        trust = evaluate_trust(finding, baseline_ids=baseline_ids)
        finding.raw_evidence = {**(finding.raw_evidence or {}), "trust": trust.to_dict()}
    return findings
