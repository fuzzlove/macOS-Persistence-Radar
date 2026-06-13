from __future__ import annotations

from collections import Counter

from persistence_radar.core.models import Finding


def calculate_posture(findings: list[Finding]) -> dict:
    severity_weights = {"CRITICAL": 18, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    deductions = 0
    factors = []
    counts = Counter(str(item.severity) for item in findings)
    for severity, weight in severity_weights.items():
        if counts[severity]:
            deduction = counts[severity] * weight
            deductions += deduction
            if weight:
                factors.append(f"{counts[severity]} {severity.lower()} severity item(s): -{deduction}")

    suspicious_trust = 0
    unknown_trust = 0
    malware_matches = 0
    for item in findings:
        trust = (item.raw_evidence or {}).get("trust", {})
        if trust.get("classification") == "Suspicious":
            suspicious_trust += 1
        elif trust.get("classification") == "Unknown":
            unknown_trust += 1
        if (item.raw_evidence or {}).get("malware_artifact_matches"):
            malware_matches += 1
    if suspicious_trust:
        deduction = suspicious_trust * 6
        deductions += deduction
        factors.append(f"{suspicious_trust} suspicious reputation item(s): -{deduction}")
    if unknown_trust:
        deduction = min(15, unknown_trust)
        deductions += deduction
        factors.append(f"{unknown_trust} unknown reputation item(s): -{deduction}")
    if malware_matches:
        deduction = malware_matches * 12
        deductions += deduction
        factors.append(f"{malware_matches} malware artifact correlation(s): -{deduction}")

    score = max(0, min(100, 100 - deductions))
    if score >= 90:
        grade = "Strong"
    elif score >= 75:
        grade = "Good"
    elif score >= 55:
        grade = "Needs Review"
    else:
        grade = "High Risk"
    return {
        "score": score,
        "grade": grade,
        "severity_counts": dict(counts),
        "suspicious_reputation_items": suspicious_trust,
        "unknown_reputation_items": unknown_trust,
        "malware_artifact_matches": malware_matches,
        "factors": factors or ["No major posture deductions from current scan."],
    }
