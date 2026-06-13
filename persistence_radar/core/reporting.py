from __future__ import annotations

from html import escape
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import json
import platform
import socket

from persistence_radar import __version__
from persistence_radar.core.models import Finding
from persistence_radar.core.scan import build_chains, coverage_catalog


def report_metadata() -> dict[str, str]:
    return {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "hostname": socket.gethostname(),
        "macos_version": platform.platform(),
        "scanner_version": __version__,
    }


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(str(item.severity) for item in findings)
    return {name: counts.get(name, 0) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}


def mitre_coverage(findings: list[Finding]) -> list[dict[str, str | int]]:
    counter = Counter(
        (item.mitre_technique_id, item.mitre_technique_name)
        for item in findings
        if item.mitre_technique_id
    )
    return [
        {"id": technique_id, "name": name, "count": count}
        for (technique_id, name), count in sorted(counter.items())
    ]


def top_risks(findings: list[Finding], limit: int = 8) -> list[Finding]:
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(findings, key=lambda item: (rank.get(str(item.severity), 9), item.category, item.title))[:limit]


def risk_factors(finding: Finding) -> list[str]:
    text = finding.explanation
    marker = "Risk factors:"
    if marker not in text:
        return []
    factors = text.split(marker, 1)[1].strip().rstrip(".")
    return [factor.strip() for factor in factors.split(";") if factor.strip()]


def verification_commands(finding: Finding) -> list[str]:
    commands = []
    if finding.path:
        commands.append(f"ls -lO {finding.path}")
    if finding.path.endswith(".plist"):
        commands.append(f"plutil -p {finding.path}")
    if finding.executable_path:
        commands.append(f"codesign -dv --verbose=4 {finding.executable_path}")
        commands.append(f"shasum -a 256 {finding.executable_path}")
    return commands


def trust_summary(finding: Finding) -> dict:
    return (finding.raw_evidence or {}).get(
        "trust",
        {
            "score": "unknown",
            "classification": "Unknown",
            "confidence": "Low",
            "why": "Trust has not been calculated for this item.",
            "positive_indicators": [],
            "negative_indicators": [],
        },
    )


def _report_payload(findings: list[Finding], warnings: list[str] | None = None, errors: list[str] | None = None) -> dict:
    metadata = report_metadata()
    return {
        "schema_version": "1.0",
        "app_version": __version__,
        "scan_metadata": metadata,
        "metadata": metadata,
        "summary": {
            "total_findings": len(findings),
            "total_inventory_items": len(findings),
            "severity_counts": severity_counts(findings),
            "mitre_coverage": mitre_coverage(findings),
            "top_risks": [item.id for item in top_risks(findings)],
            "advanced_coverage": coverage_catalog(),
            "chains": [chain.to_dict() for chain in build_chains(findings)],
        },
        "inventory_items": [item.to_dict() for item in findings],
        "findings": [item.to_dict() for item in findings],
        "warnings": warnings or [],
        "errors": errors or [],
    }


def export_json(findings: list[Finding], destination: str | Path, warnings: list[str] | None = None, errors: list[str] | None = None) -> Path:
    path = Path(destination)
    path.write_text(json.dumps(_report_payload(findings, warnings, errors), indent=2, sort_keys=True), encoding="utf-8")
    return path


def export_markdown(findings: list[Finding], destination: str | Path, warnings: list[str] | None = None, errors: list[str] | None = None) -> Path:
    path = Path(destination)
    metadata = report_metadata()
    counts = severity_counts(findings)
    lines = ["# macOS Persistence Radar Report", ""]
    lines.extend(
        [
            "## Executive Summary",
            "",
            f"- Generated: `{metadata['generated_at']}`",
            f"- Hostname: `{metadata['hostname']}`",
            f"- macOS: `{metadata['macos_version']}`",
            f"- Scanner version: `{metadata['scanner_version']}`",
            f"- Total persistence items: **{len(findings)}**",
            f"- Critical/high findings: **{counts['CRITICAL'] + counts['HIGH']}**",
            f"- Scanner warnings: **{len(warnings or [])}**",
            f"- Scanner errors: **{len(errors or [])}**",
            "",
            "## Severity Counts",
            "",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
    )
    for severity, count in counts.items():
        lines.append(f"| {severity} | {count} |")
    lines.extend(["", "## Top Risks", ""])
    for item in top_risks(findings):
        trust = trust_summary(item)
        lines.append(f"- **{item.severity}** {item.title} - reputation `{trust['score']}/100 {trust['classification']}` - `{item.path}`")
    lines.extend(["", "## MITRE ATT&CK Coverage", ""])
    for item in mitre_coverage(findings):
        lines.append(f"- `{item['id']}` {item['name']}: {item['count']} finding(s)")
    lines.extend(["", "## Advanced Persistence Coverage", ""])
    for key, item in coverage_catalog().items():
        lines.append(f"- `{key}`: {item['name']} ({item['mitre']})")
    chains = build_chains(findings)
    lines.extend(["", "## Persistence Chains", ""])
    if chains:
        for chain in chains:
            lines.append(f"- **{chain.title}**: {chain.relationship} (risk score {chain.risk_score})")
    else:
        lines.append("- No multi-item chains detected in this report.")
    lines.extend(["", "## Remediation Checklist", ""])
    for item in top_risks(findings):
        lines.append(f"- [ ] Review `{item.path}` - {item.recommendation}")
    lines.extend(["", "## Scanner Warnings And Errors", ""])
    for warning in warnings or []:
        lines.append(f"- Warning: {warning}")
    for error in errors or []:
        lines.append(f"- Error: {error}")
    if not warnings and not errors:
        lines.append("- None")
    lines.extend(["", "## Finding Appendix", ""])
    lines.append("")
    for finding in findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Severity: {finding.severity}",
                f"- Category: {finding.category}",
                f"- MITRE: {finding.mitre_technique_id} {finding.mitre_technique_name}".strip(),
                f"- Path: `{finding.path}`",
                f"- Executable: `{finding.executable_path}`",
                f"- Command: `{finding.command}`",
                f"- SHA256: `{finding.sha256}`",
                f"- Code signing: `{finding.code_signature_status}`",
                f"- Reputation: `{trust_summary(finding)['score']}/100 {trust_summary(finding)['classification']}`",
                f"- Confidence: `{trust_summary(finding)['confidence']}`",
                f"- First seen: `{finding.first_seen}`",
                f"- Last seen: `{finding.last_seen}`",
                "",
                "**Summary**",
                "",
                finding.explanation,
                "",
                "**Trust Breakdown**",
                "",
                trust_summary(finding)["why"],
                "",
                "Positive indicators:",
                *[f"- {item}" for item in trust_summary(finding).get("positive_indicators", [])],
                "",
                "Negative indicators:",
                *[f"- {item}" for item in trust_summary(finding).get("negative_indicators", [])],
                "",
                "**Suggested verification commands**",
                "",
                *[f"```bash\n{command}\n```" for command in verification_commands(finding)],
                f"**Recommendation:** {finding.recommendation}",
                "",
            ]
        )
    lines.extend(["", "## Legal / Defensive Use", "", "macOS Persistence Radar is a read-only defensive auditing tool. Use only on systems you own or are authorized to assess."])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_html(findings: list[Finding], destination: str | Path, warnings: list[str] | None = None, errors: list[str] | None = None) -> Path:
    path = Path(destination)
    metadata = report_metadata()
    counts = severity_counts(findings)
    coverage = mitre_coverage(findings)
    count_cards = "".join(
        f'<div class="card"><span>{escape(sev)}</span><strong>{count}</strong></div>'
        for sev, count in counts.items()
    )
    top_risk_rows = []
    appendix_rows = []
    for finding in findings:
        appendix_rows.append(
            "<tr>"
            f'<td><span class="badge {escape(str(finding.severity).lower())}">{escape(str(finding.severity))}</span></td>'
            f"<td>{escape(str(trust_summary(finding)['score']))}/100 {escape(str(trust_summary(finding)['classification']))}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.mitre_technique_id)} {escape(finding.mitre_technique_name)}</td>"
            f"<td><code>{escape(finding.path)}</code></td>"
            f"<td>{escape(finding.explanation)}</td>"
            "</tr>"
        )
    for finding in top_risks(findings):
        top_risk_rows.append(
            "<tr>"
            f'<td><span class="badge {escape(str(finding.severity).lower())}">{escape(str(finding.severity))}</span></td>'
            f"<td>{escape(str(trust_summary(finding)['score']))}/100 {escape(str(trust_summary(finding)['classification']))}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td><code>{escape(finding.path)}</code></td>"
            f"<td>{escape(finding.recommendation)}</td>"
            "</tr>"
        )
    mitre_items = "".join(
        f"<li><code>{escape(str(item['id']))}</code> {escape(str(item['name']))}: {item['count']} finding(s)</li>"
        for item in coverage
    ) or "<li>No mapped MITRE techniques observed.</li>"
    checklist = "".join(
        f"<li><input type='checkbox'> Review <code>{escape(item.path)}</code>: {escape(item.recommendation)}</li>"
        for item in top_risks(findings)
    ) or "<li>No remediation actions generated.</li>"
    coverage_rows = "".join(
        f"<tr><td><code>{escape(key)}</code></td><td>{escape(value['name'])}</td><td>{escape(value['mitre'])}</td></tr>"
        for key, value in coverage_catalog().items()
    )
    chain_rows = "".join(
        f"<tr><td>{escape(chain.title)}</td><td>{escape(chain.relationship)}</td><td>{chain.risk_score}</td></tr>"
        for chain in build_chains(findings)
    ) or "<tr><td colspan='3'>No multi-item chains detected in this report.</td></tr>"
    warning_rows = "".join(f"<li>Warning: {escape(warning)}</li>" for warning in (warnings or []))
    error_rows = "".join(f"<li>Error: {escape(error)}</li>" for error in (errors or []))
    scanner_notes = warning_rows + error_rows or "<li>None</li>"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>macOS Persistence Radar Report</title>
  <style>
    :root {{ color-scheme: light; --ink:#17202a; --muted:#607085; --line:#d9e0e8; --panel:#f7f9fc; --accent:#1f6feb; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; color: var(--ink); background: #fff; }}
    header {{ background:#101820; color:#fff; padding:32px 40px; }}
    main {{ padding:32px 40px; }}
    h1 {{ margin:0 0 8px; font-size:30px; }}
    h2 {{ margin-top:32px; border-bottom:1px solid var(--line); padding-bottom:8px; }}
    .meta, .muted {{ color: var(--muted); }}
    header .meta {{ color:#b8c4d2; }}
    .cards {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap:12px; margin:20px 0; }}
    .card {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }}
    .card span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
    .card strong {{ display:block; font-size:28px; margin-top:4px; }}
    table {{ border-collapse: collapse; width: 100%; font-size:14px; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: var(--panel); color:#2f3b4a; }}
    code {{ white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .badge {{ display:inline-block; min-width:72px; text-align:center; border-radius:999px; padding:3px 8px; font-weight:700; font-size:12px; }}
    .critical {{ background:#5f121b; color:#ffd8de; }}
    .high {{ background:#7a2d12; color:#ffe0cf; }}
    .medium {{ background:#6a5313; color:#fff0bd; }}
    .low {{ background:#173f2a; color:#caf7dc; }}
    .info {{ background:#173955; color:#d4ebff; }}
  </style>
</head>
<body>
  <header>
    <h1>macOS Persistence Radar Report</h1>
    <div class="meta">Generated {escape(metadata['generated_at'])} on {escape(metadata['hostname'])} | {escape(metadata['macos_version'])} | Scanner {escape(metadata['scanner_version'])}</div>
  </header>
  <main>
  <h2>Executive Summary</h2>
  <p>This read-only audit found <strong>{len(findings)}</strong> persistence item(s), including <strong>{counts['CRITICAL'] + counts['HIGH']}</strong> critical/high risk finding(s). Review top risks first, then validate remaining persistence against known business software.</p>
  <div class="cards">{count_cards}</div>
  <h2>Top Risks</h2>
  <table>
    <thead><tr><th>Severity</th><th>Reputation</th><th>Finding</th><th>Path</th><th>Recommendation</th></tr></thead>
    <tbody>{''.join(top_risk_rows)}</tbody>
  </table>
  <h2>MITRE ATT&amp;CK Coverage</h2>
  <ul>{mitre_items}</ul>
  <h2>Advanced Persistence Coverage</h2>
  <table>
    <thead><tr><th>Module</th><th>Coverage</th><th>MITRE / Risk Area</th></tr></thead>
    <tbody>{coverage_rows}</tbody>
  </table>
  <h2>Persistence Chain View</h2>
  <table>
    <thead><tr><th>Chain</th><th>Relationship</th><th>Risk Score</th></tr></thead>
    <tbody>{chain_rows}</tbody>
  </table>
  <h2>Remediation Checklist</h2>
  <ul>{checklist}</ul>
  <h2>Scanner Warnings And Errors</h2>
  <ul>{scanner_notes}</ul>
  <h2>Finding Appendix</h2>
  <table>
    <thead><tr><th>Severity</th><th>Reputation</th><th>Category</th><th>Title</th><th>MITRE</th><th>Path</th><th>Explanation</th></tr></thead>
    <tbody>{''.join(appendix_rows)}</tbody>
  </table>
  <h2>Legal / Defensive Use</h2>
  <p>macOS Persistence Radar is a read-only defensive auditing tool. Use only on systems you own or are authorized to assess. This report does not prove a system is clean and does not execute remediation.</p>
  </main>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")
    return path


def export_report(findings: list[Finding], fmt: str, destination: str | Path, warnings: list[str] | None = None, errors: list[str] | None = None) -> Path:
    if fmt == "json":
        return export_json(findings, destination, warnings, errors)
    if fmt in {"md", "markdown"}:
        return export_markdown(findings, destination, warnings, errors)
    if fmt == "html":
        return export_html(findings, destination, warnings, errors)
    raise ValueError(f"unsupported export format: {fmt}")
