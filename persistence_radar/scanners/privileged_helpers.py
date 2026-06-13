from __future__ import annotations

from persistence_radar.core.hashing import sha256_file
from persistence_radar.core.mitre import technique
from persistence_radar.core.models import Finding, Severity
from persistence_radar.core.signing import code_signature_status, notarization_status
from persistence_radar.scanners.common import root_join, stat_metadata
from persistence_radar.core.scoring import APPLE_LABEL_RE, is_world_writable


def scan_privileged_helpers(root: str = "/") -> list[Finding]:
    base = root_join(root, "/Library/PrivilegedHelperTools")
    if not base.is_dir():
        return []
    mitre_id, mitre_name = technique("host_binary")
    findings = []
    daemon_labels = set()
    daemon_dir = root_join(root, "/Library/LaunchDaemons")
    if daemon_dir.is_dir():
        daemon_labels = {item.stem for item in daemon_dir.glob("*.plist")}
    for item in sorted(base.iterdir()):
        if not item.is_file():
            continue
        owner, permissions = stat_metadata(item)
        signature = code_signature_status(item)
        helper_without_daemon = item.name not in daemon_labels
        mimics = bool(APPLE_LABEL_RE.match(item.name))
        writable = is_world_writable(item)
        severity = Severity.HIGH if signature in {"unsigned", "invalid"} or writable or mimics else Severity.MEDIUM if helper_without_daemon else Severity.INFO
        findings.append(
            Finding(
                id=f"privileged-helper:{item.name}",
                title=f"Privileged helper tool: {item.name}",
                severity=severity,
                category="Privileged Helper",
                mitre_technique_id=mitre_id,
                mitre_technique_name=mitre_name,
                path="/Library/PrivilegedHelperTools/" + item.name,
                executable_path=str(item),
                owner=owner,
                permissions=permissions,
                sha256=sha256_file(item),
                code_signature_status=signature,
                notarization_status=notarization_status(item),
                explanation="Privileged helper tools can run with elevated rights when launched by authorized clients. Helpers without matching LaunchDaemons or weak permissions are high-interest DFIR artifacts.",
                recommendation="Confirm the helper belongs to trusted software and has valid signing.",
                raw_evidence={"helper_name": item.name, "helper_without_matching_launchdaemon": helper_without_daemon, "world_writable": writable, "apple_like_name": mimics},
            )
        )
    if daemon_dir.is_dir():
        helper_names = {item.name for item in base.iterdir() if item.is_file()}
        for daemon in daemon_dir.glob("*.plist"):
            if daemon.stem not in helper_names:
                owner, permissions = stat_metadata(daemon)
                findings.append(
                    Finding(
                        id=f"launchdaemon-no-helper:{daemon.name}",
                        title=f"LaunchDaemon without matching helper: {daemon.name}",
                        severity=Severity.INFO,
                        category="Privileged Helper",
                        path="/Library/LaunchDaemons/" + daemon.name,
                        owner=owner,
                        permissions=permissions,
                        explanation="This LaunchDaemon does not have a same-named file in /Library/PrivilegedHelperTools. That can be normal, but it is useful context when reviewing helper relationships.",
                        recommendation="Review the daemon Program/ProgramArguments and verify the executable it launches.",
                        raw_evidence={"launchdaemon_without_same_named_helper": True},
                    )
                )
    return findings
