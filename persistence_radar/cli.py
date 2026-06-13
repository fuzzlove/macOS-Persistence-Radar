from __future__ import annotations

from pathlib import Path
import argparse
import json
import logging
import sys
import time

from persistence_radar.core.baseline import compare_findings
from persistence_radar.core.app_logging import setup_logging
from persistence_radar.core.database import RadarDatabase
from persistence_radar.core.models import utc_now_iso
from persistence_radar.core.reporting import export_report
from persistence_radar.core.scan import coverage_catalog, doctor, run_scan
from persistence_radar.core.timeline import events_from_diff, export_timeline
from persistence_radar.core.malware_kb import malware_kb


def _print_scan_result(result) -> None:
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))


def cmd_scan(args: argparse.Namespace) -> int:
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    result = run_scan(root=args.root, debug=args.debug, module=args.module)
    if args.save:
        db = RadarDatabase(args.db)
        db.save_snapshot(args.save, result.inventory_items, utc_now_iso())
        db.close()
    if args.json:
        _print_scan_result(result)
    else:
        print(f"Inventory items: {len(result.inventory_items)}")
        print(f"Findings: {len(result.findings)}")
        for name, count in result.scanner_counts.items():
            print(f"{name}: {count}")
        if result.warnings:
            print("Warnings:")
            for warning in result.warnings:
                print(f"  - {warning}")
        if result.errors:
            print("Errors:")
            for error in result.errors:
                print(f"  - {error}")
        for item in result.inventory_items:
            print(f"{item.severity:8} {item.category:22} {item.title}")
    return 0


def cmd_baseline_create(args: argparse.Namespace) -> int:
    findings = run_scan(root=args.root, module=getattr(args, "module", None)).inventory_items
    db = RadarDatabase(args.db)
    db.save_snapshot(args.name, findings, utc_now_iso())
    db.close()
    print(f"Created baseline '{args.name}' with {len(findings)} findings.")
    return 0


def cmd_baseline_compare(args: argparse.Namespace) -> int:
    db = RadarDatabase(args.db)
    baseline = db.load_snapshot(args.name)
    db.close()
    current = run_scan(root=args.root).inventory_items
    diff = compare_findings(baseline, current)
    payload = {
        "added": [item.to_dict() for item in diff.added],
        "removed": [item.to_dict() for item in diff.removed],
        "modified": [{"before": old.to_dict(), "after": new.to_dict()} for old, new in diff.modified],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    print(f"Watch mode polling every {args.interval}s. Press Ctrl-C to stop.")
    db = RadarDatabase(args.db)
    previous = run_scan(root=args.root).inventory_items
    db.save_snapshot("watch-last", previous, utc_now_iso())
    try:
        while True:
            time.sleep(args.interval)
            current = run_scan(root=args.root).inventory_items
            diff = compare_findings(previous, current)
            if diff.added or diff.removed or diff.modified:
                print(
                    f"{utc_now_iso()} changes: added={len(diff.added)} "
                    f"removed={len(diff.removed)} modified={len(diff.modified)}"
                )
                db.save_snapshot("watch-last", current, utc_now_iso())
                previous = current
    except KeyboardInterrupt:
        print("Watch mode stopped.")
    finally:
        db.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    if args.baseline:
        db = RadarDatabase(args.db)
        findings = db.load_snapshot(args.baseline)
        db.close()
    else:
        findings = run_scan(root=args.root, module=getattr(args, "module", None)).inventory_items
    destination = Path(args.output or f"persistence-radar-report.{args.format}")
    export_report(findings, args.format, destination)
    print(f"Exported {len(findings)} findings to {destination}.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print(json.dumps(doctor(root=args.root), indent=2, sort_keys=True))
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    print(json.dumps(coverage_catalog(), indent=2, sort_keys=True))
    return 0


def cmd_chains(args: argparse.Namespace) -> int:
    result = run_scan(root=args.root, module=args.module)
    print(json.dumps([chain.to_dict() for chain in result.chains], indent=2, sort_keys=True))
    return 0


def cmd_posture(args: argparse.Namespace) -> int:
    result = run_scan(root=args.root, module=args.module)
    print(json.dumps(result.posture, indent=2, sort_keys=True))
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    if args.baseline:
        db = RadarDatabase(args.db)
        baseline = db.load_snapshot(args.baseline)
        db.close()
        current = run_scan(root=args.root, module=args.module).inventory_items
        events = events_from_diff(compare_findings(baseline, current))
    else:
        events = run_scan(root=args.root, module=args.module).timeline_events
    if args.output:
        export_timeline(events, args.format, args.output)
        print(f"Exported {len(events)} timeline events to {args.output}.")
    else:
        print(json.dumps([event.to_dict() for event in events], indent=2, sort_keys=True))
    return 0


def cmd_malware_kb(args: argparse.Namespace) -> int:
    print(json.dumps(malware_kb(), indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="persistence-radar", description="Audit macOS persistence mechanisms.")
    parser.add_argument("--db", default=None, help="SQLite database path.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a read-only persistence scan.")
    scan.add_argument("--root", default="/", help="Alternate filesystem root for testing or mounted images.")
    scan.add_argument("--json", action="store_true", help="Print JSON scan result.")
    scan.add_argument("--debug", action="store_true", help="Enable scanner debug logging.")
    scan.add_argument("--all", action="store_true", help="Run all scanner modules. This is the default.")
    scan.add_argument("--module", help="Run one scanner module, such as launchd, browser_extensions, or profiles.")
    scan.add_argument("--save", help="Save scan results as a named snapshot.")
    scan.set_defaults(func=cmd_scan)

    baseline = sub.add_parser("baseline", help="Manage baselines.")
    baseline_sub = baseline.add_subparsers(dest="baseline_command", required=True)
    create = baseline_sub.add_parser("create", help="Create a baseline snapshot.")
    create.add_argument("name")
    create.add_argument("--root", default="/")
    create.set_defaults(func=cmd_baseline_create)
    compare = baseline_sub.add_parser("compare", help="Compare current scan with a baseline.")
    compare.add_argument("name")
    compare.add_argument("--root", default="/")
    compare.set_defaults(func=cmd_baseline_compare)

    watch = sub.add_parser("watch", help="Poll for persistence changes.")
    watch.add_argument("--root", default="/")
    watch.add_argument("--interval", type=int, default=30)
    watch.set_defaults(func=cmd_watch)

    export = sub.add_parser("export", help="Export report.")
    export.add_argument("--root", default="/")
    export.add_argument("--format", choices=["html", "json", "md"], required=True)
    export.add_argument("--output")
    export.add_argument("--baseline", help="Export a saved baseline instead of a live scan.")
    export.add_argument("--module", help="Export results for one scanner module.")
    export.set_defaults(func=cmd_export)

    doctor_parser = sub.add_parser("doctor", help="Print scanner environment diagnostics.")
    doctor_parser.add_argument("--root", default="/")
    doctor_parser.set_defaults(func=cmd_doctor)
    coverage = sub.add_parser("coverage", help="Show advanced persistence coverage.")
    coverage.set_defaults(func=cmd_coverage)
    chains = sub.add_parser("chains", help="Show persistence relationship chains.")
    chains.add_argument("--root", default="/")
    chains.add_argument("--module")
    chains.set_defaults(func=cmd_chains)
    posture = sub.add_parser("posture", help="Show Security Posture Score.")
    posture.add_argument("--root", default="/")
    posture.add_argument("--module")
    posture.set_defaults(func=cmd_posture)
    timeline = sub.add_parser("timeline", help="Show or export persistence timeline.")
    timeline.add_argument("--root", default="/")
    timeline.add_argument("--module")
    timeline.add_argument("--baseline", help="Generate change timeline against a saved baseline.")
    timeline.add_argument("--format", choices=["html", "json", "md"], default="json")
    timeline.add_argument("--output")
    timeline.set_defaults(func=cmd_timeline)
    malware = sub.add_parser("malware-kb", help="Show malware artifact knowledge base.")
    malware.set_defaults(func=cmd_malware_kb)
    return parser


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
