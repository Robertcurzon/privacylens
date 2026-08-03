"""Command-line interface for local privacy workflows."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from privacylens.io import load_table, write_table
from privacylens.policy import audit_policy, load_policy, redaction_policy, strict_policy
from privacylens.report import report_payload, write_html_report, write_json_report
from privacylens.sanitizer import sanitize_frame
from privacylens.scanner import scan_frame
from privacylens.store import RunStore


def build_parser() -> argparse.ArgumentParser:
    """Build the PrivacyLens CLI parser."""

    parser = argparse.ArgumentParser(
        prog="privacylens",
        description="Local-first sensitive-data discovery and policy enforcement.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Inventory sensitive data without changing it.")
    scan.add_argument("file", type=Path)
    scan.add_argument("--json", type=Path, default=Path("privacy-report.json"))
    scan.add_argument("--html", type=Path, default=Path("privacy-report.html"))
    scan.add_argument("--max-findings", type=int, default=5000)

    sanitize = commands.add_parser("sanitize", help="Apply a privacy policy to a data file.")
    sanitize.add_argument("file", type=Path)
    sanitize.add_argument("--policy", type=Path)
    sanitize.add_argument("--output", type=Path, required=True)
    sanitize.add_argument("--report", type=Path, default=Path("privacy-report.json"))

    demo = commands.add_parser("demo", help="Run the bundled privacy incident demo.")
    demo.add_argument("--output", type=Path, default=Path("data/runtime/runs"))
    demo.add_argument("--mode", choices=["audit", "sanitize", "strict"], default="audit")
    return parser


def _policy_for_mode(mode: str):
    if mode == "sanitize":
        return redaction_policy()
    if mode == "strict":
        return strict_policy()
    return audit_policy()


def main(argv: list[str] | None = None) -> int:
    """Execute a PrivacyLens command."""

    args = build_parser().parse_args(argv)
    fingerprint_key = os.getenv("PRIVACYLENS_HASH_KEY")
    if args.command == "scan":
        frame = load_table(args.file)
        report = scan_frame(
            frame,
            source_name=args.file.name,
            fingerprint_key=fingerprint_key,
            max_findings=args.max_findings,
        )
        payload = report_payload(report, policy=audit_policy())
        write_json_report(payload, args.json)
        write_html_report(report, args.html)
        print(json.dumps({"risk": report.risk_level, "findings": len(report.findings), "json": str(args.json), "html": str(args.html)}, indent=2))
        return 0
    if args.command == "sanitize":
        frame = load_table(args.file)
        policy = load_policy(args.policy) if args.policy else redaction_policy()
        report = scan_frame(frame, source_name=args.file.name, fingerprint_key=fingerprint_key)
        result = sanitize_frame(frame, report, policy, hash_key=fingerprint_key)
        write_json_report(report_payload(report, policy=policy, sanitization=result), args.report)
        if result.decision.status == "blocked":
            print(json.dumps(result.summary(), indent=2))
            return 2
        write_table(result.sanitized, args.output)
        print(json.dumps({**result.summary(), "output": str(args.output), "report": str(args.report)}, indent=2))
        return 0
    if args.command == "demo":
        root = Path(__file__).resolve().parents[2]
        source = root / "data/sample/customer_records.csv"
        frame = load_table(source)
        policy = _policy_for_mode(args.mode)
        report = scan_frame(frame, source_name=source.name, fingerprint_key="demo-key")
        result = None if args.mode == "audit" else sanitize_frame(frame, report, policy, hash_key="demo-key")
        manifest = RunStore(args.output).save(report, policy, result)
        print(json.dumps(manifest, indent=2))
        return 2 if result is not None and result.decision.status == "blocked" else 0
    return 2
