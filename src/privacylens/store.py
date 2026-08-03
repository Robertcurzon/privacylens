"""Immutable artifact storage for privacy runs."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from privacylens.io import write_table
from privacylens.models import SanitizationResult, ScanReport
from privacylens.policy import PrivacyPolicy
from privacylens.report import render_html_report, report_payload


class RunStore:
    """Persist and retrieve privacy-safe run artifacts."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        report: ScanReport,
        policy: PrivacyPolicy,
        sanitization: SanitizationResult | None = None,
    ) -> dict[str, Any]:
        """Persist a report and optional sanitized outputs."""

        created_at = datetime.now(UTC)
        run_id = f"{created_at:%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
        run_dir = self.root / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        artifacts: dict[str, str] = {"report": "report.json", "html_report": "report.html"}
        payload = report_payload(report, policy=policy, sanitization=sanitization)
        (run_dir / "report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        (run_dir / "report.html").write_text(render_html_report(report), encoding="utf-8")

        status = "audited"
        if sanitization is not None:
            status = sanitization.decision.status
            if sanitization.decision.status != "blocked":
                sanitized_path = write_table(sanitization.sanitized, run_dir / "sanitized.parquet")
                artifacts["sanitized"] = sanitized_path.name
            if not sanitization.quarantined.empty:
                quarantine_path = write_table(
                    sanitization.quarantined, run_dir / "quarantine_evidence.csv"
                )
                artifacts["quarantine"] = quarantine_path.name

        manifest = {
            "run_id": run_id,
            "created_at": created_at.isoformat(),
            "source_name": report.source_name,
            "status": status,
            "policy": policy.name,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level,
            "findings": len(report.findings),
            "rows": report.row_count,
            "categories": report.category_counts,
            "artifacts": artifacts,
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def list_runs(self) -> list[dict[str, Any]]:
        """List manifests newest first."""

        runs: list[dict[str, Any]] = []
        for path in self.root.glob("*/manifest.json"):
            try:
                runs.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(runs, key=lambda item: item.get("created_at", ""), reverse=True)

    def load(self, run_id: str) -> dict[str, Any]:
        """Load a manifest and masked report."""

        run_dir = self.root / run_id
        if not run_dir.is_dir() or run_dir.parent != self.root:
            raise FileNotFoundError(run_id)
        return {
            "manifest": json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")),
            **json.loads((run_dir / "report.json").read_text(encoding="utf-8")),
        }

    def artifact_path(self, run_id: str, filename: str) -> Path:
        """Resolve a whitelisted artifact for download."""

        run = self.load(run_id)
        if filename not in set(run["manifest"]["artifacts"].values()):
            raise FileNotFoundError(filename)
        path = self.root / run_id / filename
        if not path.is_file():
            raise FileNotFoundError(filename)
        return path
