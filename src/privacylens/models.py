"""Typed privacy findings, reports, and sanitization outcomes."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

import pandas as pd


@dataclass(frozen=True, slots=True)
class Finding:
    """One sensitive-data observation without the raw detected value."""

    finding_id: str
    category: str
    detector: str
    column: str
    row_number: int
    confidence: float
    severity: str
    fingerprint: str
    masked_preview: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""

        return asdict(self)


@dataclass(slots=True)
class ScanReport:
    """Aggregate privacy inventory for one tabular source."""

    source_name: str
    scanned_at: str
    row_count: int
    column_count: int
    cells_scanned: int
    findings: list[Finding]
    category_counts: dict[str, int]
    column_counts: dict[str, int]
    risk_score: int
    risk_level: str
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe report."""

        payload = asdict(self)
        payload["findings"] = [item.to_dict() for item in self.findings]
        return payload


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Result of applying policy actions to a scan report."""

    status: str
    blocked_findings: int
    action_counts: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class SanitizationResult:
    """Safe output frames and auditable policy execution metadata."""

    sanitized: pd.DataFrame
    quarantined: pd.DataFrame
    decision: PolicyDecision
    modified_cells: int
    quarantined_rows: int

    def summary(self) -> dict[str, Any]:
        """Return metadata without serializing dataframe contents."""

        return {
            "status": self.decision.status,
            "blocked_findings": self.decision.blocked_findings,
            "action_counts": self.decision.action_counts,
            "modified_cells": self.modified_cells,
            "output_rows": len(self.sanitized),
            "quarantined_rows": self.quarantined_rows,
        }
