"""Dataframe privacy scanner that never retains raw detected values."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import Counter
from datetime import UTC, datetime

import pandas as pd

from privacylens.detectors import Detection, column_hint, detect_value
from privacylens.models import Finding, ScanReport

SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 12}


def _masked_preview(category: str, value: str) -> str:
    return f"[{category} masked]"


def _fingerprint(key: bytes, category: str, value: str) -> str:
    normalized = " ".join(value.strip().split()).lower()
    digest = hmac.new(key, f"{category}:{normalized}".encode(), hashlib.sha256).hexdigest()
    return f"hmac:{digest[:16]}"


def _risk(findings: list[Finding]) -> tuple[int, str]:
    weighted = sum(SEVERITY_WEIGHT[item.severity] for item in findings)
    diversity_bonus = len({item.category for item in findings}) * 2
    score = min(100, weighted + diversity_bonus)
    if score >= 70:
        return score, "critical"
    if score >= 40:
        return score, "high"
    if score >= 15:
        return score, "moderate"
    return score, "low"


def _best_detection(items: list[Detection]) -> list[Detection]:
    by_category: dict[str, Detection] = {}
    for item in items:
        current = by_category.get(item.category)
        if current is None or item.confidence > current.confidence:
            by_category[item.category] = item
    return list(by_category.values())


def _is_null(value: object) -> bool:
    if value is None:
        return True
    try:
        result = pd.isna(value)
        if hasattr(result, "shape") and result.shape != ():
            return False
        return bool(result)
    except (TypeError, ValueError):
        return False


def scan_frame(
    frame: pd.DataFrame,
    *,
    source_name: str = "in_memory",
    fingerprint_key: str | bytes | None = None,
    max_findings: int = 5000,
) -> ScanReport:
    """Scan a dataframe and return only privacy-safe evidence."""

    if max_findings < 1:
        raise ValueError("max_findings must be positive")
    if fingerprint_key is None:
        key = secrets.token_bytes(32)
    elif isinstance(fingerprint_key, str):
        key = fingerprint_key.encode()
    else:
        key = fingerprint_key

    findings: list[Finding] = []
    cells_scanned = 0
    truncated = False
    columns = [str(column) for column in frame.columns]
    hints = {column: column_hint(column) for column in columns}

    for row_number, row in enumerate(frame.itertuples(index=False, name=None)):
        for column_number, raw_value in enumerate(row):
            if _is_null(raw_value):
                continue
            value = str(raw_value).strip()
            if not value:
                continue
            cells_scanned += 1
            column = columns[column_number]
            candidates = detect_value(value)
            if hints[column] is not None:
                candidates.append(hints[column])  # type: ignore[arg-type]
            for detection in _best_detection(candidates):
                fingerprint = _fingerprint(key, detection.category, value)
                location = f"{source_name}:{column}:{row_number}:{detection.category}"
                finding_id = hashlib.sha256(location.encode()).hexdigest()[:16]
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        category=detection.category,
                        detector=detection.detector,
                        column=column,
                        row_number=row_number,
                        confidence=round(detection.confidence, 3),
                        severity=detection.severity,
                        fingerprint=fingerprint,
                        masked_preview=_masked_preview(detection.category, value),
                    )
                )
                if len(findings) >= max_findings:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break

    category_counts = dict(sorted(Counter(item.category for item in findings).items()))
    column_counts = dict(sorted(Counter(item.column for item in findings).items()))
    score, level = _risk(findings)
    return ScanReport(
        source_name=source_name,
        scanned_at=datetime.now(UTC).isoformat(),
        row_count=len(frame),
        column_count=len(frame.columns),
        cells_scanned=cells_scanned,
        findings=findings,
        category_counts=category_counts,
        column_counts=column_counts,
        risk_score=score,
        risk_level=level,
        truncated=truncated,
    )
