"""Policy-driven masking, hashing, dropping, and row quarantine."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections import Counter, defaultdict

import pandas as pd

from privacylens.models import PolicyDecision, SanitizationResult, ScanReport
from privacylens.policy import PrivacyPolicy


ACTION_PRIORITY = {
    "allow": 0,
    "report": 1,
    "mask": 2,
    "hash": 3,
    "drop": 4,
    "quarantine": 5,
    "block": 6,
}


def _mask(category: str, value: object) -> str:
    text = str(value)
    if category == "email" and "@" in text:
        local, domain = text.rsplit("@", 1)
        prefix = local[:1] if local else "*"
        return f"{prefix}***@{domain}"
    if category == "phone":
        digits = "".join(character for character in text if character.isdigit())
        return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "[PHONE REDACTED]"
    if category == "payment_card":
        digits = "".join(character for character in text if character.isdigit())
        return f"**** **** **** {digits[-4:]}" if len(digits) >= 4 else "[CARD REDACTED]"
    return f"[{category.upper()} REDACTED]"


def _hash_value(value: object, key: bytes) -> str:
    digest = hmac.new(key, str(value).strip().encode(), hashlib.sha256).hexdigest()
    return f"hmac:{digest[:24]}"


def sanitize_frame(
    frame: pd.DataFrame,
    report: ScanReport,
    policy: PrivacyPolicy,
    *,
    hash_key: str | bytes | None = None,
) -> SanitizationResult:
    """Apply privacy policy while keeping quarantine evidence free of raw values."""

    env_key = os.getenv("PRIVACYLENS_HASH_KEY")
    selected_key = hash_key or env_key
    if selected_key is None:
        key = secrets.token_bytes(32)
    elif isinstance(selected_key, str):
        key = selected_key.encode()
    else:
        key = selected_key

    action_counts: Counter[str] = Counter()
    blocked = 0
    modified = 0
    quarantine_reasons: dict[int, set[str]] = defaultdict(set)
    cell_actions: dict[tuple[int, str], tuple[str, str]] = {}

    for finding in report.findings:
        action = policy.action_for(finding.category, finding.column)
        action_counts[action] += 1
        if action == "block":
            blocked += 1
        if action == "quarantine":
            quarantine_reasons[finding.row_number].add(finding.category)
        location = (finding.row_number, finding.column)
        previous = cell_actions.get(location)
        if previous is None or ACTION_PRIORITY[action] > ACTION_PRIORITY[previous[0]]:
            cell_actions[location] = (action, finding.category)

    sanitized = frame.copy(deep=True)
    column_positions = {str(column): index for index, column in enumerate(sanitized.columns)}
    for (row_number, column), (action, category) in cell_actions.items():
        if row_number in quarantine_reasons or action in {"allow", "report", "block", "quarantine"}:
            continue
        column_number = column_positions[column]
        value = sanitized.iat[row_number, column_number]
        if action == "mask":
            sanitized.iat[row_number, column_number] = _mask(category, value)
        elif action == "hash":
            sanitized.iat[row_number, column_number] = _hash_value(value, key)
        elif action == "drop":
            sanitized.iat[row_number, column_number] = pd.NA
        modified += 1

    quarantine_rows = sorted(quarantine_reasons)
    quarantine = pd.DataFrame(
        [
            {
                "_row_number": row,
                "_privacylens_reasons": "|".join(sorted(quarantine_reasons[row])),
            }
            for row in quarantine_rows
        ]
    )
    if quarantine_rows:
        sanitized = sanitized.drop(index=sanitized.index[quarantine_rows]).reset_index(drop=True)

    return SanitizationResult(
        sanitized=sanitized,
        quarantined=quarantine,
        decision=PolicyDecision(
            status="blocked" if blocked else "passed",
            blocked_findings=blocked,
            action_counts=dict(sorted(action_counts.items())),
        ),
        modified_cells=modified,
        quarantined_rows=len(quarantine_rows),
    )
