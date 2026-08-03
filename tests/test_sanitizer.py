from __future__ import annotations

import pandas as pd

from privacylens.policy import PolicyRule, PrivacyPolicy
from privacylens.sanitizer import sanitize_frame
from privacylens.scanner import scan_frame


def test_policy_masks_hashes_and_quarantines_without_copying_raw_rows() -> None:
    frame = pd.DataFrame(
        {
            "email": ["one@example.com", "two@example.com"],
            "ip_address": ["192.0.2.1", "192.0.2.2"],
            "ssn": [None, "078-05-1120"],
        }
    )
    policy = PrivacyPolicy(
        name="test",
        rules=[
            PolicyRule("email", "mask"),
            PolicyRule("ip_address", "hash"),
            PolicyRule("government_id", "quarantine"),
        ],
    )
    report = scan_frame(frame, fingerprint_key="test")
    result = sanitize_frame(frame, report, policy, hash_key="test")

    assert result.decision.status == "passed"
    assert len(result.sanitized) == 1
    assert result.sanitized.loc[0, "email"] == "o***@example.com"
    assert result.sanitized.loc[0, "ip_address"].startswith("hmac:")
    assert list(result.quarantined.columns) == ["_row_number", "_privacylens_reasons"]
    assert "078-05-1120" not in result.quarantined.to_string()


def test_block_action_prevents_release() -> None:
    frame = pd.DataFrame({"api_key": ["sk-testValue12345678901234567890"]})
    report = scan_frame(frame, fingerprint_key="test")
    policy = PrivacyPolicy(default_action="block")
    result = sanitize_frame(frame, report, policy, hash_key="test")
    assert result.decision.status == "blocked"
    assert result.decision.blocked_findings >= 1
