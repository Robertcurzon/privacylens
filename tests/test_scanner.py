from __future__ import annotations

import json

import pandas as pd

from privacylens.scanner import scan_frame


def test_scan_detects_structured_sensitive_data_without_raw_values() -> None:
    secret = "sk-testValue12345678901234567890"
    frame = pd.DataFrame(
        {
            "full_name": ["Avery Stone"],
            "email": ["avery@example.com"],
            "phone": ["415-555-0101"],
            "client_ip": ["192.0.2.10"],
            "card_number": ["4242 4242 4242 4242"],
            "api_key": [secret],
        }
    )

    report = scan_frame(frame, source_name="customers.csv", fingerprint_key="test")
    categories = set(report.category_counts)
    serialized = json.dumps(report.to_dict())

    assert {"person_name", "email", "phone", "ip_address", "payment_card", "credential"} <= categories
    assert "avery@example.com" not in serialized
    assert "415-555-0101" not in serialized
    assert "4242 4242" not in serialized
    assert secret not in serialized
    assert all(item.fingerprint.startswith("hmac:") for item in report.findings)


def test_luhn_validator_ignores_invalid_card_like_number() -> None:
    frame = pd.DataFrame({"notes": ["Reference 1234 5678 9012 3456"]})
    report = scan_frame(frame, fingerprint_key="test")
    assert "payment_card" not in report.category_counts
