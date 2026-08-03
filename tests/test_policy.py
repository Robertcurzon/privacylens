from __future__ import annotations

import json
from pathlib import Path

from privacylens.policy import PrivacyPolicy, load_policy


def test_policy_supports_mapping_and_column_specific_rules(tmp_path: Path) -> None:
    mapping = PrivacyPolicy.from_dict(
        {"name": "mapping", "default_action": "report", "rules": {"email": "mask"}}
    )
    assert mapping.action_for("email", "customer_email") == "mask"

    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "name": "columns",
                "rules": [
                    {"category": "email", "action": "allow", "columns": ["support_alias"]},
                    {"category": "email", "action": "mask"},
                ],
            }
        ),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)
    assert policy.action_for("email", "support_alias") == "allow"
    assert policy.action_for("email", "customer_email") == "mask"
