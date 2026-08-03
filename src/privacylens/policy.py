"""Policy-as-code models and built-in privacy profiles."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


VALID_ACTIONS = {"allow", "report", "mask", "hash", "drop", "quarantine", "block"}


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """Action applied to a sensitive category and optional columns."""

    category: str
    action: str
    columns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.action not in VALID_ACTIONS:
            raise ValueError(f"Unsupported policy action: {self.action}")


@dataclass(slots=True)
class PrivacyPolicy:
    """Versioned policy controlling how findings are handled."""

    name: str = "default"
    version: str = "1.0"
    default_action: str = "report"
    rules: list[PolicyRule] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.default_action not in VALID_ACTIONS:
            raise ValueError(f"Unsupported default action: {self.default_action}")

    def action_for(self, category: str, column: str) -> str:
        """Resolve the first matching rule or the default action."""

        for rule in self.rules:
            if rule.category == category and (not rule.columns or column in rule.columns):
                return rule.action
        return self.default_action

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable policy."""

        return {
            "name": self.name,
            "version": self.version,
            "default_action": self.default_action,
            "rules": [
                {"category": rule.category, "action": rule.action, "columns": list(rule.columns)}
                for rule in self.rules
            ],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PrivacyPolicy":
        """Create and validate a policy from JSON/YAML data."""

        raw_rules = payload.get("rules", [])
        rules: list[PolicyRule] = []
        if isinstance(raw_rules, dict):
            rules = [PolicyRule(category, str(action)) for category, action in raw_rules.items()]
        elif isinstance(raw_rules, list):
            for item in raw_rules:
                rules.append(
                    PolicyRule(
                        category=str(item["category"]),
                        action=str(item["action"]),
                        columns=tuple(str(value) for value in item.get("columns", [])),
                    )
                )
        else:
            raise ValueError("Policy rules must be a mapping or a list")
        return cls(
            name=str(payload.get("name", "custom")),
            version=str(payload.get("version", "1.0")),
            default_action=str(payload.get("default_action", "report")),
            rules=rules,
        )


def load_policy(path: str | Path) -> PrivacyPolicy:
    """Load a JSON or YAML policy file."""

    source = Path(path)
    content = source.read_text(encoding="utf-8")
    if source.suffix.lower() == ".json":
        payload = json.loads(content)
    else:
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("PyYAML is required to load YAML policies") from exc
        payload = yaml.safe_load(content)
    if not isinstance(payload, dict):
        raise ValueError("Policy root must be a mapping")
    return PrivacyPolicy.from_dict(payload)


def audit_policy() -> PrivacyPolicy:
    """Report findings without changing source values."""

    return PrivacyPolicy(name="audit", default_action="report")


def redaction_policy() -> PrivacyPolicy:
    """Conservative default policy for producing shareable data."""

    actions = {
        "email": "mask",
        "phone": "mask",
        "person_name": "mask",
        "address": "mask",
        "date_of_birth": "mask",
        "precise_location": "drop",
        "ip_address": "hash",
        "government_id": "quarantine",
        "payment_card": "quarantine",
        "credential": "block",
    }
    return PrivacyPolicy(
        name="safe-share",
        default_action="report",
        rules=[PolicyRule(category, action) for category, action in actions.items()],
    )


def strict_policy() -> PrivacyPolicy:
    """Block publication when any sensitive category is found."""

    return PrivacyPolicy(name="strict-block", default_action="block")
