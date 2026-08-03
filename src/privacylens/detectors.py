"""Deterministic detectors for common sensitive-data categories."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Detection:
    """Internal detector result before location and fingerprint enrichment."""

    category: str
    detector: str
    confidence: float
    severity: str


Validator = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class PatternDetector:
    """Regex detector with an optional semantic validator."""

    category: str
    name: str
    pattern: re.Pattern[str]
    confidence: float
    severity: str
    validator: Validator | None = None

    def matches(self, value: str) -> bool:
        """Return whether a value contains a valid match."""

        for match in self.pattern.finditer(value):
            candidate = match.group(0)
            if self.validator is None or self.validator(candidate):
                return True
        return False


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _valid_ssn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in {"000", "666"} and int(area) < 900 and group != "00" and serial != "0000"


def _valid_payment_card(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


PATTERN_DETECTORS = (
    PatternDetector(
        "email",
        "email_regex",
        re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I),
        0.99,
        "medium",
    ),
    PatternDetector(
        "phone",
        "phone_regex",
        re.compile(r"(?<!\w)(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)"),
        0.93,
        "medium",
    ),
    PatternDetector(
        "ip_address",
        "ipv4_regex",
        re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
        0.96,
        "low",
        _valid_ipv4,
    ),
    PatternDetector(
        "government_id",
        "us_ssn_regex",
        re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        0.99,
        "critical",
        _valid_ssn,
    ),
    PatternDetector(
        "payment_card",
        "payment_card_luhn",
        re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        0.98,
        "critical",
        _valid_payment_card,
    ),
    PatternDetector(
        "credential",
        "provider_token_regex",
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,255}|sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9])"),
        0.99,
        "critical",
    ),
    PatternDetector(
        "credential",
        "jwt_regex",
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])"),
        0.98,
        "critical",
    ),
)


COLUMN_HINTS: tuple[tuple[re.Pattern[str], str, str, float], ...] = (
    (re.compile(r"(^|_)(email|e_mail)($|_)"), "email", "medium", 0.92),
    (re.compile(r"(^|_)(phone|mobile|telephone)($|_)"), "phone", "medium", 0.90),
    (re.compile(r"(^|_)(ssn|tax_id|passport|national_id)($|_)"), "government_id", "critical", 0.96),
    (re.compile(r"(^|_)(card_number|credit_card|pan)($|_)"), "payment_card", "critical", 0.95),
    (re.compile(r"(^|_)(password|passwd|api_key|access_token|secret|auth_token)($|_)"), "credential", "critical", 0.97),
    (re.compile(r"(^|_)(first_name|last_name|full_name|customer_name|person_name)($|_)"), "person_name", "medium", 0.84),
    (re.compile(r"^(ip|ip_address|client_ip)$"), "ip_address", "low", 0.88),
    (re.compile(r"^(address|street|postal_address)$"), "address", "high", 0.86),
    (re.compile(r"(^|_)(date_of_birth|dob|birth_date)($|_)"), "date_of_birth", "high", 0.91),
    (re.compile(r"(^|_)(latitude|longitude|lat|lon|lng)($|_)"), "precise_location", "high", 0.82),
)


def column_hint(column_name: str) -> Detection | None:
    """Infer a sensitive category from a normalized column name."""

    lowered = column_name.strip().lower().replace(" ", "_")
    for pattern, category, severity, confidence in COLUMN_HINTS:
        if pattern.search(lowered):
            return Detection(category, "column_semantics", confidence, severity)
    return None


def detect_value(value: str) -> list[Detection]:
    """Detect value-level sensitive patterns without returning match text."""

    return [
        Detection(item.category, item.name, item.confidence, item.severity)
        for item in PATTERN_DETECTORS
        if item.matches(value)
    ]
