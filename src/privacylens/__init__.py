"""PrivacyLens public package API."""

from privacylens.models import Finding, SanitizationResult, ScanReport
from privacylens.policy import PrivacyPolicy, audit_policy, redaction_policy, strict_policy
from privacylens.sanitizer import sanitize_frame
from privacylens.scanner import scan_frame

__all__ = [
    "Finding",
    "PrivacyPolicy",
    "SanitizationResult",
    "ScanReport",
    "audit_policy",
    "redaction_policy",
    "sanitize_frame",
    "scan_frame",
    "strict_policy",
]

__version__ = "0.1.0"
