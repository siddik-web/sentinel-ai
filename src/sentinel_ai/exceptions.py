"""Custom domain exceptions for Sentinel AI."""


class SentinelError(Exception):
    """Base exception for all Sentinel AI platform errors."""


class OCSFValidationError(SentinelError):
    """Raised when an incoming event fails OCSF schema validation."""


class PolicyViolationError(SentinelError):
    """Raised when an action violates the Policy Enforcement Point (PEP)."""


class AuditIntegrityError(SentinelError):
    """Raised when an audit log cryptographic hash chain validation fails."""
