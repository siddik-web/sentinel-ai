"""Custom domain exceptions for Sentinel AI."""


class SentinelError(Exception):
    """Base exception for all Sentinel AI platform errors."""


class OCSFValidationError(SentinelError):
    """Raised when an incoming event fails OCSF schema validation."""


class PolicyViolationError(SentinelError):
    """Raised when an action violates the Policy Enforcement Point (PEP)."""

    def __init__(self, message: str, rule: str = "unspecified"):
        super().__init__(message)
        self.rule = rule


class PolicyConfigError(SentinelError):
    """Raised when a policy file is missing, unreadable, or structurally invalid."""


class AuditIntegrityError(SentinelError):
    """Raised when an audit log cryptographic hash chain validation fails."""


class TicketStateError(SentinelError):
    """Raised when a HITL ticket decision is attempted on a ticket that is not pending."""


class TicketNotFoundError(SentinelError):
    """Raised when a HITL ticket ID does not exist."""
