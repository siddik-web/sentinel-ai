"""Unit tests for Policy Enforcement Point (PEP) boundary governance."""

import pytest

from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.exceptions import PolicyViolationError
from sentinel_ai.security.pep import PolicyEnforcementPoint


def test_pep_allows_normal_actions():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)

    assert pep.evaluate_action("agent-1", "QUERY_ALERT", {}) is True
    assert pep.evaluate_action("agent-1", "CLASSIFY_SEVERITY", {}) is True
    assert audit_logger.verify_chain_integrity() is True


def test_pep_blocks_unapproved_high_risk_actions():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)

    with pytest.raises(PolicyViolationError) as exc_info:
        pep.evaluate_action("agent-1", "ISOLATE_HOST", {"host": "web-prod-01"}, hitl_approved=False)

    assert "requires Human-In-The-Loop approval" in str(exc_info.value)
    # Ensure policy denial was logged to hash-chained audit log
    assert audit_logger.entries[-1].event_type == "POLICY_DENIAL"


def test_pep_allows_hitl_approved_high_risk_actions():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)

    assert (
        pep.evaluate_action("agent-1", "ISOLATE_HOST", {"host": "web-prod-01"}, hitl_approved=True)
        is True
    )
    assert audit_logger.entries[-1].event_type == "POLICY_APPROVAL"
