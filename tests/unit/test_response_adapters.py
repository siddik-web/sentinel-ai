"""Unit tests for EDR and Identity outbound Response Adapters."""

import pytest

from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.exceptions import PolicyViolationError
from sentinel_ai.response.edr import EDRResponseAdapter
from sentinel_ai.response.identity import IdentityResponseAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


def test_edr_response_adapter_host_isolation():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    edr_adapter = EDRResponseAdapter(pep=pep)

    res = edr_adapter.execute_action(
        agent_id="agent-1",
        action_name="ISOLATE_HOST",
        parameters={"host": "host-prod-42"},
        hitl_approved=True,
    )
    assert res.success is True
    assert res.target == "host-prod-42"
    assert "isolated" in res.message
    assert res.evidence["simulated"] is True


def test_edr_response_adapter_process_termination():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    edr_adapter = EDRResponseAdapter(pep=pep)

    res = edr_adapter.execute_action(
        agent_id="agent-1",
        action_name="TERMINATE_PROCESS",
        parameters={"pid": 1337},
        hitl_approved=True,
    )
    assert res.success is True
    assert res.target == "PID_1337"


def test_identity_response_adapter_revoke_credentials():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    identity_adapter = IdentityResponseAdapter(pep=pep)

    res = identity_adapter.execute_action(
        agent_id="agent-1",
        action_name="REVOKE_CREDENTIALS",
        parameters={"user": "malicious_user"},
        hitl_approved=True,
    )
    assert res.success is True
    assert res.target == "malicious_user"


def test_response_adapter_blocks_unapproved_hitl():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    edr_adapter = EDRResponseAdapter(pep=pep)

    with pytest.raises(PolicyViolationError):
        edr_adapter.execute_action(
            agent_id="agent-1",
            action_name="ISOLATE_HOST",
            parameters={"host": "host-prod-42"},
            hitl_approved=False,
        )
