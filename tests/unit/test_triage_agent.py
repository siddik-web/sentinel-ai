"""Unit tests for TriageAgent evaluation logic."""

import pytest

from sentinel_ai.agents.triage import TriageAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.core.ocsf.models import (
    AuthenticationEvent,
    OCSFMetadata,
    ProcessActivityEvent,
    SeverityID,
)
from sentinel_ai.security.pep import PolicyEnforcementPoint


def test_triage_agent_missing_pep():
    with pytest.raises(ValueError, match="PolicyEnforcementPoint is required"):
        TriageAgent(pep=None)


def test_triage_agent_failed_auth_evaluation():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    agent = TriageAgent(pep=pep)

    metadata = OCSFMetadata(product_name="AWS IAM", vendor_name="AWS")
    event = AuthenticationEvent(
        activity_id=1,
        severity_id=SeverityID.HIGH,
        time=1600000000,
        metadata=metadata,
        user_name="admin_user",
        is_success=False,
    )

    response = agent.evaluate_event(event)

    assert response.severity_assessment == "MEDIUM"
    assert response.requires_hitl is True
    assert response.suggested_actions["action"] == "REVOKE_CREDENTIALS"


def test_triage_agent_suspicious_process_evaluation():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    agent = TriageAgent(pep=pep)

    metadata = OCSFMetadata(product_name="CrowdStrike", vendor_name="CrowdStrike")
    event = ProcessActivityEvent(
        activity_id=2,
        severity_id=SeverityID.HIGH,
        time=1600000000,
        metadata=metadata,
        process_name="powershell.exe",
        process_pid=4096,
        command_line="powershell.exe -ExecutionPolicy Bypass -File script.ps1",
    )

    response = agent.evaluate_event(event)

    assert response.requires_hitl is True
    assert "powershell.exe" in response.recommendation
    assert response.suggested_actions["action"] == "TERMINATE_PROCESS"
    assert response.suggested_actions["pid"] == 4096
