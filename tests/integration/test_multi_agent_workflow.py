"""Integration test for Multi-Agent Orchestration (Triage -> Forensic -> PEP -> Response)."""

from sentinel_ai.agents.orchestrator import OrchestratorAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.response.edr import EDRResponseAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


def test_multi_agent_orchestration_flow():
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    orchestrator = OrchestratorAgent(pep=pep)
    edr_adapter = EDRResponseAdapter(pep=pep)
    webhook_adapter = WebhookAdapter()

    # High severity ransomware payload
    raw_payload = {
        "class_uid": 2001,
        "activity_id": 99,
        "severity_id": 5,  # CRITICAL
        "title": "Ransomware Execution Detected",
        "analytic_name": "EDR-001",
        "confidence_score": 0.99,
    }
    ocsf_event = webhook_adapter.parse_and_normalize(raw_payload)

    summary = orchestrator.process_event_workflow(ocsf_event)

    assert summary.requires_hitl is True
    assert summary.triage_response is not None
    assert summary.forensic_response is not None
    assert "Forensic Analysis Complete" in summary.final_recommendation

    # Execute response adapter action with HITL approval
    action_name = summary.suggested_actions["action"]
    res = edr_adapter.execute_action(
        agent_id="orchestrator",
        action_name=action_name,
        parameters={"host": "host-infected-01"},
        hitl_approved=True,
    )
    assert res.success is True
    assert audit_logger.verify_chain_integrity() is True
