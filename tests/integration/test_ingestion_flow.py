"""Integration test verifying end-to-end flow from Webhook to Agent Triage & Audit Log."""

from sentinel_ai.agents.triage import TriageAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.ingestion.engine import IngestionEngine
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


def test_end_to_end_ingestion_and_triage_flow():
    # 1. Initialize security & audit components
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    triage_agent = TriageAgent(pep=pep)

    # 2. Setup ingestion engine & subscribe triage agent
    ingestion_engine = IngestionEngine()
    processed_responses = []

    def handle_event(event):
        response = triage_agent.evaluate_event(event)
        processed_responses.append(response)

    ingestion_engine.subscribe(handle_event)

    # 3. Simulate incoming raw webhook payload
    adapter = WebhookAdapter(vendor_name="CrowdStrike")
    raw_payload = {
        "class_uid": 2001,
        "activity_id": 99,
        "severity_id": 5,  # CRITICAL
        "time": 1710000000,
        "title": "Ransomware Execution Detected",
        "analytic_name": "EDR-BEHAVIORAL-01",
        "confidence_score": 0.99,
        "remediation_guidance": "Isolate host immediately",
    }

    ocsf_event = adapter.parse_and_normalize(raw_payload)

    # 4. Ingest and route event
    ingestion_engine.process_event(ocsf_event)

    # 5. Assertions
    assert len(processed_responses) == 1
    response = processed_responses[0]

    assert response.agent_id == "triage-agent-01"
    assert response.requires_hitl is True
    assert "Ransomware Execution Detected" in response.recommendation
    assert response.suggested_actions["action"] == "ISOLATE_HOST"

    # 6. Verify audit chain integrity
    assert audit_logger.verify_chain_integrity() is True
    assert len(audit_logger.entries) >= 2  # CLASSIFY_SEVERITY and REQUEST_HITL approvals
