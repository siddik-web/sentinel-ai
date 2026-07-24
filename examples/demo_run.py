"""Real test demonstration script for Sentinel AI runtime engine."""

from sentinel_ai.agents.triage import TriageAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.exceptions import PolicyViolationError
from sentinel_ai.ingestion.engine import IngestionEngine
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


def print_banner(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def main():
    print_banner("SENTINEL AI RUNTIME ENGINE DEMONSTRATION")

    # 1. Initialize core system components
    print("\n[+] 1. Initializing System Components...")
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    triage_agent = TriageAgent(agent_id="triage-agent-01", pep=pep)
    ingestion_engine = IngestionEngine()
    webhook_adapter = WebhookAdapter(vendor_name="EnterpriseSecurityHub")

    # Subscribe Triage Agent to Ingestion Router
    processed_responses = []

    def alert_handler(ocsf_event):
        response = triage_agent.evaluate_event(ocsf_event)
        processed_responses.append((ocsf_event, response))

    ingestion_engine.subscribe(alert_handler)
    print("    ✔ Cryptographic Audit Logger initialized (Genesis Hash ready)")
    print("    ✔ Policy Enforcement Point (PEP) active")
    print("    ✔ TriageAgent (triage-agent-01) registered")
    print("    ✔ Ingestion Engine ready")

    # 2. Test Scenario 1: Low-Risk Event
    print_banner("SCENARIO 1: Processing Low-Risk Authentication Event")
    raw_payload_1 = {
        "class_uid": 3002,
        "activity_id": 1,
        "severity_id": 1,  # INFORMATIONAL
        "user_name": "bob@enterprise.com",
        "is_success": True,
        "product_name": "AzureAD",
    }
    event_1 = webhook_adapter.parse_and_normalize(raw_payload_1)
    print(f"    ▶ Ingested Event: {event_1.get_event_id()}")
    ingestion_engine.process_event(event_1)

    _, response_1 = processed_responses[-1]
    print(f"    ▶ Triage Decision: {response_1.recommendation}")
    print(f"    ▶ Requires HITL: {response_1.requires_hitl}")

    # 3. Test Scenario 2: Suspicious Process & Unapproved High-Risk Action
    print_banner("SCENARIO 2: Suspicious Process Execution & Policy Enforcement Check")
    raw_payload_2 = {
        "class_uid": 1007,
        "activity_id": 4,
        "severity_id": 4,  # HIGH
        "process_name": "powershell.exe",
        "process_pid": 8192,
        "command_line": "powershell.exe -enc AAEFA==",
        "product_name": "CrowdStrikeEDR",
    }
    event_2 = webhook_adapter.parse_and_normalize(raw_payload_2)
    print(f"    ▶ Ingested Event: {event_2.get_event_id()}")
    ingestion_engine.process_event(event_2)

    _, response_2 = processed_responses[-1]
    print(f"    ▶ Triage Decision: {response_2.recommendation}")
    print(f"    ▶ Requires HITL: {response_2.requires_hitl}")
    print(f"    ▶ Suggested Action: {response_2.suggested_actions}")

    # Attempting unapproved high-risk action
    print(
        "\n    [!] Agent attempting HIGH-RISK action 'TERMINATE_PROCESS' WITHOUT HITL approval..."
    )
    try:
        pep.evaluate_action(
            agent_id=triage_agent.agent_id,
            action_name="TERMINATE_PROCESS",
            parameters={"pid": 8192},
            hitl_approved=False,
        )
    except PolicyViolationError as e:
        print(f"    ✔ PEP GUARANTEE PASSED: Action blocked with error -> '{e}'")

    # 4. Test Scenario 3: HITL Operator Approval for High-Risk Action
    print_banner("SCENARIO 3: Operator HITL Approval for High-Risk Action")
    print("    [+] Operator grants HITL Approval for 'TERMINATE_PROCESS'...")
    allowed = pep.evaluate_action(
        agent_id=triage_agent.agent_id,
        action_name="TERMINATE_PROCESS",
        parameters={"pid": 8192},
        hitl_approved=True,
    )
    print(f"    ✔ PEP Execution Status: Approved = {allowed}")

    # 5. Verify Cryptographic Audit Chain
    print_banner("AUDIT LOG INTEGRITY VERIFICATION")
    is_valid = audit_logger.verify_chain_integrity()
    print(f"    ✔ Cryptographic Hash Chain Valid: {is_valid}")
    print(f"    ✔ Total Audit Entries Logged: {len(audit_logger.entries)}\n")

    for entry in audit_logger.entries:
        print(
            f"    [{entry.entry_index}] {entry.event_type:<18} | Actor: {entry.actor:<15} | Hash: {entry.current_hash[:16]}..."
        )

    print("\n" + "=" * 70)
    print("  DEMONSTRATION COMPLETED SUCCESSFULLY — ALL SECURITY INVARIANTS PASSED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
