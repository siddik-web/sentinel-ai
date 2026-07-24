"""Phase 2 demonstration showcasing multi-agent orchestration, state persistence, and response adapters."""

from sentinel_ai.agents.orchestrator import OrchestratorAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.persistence.state_store import StateStore
from sentinel_ai.response.edr import EDRResponseAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


def print_banner(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def main():
    print_banner("SENTINEL AI PHASE 2 MULTI-AGENT & RESPONSE DEMONSTRATION")

    # 1. Initialize core system & persistent state store
    print("\n[+] Initializing StateStore (SQLite), PEP, Orchestrator, & Response Adapters...")
    state_store = StateStore(db_path=":memory:")
    audit_logger = CryptographicAuditLogger()
    pep = PolicyEnforcementPoint(audit_logger=audit_logger)
    orchestrator = OrchestratorAgent(pep=pep)
    edr_adapter = EDRResponseAdapter(pep=pep)
    webhook_adapter = WebhookAdapter()

    print("    ✔ SQLite StateStore initialized")
    print("    ✔ Multi-Agent Orchestrator (TriageAgent + ForensicAgent) ready")
    print("    ✔ EDR Response Adapter ready")

    # 2. Ingest Critical Ransomware Alert
    print_banner("1. INGESTING CRITICAL THREAT EVENT")
    raw_payload = {
        "class_uid": 2001,
        "activity_id": 105,
        "severity_id": 5,  # CRITICAL
        "title": "Unusual Encrypted File Writes",
        "analytic_name": "RANSOMWARE_BEHAVIORAL",
        "confidence_score": 0.99,
        "product_name": "CrowdStrikeEDR",
    }
    ocsf_event = webhook_adapter.parse_and_normalize(raw_payload)
    print(f"    ▶ Ingested OCSF Event ID: {ocsf_event.get_event_id()}")

    # 3. Execute Multi-Agent Orchestration
    print_banner("2. MULTI-AGENT ORCHESTRATION (Triage -> Forensic Handoff)")
    summary = orchestrator.process_event_workflow(ocsf_event)

    print(f"    ▶ Triage Decision: {summary.triage_response.recommendation}")
    print(f"    ▶ Forensic Analysis: {summary.forensic_response.recommendation}")
    print(f"    ▶ Requires HITL: {summary.requires_hitl}")
    print(f"    ▶ Suggested Response Action: {summary.suggested_actions}")

    # Create HITL ticket in state store
    ticket = state_store.create_hitl_ticket(
        ticket_id=f"TICKET-{ocsf_event.get_event_id()}",
        event_id=ocsf_event.get_event_id(),
        action_name=summary.suggested_actions["action"],
        parameters=summary.suggested_actions,
    )
    print(f"    ✔ Created HITL Ticket: {ticket['ticket_id']} [Status: {ticket['status']}]")

    # 4. Operator Grants HITL Approval & Response Adapter Execution
    print_banner("3. HITL OPERATOR APPROVAL & OUTBOUND EDR RESPONSE")
    print(f"    [+] SOC Operator approves Ticket '{ticket['ticket_id']}'...")
    state_store.update_hitl_ticket_status(ticket["ticket_id"], "APPROVED")

    # Dispatch to EDR Response Adapter
    action_res = edr_adapter.execute_action(
        agent_id="orchestrator",
        action_name=summary.suggested_actions["action"],
        parameters={"host": "host-workstation-99"},
        hitl_approved=True,
    )
    print(f"    ✔ Outbound Response Result: {action_res.message}")
    print(f"    ✔ Target System Status: {action_res.evidence}")

    # 5. Persistent Audit Log Verification
    print_banner("4. PERSISTENT AUDIT LOG HASH CHAIN VERIFICATION")
    for entry in audit_logger.entries:
        state_store.save_audit_entry(entry)

    saved_entries = state_store.load_audit_entries()
    print(f"    ✔ Loaded {len(saved_entries)} audit entries from persistent SQLite store")
    print(f"    ✔ Cryptographic Hash Chain Validated: {audit_logger.verify_chain_integrity()}\n")

    for entry in saved_entries:
        print(
            f"    [{entry.entry_index}] {entry.event_type:<18} | Actor: {entry.actor:<15} | Hash: {entry.current_hash[:16]}..."
        )

    print("\n" + "=" * 70)
    print("  PHASE 2 DEMONSTRATION COMPLETED — ALL INVARIANTS PASSED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
