"""Unit tests for SQLite StateStore persistence."""

from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.persistence.state_store import StateStore


def test_state_store_audit_persistence():
    store = StateStore(db_path=":memory:")
    logger = CryptographicAuditLogger()
    entry1 = logger.log_event("TEST_EVENT", "actor-1", {"val": 100})
    entry2 = logger.log_event("TEST_EVENT_2", "actor-2", {"val": 200})

    store.save_audit_entry(entry1)
    store.save_audit_entry(entry2)

    loaded = store.load_audit_entries()
    assert len(loaded) == 2
    assert loaded[0].entry_index == 0
    assert loaded[1].previous_hash == loaded[0].current_hash


def test_state_store_hitl_ticket_workflow():
    store = StateStore(db_path=":memory:")
    t1 = store.create_hitl_ticket(
        ticket_id="TICKET-01",
        event_id="EVT-100",
        action_name="ISOLATE_HOST",
        parameters={"host": "srv-01"},
    )
    assert t1["status"] == "PENDING"

    pending_tickets = store.list_hitl_tickets(status_filter="PENDING")
    assert len(pending_tickets) == 1

    updated = store.update_hitl_ticket_status("TICKET-01", "APPROVED")
    assert updated is True

    approved_tickets = store.list_hitl_tickets(status_filter="APPROVED")
    assert len(approved_tickets) == 1
