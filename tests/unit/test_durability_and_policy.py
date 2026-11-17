"""Tests for audit durability, policy integration, and deduplication."""

import json
import sqlite3

import pytest

from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.core.ocsf.models import AuthenticationEvent, OCSFMetadata
from sentinel_ai.exceptions import AuditIntegrityError, PolicyConfigError, PolicyViolationError
from sentinel_ai.ingestion.engine import IngestionEngine
from sentinel_ai.persistence.state_store import StateStore
from sentinel_ai.security.pep import PolicyEnforcementPoint
from sentinel_ai.security.policy_rules import PolicyRuleEngine
from sentinel_ai.server import SentinelServerState

FINDING = {
    "class_uid": 2001,
    "activity_id": 7,
    "severity_id": 5,
    "time": 1710000000,
    "title": "Ransomware",
    "analytic_name": "EDR-1",
    "confidence_score": 0.99,
    "device_hostname": "wks-01",
}


def _auth_event(user: str) -> AuthenticationEvent:
    return AuthenticationEvent(
        activity_id=1,
        time=1600000000,
        metadata=OCSFMetadata(product_name="Okta", vendor_name="Okta"),
        user_name=user,
        is_success=False,
    )


def test_event_ids_differ_for_distinct_events_with_same_timestamp():
    assert _auth_event("alice").get_event_id() != _auth_event("bob").get_event_id()
    assert _auth_event("alice").get_event_id() == _auth_event("alice").get_event_id()


def test_ingestion_dedup_window_expires():
    engine = IngestionEngine(deduplication_window_seconds=0)
    seen = []
    engine.subscribe(seen.append)
    assert engine.process_event(_auth_event("alice")) is True
    assert engine.process_event(_auth_event("alice")) is True  # window of 0 never dedups

    engine = IngestionEngine(deduplication_window_seconds=300)
    assert engine.process_event(_auth_event("alice")) is True
    assert engine.process_event(_auth_event("alice")) is False


def test_audit_chain_survives_restart_and_keeps_growing(tmp_path):
    db = str(tmp_path / "s.db")
    state = SentinelServerState(db_path=db)
    state.ingest_payload(FINDING)
    first_count = len(state.audit_logger.entries)
    assert first_count > 0
    state.state_store.close()

    restarted = SentinelServerState(db_path=db)
    assert len(restarted.audit_logger.entries) == first_count
    restarted.ingest_payload({**FINDING, "time": 1710000001})
    valid, total, error = restarted.verify_persisted_audit()
    assert valid is True, error
    assert total > first_count
    assert [e.entry_index for e in restarted.state_store.load_audit_entries()] == list(range(total))


def test_duplicate_event_not_reprocessed_after_restart(tmp_path):
    db = str(tmp_path / "s.db")
    state = SentinelServerState(db_path=db)
    assert state.ingest_payload(FINDING)[1] is True
    state.state_store.close()

    restarted = SentinelServerState(db_path=db)
    assert restarted.ingest_payload(FINDING)[1] is False
    assert len(restarted.state_store.list_hitl_tickets()) == 1


def test_tampered_persisted_audit_entry_is_detected(tmp_path):
    db = str(tmp_path / "s.db")
    state = SentinelServerState(db_path=db)
    state.ingest_payload(FINDING)
    state.state_store.close()

    conn = sqlite3.connect(db)
    conn.execute("UPDATE audit_log SET actor = 'attacker' WHERE entry_index = 1")
    conn.commit()
    conn.close()

    valid, _, error = SentinelServerState(db_path=db).verify_persisted_audit()
    assert valid is False
    assert "index 1" in error


def test_audit_store_is_append_only():
    store = StateStore()
    logger = CryptographicAuditLogger(sink=store.save_audit_entry)
    entry = logger.log_event("E", "a", {})
    with pytest.raises(sqlite3.IntegrityError):
        store.save_audit_entry(entry)


def test_audit_logger_fails_closed_when_sink_fails():
    def broken_sink(_entry):
        raise OSError("disk full")

    logger = CryptographicAuditLogger(sink=broken_sink)
    with pytest.raises(AuditIntegrityError):
        logger.log_event("E", "a", {})
    assert logger.entries == []


def test_audit_payload_snapshot_is_immune_to_caller_mutation():
    logger = CryptographicAuditLogger()
    payload = {"k": [1]}
    logger.log_event("E", "a", payload)
    payload["k"].append(2)
    assert logger.verify_chain_integrity() is True


def test_pep_applies_rule_engine_and_records_rule():
    logger = CryptographicAuditLogger()
    decisions = []
    pep = PolicyEnforcementPoint(
        audit_logger=logger,
        rule_engine=PolicyRuleEngine({"denied_actions": ["ENRICH_IP"]}),
        on_decision=decisions.append,
    )
    with pytest.raises(PolicyViolationError) as exc:
        pep.evaluate_action("agent", "ENRICH_IP", {})
    assert exc.value.rule == "denied_actions"
    assert logger.entries[-1].event_type == "POLICY_DENIAL"
    assert logger.entries[-1].payload["rule"] == "denied_actions"
    assert pep.evaluate_action("agent", "QUERY_ALERT", {}) is True
    assert decisions == [False, True]


def test_policy_config_cannot_relax_builtin_hitl_requirement():
    pep = PolicyEnforcementPoint(
        audit_logger=CryptographicAuditLogger(),
        rule_engine=PolicyRuleEngine({"hitl_required_actions": []}),
    )
    with pytest.raises(PolicyViolationError):
        pep.evaluate_action("agent", "ISOLATE_HOST", {"host": "h"})


def test_pep_fails_closed_on_rule_engine_error():
    class BrokenEngine:
        def evaluate_rule(self, *args, **kwargs):
            raise RuntimeError("boom")

    pep = PolicyEnforcementPoint(
        audit_logger=CryptographicAuditLogger(), rule_engine=BrokenEngine()
    )
    with pytest.raises(PolicyViolationError) as exc:
        pep.evaluate_action("agent", "QUERY_ALERT", {})
    assert exc.value.rule == "evaluation_error"


def test_agent_capability_grants():
    engine = PolicyRuleEngine({"agent_allowed_actions": {"triage-agent-01": ["CLASSIFY_SEVERITY"]}})
    assert engine.evaluate_rule("triage-agent-01", "CLASSIFY_SEVERITY", {}) is True
    with pytest.raises(PolicyViolationError, match="capability set"):
        engine.evaluate_rule("triage-agent-01", "ENRICH_IP", {})
    assert engine.evaluate_rule("other-agent", "ENRICH_IP", {}) is True


def test_policy_file_validation(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"denied_actions": ["BLOCK_IP"], "trusted_ips": ["10.0.0.1"]}))
    assert PolicyRuleEngine.from_file(str(good)).denied_actions == {"BLOCK_IP"}

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"denied_actions": "BLOCK_IP", "typo_key": []}))
    with pytest.raises(PolicyConfigError) as exc:
        PolicyRuleEngine.from_file(str(bad))
    assert "typo_key" in str(exc.value)
    assert "denied_actions" in str(exc.value)

    with pytest.raises(PolicyConfigError):
        PolicyRuleEngine.from_file(str(tmp_path / "missing.json"))


def test_policy_denial_halts_workflow_and_escalates():
    state = SentinelServerState(
        db_path=":memory:", rule_engine=PolicyRuleEngine({"denied_actions": ["CLASSIFY_SEVERITY"]})
    )
    event, processed = state.ingest_payload(FINDING)
    assert processed is True

    workflow = state.state_store.get_workflow(event.get_event_id())
    assert workflow["status"] == "paused_hitl"
    tickets = state.state_store.list_hitl_tickets()
    assert tickets[0]["action_name"] == "MANUAL_REVIEW"
    assert tickets[0]["parameters"]["rule"] == "denied_actions"
    event_types = [e.event_type for e in state.audit_logger.entries]
    assert "POLICY_DENIAL" in event_types
    assert "TRIAGE_OUTPUT" not in event_types
    assert state.metrics.policy_denials == 1
