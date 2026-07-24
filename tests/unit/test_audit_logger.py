"""Unit tests for Cryptographic Audit Logger and hash chain verification."""

import pytest

from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.exceptions import AuditIntegrityError


def test_audit_logger_hash_chain():
    logger = CryptographicAuditLogger()
    entry1 = logger.log_event("USER_LOGIN", "system", {"user": "bob"})
    entry2 = logger.log_event("ALERT_TRIAGE", "triage-agent", {"alert_id": "123"})

    assert entry1.entry_index == 0
    assert entry2.entry_index == 1
    assert entry2.previous_hash == entry1.current_hash
    assert logger.verify_chain_integrity() is True


def test_audit_logger_tamper_detection():
    logger = CryptographicAuditLogger()
    logger.log_event("EVENT_1", "actor1", {"data": "A"})
    logger.log_event("EVENT_2", "actor2", {"data": "B"})

    # Tamper with internal state
    logger._chain[0].payload["data"] = "TAMPERED_DATA"

    with pytest.raises(AuditIntegrityError):
        logger.verify_chain_integrity()
