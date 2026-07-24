"""Cryptographic hash-chained audit logger.

Implements AG1 (Audit completeness is unconditional) and tamper detection.
"""

import hashlib
import json
import time
from typing import Any

from pydantic import BaseModel

from sentinel_ai.exceptions import AuditIntegrityError


class AuditLogEntry(BaseModel):
    """Immutable entry in the cryptographic audit chain."""

    entry_index: int
    timestamp: int
    event_type: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str
    current_hash: str

    def calculate_hash(self) -> str:
        """Compute SHA-256 hash of this entry bound to the previous entry's hash."""
        payload_str = json.dumps(self.payload, sort_keys=True)
        raw = f"{self.entry_index}:{self.timestamp}:{self.event_type}:{self.actor}:{payload_str}:{self.previous_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CryptographicAuditLogger:
    """Append-only cryptographic audit logger with hash-chain integrity verification."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self):
        self._chain: list[AuditLogEntry] = []

    @property
    def entries(self) -> list[AuditLogEntry]:
        """Return a copy of current audit log entries."""
        return list(self._chain)

    def log_event(self, event_type: str, actor: str, payload: dict[str, Any]) -> AuditLogEntry:
        """Append a new audited event to the hash chain."""
        previous_hash = self._chain[-1].current_hash if self._chain else self.GENESIS_HASH
        entry_index = len(self._chain)
        timestamp = int(time.time())

        entry = AuditLogEntry(
            entry_index=entry_index,
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            payload=payload,
            previous_hash=previous_hash,
            current_hash="",
        )
        entry.current_hash = entry.calculate_hash()
        self._chain.append(entry)
        return entry

    def verify_chain_integrity(self) -> bool:
        """Validate all hash linkages across the entire audit chain.

        Raises:
            AuditIntegrityError: If any link in the hash chain is corrupted or tampered with.
        """
        for i, entry in enumerate(self._chain):
            expected_prev = self._chain[i - 1].current_hash if i > 0 else self.GENESIS_HASH
            if entry.previous_hash != expected_prev:
                raise AuditIntegrityError(
                    f"Hash chain broken at index {i}: previous_hash mismatch."
                )

            recomputed_hash = entry.calculate_hash()
            if entry.current_hash != recomputed_hash:
                raise AuditIntegrityError(
                    f"Audit entry tampered at index {i}: current_hash validation failed."
                )

        return True
