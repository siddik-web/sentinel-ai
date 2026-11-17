"""Cryptographic hash-chained audit logger.

Implements AG1 (Audit completeness is unconditional) and tamper detection.
"""

import hashlib
import json
import threading
import time
from collections.abc import Callable, Iterable
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
        raw = (
            f"{self.entry_index}:{self.timestamp}:{self.event_type}:{self.actor}"
            f":{payload_str}:{self.previous_hash}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CryptographicAuditLogger:
    """Append-only cryptographic audit logger with hash-chain integrity verification.

    Args:
        sink: Optional durable writer invoked for every entry *before* the entry joins the
            in-memory chain (write-before-act). If the sink raises, the event is not logged
            and the caller's action must not proceed.
        entries: Previously persisted entries to resume the chain from after a restart.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(
        self,
        sink: Callable[[AuditLogEntry], None] | None = None,
        entries: Iterable[AuditLogEntry] | None = None,
    ):
        self._chain: list[AuditLogEntry] = list(entries) if entries else []
        self._sink = sink
        self._lock = threading.RLock()

    @property
    def entries(self) -> list[AuditLogEntry]:
        """Return a copy of current audit log entries."""
        with self._lock:
            return list(self._chain)

    def log_event(self, event_type: str, actor: str, payload: dict[str, Any]) -> AuditLogEntry:
        """Append a new audited event to the hash chain.

        Raises:
            AuditIntegrityError: If the entry cannot be durably persisted (fail closed).
        """
        # Snapshot the payload so later mutation by the caller cannot invalidate the hash,
        # and so the stored form is exactly what was hashed.
        frozen_payload = json.loads(json.dumps(payload, sort_keys=True, default=str))

        with self._lock:
            previous_hash = self._chain[-1].current_hash if self._chain else self.GENESIS_HASH
            entry = AuditLogEntry(
                entry_index=len(self._chain),
                timestamp=int(time.time()),
                event_type=event_type,
                actor=actor,
                payload=frozen_payload,
                previous_hash=previous_hash,
                current_hash="",
            )
            entry.current_hash = entry.calculate_hash()

            if self._sink is not None:
                try:
                    self._sink(entry)
                except Exception as e:
                    raise AuditIntegrityError(
                        f"Audit entry {entry.entry_index} could not be persisted: {e!s}"
                    ) from e

            self._chain.append(entry)
            return entry

    @classmethod
    def verify_entries(cls, entries: list[AuditLogEntry]) -> bool:
        """Validate hash linkages across an arbitrary ordered list of audit entries.

        Raises:
            AuditIntegrityError: If any link in the hash chain is corrupted or tampered with.
        """
        for i, entry in enumerate(entries):
            if entry.entry_index != i:
                raise AuditIntegrityError(
                    f"Audit sequence gap at position {i}: found entry_index {entry.entry_index}."
                )

            expected_prev = entries[i - 1].current_hash if i > 0 else cls.GENESIS_HASH
            if entry.previous_hash != expected_prev:
                raise AuditIntegrityError(
                    f"Hash chain broken at index {i}: previous_hash mismatch."
                )

            if entry.current_hash != entry.calculate_hash():
                raise AuditIntegrityError(
                    f"Audit entry tampered at index {i}: current_hash validation failed."
                )

        return True

    def verify_chain_integrity(self) -> bool:
        """Validate all hash linkages across the entire in-memory audit chain.

        Raises:
            AuditIntegrityError: If any link in the hash chain is corrupted or tampered with.
        """
        return self.verify_entries(self.entries)

    @staticmethod
    def export_jsonl(entries: Iterable[AuditLogEntry]) -> str:
        """Serialize entries as JSON Lines (one entry per line) for offline verification."""
        return "".join(json.dumps(e.model_dump(), sort_keys=True) + "\n" for e in entries)
