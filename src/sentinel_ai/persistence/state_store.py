"""Durable SQLite StateStore for workflow state, HITL escalations, and audit entries.

Implements AG4 (State is durable and explicit).
"""

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from sentinel_ai.audit.logger import AuditLogEntry

HITL_PENDING = "PENDING"
HITL_APPROVED = "APPROVED"
HITL_REJECTED = "REJECTED"


class StateStore:
    """SQLite-backed durable state store for Sentinel AI workflows and audit logs."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    def _init_db(self) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    entry_index INTEGER PRIMARY KEY,
                    timestamp INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL
                )
            """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS hitl_tickets (
                    ticket_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """
            )
            # Columns added after the first schema; applied to databases created earlier.
            existing = {r["name"] for r in cursor.execute("PRAGMA table_info(hitl_tickets)")}
            for column in ("decided_by", "execution_result"):
                if column not in existing:
                    cursor.execute(f"ALTER TABLE hitl_tickets ADD COLUMN {column} TEXT")
            # Current state per workflow (derived from workflow_events).
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS workflow_states (
                    event_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """
            )
            # Append-only transition history.
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS workflow_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """
            )
            self._conn.commit()

    # --- Audit Log Persistence ---

    def save_audit_entry(self, entry: AuditLogEntry) -> None:
        """Append an audit entry. Existing entries are never overwritten.

        Raises:
            sqlite3.IntegrityError: If an entry with the same index already exists.
        """
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_log
                (entry_index, timestamp, event_type, actor, payload, previous_hash, current_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    entry.entry_index,
                    entry.timestamp,
                    entry.event_type,
                    entry.actor,
                    json.dumps(entry.payload, sort_keys=True),
                    entry.previous_hash,
                    entry.current_hash,
                ),
            )
            self._conn.commit()

    def load_audit_entries(self) -> list[AuditLogEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY entry_index ASC"
            ).fetchall()
        return [
            AuditLogEntry(
                entry_index=r["entry_index"],
                timestamp=r["timestamp"],
                event_type=r["event_type"],
                actor=r["actor"],
                payload=json.loads(r["payload"]),
                previous_hash=r["previous_hash"],
                current_hash=r["current_hash"],
            )
            for r in rows
        ]

    # --- HITL Ticket Persistence ---

    @staticmethod
    def _ticket_from_row(r: sqlite3.Row) -> dict[str, Any]:
        result = r["execution_result"]
        return {
            "ticket_id": r["ticket_id"],
            "event_id": r["event_id"],
            "action_name": r["action_name"],
            "parameters": json.loads(r["parameters"]),
            "status": r["status"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "decided_by": r["decided_by"],
            "execution_result": json.loads(result) if result else None,
        }

    def create_hitl_ticket(
        self, ticket_id: str, event_id: str, action_name: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a pending ticket. If the ticket ID already exists it is returned unchanged."""
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO hitl_tickets
                (ticket_id, event_id, action_name, parameters, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (ticket_id, event_id, action_name, json.dumps(parameters), HITL_PENDING, now, now),
            )
            self._conn.commit()
            return self.get_hitl_ticket(ticket_id)

    def get_hitl_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM hitl_tickets WHERE ticket_id = ?", (ticket_id,)
            ).fetchone()
        return self._ticket_from_row(row) if row else None

    def update_hitl_ticket_status(self, ticket_id: str, new_status: str) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE hitl_tickets SET status = ?, updated_at = ? WHERE ticket_id = ?",
                (new_status, int(time.time()), ticket_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def decide_hitl_ticket(self, ticket_id: str, new_status: str, decided_by: str) -> bool:
        """Record an operator decision. Only a PENDING ticket can be decided.

        Returns:
            bool: True if the decision was recorded, False if the ticket was not pending.
        """
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE hitl_tickets SET status = ?, decided_by = ?, updated_at = ?
                WHERE ticket_id = ? AND status = ?
            """,
                (new_status, decided_by, int(time.time()), ticket_id, HITL_PENDING),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def set_hitl_execution_result(self, ticket_id: str, result: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE hitl_tickets SET execution_result = ?, updated_at = ? WHERE ticket_id = ?",
                (json.dumps(result), int(time.time()), ticket_id),
            )
            self._conn.commit()

    def list_hitl_tickets(self, status_filter: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if status_filter:
                rows = self._conn.execute(
                    "SELECT * FROM hitl_tickets WHERE status = ? "
                    "ORDER BY created_at DESC, rowid DESC",
                    (status_filter,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM hitl_tickets ORDER BY created_at DESC, rowid DESC"
                ).fetchall()
        return [self._ticket_from_row(r) for r in rows]

    # --- Workflow State Persistence ---

    def record_workflow_transition(
        self, event_id: str, status: str, detail: dict[str, Any] | None = None
    ) -> None:
        """Append a workflow state transition and update the workflow's current state."""
        now = int(time.time())
        detail_json = json.dumps(detail or {}, default=str)
        with self._lock:
            self._conn.execute(
                "INSERT INTO workflow_events (event_id, status, detail, created_at) "
                "VALUES (?, ?, ?, ?)",
                (event_id, status, detail_json, now),
            )
            self._conn.execute(
                """
                INSERT INTO workflow_states (event_id, status, summary, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    status = excluded.status,
                    summary = excluded.summary,
                    updated_at = excluded.updated_at
            """,
                (event_id, status, detail_json, now),
            )
            self._conn.commit()

    def get_workflow(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM workflow_states WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "event_id": row["event_id"],
            "status": row["status"],
            "detail": json.loads(row["summary"]),
            "updated_at": row["updated_at"],
        }

    def list_workflows(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM workflow_states ORDER BY updated_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "event_id": r["event_id"],
                "status": r["status"],
                "detail": json.loads(r["summary"]),
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def get_workflow_history(self, event_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM workflow_events WHERE event_id = ? ORDER BY seq ASC", (event_id,)
            ).fetchall()
        return [
            {"status": r["status"], "detail": json.loads(r["detail"]), "created_at": r["created_at"]}
            for r in rows
        ]
