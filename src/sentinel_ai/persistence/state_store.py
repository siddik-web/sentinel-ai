"""Durable SQLite StateStore for workflow state, HITL escalations, and audit entries.

Implements AG4 (State is durable and explicit).
"""

import json
import sqlite3
import time
from typing import Any

from sentinel_ai.audit.logger import AuditLogEntry


class StateStore:
    """SQLite-backed durable state store for Sentinel AI workflows and audit logs."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()

    def _init_db(self):
        cursor = self._conn.cursor()
        # Audit log table
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
        # HITL Escalation Tickets table
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
        # Workflow State table
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
        self._conn.commit()

    # --- Audit Log Persistence ---

    def save_audit_entry(self, entry: AuditLogEntry) -> None:
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO audit_log
            (entry_index, timestamp, event_type, actor, payload, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                entry.entry_index,
                entry.timestamp,
                entry.event_type,
                entry.actor,
                json.dumps(entry.payload),
                entry.previous_hash,
                entry.current_hash,
            ),
        )
        self._conn.commit()

    def load_audit_entries(self) -> list[AuditLogEntry]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM audit_log ORDER BY entry_index ASC")
        rows = cursor.fetchall()
        entries = []
        for r in rows:
            entries.append(
                AuditLogEntry(
                    entry_index=r["entry_index"],
                    timestamp=r["timestamp"],
                    event_type=r["event_type"],
                    actor=r["actor"],
                    payload=json.loads(r["payload"]),
                    previous_hash=r["previous_hash"],
                    current_hash=r["current_hash"],
                )
            )
        return entries

    # --- HITL Ticket Persistence ---

    def create_hitl_ticket(
        self, ticket_id: str, event_id: str, action_name: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        now = int(time.time())
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO hitl_tickets
            (ticket_id, event_id, action_name, parameters, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (ticket_id, event_id, action_name, json.dumps(parameters), "PENDING", now, now),
        )
        self._conn.commit()

        return {
            "ticket_id": ticket_id,
            "event_id": event_id,
            "action_name": action_name,
            "parameters": parameters,
            "status": "PENDING",
            "created_at": now,
        }

    def update_hitl_ticket_status(self, ticket_id: str, new_status: str) -> bool:
        now = int(time.time())
        cursor = self._conn.cursor()
        cursor.execute(
            """
            UPDATE hitl_tickets SET status = ?, updated_at = ? WHERE ticket_id = ?
        """,
            (new_status, now, ticket_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_hitl_tickets(self, status_filter: str | None = None) -> list[dict[str, Any]]:
        cursor = self._conn.cursor()
        if status_filter:
            cursor.execute(
                "SELECT * FROM hitl_tickets WHERE status = ? ORDER BY created_at DESC",
                (status_filter,),
            )
        else:
            cursor.execute("SELECT * FROM hitl_tickets ORDER BY created_at DESC")

        rows = cursor.fetchall()
        results = []
        for r in rows:
            results.append(
                {
                    "ticket_id": r["ticket_id"],
                    "event_id": r["event_id"],
                    "action_name": r["action_name"],
                    "parameters": json.loads(r["parameters"]),
                    "status": r["status"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            )
        return results
