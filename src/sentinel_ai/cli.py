"""Command Line Interface (CLI) for Sentinel AI platform administration."""

import argparse
import json
import sys


def main(args_list: list | None = None):
    # Common parent parser for shared flags
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--db", default="sentinel_ai.db", help="SQLite database path")

    parser = argparse.ArgumentParser(
        description="Sentinel AI Platform CLI", parents=[parent_parser]
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest", parents=[parent_parser], help="Ingest a raw JSON alert file"
    )
    ingest_parser.add_argument("file", help="Path to JSON file containing raw alert payload")

    # HITL command
    hitl_parser = subparsers.add_parser(
        "hitl", parents=[parent_parser], help="Manage HITL approval tickets"
    )
    hitl_subparsers = hitl_parser.add_subparsers(dest="hitl_action")

    hitl_subparsers.add_parser("list", parents=[parent_parser], help="List active HITL tickets")
    approve_parser = hitl_subparsers.add_parser(
        "approve", parents=[parent_parser], help="Approve a pending HITL ticket"
    )
    approve_parser.add_argument("ticket_id", help="Ticket ID to approve")

    # Audit command
    audit_parser = subparsers.add_parser(
        "audit", parents=[parent_parser], help="Verify cryptographic audit log"
    )
    audit_subparsers = audit_parser.add_subparsers(dest="audit_action")
    audit_subparsers.add_parser(
        "verify", parents=[parent_parser], help="Verify audit log hash chain integrity"
    )

    parsed_args = parser.parse_args(args_list if args_list is not None else sys.argv[1:])

    # Deferred import to avoid circular dependency
    from sentinel_ai.server import SentinelServerState

    db_path = getattr(parsed_args, "db", "sentinel_ai.db")
    server_state = SentinelServerState(db_path=db_path)

    if parsed_args.command == "ingest":
        with open(parsed_args.file, "r") as f:
            raw_payload = json.load(f)

        event = server_state.webhook_adapter.parse_and_normalize(raw_payload)
        processed = server_state.ingestion_engine.process_event(event)
        print(f"[+] Ingested Event ID: {event.get_event_id()}")
        print(f"[+] Process Status: {'PROCESSED' if processed else 'DEDUPLICATED'}")

    elif parsed_args.command == "hitl":
        if parsed_args.hitl_action == "list":
            tickets = server_state.state_store.list_hitl_tickets()
            print(f"\nFound {len(tickets)} HITL Tickets:")
            for t in tickets:
                print(
                    f"  - [{t['status']}] Ticket ID: {t['ticket_id']} | Action: {t['action_name']} | Event: {t['event_id']}"
                )
            print()
        elif parsed_args.hitl_action == "approve":
            updated = server_state.state_store.update_hitl_ticket_status(
                parsed_args.ticket_id, "APPROVED"
            )
            if updated:
                print(f"[✔] Ticket '{parsed_args.ticket_id}' APPROVED successfully.")
            else:
                print(f"[✘] Ticket '{parsed_args.ticket_id}' not found.")

    elif parsed_args.command == "audit":
        if parsed_args.audit_action == "verify":
            entries = server_state.state_store.load_audit_entries()
            print(f"[+] Total Persistent Audit Entries: {len(entries)}")
            is_valid = server_state.audit_logger.verify_chain_integrity()
            print(f"[✔] Cryptographic Hash Chain Integrity: {'VALID' if is_valid else 'CORRUPTED'}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
