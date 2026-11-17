"""Command Line Interface (CLI) for Sentinel AI platform administration."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from sentinel_ai.exceptions import SentinelError


def _build_parser() -> argparse.ArgumentParser:
    default_db = os.environ.get("SENTINEL_DB_PATH", "sentinel_ai.db")

    # --db is accepted both before and after the subcommand. The subcommand copy uses
    # SUPPRESS so it does not overwrite a value given before the subcommand.
    top_parent = argparse.ArgumentParser(add_help=False)
    top_parent.add_argument("--db", default=default_db, help="SQLite database path")
    sub_parent = argparse.ArgumentParser(add_help=False)
    sub_parent.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")

    parser = argparse.ArgumentParser(
        prog="sentinel-ai", description="Sentinel AI Platform CLI", parents=[top_parent]
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    serve_parser = subparsers.add_parser(
        "serve", parents=[sub_parent], help="Run the HTTP API server and web console"
    )
    serve_parser.add_argument("--host", default=None, help="Bind address (default 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=None, help="Bind port (default 8000)")

    ingest_parser = subparsers.add_parser(
        "ingest", parents=[sub_parent], help="Ingest a raw JSON alert file"
    )
    ingest_parser.add_argument("file", help="Path to JSON file containing raw alert payload")

    replay_parser = subparsers.add_parser(
        "replay",
        help="Run a recorded alert through the agents without persisting anything",
    )
    replay_parser.add_argument("file", help="Raw alert payload, or a corpus fixture file")

    hitl_parser = subparsers.add_parser(
        "hitl", parents=[sub_parent], help="Manage HITL approval tickets"
    )
    hitl_subparsers = hitl_parser.add_subparsers(dest="hitl_action")
    list_parser = hitl_subparsers.add_parser(
        "list", parents=[sub_parent], help="List HITL tickets"
    )
    list_parser.add_argument("--status", default=None, help="Filter by status, e.g. PENDING")
    for name, help_text in (
        ("approve", "Approve a pending HITL ticket and execute its action"),
        ("reject", "Reject a pending HITL ticket"),
    ):
        decision_parser = hitl_subparsers.add_parser(name, parents=[sub_parent], help=help_text)
        decision_parser.add_argument("ticket_id", help="Ticket ID")
        decision_parser.add_argument(
            "--approver", default="cli-operator", help="Operator identity for the audit log"
        )

    audit_parser = subparsers.add_parser(
        "audit", parents=[sub_parent], help="Inspect the cryptographic audit log"
    )
    audit_subparsers = audit_parser.add_subparsers(dest="audit_action")
    audit_subparsers.add_parser(
        "verify", parents=[sub_parent], help="Verify audit log hash chain integrity"
    )
    export_parser = audit_subparsers.add_parser(
        "export", parents=[sub_parent], help="Export the audit log as JSON Lines"
    )
    export_parser.add_argument("--output", "-o", default=None, help="Output file (default stdout)")

    workflows_parser = subparsers.add_parser(
        "workflows", parents=[sub_parent], help="List recent alert workflows and their state"
    )
    workflows_parser.add_argument("--limit", type=int, default=20)

    policy_parser = subparsers.add_parser("policy", help="Work with policy files")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_action")
    validate_parser = policy_subparsers.add_parser("validate", help="Validate a JSON policy file")
    validate_parser.add_argument("file", help="Path to policy file")

    evaluate_parser = subparsers.add_parser(
        "evaluate", help="Run the behavioral evaluation suite over an alert corpus"
    )
    evaluate_parser.add_argument("corpus_dir", help="Directory of corpus fixture JSON files")

    return parser


def _load_json_object(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as e:
        raise SentinelError(f"Cannot read '{path}': {e!s}") from e
    except json.JSONDecodeError as e:
        raise SentinelError(f"'{path}' is not valid JSON: {e!s}") from e
    if not isinstance(data, dict):
        raise SentinelError(f"'{path}' must contain a JSON object.")
    return data


def _cmd_policy(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sentinel_ai.security.policy_rules import PolicyRuleEngine

    if args.policy_action != "validate":
        parser.print_help()
        return 2
    PolicyRuleEngine.from_file(args.file)
    print(f"[✔] Policy file '{args.file}' is valid.")
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    from sentinel_ai.evaluation.evaluator import BehavioralEvaluator

    report = BehavioralEvaluator().evaluate_corpus(args.corpus_dir)
    for result in report.scenario_results:
        print(f"  [{'PASS' if result.passed else 'FAIL'}] {result.scenario_name} — {result.details}")
    print(
        f"\n[+] {report.passed_scenarios}/{report.total_scenarios} scenarios passed "
        f"({report.accuracy_percentage:.1f}%); severity accuracy "
        f"{report.severity_accuracy_percentage:.1f}%"
    )
    print(f"[+] Meets 85% threshold: {'YES' if report.charter_compliant else 'NO'}")
    return 0 if report.charter_compliant else 1


def _cmd_replay(args: argparse.Namespace) -> int:
    from sentinel_ai.server import build_state_from_env

    data = _load_json_object(args.file)
    raw_payload = data.get("raw_payload", data)
    # Replay uses an in-memory store and never notifies operators.
    env = {k: v for k, v in os.environ.items() if k != "SENTINEL_HITL_WEBHOOK_URL"}
    state = build_state_from_env(env=env, db_path=":memory:")
    event, _ = state.ingest_payload(raw_payload)
    event_id = event.get_event_id()
    output = {
        "event_id": event_id,
        "workflow": state.state_store.get_workflow(event_id),
        "audit_trail": [
            {"event_type": e.event_type, "actor": e.actor, "payload": e.payload}
            for e in state.audit_logger.entries
        ],
    }
    print(json.dumps(output, indent=2))
    return 0


def main(args_list: list[str] | None = None) -> int:
    """Run the CLI. Returns a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(args_list if args_list is not None else sys.argv[1:])

    try:
        return _dispatch(args, parser)
    except SentinelError as e:
        print(f"[✘] {e!s}", file=sys.stderr)
        return 1


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.command is None:
        parser.print_help()
        return 2
    if args.command == "policy":
        return _cmd_policy(args, parser)
    if args.command == "evaluate":
        return _cmd_evaluate(args)
    if args.command == "replay":
        return _cmd_replay(args)

    # Deferred import keeps `--help` and the commands above fast and side-effect free.
    from sentinel_ai.server import build_state_from_env, run_server

    if args.command == "serve":
        return run_server(host=args.host, port=args.port, db_path=args.db)

    server_state = build_state_from_env(db_path=args.db)
    store = server_state.state_store
    try:
        if args.command == "ingest":
            event, processed = server_state.ingest_payload(_load_json_object(args.file))
            event_id = event.get_event_id()
            print(f"[+] Ingested Event ID: {event_id}")
            print(f"[+] Process Status: {'PROCESSED' if processed else 'DEDUPLICATED'}")
            workflow = store.get_workflow(event_id)
            if workflow:
                print(f"[+] Workflow State: {workflow['status']}")
            return 0

        if args.command == "hitl":
            if args.hitl_action == "list":
                tickets = store.list_hitl_tickets(status_filter=args.status)
                print(f"\nFound {len(tickets)} HITL Tickets:")
                for t in tickets:
                    print(
                        f"  - [{t['status']}] Ticket ID: {t['ticket_id']} | "
                        f"Action: {t['action_name']} | Event: {t['event_id']}"
                    )
                print()
                return 0
            if args.hitl_action in ("approve", "reject"):
                approve = args.hitl_action == "approve"
                ticket = server_state.decide_ticket(
                    args.ticket_id, approve=approve, decided_by=args.approver
                )
                print(f"[✔] Ticket '{args.ticket_id}' {ticket['status']} successfully.")
                result = ticket["execution_result"]
                if result:
                    marker = "✔" if result["success"] else "✘"
                    print(f"[{marker}] {ticket['action_name']}: {result['message']}")
                    return 0 if result["success"] else 1
                return 0

        if args.command == "audit":
            if args.audit_action == "verify":
                is_valid, total, error = server_state.verify_persisted_audit()
                print(f"[+] Total Persistent Audit Entries: {total}")
                marker = "✔" if is_valid else "✘"
                print(
                    f"[{marker}] Cryptographic Hash Chain Integrity: "
                    f"{'VALID' if is_valid else 'CORRUPTED'}"
                )
                if error:
                    print(f"    {error}")
                return 0 if is_valid else 1
            if args.audit_action == "export":
                jsonl = server_state.audit_logger.export_jsonl(store.load_audit_entries())
                if args.output:
                    Path(args.output).write_text(jsonl, encoding="utf-8")
                    print(f"[+] Wrote {jsonl.count(chr(10))} audit entries to {args.output}")
                else:
                    sys.stdout.write(jsonl)
                return 0

        if args.command == "workflows":
            workflows = store.list_workflows(limit=args.limit)
            print(f"\nFound {len(workflows)} workflows:")
            for w in workflows:
                print(f"  - [{w['status']}] {w['event_id']}")
            print()
            return 0

        parser.print_help()
        return 2
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
