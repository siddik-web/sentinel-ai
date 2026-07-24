"""Unit tests for Sentinel AI CLI and REST API server."""

import json

from sentinel_ai.cli import main as cli_main
from sentinel_ai.server import SentinelServerState


def test_server_state_initialization():
    state = SentinelServerState(db_path=":memory:")
    assert state.state_store is not None
    assert state.pep is not None
    assert state.orchestrator is not None


def test_cli_ingest_and_hitl_workflow(tmp_path, capsys):
    db_file = str(tmp_path / "test_sentinel.db")
    alert_file = str(tmp_path / "alert.json")

    payload = {
        "class_uid": 2001,
        "activity_id": 88,
        "severity_id": 5,
        "title": "Critical Malicious Activity",
        "analytic_name": "TEST_ANALYTIC",
        "confidence_score": 0.95,
    }
    with open(alert_file, "w") as f:
        json.dump(payload, f)

    # Ingest via CLI
    cli_main(["--db", db_file, "ingest", alert_file])
    captured = capsys.readouterr()
    assert "Ingested Event ID" in captured.out

    # List HITL via CLI
    cli_main(["--db", db_file, "hitl", "list"])
    captured = capsys.readouterr()
    assert "Found 1 HITL Tickets" in captured.out

    ticket_id = "TICKET-2001:1710000000:GenericWebhook:88"
    for line in captured.out.splitlines():
        if "Ticket ID:" in line:
            ticket_id = line.split("Ticket ID: ")[1].split(" |")[0].strip()

    # Approve HITL via CLI
    cli_main(["--db", db_file, "hitl", "approve", ticket_id])
    captured = capsys.readouterr()
    assert "APPROVED successfully" in captured.out

    # Verify Audit via CLI
    cli_main(["--db", db_file, "audit", "verify"])
    captured = capsys.readouterr()
    assert "Cryptographic Hash Chain Integrity: VALID" in captured.out
