"""Tests for CLI commands beyond the basic ingest/approve flow."""

import json
import sqlite3
from types import SimpleNamespace

from sentinel_ai.cli import main as cli_main

FINDING = {
    "class_uid": 2001,
    "activity_id": 88,
    "severity_id": 5,
    "time": 1710000000,
    "title": "Critical Malicious Activity",
    "analytic_name": "TEST_ANALYTIC",
    "confidence_score": 0.95,
    "device_hostname": "wks-09",
}


def _alert_file(tmp_path, payload=FINDING):
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(payload))
    return str(path)


def _ticket_id(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT ticket_id FROM hitl_tickets").fetchone()[0]
    finally:
        conn.close()


def test_db_flag_is_honored_before_and_after_subcommand(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = str(tmp_path / "custom.db")
    alert = _alert_file(tmp_path)

    assert cli_main(["--db", db, "ingest", alert]) == 0
    assert "PROCESSED" in capsys.readouterr().out
    assert cli_main(["ingest", alert, "--db", db]) == 0
    assert "DEDUPLICATED" in capsys.readouterr().out
    assert not (tmp_path / "sentinel_ai.db").exists()


def test_approve_executes_and_second_decision_fails(tmp_path, capsys):
    db = str(tmp_path / "s.db")
    cli_main(["--db", db, "ingest", _alert_file(tmp_path)])
    ticket_id = _ticket_id(db)
    capsys.readouterr()

    assert cli_main(["--db", db, "hitl", "approve", ticket_id, "--approver", "bob"]) == 0
    out = capsys.readouterr().out
    assert "APPROVED successfully" in out
    assert "ISOLATE_HOST" in out and "wks-09" in out

    assert cli_main(["--db", db, "hitl", "reject", ticket_id]) == 1
    assert "already APPROVED" in capsys.readouterr().err

    assert cli_main(["--db", db, "hitl", "list", "--status", "PENDING"]) == 0
    assert "Found 0 HITL Tickets" in capsys.readouterr().out
    assert cli_main(["--db", db, "workflows"]) == 0
    assert "[completed]" in capsys.readouterr().out


def test_audit_verify_detects_tampering_and_export_writes_jsonl(tmp_path, capsys):
    db = str(tmp_path / "s.db")
    cli_main(["--db", db, "ingest", _alert_file(tmp_path)])

    out_file = tmp_path / "audit.jsonl"
    assert cli_main(["--db", db, "audit", "export", "-o", str(out_file)]) == 0
    lines = out_file.read_text().splitlines()
    assert len(lines) > 0
    first = json.loads(lines[0])
    assert first["entry_index"] == 0 and set(first) >= {"current_hash", "previous_hash", "payload"}

    assert cli_main(["--db", db, "audit", "verify"]) == 0
    conn = sqlite3.connect(db)
    conn.execute("UPDATE audit_log SET payload = '{}' WHERE entry_index = 0")
    conn.commit()
    conn.close()
    capsys.readouterr()
    assert cli_main(["--db", db, "audit", "verify"]) == 1
    assert "CORRUPTED" in capsys.readouterr().out


def test_policy_validate(tmp_path, capsys):
    good = tmp_path / "good.json"
    good.write_text('{"denied_actions": ["BLOCK_IP"]}')
    assert cli_main(["policy", "validate", str(good)]) == 0

    bad = tmp_path / "bad.json"
    bad.write_text('{"denied_actions": 5}')
    assert cli_main(["policy", "validate", str(bad)]) == 1
    assert "denied_actions" in capsys.readouterr().err


def test_replay_is_deterministic_and_does_not_persist(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # The adapter stamps a processing time on each event; pin it so runs are comparable.
    monkeypatch.setattr(
        "sentinel_ai.ingress.webhook.time", SimpleNamespace(time=lambda: 1710000500)
    )
    alert = _alert_file(tmp_path)

    assert cli_main(["replay", alert]) == 0
    first = json.loads(capsys.readouterr().out)
    assert cli_main(["replay", alert]) == 0
    second = json.loads(capsys.readouterr().out)

    for run in (first, second):
        run["workflow"].pop("updated_at")
    assert first == second
    assert first["workflow"]["status"] == "paused_hitl"
    assert first["audit_trail"][0]["event_type"] == "EVENT_RECEIVED"
    assert list(tmp_path.glob("*.db")) == []


def test_replay_applies_policy_file(tmp_path, capsys, monkeypatch):
    policy = tmp_path / "policy.json"
    policy.write_text('{"denied_actions": ["ENRICH_IP"]}')
    monkeypatch.setenv("SENTINEL_POLICY_FILE", str(policy))

    assert cli_main(["replay", _alert_file(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    denial = next(e for e in result["audit_trail"] if e["event_type"] == "POLICY_DENIAL")
    assert denial["payload"]["rule"] == "denied_actions"
    assert result["workflow"]["status"] == "paused_hitl"


def test_evaluate_command(capsys):
    assert cli_main(["evaluate", "tests/fixtures/alert_corpus"]) == 0
    assert "Meets 85% threshold: YES" in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert cli_main([]) == 2
    assert "usage:" in capsys.readouterr().out
