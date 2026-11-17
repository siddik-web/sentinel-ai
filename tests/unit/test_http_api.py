"""Tests for the HTTP API: auth, validation, HITL decisions, audit endpoints."""

import http.client
import json
import threading
import urllib.error
import urllib.request

import pytest

from sentinel_ai.server import create_sentinel_server

FINDING = {
    "class_uid": 2001,
    "activity_id": 7,
    "severity_id": 5,
    "time": 1710000000,
    "title": "<img src=x onerror=alert(1)>",
    "analytic_name": "EDR-1",
    "confidence_score": 0.99,
    "device_hostname": "wks-01",
}


class Client:
    def __init__(self, server, token=None):
        self.base = f"http://127.0.0.1:{server.server_address[1]}"
        self.token = token

    def request(self, method, path, body=None, raw=None, token="default"):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        token = self.token if token == "default" else token
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def declared_length_status(self, path, content_length):
        """POST headers declaring a body size without sending it; return the status."""
        conn = http.client.HTTPConnection(self.base.removeprefix("http://"), timeout=5)
        try:
            conn.putrequest("POST", path)
            conn.putheader("Content-Length", str(content_length))
            conn.endheaders()
            return conn.getresponse().status
        finally:
            conn.close()

    def json(self, method, path, body=None, **kwargs):
        status, data = self.request(method, path, body, **kwargs)
        return status, json.loads(data)


@pytest.fixture
def make_client():
    servers = []

    def _make(**kwargs):
        server = create_sentinel_server(port=0, db_path=":memory:", **kwargs)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return Client(server, token=kwargs.get("api_token"))

    yield _make
    for server in servers:
        server.shutdown()
        server.server_close()


def test_full_alert_to_response_flow_over_http(make_client):
    client = make_client()

    status, body = client.json("POST", "/api/v1/webhook", FINDING)
    assert status == 200 and body["processed"] is True
    status, body = client.json("POST", "/api/v1/webhook", FINDING)
    assert body["processed"] is False  # deduplicated

    _, body = client.json("GET", "/api/v1/hitl?status=PENDING")
    ticket_id = body["tickets"][0]["ticket_id"]

    status, body = client.json(
        "POST", "/api/v1/hitl/approve", {"ticket_id": ticket_id, "approver": "alice"}
    )
    assert status == 200
    assert body["approval_status"] == "APPROVED"
    assert body["execution_result"]["success"] is True

    status, body = client.json("POST", "/api/v1/hitl/approve", {"ticket_id": ticket_id})
    assert status == 409
    status, _ = client.json("POST", "/api/v1/hitl/reject", {"ticket_id": "TICKET-missing"})
    assert status == 404
    status, _ = client.json("POST", "/api/v1/hitl/reject", {})
    assert status == 400

    _, body = client.json("GET", "/api/v1/workflows")
    assert body["workflows"][0]["status"] == "completed"

    _, body = client.json("GET", "/api/v1/audit/verify")
    assert body["hash_chain_valid"] is True and body["total_entries"] > 0
    _, audit = client.json("GET", "/api/v1/audit?limit=3")
    assert len(audit["entries"]) == 3
    assert audit["total_entries"] == body["total_entries"]

    _, stats = client.json("GET", "/api/v1/stats")
    assert stats["events_ingested"] == 1
    assert stats["hitl_tickets_approved"] == 1
    assert stats["policy_approvals"] > 0
    assert stats["policy_denials"] == 0

    status, metrics = client.request("GET", "/metrics")
    assert b"sentinel_response_actions_executed_total 1" in metrics


def test_request_validation(make_client):
    client = make_client()
    assert client.json("POST", "/api/v1/webhook", raw=b"{not json")[0] == 400
    assert client.json("POST", "/api/v1/webhook", ["a", "list"])[0] == 400
    assert client.json("POST", "/api/v1/webhook", {"activity_id": 1})[0] == 400
    assert client.json("POST", "/api/v1/webhook", {"class_uid": 9999, "activity_id": 1})[0] == 400
    assert client.declared_length_status("/api/v1/webhook", 1024 * 1024 + 1) == 413
    assert client.json("POST", "/api/v1/nope", {})[0] == 404
    assert client.json("GET", "/api/v1/nope")[0] == 404
    assert client.json("GET", "/healthz") == (200, {"status": "ok"})


def test_api_token_is_enforced_when_configured(make_client):
    client = make_client(api_token="s3cret-token")

    assert client.json("GET", "/api/v1/hitl", token=None)[0] == 401
    assert client.json("GET", "/api/v1/hitl", token="wrong")[0] == 401
    assert client.json("POST", "/api/v1/webhook", FINDING, token=None)[0] == 401
    assert client.json("POST", "/api/v1/hitl/approve", {"ticket_id": "x"}, token=None)[0] == 401

    assert client.json("GET", "/api/v1/hitl")[0] == 200
    assert client.json("POST", "/api/v1/webhook", FINDING)[0] == 200

    # The console shell and liveness probe carry no data and stay reachable.
    assert client.request("GET", "/", token=None)[0] == 200
    assert client.request("GET", "/healthz", token=None)[0] == 200


def test_servers_do_not_share_state(make_client):
    first, second = make_client(), make_client()
    first.json("POST", "/api/v1/webhook", FINDING)
    assert second.json("GET", "/api/v1/stats")[1]["events_ingested"] == 0


def test_dashboard_is_self_contained_and_escapes_server_data(make_client):
    _, html = make_client().request("GET", "/")
    page = html.decode("utf-8")
    assert "Sentinel AI — Security Response Console" in page
    assert "https://" not in page and "http://" not in page  # no third-party requests
    assert "${esc(t.ticket_id)}" in page
    assert "onclick=" not in page
