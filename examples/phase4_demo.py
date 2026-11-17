"""Phase 4 demonstration showcasing Telemetry, Web Security Dashboard, and Server Ingestion."""

import json
import threading
import time
import urllib.request

from sentinel_ai.server import create_sentinel_server


def print_banner(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def main():
    print_banner("SENTINEL AI PHASE 4 DASHBOARD & TELEMETRY DEMONSTRATION")

    # 1. Start Sentinel Server on localhost:8088 in background thread
    print("\n[+] Starting Sentinel Server on http://127.0.0.1:8088...")
    server = create_sentinel_server(host="127.0.0.1", port=8088, db_path=":memory:")
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    print("    ✔ Web Console running at http://127.0.0.1:8088/")
    print("    ✔ Prometheus Metrics endpoint running at http://127.0.0.1:8088/metrics")

    # 2. Simulate Webhook Ingestion over HTTP
    print_banner("1. HTTP WEBHOOK INGESTION")
    payload = {
        "class_uid": 2001,
        "activity_id": 101,
        "severity_id": 5,
        "title": "Critical Ransomware Ingress Event",
        "analytic_name": "EDR-BEHAVIORAL",
        "confidence_score": 0.99,
        "product_name": "CrowdStrike",
    }
    req = urllib.request.Request(
        "http://127.0.0.1:8088/api/v1/webhook",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode("utf-8"))
        print(f"    ✔ Ingestion Status: {res['status']}")
        print(f"    ✔ Processed Event ID: {res['event_id']}")
    except urllib.error.HTTPError as e:
        print(f"    ✘ HTTP Error {e.code}: {e.fp.read().decode('utf-8')}")
        raise

    # 3. Inspect Stats & Prometheus Telemetry
    print_banner("2. PROMETHEUS TELEMETRY METRICS INSPECTION")
    metrics_req = urllib.request.Request("http://127.0.0.1:8088/metrics")
    with urllib.request.urlopen(metrics_req) as resp:
        metrics_body = resp.read().decode("utf-8")

    for line in metrics_body.splitlines():
        if line and not line.startswith("#"):
            print(f"    ▶ {line}")

    # 4. Fetch Active HITL Tickets
    print_banner("3. HITL TICKET MANAGEMENT")
    hitl_req = urllib.request.Request("http://127.0.0.1:8088/api/v1/hitl")
    with urllib.request.urlopen(hitl_req) as resp:
        hitl_res = json.loads(resp.read().decode("utf-8"))

    tickets = hitl_res.get("tickets", [])
    print(f"    ✔ Total Pending HITL Tickets: {len(tickets)}")
    if tickets:
        ticket_id = tickets[0]["ticket_id"]
        print(f"    ▶ Approving Ticket ID '{ticket_id}' via POST /api/v1/hitl/approve...")
        approve_req = urllib.request.Request(
            "http://127.0.0.1:8088/api/v1/hitl/approve",
            data=json.dumps({"ticket_id": ticket_id}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(approve_req) as resp:
            approve_res = json.loads(resp.read().decode("utf-8"))
        print(f"    ✔ Approval Status: {approve_res['approval_status']}")

    server.shutdown()
    print("\n" + "=" * 70)
    print("  PHASE 4 DEMONSTRATION COMPLETED — ALL SYSTEMS GO")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
