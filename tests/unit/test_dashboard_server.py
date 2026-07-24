"""Unit tests for Server Dashboard and Telemetry HTTP endpoints."""

import json
import threading
import time
import urllib.request

from sentinel_ai.server import create_sentinel_server


def test_dashboard_server_http_endpoints():
    server = create_sentinel_server(host="127.0.0.1", port=8999, db_path=":memory:")
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)

    try:
        # Test / (Dashboard HTML)
        with urllib.request.urlopen("http://127.0.0.1:8999/") as resp:
            html_content = resp.read().decode("utf-8")
            assert "Sentinel AI — Security Response Console" in html_content

        # Test /metrics
        with urllib.request.urlopen("http://127.0.0.1:8999/metrics") as resp:
            metrics_content = resp.read().decode("utf-8")
            assert "sentinel_events_ingested_total" in metrics_content

        # Test /api/v1/stats
        with urllib.request.urlopen("http://127.0.0.1:8999/api/v1/stats") as resp:
            stats = json.loads(resp.read().decode("utf-8"))
            assert "events_ingested" in stats
            assert "uptime_seconds" in stats
    finally:
        server.shutdown()
