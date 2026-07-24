"""Unit tests for MetricsCollector and Prometheus formatting."""

from sentinel_ai.telemetry.metrics import MetricsCollector


def test_metrics_collector_counters():
    metrics = MetricsCollector()
    metrics.record_ingest()
    metrics.record_triage()
    metrics.record_hitl_created()
    metrics.record_hitl_approved()
    metrics.record_policy_denial()

    stats = metrics.get_stats()
    assert stats["events_ingested"] == 1
    assert stats["alerts_triaged"] == 1
    assert stats["hitl_tickets_created"] == 1
    assert stats["hitl_tickets_approved"] == 1
    assert stats["policy_denials"] == 1


def test_prometheus_formatting():
    metrics = MetricsCollector()
    metrics.record_ingest()
    prom_str = metrics.generate_prometheus_metrics()

    assert "sentinel_events_ingested_total 1" in prom_str
    assert "sentinel_policy_denials_total 0" in prom_str
    assert "sentinel_uptime_seconds" in prom_str
