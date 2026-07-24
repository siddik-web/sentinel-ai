"""Telemetry and Prometheus metrics collection for Sentinel AI engine."""

import time


class MetricsCollector:
    """Singleton telemetry collector gathering runtime performance and security metrics."""

    def __init__(self):
        self.events_ingested: int = 0
        self.alerts_triaged: int = 0
        self.hitl_tickets_created: int = 0
        self.hitl_tickets_approved: int = 0
        self.policy_approvals: int = 0
        self.policy_denials: int = 0
        self.start_time: float = time.time()

    def record_ingest(self):
        self.events_ingested += 1

    def record_triage(self):
        self.alerts_triaged += 1

    def record_hitl_created(self):
        self.hitl_tickets_created += 1

    def record_hitl_approved(self):
        self.hitl_tickets_approved += 1

    def record_policy_approval(self):
        self.policy_approvals += 1

    def record_policy_denial(self):
        self.policy_denials += 1

    def get_stats(self) -> dict[str, float | int]:
        uptime_seconds = round(time.time() - self.start_time, 2)
        return {
            "events_ingested": self.events_ingested,
            "alerts_triaged": self.alerts_triaged,
            "hitl_tickets_created": self.hitl_tickets_created,
            "hitl_tickets_approved": self.hitl_tickets_approved,
            "policy_approvals": self.policy_approvals,
            "policy_denials": self.policy_denials,
            "uptime_seconds": uptime_seconds,
        }

    def generate_prometheus_metrics(self) -> str:
        stats = self.get_stats()
        lines = [
            "# HELP sentinel_events_ingested_total Total count of OCSF events ingested",
            "# TYPE sentinel_events_ingested_total counter",
            f"sentinel_events_ingested_total {stats['events_ingested']}",
            "# HELP sentinel_alerts_triaged_total Total count of alerts evaluated by agents",
            "# TYPE sentinel_alerts_triaged_total counter",
            f"sentinel_alerts_triaged_total {stats['alerts_triaged']}",
            "# HELP sentinel_hitl_tickets_created_total Count of Human-in-the-loop tickets created",
            "# TYPE sentinel_hitl_tickets_created_total counter",
            f"sentinel_hitl_tickets_created_total {stats['hitl_tickets_created']}",
            "# HELP sentinel_policy_denials_total Total count of security policy denials",
            "# TYPE sentinel_policy_denials_total counter",
            f"sentinel_policy_denials_total {stats['policy_denials']}",
            "# HELP sentinel_uptime_seconds Process uptime in seconds",
            "# TYPE sentinel_uptime_seconds gauge",
            f"sentinel_uptime_seconds {stats['uptime_seconds']}",
        ]
        return "\n".join(lines) + "\n"
