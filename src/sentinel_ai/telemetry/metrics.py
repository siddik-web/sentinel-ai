"""Telemetry and Prometheus metrics collection for Sentinel AI engine."""

import threading
import time

# (stat key, Prometheus metric name, help text)
_COUNTERS = (
    ("events_ingested", "sentinel_events_ingested_total", "Total count of OCSF events ingested"),
    ("alerts_triaged", "sentinel_alerts_triaged_total", "Total count of alerts evaluated by agents"),
    (
        "hitl_tickets_created",
        "sentinel_hitl_tickets_created_total",
        "Count of Human-in-the-loop tickets created",
    ),
    (
        "hitl_tickets_approved",
        "sentinel_hitl_tickets_approved_total",
        "Count of Human-in-the-loop tickets approved",
    ),
    (
        "hitl_tickets_rejected",
        "sentinel_hitl_tickets_rejected_total",
        "Count of Human-in-the-loop tickets rejected",
    ),
    (
        "hitl_delivery_failures",
        "sentinel_hitl_delivery_failures_total",
        "Count of HITL notifications that could not be delivered",
    ),
    (
        "policy_approvals",
        "sentinel_policy_approvals_total",
        "Total count of security policy approvals",
    ),
    ("policy_denials", "sentinel_policy_denials_total", "Total count of security policy denials"),
    (
        "response_actions_executed",
        "sentinel_response_actions_executed_total",
        "Count of approved response actions executed successfully",
    ),
    (
        "response_actions_failed",
        "sentinel_response_actions_failed_total",
        "Count of approved response actions that failed",
    ),
    ("workflow_failures", "sentinel_workflow_failures_total", "Count of workflows that failed"),
)


class MetricsCollector:
    """Telemetry collector gathering runtime performance and security metrics."""

    def __init__(self):
        self._lock = threading.Lock()
        self.events_ingested: int = 0
        self.alerts_triaged: int = 0
        self.hitl_tickets_created: int = 0
        self.hitl_tickets_approved: int = 0
        self.hitl_tickets_rejected: int = 0
        self.hitl_delivery_failures: int = 0
        self.policy_approvals: int = 0
        self.policy_denials: int = 0
        self.response_actions_executed: int = 0
        self.response_actions_failed: int = 0
        self.workflow_failures: int = 0
        self.triage_seconds_total: float = 0.0
        self.start_time: float = time.time()

    def _increment(self, name: str) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + 1)

    def record_ingest(self) -> None:
        self._increment("events_ingested")

    def record_triage(self, duration_seconds: float = 0.0) -> None:
        with self._lock:
            self.alerts_triaged += 1
            self.triage_seconds_total += duration_seconds

    def record_hitl_created(self) -> None:
        self._increment("hitl_tickets_created")

    def record_hitl_approved(self) -> None:
        self._increment("hitl_tickets_approved")

    def record_hitl_rejected(self) -> None:
        self._increment("hitl_tickets_rejected")

    def record_hitl_delivery_failure(self) -> None:
        self._increment("hitl_delivery_failures")

    def record_policy_approval(self) -> None:
        self._increment("policy_approvals")

    def record_policy_denial(self) -> None:
        self._increment("policy_denials")

    def record_policy_decision(self, approved: bool) -> None:
        self._increment("policy_approvals" if approved else "policy_denials")

    def record_response_action(self, success: bool) -> None:
        self._increment("response_actions_executed" if success else "response_actions_failed")

    def record_workflow_failure(self) -> None:
        self._increment("workflow_failures")

    def get_stats(self) -> dict[str, float | int]:
        with self._lock:
            stats: dict[str, float | int] = {key: getattr(self, key) for key, _, _ in _COUNTERS}
            stats["triage_seconds_total"] = round(self.triage_seconds_total, 6)
            stats["uptime_seconds"] = round(time.time() - self.start_time, 2)
        return stats

    def generate_prometheus_metrics(self) -> str:
        stats = self.get_stats()
        lines: list[str] = []
        for key, metric, help_text in _COUNTERS:
            lines += [
                f"# HELP {metric} {help_text}",
                f"# TYPE {metric} counter",
                f"{metric} {stats[key]}",
            ]
        lines += [
            "# HELP sentinel_triage_seconds_total Cumulative time spent in agent triage workflows",
            "# TYPE sentinel_triage_seconds_total counter",
            f"sentinel_triage_seconds_total {stats['triage_seconds_total']}",
            "# HELP sentinel_uptime_seconds Process uptime in seconds",
            "# TYPE sentinel_uptime_seconds gauge",
            f"sentinel_uptime_seconds {stats['uptime_seconds']}",
        ]
        return "\n".join(lines) + "\n"
