"""Outbound webhook delivery of HITL escalation tickets."""

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from sentinel_ai.exceptions import SentinelError


class HITLWebhookNotifier:
    """Delivers escalation tickets to an operator notification channel via HTTP POST.

    Delivery is attempted up to ``max_attempts`` times. A 2xx response confirms delivery.
    """

    def __init__(self, url: str, timeout_seconds: float = 5.0, max_attempts: int = 3):
        if urlsplit(url).scheme not in ("http", "https"):
            raise SentinelError("HITL webhook URL must use http or https.")
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max(1, max_attempts)

    def notify(self, ticket: dict[str, Any]) -> tuple[bool, str]:
        """Send the ticket. Returns ``(delivered, detail)``; never raises on delivery failure."""
        body = json.dumps({"type": "hitl_escalation", "ticket": ticket}).encode("utf-8")
        detail = "not attempted"
        for attempt in range(1, self.max_attempts + 1):
            req = urllib.request.Request(
                self.url, data=body, headers={"Content-Type": "application/json"}, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    return True, f"delivered on attempt {attempt} (HTTP {resp.status})"
            except (urllib.error.URLError, OSError) as e:
                detail = f"attempt {attempt} failed: {e!s}"
        return False, detail
