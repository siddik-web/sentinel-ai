"""Ingestion layer engine for Sentinel AI.

Preserves original OCSF events, handles deduplication, and routes alerts to agent queues.
"""

from collections.abc import Callable

from sentinel_ai.core.ocsf.models import OCSFBaseEvent


class IngestionEngine:
    """Ingestion engine managing event routing and deduplication."""

    def __init__(self, deduplication_window_seconds: int = 300):
        self.deduplication_window_seconds = deduplication_window_seconds
        self._seen_event_fingerprints: set[str] = set()
        self._subscribers: list[Callable[[OCSFBaseEvent], None]] = []

    def subscribe(self, handler: Callable[[OCSFBaseEvent], None]) -> None:
        """Register a subscriber handler for routed alerts."""
        self._subscribers.append(handler)

    def process_event(self, event: OCSFBaseEvent) -> bool:
        """Process an incoming OCSF event.

        Returns:
            bool: True if the event was processed and routed, False if it was deduplicated.
        """
        fingerprint = event.get_event_id()

        # Check deduplication
        if fingerprint in self._seen_event_fingerprints:
            return False

        self._seen_event_fingerprints.add(fingerprint)

        # Dispatch to all registered subscribers
        for handler in self._subscribers:
            handler(event)

        return True

    def clear_deduplication_cache(self) -> None:
        """Reset the deduplication cache."""
        self._seen_event_fingerprints.clear()
