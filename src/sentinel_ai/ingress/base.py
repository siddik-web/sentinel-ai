"""Base DataSourceAdapter interface for Sentinel AI ingress layer."""

from abc import ABC, abstractmethod
from typing import Any

from sentinel_ai.core.ocsf.models import OCSFBaseEvent


class DataSourceAdapter(ABC):
    """Abstract base class for all data source adapters transforming external logs to OCSF."""

    def __init__(self, adapter_id: str, vendor_name: str):
        self.adapter_id = adapter_id
        self.vendor_name = vendor_name

    @abstractmethod
    def parse_and_normalize(self, raw_payload: dict[str, Any]) -> OCSFBaseEvent:
        """Parse raw external payload and return a validated OCSF event.

        Raises:
            OCSFValidationError: If normalization or validation fails.
        """
