"""Webhook JSON DataSourceAdapter implementation."""

import time
from typing import Any

from pydantic import ValidationError

from sentinel_ai.core.ocsf.models import (
    AuthenticationEvent,
    CategoryUID,
    ClassUID,
    FindingEvent,
    NetworkActivityEvent,
    OCSFBaseEvent,
    OCSFMetadata,
    ProcessActivityEvent,
)
from sentinel_ai.exceptions import OCSFValidationError
from sentinel_ai.ingress.base import DataSourceAdapter


class WebhookAdapter(DataSourceAdapter):
    """Adapter for normalizing webhook JSON payloads into OCSF events."""

    def __init__(self, adapter_id: str = "webhook-adapter", vendor_name: str = "GenericWebhook"):
        super().__init__(adapter_id=adapter_id, vendor_name=vendor_name)

    def parse_and_normalize(self, raw_payload: dict[str, Any]) -> OCSFBaseEvent:
        """Parse raw payload and construct the appropriate OCSF event model.

        Raises:
            OCSFValidationError: On invalid fields or schema mismatches.
        """
        try:
            class_uid_val = raw_payload.get("class_uid")
            if not class_uid_val:
                raise OCSFValidationError("Missing required 'class_uid' field in payload.")
            if isinstance(class_uid_val, str) and class_uid_val.isdigit():
                class_uid_val = int(class_uid_val)

            metadata = OCSFMetadata(
                product_name=raw_payload.get("product_name", "WebhookSource"),
                vendor_name=self.vendor_name,
                processed_time=int(time.time()),
            )

            event_data = {**raw_payload, "class_uid": class_uid_val, "metadata": metadata}
            if "time" not in event_data:
                event_data["time"] = int(time.time())

            if "category_uid" not in event_data:
                if class_uid_val in (ClassUID.AUTHENTICATION, 3002):
                    event_data["category_uid"] = CategoryUID.IDENTITY_MANAGEMENT
                elif class_uid_val in (ClassUID.NETWORK_ACTIVITY, 4001):
                    event_data["category_uid"] = CategoryUID.NETWORK_ACTIVITY
                elif class_uid_val in (ClassUID.PROCESS_ACTIVITY, 1007):
                    event_data["category_uid"] = CategoryUID.SYSTEM_ACTIVITY
                elif class_uid_val in (ClassUID.FINDING, 2001):
                    event_data["category_uid"] = CategoryUID.FINDINGS
                else:
                    event_data["category_uid"] = CategoryUID.SYSTEM_ACTIVITY

            if class_uid_val in (ClassUID.AUTHENTICATION, 3002):
                return AuthenticationEvent(**event_data)
            elif class_uid_val in (ClassUID.NETWORK_ACTIVITY, 4001):
                return NetworkActivityEvent(**event_data)
            elif class_uid_val in (ClassUID.PROCESS_ACTIVITY, 1007):
                return ProcessActivityEvent(**event_data)
            elif class_uid_val in (ClassUID.FINDING, 2001):
                return FindingEvent(**event_data)
            else:
                return OCSFBaseEvent(**event_data)

        except ValidationError as e:
            raise OCSFValidationError(f"Payload failed OCSF validation: {e!s}") from e
        except Exception as e:
            if isinstance(e, OCSFValidationError):
                raise
            raise OCSFValidationError(f"Unexpected error during event normalization: {e!s}") from e
