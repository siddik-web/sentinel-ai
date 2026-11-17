"""Unit tests for OCSF schema models and validation."""

import pytest

from sentinel_ai.core.ocsf.models import (
    AuthenticationEvent,
    CategoryUID,
    ClassUID,
    FindingEvent,
    OCSFMetadata,
    SeverityID,
)
from sentinel_ai.exceptions import OCSFValidationError
from sentinel_ai.ingress.webhook import WebhookAdapter


def test_authentication_event_creation():
    metadata = OCSFMetadata(product_name="Okta", vendor_name="OktaInc")
    event = AuthenticationEvent(
        activity_id=1,
        severity_id=SeverityID.HIGH,
        time=1600000000,
        metadata=metadata,
        user_name="alice@example.com",
        is_success=False,
    )
    assert event.class_uid == ClassUID.AUTHENTICATION
    assert event.category_uid == CategoryUID.IDENTITY_MANAGEMENT
    assert event.user_name == "alice@example.com"
    assert not event.is_success
    assert event.get_event_id().startswith("3002:1600000000:OktaInc:1:")
    assert event.get_event_id() == event.model_copy().get_event_id()


def test_webhook_adapter_valid_payload():
    adapter = WebhookAdapter(vendor_name="TestVendor")
    payload = {
        "class_uid": 2001,
        "activity_id": 10,
        "severity_id": 4,
        "time": 1700000000,
        "title": "Malware Outbreak",
        "analytic_name": "EDR-001",
        "confidence_score": 0.95,
    }
    event = adapter.parse_and_normalize(payload)
    assert isinstance(event, FindingEvent)
    assert event.title == "Malware Outbreak"
    assert event.confidence_score == 0.95
    assert event.severity_id == SeverityID.HIGH


def test_webhook_adapter_invalid_payload():
    adapter = WebhookAdapter(vendor_name="TestVendor")
    payload = {
        "activity_id": 10,
        # missing class_uid
    }
    with pytest.raises(OCSFValidationError):
        adapter.parse_and_normalize(payload)
