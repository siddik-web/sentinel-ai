"""Ingress module exports."""

from sentinel_ai.ingress.base import DataSourceAdapter
from sentinel_ai.ingress.webhook import WebhookAdapter

__all__ = ["DataSourceAdapter", "WebhookAdapter"]
