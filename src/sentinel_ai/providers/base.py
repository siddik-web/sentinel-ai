"""Base LLMProvider contract for Sentinel AI reasoning engine."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class LLMResponse(BaseModel):
    """Structured response output returned by an LLM provider."""

    content: str
    model_name: str
    structured_json: dict[str, Any] | None = None
    token_usage: dict[str, Any] = Field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0}
    )


class LLMProvider(ABC):
    """Abstract base class for model providers (OpenAI, Anthropic, local LLM, Mock)."""

    def __init__(self, model_name: str):
        self.model_name = model_name

    @abstractmethod
    def generate_completion(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Generate a text or JSON completion from the model."""
