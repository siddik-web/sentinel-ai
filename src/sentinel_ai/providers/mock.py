"""Mock LLM Provider for deterministic behavioral evaluations and offline testing."""

from typing import Any

from sentinel_ai.providers.base import LLMProvider, LLMResponse


class MockLLMProvider(LLMProvider):
    """Deterministic Mock LLM Provider returning pre-configured reasoning outputs."""

    def __init__(self, model_name: str = "mock-gpt-4o"):
        super().__init__(model_name=model_name)
        self._preset_responses: dict[str, dict[str, Any]] = {}

    def register_response(self, keyword: str, response_data: dict[str, Any]):
        """Register a keyword-matched mock JSON response."""
        self._preset_responses[keyword] = response_data

    def generate_completion(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Return matching preset mock response or default reasoning."""
        matched_json = None
        for kw, res in self._preset_responses.items():
            if kw.lower() in prompt.lower():
                matched_json = res
                break

        if matched_json is None:
            matched_json = {
                "reasoning": "Default triage analysis",
                "severity": "MEDIUM",
                "requires_hitl": False,
                "confidence": 0.90,
            }

        return LLMResponse(
            content=str(matched_json),
            model_name=self.model_name,
            structured_json=matched_json,
            token_usage={"prompt_tokens": 120, "completion_tokens": 45},
        )
