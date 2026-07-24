"""LM Studio Local LLM Provider implementation using OpenAI-compatible API."""

from sentinel_ai.providers.openai import OpenAICompatibleProvider


class LMStudioProvider(OpenAICompatibleProvider):
    """Provider for connecting to local LM Studio instances (default http://localhost:1234/v1)."""

    def __init__(
        self,
        model_name: str = "local-model",
        api_base: str = "http://localhost:1234/v1",
    ):
        super().__init__(
            api_key="lm-studio",
            api_base=api_base,
            model_name=model_name,
        )
