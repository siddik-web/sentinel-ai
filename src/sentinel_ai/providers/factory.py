"""Build an LLM provider from environment configuration."""

from collections.abc import Mapping

from sentinel_ai.exceptions import SentinelError
from sentinel_ai.providers.base import LLMProvider
from sentinel_ai.providers.lmstudio import LMStudioProvider
from sentinel_ai.providers.mock import MockLLMProvider
from sentinel_ai.providers.ollama import OllamaProvider
from sentinel_ai.providers.openai import OpenAICompatibleProvider


def create_provider_from_env(env: Mapping[str, str]) -> LLMProvider | None:
    """Create the provider selected by ``SENTINEL_LLM_PROVIDER``.

    Supported values: ``none`` (default, rule-based triage only), ``mock``, ``openai``
    (any OpenAI-compatible endpoint), ``ollama``, ``lmstudio``. ``SENTINEL_LLM_MODEL`` and
    ``SENTINEL_LLM_API_BASE`` override the provider defaults; ``SENTINEL_LLM_API_KEY`` is
    required for ``openai``.

    Raises:
        SentinelError: If the provider name is unknown or required settings are missing.
    """
    name = env.get("SENTINEL_LLM_PROVIDER", "none").strip().lower()
    if name in ("", "none"):
        return None

    kwargs: dict[str, str] = {}
    if env.get("SENTINEL_LLM_MODEL"):
        kwargs["model_name"] = env["SENTINEL_LLM_MODEL"]

    if name == "mock":
        return MockLLMProvider(**kwargs)

    if env.get("SENTINEL_LLM_API_BASE"):
        kwargs["api_base"] = env["SENTINEL_LLM_API_BASE"]

    if name == "ollama":
        return OllamaProvider(**kwargs)
    if name == "lmstudio":
        return LMStudioProvider(**kwargs)
    if name == "openai":
        api_key = env.get("SENTINEL_LLM_API_KEY")
        if not api_key:
            raise SentinelError("SENTINEL_LLM_API_KEY is required when SENTINEL_LLM_PROVIDER=openai.")
        return OpenAICompatibleProvider(api_key=api_key, **kwargs)

    raise SentinelError(
        f"Unknown SENTINEL_LLM_PROVIDER '{name}'. Expected none, mock, openai, ollama or lmstudio."
    )
