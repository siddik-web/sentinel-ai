"""Unit tests for local LLM provider implementations (Ollama and LM Studio)."""

from sentinel_ai.providers.lmstudio import LMStudioProvider
from sentinel_ai.providers.ollama import OllamaProvider


def test_ollama_provider_init():
    provider = OllamaProvider(model_name="llama3", api_base="http://localhost:11434")
    assert provider.model_name == "llama3"
    assert provider.api_base == "http://localhost:11434"


def test_lmstudio_provider_init():
    provider = LMStudioProvider(model_name="mistral-7b", api_base="http://localhost:1234/v1")
    assert provider.model_name == "mistral-7b"
    assert provider.api_base == "http://localhost:1234/v1"
    assert provider.api_key == "lm-studio"
