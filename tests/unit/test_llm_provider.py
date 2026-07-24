"""Unit tests for Mock and OpenAI LLM provider abstractions."""

from sentinel_ai.providers.mock import MockLLMProvider


def test_mock_llm_provider_default_response():
    provider = MockLLMProvider()
    resp = provider.generate_completion("Analyze unusual SSH traffic")
    assert resp.model_name == "mock-gpt-4o"
    assert resp.structured_json["severity"] == "MEDIUM"


def test_mock_llm_provider_registered_response():
    provider = MockLLMProvider()
    provider.register_response(
        keyword="ransomware",
        response_data={"severity": "CRITICAL", "requires_hitl": True, "action": "ISOLATE_HOST"},
    )

    resp = provider.generate_completion("Detected Ransomware file activity")
    assert resp.structured_json["severity"] == "CRITICAL"
    assert resp.structured_json["action"] == "ISOLATE_HOST"
