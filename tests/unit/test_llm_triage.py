"""Tests for LLM-assisted triage and provider configuration."""

import pytest

from sentinel_ai.agents.triage import TriageAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.exceptions import SentinelError
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.providers import (
    LMStudioProvider,
    MockLLMProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    create_provider_from_env,
)
from sentinel_ai.providers.base import LLMProvider
from sentinel_ai.security.pep import PolicyEnforcementPoint

ROUTINE_AUTH = {"class_uid": 3002, "activity_id": 1, "severity_id": 1, "user_name": "svc"}
CRITICAL_FINDING = {
    "class_uid": 2001,
    "activity_id": 1,
    "severity_id": 5,
    "title": "Ransomware",
    "analytic_name": "EDR",
    "confidence_score": 0.99,
}


def _triage(payload, provider):
    logger = CryptographicAuditLogger()
    agent = TriageAgent(pep=PolicyEnforcementPoint(audit_logger=logger), llm_provider=provider)
    return agent.evaluate_event(WebhookAdapter().parse_and_normalize(payload)), logger


def _mock(**assessment):
    provider = MockLLMProvider()
    provider.register_response("Security event", assessment)
    return provider


def test_llm_can_escalate_a_routine_event():
    provider = _mock(
        reasoning="Service account login at an unusual hour.",
        severity="HIGH",
        requires_hitl=True,
        confidence=0.7,
    )
    response, logger = _triage(ROUTINE_AUTH, provider)
    assert response.requires_hitl is True
    assert response.severity_assessment == "HIGH"
    assert response.confidence == 0.7
    assert response.reasoning == "Service account login at an unusual hour."
    assert response.suggested_actions == {}
    types = [e.event_type for e in logger.entries]
    assert "LLM_ASSESSMENT" in types
    assert types.count("POLICY_APPROVAL") == 3  # CLASSIFY_SEVERITY, GENERATE_SUMMARY, REQUEST_HITL


def test_llm_cannot_downgrade_rule_based_escalation():
    provider = _mock(
        reasoning="Looks benign.", severity="LOW", requires_hitl=False, confidence=0.99
    )
    response, _ = _triage(CRITICAL_FINDING, provider)
    assert response.requires_hitl is True
    assert response.severity_assessment == "CRITICAL"
    assert response.suggested_actions["action"] == "ISOLATE_HOST"


def test_invalid_llm_output_falls_back_to_rules():
    provider = _mock(reasoning="x", severity="APOCALYPTIC", requires_hitl="maybe", confidence=7)
    response, logger = _triage(ROUTINE_AUTH, provider)
    assert response.requires_hitl is False
    assert response.severity_assessment == "INFORMATIONAL"
    assert "unavailable" in response.reasoning
    assert "LLM_ASSESSMENT_FAILED" in [e.event_type for e in logger.entries]


def test_llm_provider_error_falls_back_to_rules():
    class FailingProvider(LLMProvider):
        def generate_completion(self, prompt, system_prompt=None):
            raise SentinelError("connection refused")

    response, logger = _triage(CRITICAL_FINDING, FailingProvider(model_name="down"))
    assert response.requires_hitl is True
    assert "LLM_ASSESSMENT_FAILED" in [e.event_type for e in logger.entries]


def test_create_provider_from_env():
    assert create_provider_from_env({}) is None
    assert create_provider_from_env({"SENTINEL_LLM_PROVIDER": "none"}) is None
    assert isinstance(create_provider_from_env({"SENTINEL_LLM_PROVIDER": "mock"}), MockLLMProvider)

    ollama = create_provider_from_env(
        {
            "SENTINEL_LLM_PROVIDER": "ollama",
            "SENTINEL_LLM_MODEL": "mistral",
            "SENTINEL_LLM_API_BASE": "http://ollama:11434/",
        }
    )
    assert isinstance(ollama, OllamaProvider)
    assert (ollama.model_name, ollama.api_base) == ("mistral", "http://ollama:11434")

    assert isinstance(
        create_provider_from_env({"SENTINEL_LLM_PROVIDER": "lmstudio"}), LMStudioProvider
    )
    openai = create_provider_from_env(
        {"SENTINEL_LLM_PROVIDER": "openai", "SENTINEL_LLM_API_KEY": "k"}
    )
    assert isinstance(openai, OpenAICompatibleProvider)
    assert openai.api_key == "k"

    with pytest.raises(SentinelError, match="SENTINEL_LLM_API_KEY"):
        create_provider_from_env({"SENTINEL_LLM_PROVIDER": "openai"})
    with pytest.raises(SentinelError, match="Unknown"):
        create_provider_from_env({"SENTINEL_LLM_PROVIDER": "skynet"})
