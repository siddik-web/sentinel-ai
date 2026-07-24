"""Unit tests for configurable PolicyRuleEngine."""

import pytest

from sentinel_ai.exceptions import PolicyViolationError
from sentinel_ai.security.policy_rules import PolicyRuleEngine


def test_policy_rule_engine_denied_actions():
    engine = PolicyRuleEngine(rule_config={"denied_actions": ["SHUTDOWN_SERVER"]})

    with pytest.raises(PolicyViolationError, match="explicitly forbidden"):
        engine.evaluate_rule(agent_id="agent-1", action_name="SHUTDOWN_SERVER", parameters={})


def test_policy_rule_engine_trusted_ip_protection():
    engine = PolicyRuleEngine(rule_config={"trusted_ips": ["10.0.0.1", "192.168.1.100"]})

    with pytest.raises(PolicyViolationError, match="protected trusted IP whitelist"):
        engine.evaluate_rule(
            agent_id="agent-1", action_name="BLOCK_IP", parameters={"ip": "10.0.0.1"}
        )


def test_policy_rule_engine_hitl_check():
    engine = PolicyRuleEngine()

    with pytest.raises(PolicyViolationError, match="Requires Human-In-The-Loop"):
        engine.evaluate_rule(
            agent_id="agent-1",
            action_name="ISOLATE_HOST",
            parameters={"host": "srv-01"},
            hitl_approved=False,
        )

    assert (
        engine.evaluate_rule(
            agent_id="agent-1",
            action_name="ISOLATE_HOST",
            parameters={"host": "srv-01"},
            hitl_approved=True,
        )
        is True
    )
