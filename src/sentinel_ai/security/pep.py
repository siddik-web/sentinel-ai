"""Policy Enforcement Point (PEP) for Sentinel AI security boundary.

Implements AG2 (Governance is enforced at the boundary).
"""

from collections.abc import Callable
from typing import Any, ClassVar

from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.exceptions import PolicyViolationError
from sentinel_ai.security.policy_rules import PolicyRuleEngine


class PolicyEnforcementPoint:
    """Evaluates agent tool invocations and action requests against security policies.

    Built-in rules (the action allowlist and HITL approval for high-risk actions) always
    apply. An optional operator-supplied ``PolicyRuleEngine`` can only add restrictions on
    top of them; it cannot relax the built-in rules.
    """

    HIGH_RISK_ACTIONS: ClassVar[set[str]] = {
        "ISOLATE_HOST",
        "REVOKE_CREDENTIALS",
        "TERMINATE_PROCESS",
        "BLOCK_IP",
    }

    def __init__(
        self,
        audit_logger: CryptographicAuditLogger,
        rule_engine: PolicyRuleEngine | None = None,
        on_decision: Callable[[bool], None] | None = None,
    ):
        self.audit_logger = audit_logger
        self.rule_engine = rule_engine
        self._on_decision = on_decision
        self._allowed_actions = {
            "QUERY_ALERT",
            "CLASSIFY_SEVERITY",
            "ENRICH_IP",
            "REQUEST_HITL",
            "GENERATE_SUMMARY",
            *self.HIGH_RISK_ACTIONS,
        }

    def _deny(
        self, agent_id: str, action_name: str, parameters: dict[str, Any], reason: str, rule: str
    ) -> PolicyViolationError:
        self.audit_logger.log_event(
            event_type="POLICY_DENIAL",
            actor=agent_id,
            payload={
                "action": action_name,
                "reason": reason,
                "rule": rule,
                "parameters": parameters,
            },
        )
        if self._on_decision:
            self._on_decision(False)
        return PolicyViolationError(reason, rule=rule)

    def evaluate_action(
        self,
        agent_id: str,
        action_name: str,
        parameters: dict[str, Any],
        hitl_approved: bool = False,
    ) -> bool:
        """Evaluate if an agent action is authorized for execution.

        The decision is written to the audit log before this method returns or raises.

        Raises:
            PolicyViolationError: If the action violates policy boundaries.
        """
        if action_name not in self._allowed_actions:
            raise self._deny(
                agent_id,
                action_name,
                parameters,
                f"Action '{action_name}' is not allowed by policy.",
                "action_allowlist",
            )

        if self.rule_engine is not None:
            try:
                self.rule_engine.evaluate_rule(agent_id, action_name, parameters, hitl_approved)
            except PolicyViolationError as e:
                raise self._deny(agent_id, action_name, parameters, str(e), e.rule) from e
            except Exception as e:
                # Fail closed: an evaluation error is a denial.
                raise self._deny(
                    agent_id,
                    action_name,
                    parameters,
                    f"Policy evaluation error for '{action_name}': {e!s}",
                    "evaluation_error",
                ) from e

        if action_name in self.HIGH_RISK_ACTIONS and not hitl_approved:
            raise self._deny(
                agent_id,
                action_name,
                parameters,
                f"High-risk action '{action_name}' blocked: requires Human-In-The-Loop approval.",
                "high_risk_requires_hitl",
            )

        self.audit_logger.log_event(
            event_type="POLICY_APPROVAL",
            actor=agent_id,
            payload={
                "action": action_name,
                "hitl_approved": hitl_approved,
                "parameters": parameters,
            },
        )
        if self._on_decision:
            self._on_decision(True)
        return True
