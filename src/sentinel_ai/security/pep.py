"""Policy Enforcement Point (PEP) for Sentinel AI security boundary.

Implements AG2 (Governance is enforced at the boundary).
"""

from typing import Any, ClassVar

from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.exceptions import PolicyViolationError


class PolicyEnforcementPoint:
    """Evaluates agent tool invocations and action requests against security policies."""

    HIGH_RISK_ACTIONS: ClassVar[set[str]] = {
        "ISOLATE_HOST",
        "REVOKE_CREDENTIALS",
        "TERMINATE_PROCESS",
        "BLOCK_IP",
    }

    def __init__(self, audit_logger: CryptographicAuditLogger):
        self.audit_logger = audit_logger
        self._allowed_actions = {
            "QUERY_ALERT",
            "CLASSIFY_SEVERITY",
            "ENRICH_IP",
            "REQUEST_HITL",
            "GENERATE_SUMMARY",
            *self.HIGH_RISK_ACTIONS,
        }

    def evaluate_action(
        self,
        agent_id: str,
        action_name: str,
        parameters: dict[str, Any],
        hitl_approved: bool = False,
    ) -> bool:
        """Evaluate if an agent action is authorized for execution.

        Raises:
            PolicyViolationError: If the action violates policy boundaries.
        """
        if action_name not in self._allowed_actions:
            self.audit_logger.log_event(
                event_type="POLICY_DENIAL",
                actor=agent_id,
                payload={
                    "action": action_name,
                    "reason": "Unknown or unapproved action name",
                    "parameters": parameters,
                },
            )
            raise PolicyViolationError(f"Action '{action_name}' is not allowed by policy.")

        if action_name in self.HIGH_RISK_ACTIONS and not hitl_approved:
            self.audit_logger.log_event(
                event_type="POLICY_DENIAL",
                actor=agent_id,
                payload={
                    "action": action_name,
                    "reason": "High-risk action requires Human-In-The-Loop (HITL) approval.",
                    "parameters": parameters,
                },
            )
            raise PolicyViolationError(
                f"High-risk action '{action_name}' blocked: requires Human-In-The-Loop approval."
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
        return True
