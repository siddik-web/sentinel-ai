"""Dynamic Policy Rules Engine for operator-configurable ABAC/RBAC rules."""

from typing import Any

from sentinel_ai.exceptions import PolicyViolationError


class PolicyRuleEngine:
    """Evaluates configurable policy rules against agent action contexts."""

    def __init__(self, rule_config: dict[str, Any] | None = None):
        self.config = rule_config or {}
        self.denied_actions: set[str] = set(self.config.get("denied_actions", []))
        self.hitl_required_actions: set[str] = set(
            self.config.get(
                "hitl_required_actions",
                ["ISOLATE_HOST", "REVOKE_CREDENTIALS", "TERMINATE_PROCESS", "BLOCK_IP"],
            )
        )
        self.trusted_ips: set[str] = set(self.config.get("trusted_ips", []))

    def evaluate_rule(
        self,
        agent_id: str,
        action_name: str,
        parameters: dict[str, Any],
        hitl_approved: bool = False,
    ) -> bool:
        """Evaluate action request against dynamic policy rules.

        Raises:
            PolicyViolationError: If a policy rule is violated.
        """
        # Rule 1: Explicitly denied actions
        if action_name in self.denied_actions:
            raise PolicyViolationError(
                f"Action '{action_name}' is explicitly forbidden by security policy rules."
            )

        # Rule 2: Trusted IP exemption for IP blocks
        target_ip = parameters.get("ip") or parameters.get("src_endpoint_ip")
        if action_name == "BLOCK_IP" and target_ip in self.trusted_ips:
            raise PolicyViolationError(
                f"Action 'BLOCK_IP' denied: IP '{target_ip}' is on the protected trusted IP whitelist."
            )

        # Rule 3: HITL enforcement
        if action_name in self.hitl_required_actions and not hitl_approved:
            raise PolicyViolationError(
                f"Action '{action_name}' blocked: Requires Human-In-The-Loop (HITL) approval."
            )

        return True
