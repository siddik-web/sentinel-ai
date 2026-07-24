"""Base ResponseAdapter contract for outbound remediation actions."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from sentinel_ai.security.pep import PolicyEnforcementPoint


class ActionExecutionResult(BaseModel):
    """Result payload returned by a response adapter execution."""

    action_name: str
    target: str
    success: bool
    message: str
    evidence: dict[str, Any] = {}


class ResponseAdapter(ABC):
    """Abstract base class for all outbound response execution adapters."""

    def __init__(self, adapter_id: str, target_system: str, pep: PolicyEnforcementPoint):
        self.adapter_id = adapter_id
        self.target_system = target_system
        self.pep = pep

    def execute_action(
        self,
        agent_id: str,
        action_name: str,
        parameters: dict[str, Any],
        hitl_approved: bool = False,
    ) -> ActionExecutionResult:
        """Execute an action after passing PEP governance validation."""
        # 1. Enforce PEP boundary authorization
        self.pep.evaluate_action(
            agent_id=agent_id,
            action_name=action_name,
            parameters=parameters,
            hitl_approved=hitl_approved,
        )

        # 2. Dispatch to internal adapter execution
        return self._dispatch_action(action_name=action_name, parameters=parameters)

    @abstractmethod
    def _dispatch_action(
        self, action_name: str, parameters: dict[str, Any]
    ) -> ActionExecutionResult:
        """Internal dispatch method implemented by specific target adapters."""
