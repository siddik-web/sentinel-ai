"""Base Agent class contract for Sentinel AI."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from sentinel_ai.core.ocsf.models import OCSFBaseEvent
from sentinel_ai.security.pep import PolicyEnforcementPoint


class AgentResponse(BaseModel):
    """Standardized output response from an agent execution cycle."""

    agent_id: str
    event_id: str
    recommendation: str
    severity_assessment: str
    confidence: float
    requires_hitl: bool = False
    suggested_actions: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = ""


class BaseAgent(ABC):
    """Abstract agent runtime class enforcing PEP policy checks on all actions."""

    def __init__(self, agent_id: str, role_name: str, pep: PolicyEnforcementPoint):
        self.agent_id = agent_id
        self.role_name = role_name
        self.pep = pep

    def execute_tool(
        self, action_name: str, parameters: dict[str, Any], hitl_approved: bool = False
    ) -> bool:
        """Execute a tool action after passing through Policy Enforcement Point (PEP)."""
        return self.pep.evaluate_action(
            agent_id=self.agent_id,
            action_name=action_name,
            parameters=parameters,
            hitl_approved=hitl_approved,
        )

    def emit_audit(self, event_type: str, payload: dict[str, Any]) -> None:
        """Emit a structured event to the audit log writer on behalf of this agent."""
        self.pep.audit_logger.log_event(event_type=event_type, actor=self.agent_id, payload=payload)

    @abstractmethod
    def evaluate_event(self, event: OCSFBaseEvent) -> AgentResponse:
        """Process an OCSF event and return an AgentResponse decision."""
