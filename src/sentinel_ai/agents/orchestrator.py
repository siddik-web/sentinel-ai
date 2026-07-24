"""OrchestratorAgent managing multi-agent handoffs and workflow execution."""

from typing import Any

from pydantic import BaseModel

from sentinel_ai.agents.base import AgentResponse
from sentinel_ai.agents.forensic import ForensicAgent
from sentinel_ai.agents.triage import TriageAgent
from sentinel_ai.core.ocsf.models import OCSFBaseEvent
from sentinel_ai.security.pep import PolicyEnforcementPoint


class WorkflowExecutionSummary(BaseModel):
    """Unified summary of multi-agent workflow execution."""

    event_id: str
    triage_response: AgentResponse
    forensic_response: AgentResponse | None = None
    requires_hitl: bool
    final_recommendation: str
    suggested_actions: dict[str, Any] = {}


class OrchestratorAgent:
    """Orchestrates triage, forensic investigation, and response agent handoffs."""

    def __init__(self, pep: PolicyEnforcementPoint):
        self.pep = pep
        self.triage_agent = TriageAgent(pep=pep)
        self.forensic_agent = ForensicAgent(pep=pep)

    def process_event_workflow(self, event: OCSFBaseEvent) -> WorkflowExecutionSummary:
        """Run complete multi-agent workflow over an incoming alert."""
        # 1. Execute Triage Stage
        triage_resp = self.triage_agent.evaluate_event(event)

        # 2. Execute Forensic Stage if triage requires deeper analysis or HITL
        forensic_resp = None
        if triage_resp.requires_hitl or triage_resp.confidence < 0.95:
            forensic_resp = self.forensic_agent.evaluate_event(event)

        requires_hitl = triage_resp.requires_hitl
        final_recommendation = triage_resp.recommendation
        if forensic_resp:
            final_recommendation += f" | {forensic_resp.recommendation}"

        return WorkflowExecutionSummary(
            event_id=event.get_event_id(),
            triage_response=triage_resp,
            forensic_response=forensic_resp,
            requires_hitl=requires_hitl,
            final_recommendation=final_recommendation,
            suggested_actions=triage_resp.suggested_actions,
        )
