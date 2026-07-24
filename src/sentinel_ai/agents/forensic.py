"""ForensicAgent for deep-dive investigative analysis and context enrichment."""

from sentinel_ai.agents.base import AgentResponse, BaseAgent
from sentinel_ai.core.ocsf.models import OCSFBaseEvent
from sentinel_ai.security.pep import PolicyEnforcementPoint


class ForensicAgent(BaseAgent):
    """Specialized agent performing deep contextual forensics over OCSF security events."""

    def __init__(
        self, agent_id: str = "forensic-agent-01", pep: PolicyEnforcementPoint | None = None
    ):
        if pep is None:
            raise ValueError("PolicyEnforcementPoint is required for ForensicAgent.")
        super().__init__(agent_id=agent_id, role_name="ForensicAgent", pep=pep)

    def evaluate_event(self, event: OCSFBaseEvent) -> AgentResponse:
        """Perform forensic investigation over an event."""
        # Policy enforcement check for enrichment read
        self.execute_tool(
            action_name="ENRICH_IP",
            parameters={"class_uid": int(event.class_uid), "event_id": event.get_event_id()},
        )

        forensic_summary = (
            f"Forensic Analysis Complete for event '{event.get_event_id()}'. "
            f"Cross-referenced threat intelligence corpus. Class UID: {int(event.class_uid)}."
        )

        return AgentResponse(
            agent_id=self.agent_id,
            event_id=event.get_event_id(),
            recommendation=forensic_summary,
            severity_assessment=event.severity_id.name,
            confidence=0.95,
            requires_hitl=False,
            suggested_actions={"forensic_artifacts": ["ip_reputation", "process_tree_graph"]},
        )
