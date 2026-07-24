"""MVP TriageAgent implementation for Sentinel AI."""

from sentinel_ai.agents.base import AgentResponse, BaseAgent
from sentinel_ai.core.ocsf.models import (
    AuthenticationEvent,
    FindingEvent,
    OCSFBaseEvent,
    ProcessActivityEvent,
    SeverityID,
)
from sentinel_ai.security.pep import PolicyEnforcementPoint


class TriageAgent(BaseAgent):
    """Specialized agent responsible for initial alert triage, severity scoring, and HITL routing."""

    def __init__(
        self, agent_id: str = "triage-agent-01", pep: PolicyEnforcementPoint | None = None
    ):
        if pep is None:
            raise ValueError("PolicyEnforcementPoint is required for agent initialization.")
        super().__init__(agent_id=agent_id, role_name="TriageAgent", pep=pep)

    def evaluate_event(self, event: OCSFBaseEvent) -> AgentResponse:
        """Triage an incoming OCSF event."""
        # Enforce boundary policy check for classification tool
        self.execute_tool(
            action_name="CLASSIFY_SEVERITY",
            parameters={"class_uid": int(event.class_uid), "severity_id": int(event.severity_id)},
        )

        requires_hitl = False
        recommendation = "Monitor routine event"
        severity_assessment = event.severity_id.name
        confidence = 0.90
        suggested_actions = {}

        # Triage logic based on OCSF event class
        if isinstance(event, AuthenticationEvent):
            if not event.is_success:
                severity_assessment = "MEDIUM"
                recommendation = "Investigate failed authentication attempt"
                if event.severity_id >= SeverityID.HIGH:
                    requires_hitl = True
                    suggested_actions = {"action": "REVOKE_CREDENTIALS", "user": event.user_name}

        elif isinstance(event, FindingEvent):
            if event.confidence_score > 0.80 or event.severity_id >= SeverityID.HIGH:
                requires_hitl = True
                recommendation = f"High-confidence security finding: {event.title}"
                suggested_actions = {
                    "action": "ISOLATE_HOST",
                    "remediation": event.remediation_guidance,
                }

        elif isinstance(event, ProcessActivityEvent):
            suspicious_bins = {"powershell.exe", "cmd.exe", "nc", "ncat", "bash"}
            if (
                event.process_name.lower() in suspicious_bins
                and event.severity_id >= SeverityID.MEDIUM
            ):
                requires_hitl = True
                recommendation = f"Suspicious execution of process '{event.process_name}'"
                suggested_actions = {"action": "TERMINATE_PROCESS", "pid": event.process_pid}

        if requires_hitl:
            self.execute_tool(
                action_name="REQUEST_HITL",
                parameters={"event_id": event.get_event_id(), "reason": recommendation},
            )

        return AgentResponse(
            agent_id=self.agent_id,
            event_id=event.get_event_id(),
            recommendation=recommendation,
            severity_assessment=severity_assessment,
            confidence=confidence,
            requires_hitl=requires_hitl,
            suggested_actions=suggested_actions,
        )
