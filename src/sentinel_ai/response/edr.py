"""EDR Response Adapter for host isolation and process termination.

This is a reference adapter: it validates and records the action but does not call a real
EDR product. Replace ``_dispatch_action`` with vendor API calls to act on real endpoints.
"""

import time
from typing import Any

from sentinel_ai.exceptions import SentinelError
from sentinel_ai.response.base import ActionExecutionResult, ResponseAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


class EDRResponseAdapter(ResponseAdapter):
    """Adapter for executing EDR remediation actions against host endpoints."""

    def __init__(
        self, adapter_id: str = "edr-response-adapter", pep: PolicyEnforcementPoint | None = None
    ):
        if pep is None:
            raise ValueError("PolicyEnforcementPoint is required for EDRResponseAdapter.")
        super().__init__(adapter_id=adapter_id, target_system="EDR_Platform", pep=pep)

    def _dispatch_action(
        self, action_name: str, parameters: dict[str, Any]
    ) -> ActionExecutionResult:
        if action_name == "ISOLATE_HOST":
            host = parameters.get("host") or parameters.get("target")
            if not host:
                raise SentinelError("Missing required parameter 'host' for ISOLATE_HOST.")
            return ActionExecutionResult(
                action_name=action_name,
                target=str(host),
                success=True,
                message=f"[SIMULATED] Host '{host}' network interface isolated.",
                evidence={
                    "isolated_at_timestamp": int(time.time()),
                    "status": "NETWORK_ISOLATED",
                    "simulated": True,
                },
            )

        elif action_name == "TERMINATE_PROCESS":
            pid = parameters.get("pid")
            if not pid:
                raise SentinelError("Missing required parameter 'pid' for TERMINATE_PROCESS.")
            return ActionExecutionResult(
                action_name=action_name,
                target=f"PID_{pid}",
                success=True,
                message=f"[SIMULATED] Process PID {pid} terminated.",
                evidence={"pid": pid, "status": "KILLED", "simulated": True},
            )

        else:
            raise SentinelError(f"Unsupported action '{action_name}' for EDRResponseAdapter.")
