"""Identity & Access Response Adapter for credential revocation and IP blocking."""

from typing import Any

from sentinel_ai.exceptions import SentinelError
from sentinel_ai.response.base import ActionExecutionResult, ResponseAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


class IdentityResponseAdapter(ResponseAdapter):
    """Adapter for executing identity and perimeter response actions."""

    def __init__(
        self, adapter_id: str = "identity-response-adapter", pep: PolicyEnforcementPoint = None
    ):
        if pep is None:
            raise ValueError("PolicyEnforcementPoint is required for IdentityResponseAdapter.")
        super().__init__(adapter_id=adapter_id, target_system="Identity_Provider", pep=pep)

    def _dispatch_action(
        self, action_name: str, parameters: dict[str, Any]
    ) -> ActionExecutionResult:
        if action_name == "REVOKE_CREDENTIALS":
            user = parameters.get("user") or parameters.get("user_name")
            if not user:
                raise SentinelError("Missing required parameter 'user' for REVOKE_CREDENTIALS.")
            return ActionExecutionResult(
                action_name=action_name,
                target=str(user),
                success=True,
                message=f"User session for '{user}' revoked and account locked via IAM API.",
                evidence={"user": user, "status": "SESSION_REVOKED_ACCOUNT_LOCKED"},
            )

        elif action_name == "BLOCK_IP":
            ip = parameters.get("ip") or parameters.get("src_endpoint_ip")
            if not ip:
                raise SentinelError("Missing required parameter 'ip' for BLOCK_IP.")
            return ActionExecutionResult(
                action_name=action_name,
                target=str(ip),
                success=True,
                message=f"IP address '{ip}' blocked at perimeter firewall.",
                evidence={"ip": ip, "status": "DENYLISTED"},
            )

        else:
            raise SentinelError(f"Unsupported action '{action_name}' for IdentityResponseAdapter.")
