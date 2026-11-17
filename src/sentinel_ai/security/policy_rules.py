"""Dynamic Policy Rules Engine for operator-configurable ABAC/RBAC rules.

Policy files are JSON objects with these optional keys:

- ``denied_actions``: actions no agent may perform.
- ``hitl_required_actions``: actions that need Human-In-The-Loop approval.
- ``trusted_ips``: IP addresses that may never be blocked.
- ``agent_allowed_actions``: per-agent capability grants, ``{agent_id: [action, ...]}``.
  An agent listed here may only perform the actions granted to it.
"""

import json
from pathlib import Path
from typing import Any

from sentinel_ai.exceptions import PolicyConfigError, PolicyViolationError

DEFAULT_HITL_REQUIRED_ACTIONS = ("ISOLATE_HOST", "REVOKE_CREDENTIALS", "TERMINATE_PROCESS", "BLOCK_IP")

_LIST_KEYS = ("denied_actions", "hitl_required_actions", "trusted_ips")
_KNOWN_KEYS = {*_LIST_KEYS, "agent_allowed_actions"}


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


class PolicyRuleEngine:
    """Evaluates configurable policy rules against agent action contexts."""

    def __init__(self, rule_config: dict[str, Any] | None = None):
        self.config = rule_config or {}
        errors = self.validate_config(self.config)
        if errors:
            raise PolicyConfigError("Invalid policy configuration: " + "; ".join(errors))

        self.denied_actions: set[str] = set(self.config.get("denied_actions", []))
        self.hitl_required_actions: set[str] = set(
            self.config.get("hitl_required_actions", DEFAULT_HITL_REQUIRED_ACTIONS)
        )
        self.trusted_ips: set[str] = set(self.config.get("trusted_ips", []))
        self.agent_allowed_actions: dict[str, set[str]] = {
            agent: set(actions)
            for agent, actions in self.config.get("agent_allowed_actions", {}).items()
        }

    @staticmethod
    def validate_config(config: Any) -> list[str]:
        """Return a list of human-readable problems with a policy config (empty if valid)."""
        if not isinstance(config, dict):
            return ["policy must be a JSON object"]

        errors = [f"unknown key '{key}'" for key in sorted(set(config) - _KNOWN_KEYS)]
        for key in _LIST_KEYS:
            if key in config and not _is_str_list(config[key]):
                errors.append(f"'{key}' must be a list of strings")

        grants = config.get("agent_allowed_actions", {})
        if not isinstance(grants, dict):
            errors.append("'agent_allowed_actions' must be an object mapping agent IDs to lists")
        else:
            for agent, actions in grants.items():
                if not _is_str_list(actions):
                    errors.append(f"'agent_allowed_actions.{agent}' must be a list of strings")
        return errors

    @classmethod
    def from_file(cls, path: str) -> "PolicyRuleEngine":
        """Load and validate a JSON policy file.

        Raises:
            PolicyConfigError: If the file cannot be read, parsed, or validated.
        """
        try:
            config = json.loads(Path(path).read_text(encoding="utf-8"))
        except OSError as e:
            raise PolicyConfigError(f"Cannot read policy file '{path}': {e!s}") from e
        except json.JSONDecodeError as e:
            raise PolicyConfigError(f"Policy file '{path}' is not valid JSON: {e!s}") from e
        return cls(config)

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
                f"Action '{action_name}' is explicitly forbidden by security policy rules.",
                rule="denied_actions",
            )

        # Rule 2: Per-agent capability grants
        granted = self.agent_allowed_actions.get(agent_id)
        if granted is not None and action_name not in granted:
            raise PolicyViolationError(
                f"Action '{action_name}' is not in the capability set of agent '{agent_id}'.",
                rule="agent_allowed_actions",
            )

        # Rule 3: Trusted IP exemption for IP blocks
        target_ip = parameters.get("ip") or parameters.get("src_endpoint_ip")
        if action_name == "BLOCK_IP" and target_ip in self.trusted_ips:
            raise PolicyViolationError(
                f"Action 'BLOCK_IP' denied: IP '{target_ip}' is on the protected trusted IP "
                "whitelist.",
                rule="trusted_ips",
            )

        # Rule 4: HITL enforcement
        if action_name in self.hitl_required_actions and not hitl_approved:
            raise PolicyViolationError(
                f"Action '{action_name}' blocked: Requires Human-In-The-Loop (HITL) approval.",
                rule="hitl_required_actions",
            )

        return True
