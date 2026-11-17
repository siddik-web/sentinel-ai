"""Behavioral Evaluation Framework enforcing charter accuracy thresholds (>=85%)."""

import json
from pathlib import Path

from pydantic import BaseModel

from sentinel_ai.agents.triage import TriageAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.providers.base import LLMProvider
from sentinel_ai.security.pep import PolicyEnforcementPoint

ACCURACY_THRESHOLD_PERCENT = 85.0


class ScenarioEvaluationResult(BaseModel):
    """Result of a single behavioral test scenario."""

    scenario_name: str
    passed: bool
    expected_hitl: bool
    actual_hitl: bool
    expected_severity: str | None = None
    actual_severity: str | None = None
    severity_matches: bool = True
    details: str


class EvaluationReport(BaseModel):
    """Aggregate evaluation report for behavioral suite."""

    total_scenarios: int
    passed_scenarios: int
    accuracy_percentage: float
    severity_accuracy_percentage: float = 0.0
    charter_compliant: bool
    scenario_results: list[ScenarioEvaluationResult]


class BehavioralEvaluator:
    """Evaluates agent performance against benchmark alert corpus.

    Each fixture declares ``raw_payload`` and ``expected_hitl``, and optionally
    ``expected_severity`` and ``expected_action`` (``null`` means no action is expected).
    """

    def __init__(self, llm_provider: LLMProvider | None = None):
        self.audit_logger = CryptographicAuditLogger()
        self.pep = PolicyEnforcementPoint(audit_logger=self.audit_logger)
        self.agent = TriageAgent(pep=self.pep, llm_provider=llm_provider)
        self.adapter = WebhookAdapter()

    def evaluate_corpus(self, corpus_dir_path: str) -> EvaluationReport:
        """Run evaluation across all fixture files in corpus directory."""
        fixture_files = sorted(Path(corpus_dir_path).glob("*.json"))

        results: list[ScenarioEvaluationResult] = []
        for filepath in fixture_files:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)

            scenario_name = data.get("scenario_name", filepath.stem)
            expected_hitl = data["expected_hitl"]
            expected_severity = data.get("expected_severity")

            event = self.adapter.parse_and_normalize(data["raw_payload"])
            response = self.agent.evaluate_event(event)

            actual_action = response.suggested_actions.get("action")
            hitl_matches = response.requires_hitl == expected_hitl
            action_matches = (
                actual_action == data["expected_action"] if "expected_action" in data else True
            )
            severity_matches = (
                response.severity_assessment == expected_severity if expected_severity else True
            )

            details = (
                f"HITL Match: {hitl_matches} (Expected: {expected_hitl}, "
                f"Actual: {response.requires_hitl}) | "
                f"Action Match: {action_matches} (Actual: {actual_action}) | "
                f"Severity Match: {severity_matches} (Expected: {expected_severity}, "
                f"Actual: {response.severity_assessment})"
            )

            results.append(
                ScenarioEvaluationResult(
                    scenario_name=scenario_name,
                    passed=hitl_matches and action_matches and severity_matches,
                    expected_hitl=expected_hitl,
                    actual_hitl=response.requires_hitl,
                    expected_severity=expected_severity,
                    actual_severity=response.severity_assessment,
                    severity_matches=severity_matches,
                    details=details,
                )
            )

        total = len(results)
        passed_count = sum(1 for r in results if r.passed)
        severity_count = sum(1 for r in results if r.severity_matches)
        accuracy = (passed_count / total * 100.0) if total > 0 else 0.0
        severity_accuracy = (severity_count / total * 100.0) if total > 0 else 0.0

        return EvaluationReport(
            total_scenarios=total,
            passed_scenarios=passed_count,
            accuracy_percentage=accuracy,
            severity_accuracy_percentage=severity_accuracy,
            charter_compliant=accuracy >= ACCURACY_THRESHOLD_PERCENT,
            scenario_results=results,
        )
