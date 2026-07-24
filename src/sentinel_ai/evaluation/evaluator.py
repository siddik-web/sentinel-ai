"""Behavioral Evaluation Framework enforcing charter accuracy thresholds (>=85%)."""

import json
from pathlib import Path

from pydantic import BaseModel

from sentinel_ai.agents.triage import TriageAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


class ScenarioEvaluationResult(BaseModel):
    """Result of a single behavioral test scenario."""

    scenario_name: str
    passed: bool
    expected_hitl: bool
    actual_hitl: bool
    details: str


class EvaluationReport(BaseModel):
    """Aggregate evaluation report for behavioral suite."""

    total_scenarios: int
    passed_scenarios: int
    accuracy_percentage: float
    charter_compliant: bool
    scenario_results: list[ScenarioEvaluationResult]


class BehavioralEvaluator:
    """Evaluates agent performance against benchmark alert corpus."""

    def __init__(self):
        self.audit_logger = CryptographicAuditLogger()
        self.pep = PolicyEnforcementPoint(audit_logger=self.audit_logger)
        self.agent = TriageAgent(pep=self.pep)
        self.adapter = WebhookAdapter()

    def evaluate_corpus(self, corpus_dir_path: str) -> EvaluationReport:
        """Run evaluation across all fixture files in corpus directory."""
        corpus_dir = Path(corpus_dir_path)
        fixture_files = list(corpus_dir.glob("*.json"))

        results: list[ScenarioEvaluationResult] = []
        for filepath in fixture_files:
            with open(filepath, "r") as f:
                data = json.load(f)

            scenario_name = data.get("scenario_name", filepath.stem)
            raw_payload = data["raw_payload"]
            expected_hitl = data["expected_hitl"]
            expected_action = data.get("expected_action")

            event = self.adapter.parse_and_normalize(raw_payload)
            response = self.agent.evaluate_event(event)

            hitl_matches = response.requires_hitl == expected_hitl
            action_matches = True
            if expected_action and response.suggested_actions:
                action_matches = response.suggested_actions.get("action") == expected_action

            passed = hitl_matches and action_matches
            details = (
                f"HITL Match: {hitl_matches} (Expected: {expected_hitl}, Actual: {response.requires_hitl}) | "
                f"Action Match: {action_matches}"
            )

            results.append(
                ScenarioEvaluationResult(
                    scenario_name=scenario_name,
                    passed=passed,
                    expected_hitl=expected_hitl,
                    actual_hitl=response.requires_hitl,
                    details=details,
                )
            )

        total = len(results)
        passed_count = sum(1 for r in results if r.passed)
        accuracy = (passed_count / total * 100.0) if total > 0 else 0.0
        charter_compliant = accuracy >= 85.0

        return EvaluationReport(
            total_scenarios=total,
            passed_scenarios=passed_count,
            accuracy_percentage=accuracy,
            charter_compliant=charter_compliant,
            scenario_results=results,
        )
