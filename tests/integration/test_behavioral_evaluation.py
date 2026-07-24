"""Integration test running BehavioralEvaluator over alert corpus and asserting accuracy >= 85%."""

from sentinel_ai.evaluation.evaluator import BehavioralEvaluator


def test_behavioral_evaluation_suite():
    evaluator = BehavioralEvaluator()
    report = evaluator.evaluate_corpus("tests/fixtures/alert_corpus")

    assert report.total_scenarios >= 3
    assert report.passed_scenarios == report.total_scenarios
    assert report.accuracy_percentage == 100.0
    assert report.charter_compliant is True
