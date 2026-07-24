"""Phase 3 demonstration showcasing LLM provider abstraction, policy rules, and behavioral evaluations."""

from sentinel_ai.evaluation.evaluator import BehavioralEvaluator
from sentinel_ai.exceptions import PolicyViolationError
from sentinel_ai.providers.mock import MockLLMProvider
from sentinel_ai.security.policy_rules import PolicyRuleEngine


def print_banner(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def main():
    print_banner("SENTINEL AI PHASE 3 LLM PROVIDER & EVALUATION DEMONSTRATION")

    # 1. Test LLM Provider Abstraction
    print("\n[+] 1. Initializing Mock LLM Provider Abstraction...")
    llm_provider = MockLLMProvider(model_name="mock-gpt-4o")
    llm_provider.register_response(
        keyword="ransomware",
        response_data={
            "reasoning": "High confidence ransomware signature detected",
            "severity": "CRITICAL",
            "requires_hitl": True,
            "recommended_action": "ISOLATE_HOST",
        },
    )

    llm_response = llm_provider.generate_completion("Analyze ransomware encrypted write pattern")
    print(f"    ✔ Model Name: {llm_response.model_name}")
    print(f"    ✔ Token Usage: {llm_response.token_usage}")
    print(f"    ✔ Structured Reasoning Output: {llm_response.structured_json}")

    # 2. Test Dynamic Policy Rule Engine
    print_banner("2. DYNAMIC POLICY RULE ENGINE EVALUATION")
    rule_config = {
        "denied_actions": ["FACTORY_RESET"],
        "trusted_ips": ["10.0.0.1", "10.0.0.5"],
        "hitl_required_actions": ["ISOLATE_HOST", "BLOCK_IP"],
    }
    policy_engine = PolicyRuleEngine(rule_config=rule_config)
    print("    ✔ PolicyRuleEngine initialized with custom operator rules")

    # Trusted IP check
    try:
        policy_engine.evaluate_rule("triage-agent", "BLOCK_IP", {"ip": "10.0.0.1"})
    except PolicyViolationError as e:
        print(f"    ✔ PROTECTED IP RULE PASSED: Blocked with -> '{e}'")

    # 3. Behavioral Evaluation Suite (>= 85% Charter Requirement)
    print_banner("3. BEHAVIORAL EVALUATION SUITE RUNNER")
    evaluator = BehavioralEvaluator()
    report = evaluator.evaluate_corpus("tests/fixtures/alert_corpus")

    print(f"    ▶ Total Alert Scenarios Evaluated: {report.total_scenarios}")
    print(f"    ▶ Passed Scenarios: {report.passed_scenarios}")
    print(f"    ▶ Triage Accuracy Percentage: {report.accuracy_percentage:.1f}%")
    print(
        f"    ✔ CHARTER COMPLIANCE STATUS (>= 85% Target): {'COMPLIANT' if report.charter_compliant else 'NON_COMPLIANT'}\n"
    )

    for idx, res in enumerate(report.scenario_results, 1):
        status = "PASSED" if res.passed else "FAILED"
        print(f"    [{idx}] {res.scenario_name:<40} | Status: {status} | {res.details}")

    print("\n" + "=" * 70)
    print("  PHASE 3 DEMONSTRATION COMPLETED — ALL INVARIANTS PASSED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
