from __future__ import annotations

from contracts.models import AppOutput, MetricResult
from dataset.schema import TestCase
from evaluators.base import BaseEvaluator


class CorrectnessEvaluator(BaseEvaluator):
    """
    Evaluates answer correctness using deterministic gold checks.

    This evaluator checks the system's final answer against the
    gold-standard rules defined in the test case:

        must_contain      — every phrase must appear in the answer
        must_contain_any  — at least one phrase must appear in the answer
        must_not_contain  — no phrase may appear in the answer

    All comparisons are case-insensitive.

    Score is computed as the fraction of checks that pass.
    The evaluator passes if all checks pass (score == 1.0).

    This evaluator is fully deterministic and requires no LLM calls,
    making it the fastest and most reliable evaluator in the harness.
    """

    @property
    def name(self) -> str:
        return "correctness"

    def evaluate(self, case: TestCase, output: AppOutput) -> MetricResult:
        """
        Run all gold checks against the final answer.

        Args:
            case:   Test case containing gold check rules.
            output: System output containing the final answer to check.

        Returns:
            MetricResult with score, pass/fail status, and failure reasons.
        """
        answer_lower = output.final_answer.lower()
        failures: list[str] = []
        total_checks = 0

        # ── must_contain: every phrase must be present ──────────────────
        for phrase in case.gold.must_contain:
            total_checks += 1
            if phrase.lower() not in answer_lower:
                failures.append(f"missing required phrase: '{phrase}'")

        # ── must_contain_any: at least one phrase must be present ──────
        if case.gold.must_contain_any:
            total_checks += 1
            found_any = any(
                phrase.lower() in answer_lower
                for phrase in case.gold.must_contain_any
            )
            if not found_any:
                options = ", ".join(f"'{p}'" for p in case.gold.must_contain_any)
                failures.append(f"none of the expected phrases found: {options}")

        # ── must_not_contain: no phrase may be present ─────────────────
        for phrase in case.gold.must_not_contain:
            total_checks += 1
            if phrase.lower() in answer_lower:
                failures.append(f"prohibited phrase found: '{phrase}'")

        # ── Compute score and result ───────────────────────────────────
        if total_checks == 0:
            return MetricResult(
                name=self.name,
                score=1.0,
                passed=True,
                reason="no gold checks defined, passed by default",
            )

        passed_checks = total_checks - len(failures)
        score = passed_checks / total_checks
        passed = len(failures) == 0

        if passed:
            reason = f"all {total_checks} gold checks passed"
        else:
            reason = "; ".join(failures)

        return MetricResult(
            name=self.name,
            score=round(score, 4),
            passed=passed,
            reason=reason,
        )
