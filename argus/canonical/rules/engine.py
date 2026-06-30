"""
Rule protocol + RuleRegistry + RuleEngine.

Each Rule:
  - Has a rule_id and rule_version
  - Implements evaluate(CorrelationResult) -> ProposedDecision | None
  - MUST NOT modify the database
  - MUST be deterministic (same input → same output)

The RuleEngine:
  - Runs all registered rules against a CorrelationResult
  - Collects all ProposedDecisions
  - Resolves conflicts via resolve_conflicts() (most conservative wins)
  - Returns the final ProposedDecision (or None if no rule fires)
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable, Optional
import logging

from canonical.correlation import CorrelationResult
from canonical.rules.proposed_decision import ProposedDecision, resolve_conflicts

logger = logging.getLogger("argus.canonical.rules")


@runtime_checkable
class Rule(Protocol):
    """
    Protocol for all rules.

    A rule takes a CorrelationResult and returns a ProposedDecision
    (if the rule's conditions are met) or None (if the rule doesn't apply).
    """
    rule_id: str
    rule_version: str

    def evaluate(self, correlation: CorrelationResult) -> Optional[ProposedDecision]:
        ...


class RuleRegistry:
    """
    Registry of rules. Rules are registered by rule_id.

    A rule can only be registered once. Re-registration requires
    explicit overwrite=True.
    """

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule, *, overwrite: bool = False) -> None:
        if not rule.rule_id:
            raise ValueError(f"Rule {type(rule).__name__} has empty rule_id")
        if rule.rule_id in self._rules and not overwrite:
            raise ValueError(
                f"Rule already registered: {rule.rule_id}. "
                f"Pass overwrite=True to replace."
            )
        self._rules[rule.rule_id] = rule
        logger.debug("Registered rule: %s v%s", rule.rule_id, rule.rule_version)

    def get(self, rule_id: str) -> Rule:
        if rule_id not in self._rules:
            raise KeyError(f"Rule not registered: {rule_id}")
        return self._rules[rule_id]

    def list_rules(self) -> list[str]:
        return sorted(self._rules.keys())

    def all_rules(self) -> list[Rule]:
        return list(self._rules.values())

    def clear(self) -> None:
        self._rules.clear()

    def __len__(self) -> int:
        return len(self._rules)


class RuleEngine:
    """
    Runs all registered rules against a CorrelationResult and resolves
    conflicts.

    Usage:
        engine = RuleEngine(registry)
        decision = engine.evaluate(correlation_result)
        if decision:
            # send to Decision Engine
    """

    def __init__(self, registry: RuleRegistry) -> None:
        self.registry = registry

    def evaluate(self, correlation: CorrelationResult) -> Optional[ProposedDecision]:
        """
        Run all rules, collect ProposedDecisions, resolve conflicts.

        Returns the winning ProposedDecision (most conservative wins),
        or None if no rule fires.
        """
        decisions: list[ProposedDecision] = []
        for rule in self.registry.all_rules():
            try:
                decision = rule.evaluate(correlation)
                if decision is not None:
                    decisions.append(decision)
                    logger.debug(
                        "Rule %s fired: %s (score=%s)",
                        rule.rule_id, decision.kind.value, decision.correlation_score,
                    )
            except Exception as e:
                logger.error(
                    "Rule %s raised exception during evaluate: %s",
                    rule.rule_id, e, exc_info=True,
                )
                # A rule error doesn't stop other rules from running.
                # But it should be visible — log at error level.

        if not decisions:
            return None

        winner = resolve_conflicts(decisions)
        if winner:
            logger.info(
                "Conflict resolution: %d rules fired, winner=%s (%s)",
                len(decisions), winner.rule_id, winner.kind.value,
            )
        return winner

    def evaluate_all(self, correlation: CorrelationResult) -> list[ProposedDecision]:
        """
        Run all rules and return ALL ProposedDecisions (before conflict resolution).
        Useful for debugging and explainability — shows what each rule said.
        """
        decisions: list[ProposedDecision] = []
        for rule in self.registry.all_rules():
            try:
                decision = rule.evaluate(correlation)
                if decision is not None:
                    decisions.append(decision)
            except Exception as e:
                logger.error("Rule %s raised: %s", rule.rule_id, e)
        return decisions


# Module-level singleton registry
registry: RuleRegistry = RuleRegistry()


__all__ = [
    "Rule", "RuleRegistry", "RuleEngine", "registry",
]
