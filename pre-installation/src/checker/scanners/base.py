"""Base scanner interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..engine import RuleEngine
from ..models import ModelTarget, RuleFinding


class BaseScanner(ABC):
    """All scanner modules must implement this interface."""

    def __init__(self, engine: RuleEngine) -> None:
        self.engine = engine

    @abstractmethod
    def scan(self, target: ModelTarget) -> list[RuleFinding]:
        """Run this scanner against a model target and return findings."""
        ...

    def _finding(self, rule_id: str, message: str, evidence: str = "") -> RuleFinding | None:
        """Helper to create a finding from the rule store."""
        return self.engine.make_finding(rule_id, message, evidence)
