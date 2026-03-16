"""Rule engine — loads YAML rules and applies verdict logic."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Action, RuleFinding, Verdict

# Default rules directory: pre-installation/rules/ relative to this file
_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


class RuleEngine:
    """Loads the YAML rule store and provides lookup + verdict logic."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or _DEFAULT_RULES_DIR
        self._rules: dict[str, dict[str, Any]] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        if not self._rules_dir.is_dir():
            raise FileNotFoundError(f"Rules directory not found: {self._rules_dir}")
        for path in sorted(self._rules_dir.rglob("*.yaml")):
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and "rule_id" in data:
                self._rules[data["rule_id"]] = data

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        return self._rules.get(rule_id)

    def list_rules(self) -> list[dict[str, Any]]:
        return list(self._rules.values())

    def make_finding(self, rule_id: str, message: str, evidence: str = "") -> RuleFinding | None:
        """Create a RuleFinding from a rule_id, filling metadata from the rule store."""
        rule = self.get_rule(rule_id)
        if rule is None:
            return None
        return RuleFinding(
            rule_id=rule_id,
            rule_name=rule.get("name", ""),
            severity=rule.get("severity", "INFO"),
            action=rule.get("action", "AUDIT"),
            message=message,
            evidence=evidence,
            remediation=rule.get("remediation", ""),
        )

    @staticmethod
    def apply_verdict(findings: list[RuleFinding]) -> Verdict:
        """Determine overall verdict from a list of findings.

        BLOCK if any finding has action=BLOCK, else WARN if any WARN, else PASS.
        """
        has_block = any(f.action == Action.BLOCK for f in findings)
        if has_block:
            return Verdict.BLOCK
        has_warn = any(f.action == Action.WARN for f in findings)
        if has_warn:
            return Verdict.WARN
        return Verdict.PASS
