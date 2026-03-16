"""End-to-end and unit tests for the AI Security Checker Phase 1."""

from __future__ import annotations

from pathlib import Path

import pytest

from checker.engine import RuleEngine
from checker.models import Action, ModelTarget, Platform, Verdict
from checker.orchestrator import run_scan

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class TestRuleEngine:
    def test_loads_all_rules(self):
        engine = RuleEngine()
        assert engine.rule_count == 43

    def test_get_rule(self):
        engine = RuleEngine()
        rule = engine.get_rule("AI-CE-001")
        assert rule is not None
        assert rule["action"] == "BLOCK"
        assert rule["severity"] == "CRITICAL"

    def test_get_unknown_rule(self):
        engine = RuleEngine()
        assert engine.get_rule("AI-XX-999") is None

    def test_make_finding(self):
        engine = RuleEngine()
        finding = engine.make_finding("AI-CE-001", "test message", "test evidence")
        assert finding is not None
        assert finding.action == Action.BLOCK
        assert finding.rule_id == "AI-CE-001"

    def test_verdict_block(self):
        engine = RuleEngine()
        f1 = engine.make_finding("AI-CE-001", "bad pickle")
        f2 = engine.make_finding("AI-ID-004", "not pinned")
        assert RuleEngine.apply_verdict([f1, f2]) == Verdict.BLOCK

    def test_verdict_warn(self):
        engine = RuleEngine()
        f1 = engine.make_finding("AI-MF-001", "pickle exists")
        f2 = engine.make_finding("AI-ID-004", "not pinned")
        assert RuleEngine.apply_verdict([f1, f2]) == Verdict.WARN

    def test_verdict_pass(self):
        engine = RuleEngine()
        f1 = engine.make_finding("AI-ID-004", "not pinned")
        assert RuleEngine.apply_verdict([f1]) == Verdict.PASS

    def test_verdict_empty(self):
        assert RuleEngine.apply_verdict([]) == Verdict.PASS


# ---------------------------------------------------------------------------
# End-to-end: clean model -> PASS (only AUDIT findings expected)
# ---------------------------------------------------------------------------

class TestCleanModel:
    def test_clean_model_passes(self):
        target = ModelTarget(
            model_id="clean-test-model",
            platform=Platform.LOCAL,
            path=FIXTURES / "clean_model",
        )
        report = run_scan(target)
        assert report.verdict in (Verdict.PASS,)
        assert report.summary.block_count == 0
        assert report.summary.warn_count == 0


# ---------------------------------------------------------------------------
# End-to-end: malicious pickle -> BLOCK
# ---------------------------------------------------------------------------

class TestMaliciousPickle:
    def test_malicious_pickle_blocked(self):
        target = ModelTarget(
            model_id="malicious-pickle-test",
            platform=Platform.LOCAL,
            path=FIXTURES / "malicious_pickle",
        )
        report = run_scan(target)
        assert report.verdict == Verdict.BLOCK
        assert report.summary.block_count >= 1
        block_ids = [f.rule_id for f in report.findings if f.action == Action.BLOCK]
        assert "AI-CE-001" in block_ids


# ---------------------------------------------------------------------------
# End-to-end: malicious GGUF (SSTI template) -> WARN
# ---------------------------------------------------------------------------

class TestMaliciousGGUF:
    def test_gguf_ssti_warned(self):
        target = ModelTarget(
            model_id="malicious-gguf-test",
            platform=Platform.LOCAL,
            path=FIXTURES / "malicious_gguf",
        )
        report = run_scan(target)
        warn_ids = [f.rule_id for f in report.findings if f.action == Action.WARN]
        assert "AI-MF-002" in warn_ids


# ---------------------------------------------------------------------------
# End-to-end: uncensored model name -> WARN
# ---------------------------------------------------------------------------

class TestUncensoredModel:
    def test_uncensored_name_warned(self):
        target = ModelTarget(
            model_id="dolphin-uncensored-7b",
            platform=Platform.LOCAL,
            path=FIXTURES / "uncensored_model",
        )
        report = run_scan(target)
        warn_ids = [f.rule_id for f in report.findings if f.action == Action.WARN]
        assert "AI-ID-002" in warn_ids


# ---------------------------------------------------------------------------
# End-to-end: no README model -> WARN (AI-ID-001)
# ---------------------------------------------------------------------------

class TestNoReadmeModel:
    def test_no_readme_warned(self):
        target = ModelTarget(
            model_id="no-readme-model",
            platform=Platform.LOCAL,
            path=FIXTURES / "no_readme_model",
        )
        report = run_scan(target)
        warn_ids = [f.rule_id for f in report.findings if f.action == Action.WARN]
        assert "AI-ID-001" in warn_ids


# ---------------------------------------------------------------------------
# End-to-end: version pinning -> AUDIT (AI-ID-004)
# ---------------------------------------------------------------------------

class TestVersionPinning:
    def test_unpinned_model_audit(self):
        target = ModelTarget(
            model_id="meta-llama/Llama-3-8B",
            platform=Platform.LOCAL,
            path=FIXTURES / "clean_model",
        )
        report = run_scan(target)
        audit_ids = [f.rule_id for f in report.findings if f.action == Action.AUDIT]
        assert "AI-ID-004" in audit_ids
