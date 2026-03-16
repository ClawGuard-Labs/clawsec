"""Orchestrator — coordinates scanners and produces a ScanReport."""

from __future__ import annotations

from .engine import RuleEngine
from .models import Action, ModelTarget, ScanReport, ScanSummary
from .scanners.base import BaseScanner
from .scanners.format_scanner import FormatScanner
from .scanners.gguf_scanner import GGUFScanner
from .scanners.identity_scanner import IdentityScanner
from .scanners.pickle_scanner import PickleScanner


def default_scanners(engine: RuleEngine) -> list[BaseScanner]:
    """Return the standard Phase-1 scanner set."""
    return [
        FormatScanner(engine),
        PickleScanner(engine),
        GGUFScanner(engine),
        IdentityScanner(engine),
    ]


def run_scan(
    target: ModelTarget,
    engine: RuleEngine | None = None,
    scanners: list[BaseScanner] | None = None,
) -> ScanReport:
    """Run all scanners against a model target and return a complete ScanReport."""
    if engine is None:
        engine = RuleEngine()
    if scanners is None:
        scanners = default_scanners(engine)

    all_findings = []
    for scanner in scanners:
        findings = scanner.scan(target)
        all_findings.extend(findings)

    verdict = engine.apply_verdict(all_findings)

    summary = ScanSummary(
        total_findings=len(all_findings),
        block_count=sum(1 for f in all_findings if f.action == Action.BLOCK),
        warn_count=sum(1 for f in all_findings if f.action == Action.WARN),
        audit_count=sum(1 for f in all_findings if f.action == Action.AUDIT),
    )

    return ScanReport(
        target=target,
        findings=all_findings,
        verdict=verdict,
        summary=summary,
    )
