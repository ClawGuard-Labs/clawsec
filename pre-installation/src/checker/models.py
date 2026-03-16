"""Pydantic data models for the AI Security Checker pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Platform(str, Enum):
    HUGGINGFACE = "huggingface"
    OLLAMA = "ollama"
    LM_STUDIO = "lm-studio"
    LOCAL = "local"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Action(str, Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    AUDIT = "AUDIT"


class Verdict(str, Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    PASS = "PASS"


class ModelTarget(BaseModel):
    """Describes the model being scanned."""

    model_config = {"protected_namespaces": ()}

    model_id: str = Field(description="Model identifier (e.g. meta-llama/Meta-Llama-3-8B or local path)")
    platform: Platform = Platform.LOCAL
    path: Path | None = Field(default=None, description="Local file or directory path")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata (model card, tags, etc.)")


class RuleFinding(BaseModel):
    """A single finding produced by a scanner, mapped to a rule."""

    rule_id: str = Field(description="Rule identifier (e.g. AI-CE-001)")
    rule_name: str
    severity: Severity
    action: Action
    message: str = Field(description="Human-readable description of what was found")
    evidence: str = Field(default="", description="Specific evidence (file path, opcode, etc.)")
    remediation: str = Field(default="")


class ScanSummary(BaseModel):
    """Aggregate counts for a scan report."""

    total_findings: int = 0
    block_count: int = 0
    warn_count: int = 0
    audit_count: int = 0


class ScanReport(BaseModel):
    """Complete scan result for one model target."""

    target: ModelTarget
    findings: list[RuleFinding] = Field(default_factory=list)
    verdict: Verdict = Verdict.PASS
    summary: ScanSummary = Field(default_factory=ScanSummary)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    checker_version: str = "0.1.0"
