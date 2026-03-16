"""Format scanner — detects model file types and flags risky serialization formats."""

from __future__ import annotations

from pathlib import Path

from ..models import ModelTarget, RuleFinding
from .base import BaseScanner

PICKLE_EXTENSIONS = {".pkl", ".pt", ".pth", ".bin"}
SAFETENSORS_EXTENSION = ".safetensors"
HIGH_RISK_EXTENSIONS = {".ckpt", ".joblib", ".dill"}


class FormatScanner(BaseScanner):
    """Check AI-MF-001 (pickle when safetensors exists) and AI-MF-003 (high-risk formats)."""

    def scan(self, target: ModelTarget) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        if target.path is None:
            return findings

        path = Path(target.path)
        files = list(path.rglob("*")) if path.is_dir() else [path]

        extensions = {f.suffix.lower() for f in files if f.is_file()}
        pickle_files = [f for f in files if f.is_file() and f.suffix.lower() in PICKLE_EXTENSIONS]
        high_risk_files = [f for f in files if f.is_file() and f.suffix.lower() in HIGH_RISK_EXTENSIONS]
        has_safetensors = SAFETENSORS_EXTENSION in extensions

        if pickle_files and has_safetensors:
            names = ", ".join(f.name for f in pickle_files[:5])
            f = self._finding(
                "AI-MF-001",
                f"Pickle-based files found when safetensors alternative exists: {names}",
                evidence=names,
            )
            if f:
                findings.append(f)

        for hrf in high_risk_files:
            f = self._finding(
                "AI-MF-003",
                f"High-risk serialization format detected: {hrf.name}",
                evidence=str(hrf),
            )
            if f:
                findings.append(f)

        return findings
