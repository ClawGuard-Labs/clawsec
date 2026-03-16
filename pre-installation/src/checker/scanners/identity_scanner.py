"""Identity scanner — checks model card presence, naming, and training data documentation."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import ModelTarget, RuleFinding
from .base import BaseScanner

DANGEROUS_NAME_PATTERNS = re.compile(
    r"(uncensored|unfiltered|jailbroken|jailbreak|nsfw)", re.IGNORECASE
)

TRAINING_DATA_KEYWORDS = [
    "training data", "training-data", "training_data",
    "dataset", "data source", "data sources",
    "trained on", "fine-tuned on", "finetuned on",
    "pre-training", "pretraining",
]


class IdentityScanner(BaseScanner):
    """Check AI-ID-001 through AI-ID-004: model card and naming rules."""

    def scan(self, target: ModelTarget) -> list[RuleFinding]:
        findings: list[RuleFinding] = []

        self._check_name(target, findings)
        self._check_model_card(target, findings)
        self._check_version_pinning(target, findings)

        return findings

    def _check_name(self, target: ModelTarget, findings: list[RuleFinding]) -> None:
        name = target.model_id
        if target.path:
            name = f"{name} {target.path.name}"
        if DANGEROUS_NAME_PATTERNS.search(name):
            match = DANGEROUS_NAME_PATTERNS.search(name)
            f = self._finding(
                "AI-ID-002",
                f"Model name contains safety-concerning keyword: '{match.group()}'",
                evidence=f"model_id={target.model_id}",
            )
            if f:
                findings.append(f)

    def _check_model_card(self, target: ModelTarget, findings: list[RuleFinding]) -> None:
        if target.path is None:
            return

        path = Path(target.path)
        readme_candidates = []
        if path.is_dir():
            readme_candidates = [
                path / "README.md",
                path / "readme.md",
                path / "MODEL_CARD.md",
                path / "model_card.md",
            ]
        elif path.is_file() and path.parent.is_dir():
            readme_candidates = [
                path.parent / "README.md",
                path.parent / "readme.md",
            ]

        readme_path = next((r for r in readme_candidates if r.is_file()), None)

        if readme_path is None:
            f = self._finding(
                "AI-ID-001",
                "No model card (README.md) found in model directory",
                evidence=f"searched={[str(r) for r in readme_candidates[:2]]}",
            )
            if f:
                findings.append(f)
            return

        try:
            content = readme_path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            return

        has_training_info = any(kw in content for kw in TRAINING_DATA_KEYWORDS)
        if not has_training_info:
            f = self._finding(
                "AI-ID-003",
                "Model card exists but contains no training data or dataset section",
                evidence=f"file={readme_path}",
            )
            if f:
                findings.append(f)

    def _check_version_pinning(self, target: ModelTarget, findings: list[RuleFinding]) -> None:
        model_id = target.model_id
        looks_pinned = (
            len(model_id) >= 40
            and all(c in "0123456789abcdef" for c in model_id.replace("-", "").lower()[-40:])
        )
        if not looks_pinned and "@" not in model_id and "sha256:" not in model_id.lower():
            f = self._finding(
                "AI-ID-004",
                "Model is referenced by name, not by content hash or commit SHA",
                evidence=f"model_id={model_id}",
            )
            if f:
                findings.append(f)
