"""CLI entry point — Typer-based command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from .engine import RuleEngine
from .models import ModelTarget, Platform
from .orchestrator import run_scan
from .report import print_text, to_json

app = typer.Typer(
    name="checker",
    help="AI Security Checker — pre-installation model scanning",
    add_completion=False,
)


@app.command()
def scan(
    path: Path = typer.Option(..., "--path", "-p", help="Path to model file or directory"),
    model_id: Optional[str] = typer.Option(None, "--model", "-m", help="Model identifier (defaults to path basename)"),
    platform: str = typer.Option("local", "--platform", help="Platform: local, huggingface, ollama, lm-studio"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report to file"),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format: text or json"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", help="Override rules directory"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
) -> None:
    """Scan a model file or directory against the pre-installation security ruleset."""
    if not path.exists():
        typer.echo(f"Error: path does not exist: {path}", err=True)
        raise typer.Exit(code=2)

    target = ModelTarget(
        model_id=model_id or path.name,
        platform=Platform(platform),
        path=path,
    )

    engine = RuleEngine(rules_dir=rules_dir)

    if verbose:
        typer.echo(f"Loaded {engine.rule_count} rules")
        typer.echo(f"Scanning: {path}")

    report = run_scan(target=target, engine=engine)

    if fmt == "json" or output:
        json_str = to_json(report)
        if output:
            output.write_text(json_str, encoding="utf-8")
            if verbose:
                typer.echo(f"Report written to {output}")
        if fmt == "json":
            typer.echo(json_str)
    else:
        print_text(report)

    if report.verdict.value == "BLOCK":
        raise typer.Exit(code=1)


@app.command(name="list-rules")
def list_rules(
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", help="Override rules directory"),
) -> None:
    """List all loaded rules with their action and severity."""
    engine = RuleEngine(rules_dir=rules_dir)
    typer.echo(f"Loaded {engine.rule_count} rules\n")
    typer.echo(f"{'Rule ID':<12} {'Action':<8} {'Severity':<10} {'Name'}")
    typer.echo("-" * 80)
    for rule in sorted(engine.list_rules(), key=lambda r: r["rule_id"]):
        typer.echo(f"{rule['rule_id']:<12} {rule['action']:<8} {rule['severity']:<10} {rule['name']}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
