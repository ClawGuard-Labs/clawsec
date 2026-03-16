"""Report formatters — JSON and colored text output."""

from __future__ import annotations

import json
from typing import TextIO

from rich.console import Console
from rich.table import Table

from .models import Action, ScanReport, Verdict


def to_json(report: ScanReport, indent: int = 2) -> str:
    """Serialize a ScanReport to JSON string."""
    return report.model_dump_json(indent=indent)


def print_text(report: ScanReport, file: TextIO | None = None) -> None:
    """Print a human-readable colored report to the terminal."""
    console = Console(file=file)
    console.print()

    # Header
    console.rule("[bold]AI Security Checker — Scan Report[/bold]")
    console.print(f"  Model:    [cyan]{report.target.model_id}[/cyan]")
    console.print(f"  Platform: {report.target.platform.value}")
    if report.target.path:
        console.print(f"  Path:     {report.target.path}")
    console.print(f"  Time:     {report.timestamp.isoformat()}")
    console.print()

    # Findings table
    if report.findings:
        table = Table(title="Findings", show_lines=True)
        table.add_column("Action", width=7)
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=12)
        table.add_column("Name", width=40)
        table.add_column("Message", ratio=1)

        action_style = {
            Action.BLOCK: "bold red",
            Action.WARN: "bold yellow",
            Action.AUDIT: "dim",
        }

        sorted_findings = sorted(
            report.findings,
            key=lambda f: (
                0 if f.action == Action.BLOCK else 1 if f.action == Action.WARN else 2
            ),
        )

        for f in sorted_findings:
            style = action_style.get(f.action, "")
            table.add_row(
                f"[{style}]{f.action.value}[/{style}]",
                f.severity.value,
                f.rule_id,
                f.rule_name,
                f.message,
            )

        console.print(table)
    else:
        console.print("  [green]No findings.[/green]")

    console.print()

    # Summary
    s = report.summary
    console.print(
        f"  Total: {s.total_findings}  |  "
        f"[red]BLOCK: {s.block_count}[/red]  |  "
        f"[yellow]WARN: {s.warn_count}[/yellow]  |  "
        f"[dim]AUDIT: {s.audit_count}[/dim]"
    )
    console.print()

    # Verdict banner
    if report.verdict == Verdict.BLOCK:
        console.print("[bold white on red]  ✖ VERDICT: BLOCKED — installation denied  [/bold white on red]")
    elif report.verdict == Verdict.WARN:
        console.print("[bold black on yellow]  ⚠ VERDICT: WARNING — review required before installation  [/bold black on yellow]")
    else:
        console.print("[bold white on green]  ✔ VERDICT: PASSED — no blocking or warning findings  [/bold white on green]")

    console.print()
