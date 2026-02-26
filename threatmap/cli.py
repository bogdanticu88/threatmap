"""
threatmap CLI entry point.
"""
import os
import random
import sys
from typing import List, Optional, Tuple

import click
from rich.console import Console
from rich.table import Table

from threatmap import __version__
from threatmap.analyzers import engine
from threatmap.detect import detect_format
from threatmap.models.resource import Resource
from threatmap.models.threat import Severity, Threat
from threatmap.parsers import cloudformation, kubernetes, terraform
from threatmap.reporters import html_reporter, json_reporter, markdown, sarif_reporter

console = Console(stderr=True)

_BANNER = r"""
  _   _                    _
 | |_| |__  _ __ ___  __ _| |_ _ __ ___   __ _ _ __
 | __| '_ \| '__/ _ \/ _` | __| '_ ` _ \ / _` | '_ \
 | |_| | | | | |  __/ (_| | |_| | | | | | (_| | |_) |
  \__|_| |_|_|  \___|\__,_|\__|_| |_| |_|\__,_| .__/
                                               |_|
"""


def _print_banner(no_color: bool = False) -> None:
    c = Console(stderr=True, no_color=no_color)
    c.print(f"[bold red]{_BANNER}[/bold red]")
    c.print(f"  [dim]by Bogdan Ticu[/dim]   [dim]v{__version__}[/dim]")
    
    joke = random.choice(_JOKES)
    c.print(f"  [italic cyan]\"{joke}\"[/italic cyan]\n")

_JOKES = [
    "A SQL query walks into a bar, walks up to two tables, and asks: 'Can I join you?'",
    "Why do security researchers prefer dark mode? Because light attracts bugs.",
    "The 'S' in IoT stands for Security.",
    "STRIDE: Because 'winging it' isn't a security control.",
    "If you think compliance is expensive, try a data breach.",
    "Knock, knock. Who's there? (Long silence...) Java.",
    "Encryption: Turning your secrets into someone else's headache.",
    "My password is the last 8 digits of Pi.",
    "Why did the attacker cross the road? To get to the other (server) side.",
    "There are only 10 types of people: those who understand binary, and those who don't."
]

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}

_SEVERITY_ASCII = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
    "INFO": "[INFO]",
}


def _collect_files(paths: Tuple[str, ...]) -> List[str]:
    """Expand directories into file paths."""
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for root, _, fnames in os.walk(p):
                for fname in fnames:
                    files.append(os.path.join(root, fname))
        else:
            console.print(f"[yellow]Warning:[/yellow] '{p}' does not exist, skipping.")
    return files


def _parse_files(file_paths: List[str]) -> List[Resource]:
    resources: List[Resource] = []
    for fp in file_paths:
        fmt = detect_format(fp)
        if fmt == "terraform":
            resources.extend(terraform.parse_file(fp))
        elif fmt == "cloudformation":
            resources.extend(cloudformation.parse_file(fp))
        elif fmt == "kubernetes":
            resources.extend(kubernetes.parse_file(fp))
        else:
            console.print(f"[dim]Skipping unsupported file:[/dim] {fp}")
    return resources


def _print_summary_table(threats: List[Threat], no_color: bool, ascii_mode: bool = False) -> None:
    """Print a rich summary table to stderr."""
    tbl = Table(title="Threat Summary", show_header=True, header_style="bold")
    tbl.add_column("ID", style="dim", width=7)
    tbl.add_column("Severity", width=12 if ascii_mode else 10)
    tbl.add_column("STRIDE", width=25)
    tbl.add_column("Resource", width=30)
    tbl.add_column("Description")

    for t in threats:
        color = _SEVERITY_COLORS.get(t.severity.value, "") if not no_color else ""
        sev_val = _SEVERITY_ASCII.get(t.severity.value, t.severity.value) if ascii_mode else t.severity.value
        tbl.add_row(
            t.threat_id,
            f"[{color}]{sev_val}[/{color}]" if color else sev_val,
            t.stride_category.value,
            t.resource_name,
            t.description[:80] + "…" if len(t.description) > 80 else t.description,
        )

    Console(stderr=True).print(tbl)


def _count_by_severity(threats: List[Threat]) -> dict:
    return {s.value: sum(1 for t in threats if t.severity == s) for s in Severity}


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option(__version__)
@click.pass_context
def cli(ctx):
    """threatmap — static IaC threat modeler using STRIDE."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        ctx.exit()


@cli.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path())
@click.option(
    "--format", "output_format",
    type=click.Choice(["markdown", "json", "sarif", "html"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write report to this file (default: stdout).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM"], case_sensitive=False),
    default=None,
    help="Exit with code 1 if any threat at or above this severity is found (for CI gates).",
)
@click.option(
    "--summary",
    is_flag=True,
    default=False,
    help="Print terminal summary table only, do not write a full report.",
)
@click.option(
    "--ascii",
    is_flag=True,
    default=False,
    help="Use ASCII-only severity indicators (no emojis).",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable rich terminal color output.",
)
def scan(
    paths: Tuple[str, ...],
    output_format: str,
    output: Optional[str],
    fail_on: Optional[str],
    summary: bool,
    ascii: bool,
    no_color: bool,
) -> None:
    """
    Scan IaC files or directories for STRIDE threats.

    PATHS can be files or directories; multiple values accepted.
    """
    _print_banner(no_color)
    stderr = Console(stderr=True, no_color=no_color)
    source_label = ", ".join(paths)

    # 1. Collect and parse
    with stderr.status("[bold]Collecting files…"):
        file_paths = _collect_files(paths)

    if not file_paths:
        stderr.print("[red]No files found.[/red]")
        sys.exit(2)

    with stderr.status(f"[bold]Parsing {len(file_paths)} file(s)…"):
        try:
            resources = _parse_files(file_paths)
        except Exception as exc:
            stderr.print(f"[red]Parse error:[/red] {exc}")
            sys.exit(2)

    if not resources:
        stderr.print("[yellow]No IaC resources found in the provided paths.[/yellow]")
        sys.exit(0)

    stderr.print(f"Found [bold]{len(resources)}[/bold] resources.")

    # 2. Analyze
    with stderr.status("[bold]Running STRIDE analysis…"):
        threats = engine.run(resources)

    counts = _count_by_severity(threats)
    stderr.print(
        f"Identified [bold]{len(threats)}[/bold] threats — "
        + "  ".join(
            f"[{_SEVERITY_COLORS.get(s, '')}]{s}: {counts[s]}[/{_SEVERITY_COLORS.get(s, '')}]"
            for s in _SEVERITY_ORDER
            if counts[s] > 0
        )
    )

    # 3. Print terminal summary table when writing to file, or when --summary is requested
    if summary or output:
        _print_summary_table(threats, no_color, ascii_mode=ascii)

    # 4. Generate report
    if not summary:
        fmt = output_format.lower()
        if fmt == "json":
            report_content = json_reporter.build_report(resources, threats, source_label)
        elif fmt == "sarif":
            report_content = sarif_reporter.build_report(resources, threats, source_label)
        elif fmt == "html":
            report_content = html_reporter.build_report(resources, threats, source_label)
        else:
            report_content = markdown.build_report(resources, threats, source_label, ascii_mode=ascii)

        if output:
            with open(output, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(report_content)
            stderr.print(f"Report written to [bold]{output}[/bold]")
        else:
            # Print report to stdout
            click.echo(report_content)

    # 5. CI gate
    if fail_on:
        threshold_rank = _SEVERITY_ORDER.index(fail_on.upper())
        for sev in _SEVERITY_ORDER[: threshold_rank + 1]:
            if counts.get(sev, 0) > 0:
                stderr.print(
                    f"[red]CI gate triggered:[/red] {counts[sev]} {sev} threat(s) found "
                    f"(--fail-on {fail_on})."
                )
                sys.exit(1)

    sys.exit(0)


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
