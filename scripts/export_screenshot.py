"""
Generates a terminal screenshot SVG of a threatmap scan run.
Usage: python scripts/export_screenshot.py
Output: threatmap_screenshot.svg
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.text import Text

# ── constants ────────────────────────────────────────────────────────────────
WIDTH = 100
OUTPUT = "threatmap_screenshot.svg"

BANNER = r"""
  _   _                    _
 | |_| |__  _ __ ___  __ _| |_ _ __ ___   __ _ _ __
 | __| '_ \| '__/ _ \/ _` | __| '_ ` _ \ / _` | '_ \
 | |_| | | | | |  __/ (_| | |_| | | | | | (_| | |_) |
  \__|_| |_|_|  \___|\__,_|\__|_| |_| |_|\__,_| .__/
                                               |_|
"""

THREATS = [
    ("T-001", "CRITICAL", "Elevation of Privilege",   "admin_role",         "IAM role trust policy allows Principal:* — any entity can assume this role."),
    ("T-002", "CRITICAL", "Spoofing",                 "open_sg",            "Security group exposes SSH/RDP (port 22/3389) to 0.0.0.0/0."),
    ("T-003", "CRITICAL", "Information Disclosure",   "data_bucket",        "S3 bucket has no public access block configured."),
    ("T-004", "CRITICAL", "Elevation of Privilege",   "wildcard_policy",    "IAM policy grants Action:* on Resource:* — full admin access."),
    ("T-005", "HIGH",     "Information Disclosure",   "main_db",            "RDS instance is publicly accessible from the internet."),
    ("T-006", "HIGH",     "Elevation of Privilege",   "insecure-api",       "Container 'api' runs as privileged — full host kernel access."),
    ("T-007", "HIGH",     "Information Disclosure",   "main_cluster",       "EKS API server is publicly accessible without CIDR restrictions."),
    ("T-008", "HIGH",     "Elevation of Privilege",   "web",                "EC2 instance allows IMDSv1 — SSRF-based credential theft possible."),
    ("T-009", "MEDIUM",   "Repudiation",              "data_bucket",        "S3 bucket does not have access logging enabled."),
    ("T-010", "MEDIUM",   "Tampering",                "insecure-api",       "Container does not enforce a read-only root filesystem."),
]

SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}

# ── build ─────────────────────────────────────────────────────────────────────
c = Console(record=True, width=WIDTH)

# Banner
c.print(f"[bold red]{BANNER}[/bold red]")
c.print("  [dim]by Bogdan Ticu[/dim]   [dim]v1.0.0[/dim]\n")

# Simulated scan status lines
c.print("[bold]$[/bold] threatmap scan ./infra/ --output report.md --fail-on HIGH\n")
c.print("  Found [bold]43[/bold] resources across terraform, cloudformation, kubernetes.")
c.print("  Identified [bold]85[/bold] threats — "
        "[bold red]CRITICAL: 18[/bold red]  "
        "[red]HIGH: 42[/red]  "
        "[yellow]MEDIUM: 24[/yellow]  "
        "[green]LOW: 1[/green]\n")

# Threat table
tbl = Table(
    title="Threat Summary (top 10 of 85)",
    show_header=True,
    header_style="bold white on grey23",
    border_style="grey50",
    width=WIDTH - 2,
)
tbl.add_column("ID",       style="dim",         width=7,  no_wrap=True)
tbl.add_column("Severity",                      width=10, no_wrap=True)
tbl.add_column("STRIDE",                        width=25, no_wrap=True)
tbl.add_column("Resource",                      width=18, no_wrap=True)
tbl.add_column("Description")

for tid, sev, stride, resource, desc in THREATS:
    style = SEV_STYLE.get(sev, "")
    tbl.add_row(
        tid,
        f"[{style}]{sev}[/{style}]",
        stride,
        resource,
        desc,
    )

c.print(tbl)
c.print("\n  [bold green]✓[/bold green] Report written to [bold]report.md[/bold]")
c.print("  [bold red]✗[/bold red] CI gate triggered — 18 CRITICAL threat(s) found [dim](--fail-on HIGH)[/dim]")

# ── export ────────────────────────────────────────────────────────────────────
svg = c.export_svg(title="threatmap — IaC threat modeler")
with open(OUTPUT, "w") as fh:
    fh.write(svg)

print(f"Saved: {OUTPUT}")
