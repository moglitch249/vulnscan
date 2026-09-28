"""VulnScanner CLI — main entry point.

Usage:
    vulnscan scan --target 192.168.1.10
    vulnscan scan --target 10.0.0.0/24 --profile standard
    vulnscan scan --target 10.10.10.5 --scan-file scan.xml
    vulnscan update
    vulnscan cve CVE-2024-12345
    vulnscan search --product apache
    vulnscan sources
    vulnscan health
    vulnscan config
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(
    name="vulnscan",
    help=(
        "VulnScanner — Vulnerability Assessment & Intelligence Framework.\n\n"
        "For authorized security assessments, owned infrastructure, labs, "
        "and CTF environments only."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _get_config(config_file: str | None = None):
    """Load configuration."""
    from vulnscanner.core.config import load_config
    return load_config(config_path=config_file)


def _setup_logging(config):
    """Initialize structured logging."""
    from vulnscanner.core.logging import setup_logging
    setup_logging(
        level=config.logging.level,
        log_format=config.logging.format,
        log_file=config.logging.file,
    )


# =============================================================================
# Scan command
# =============================================================================


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target: IP, hostname, CIDR, or URL"),
    target_file: str | None = typer.Option(None, "--file", "-f", help="File with targets (one per line)"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile: quick|standard|deep|web"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    offline: bool = typer.Option(False, "--offline", help="Use only local/cached vulnerability data"),
    scan_file: str | None = typer.Option(None, "--scan-file", help="Import Nmap XML file instead of scanning"),
    config_file: str | None = typer.Option(None, "--config", help="Path to config.yaml"),
) -> None:
    """Run a vulnerability scan against one or more targets."""
    config = _get_config(config_file)
    _setup_logging(config)

    console.print(Panel.fit(
        "[bold cyan]VulnScanner[/] — Vulnerability Assessment Framework",
        subtitle="Authorized Use Only",
    ))

    # Collect targets
    targets = [target]
    if target_file:
        tf = Path(target_file)
        if tf.exists():
            targets.extend(
                line.strip() for line in tf.read_text().splitlines() if line.strip()
            )

    # Map profile string
    from vulnscanner.core.models import ScanProfile
    profile_map = {
        "quick": ScanProfile.QUICK,
        "standard": ScanProfile.STANDARD,
        "deep": ScanProfile.DEEP,
        "web": ScanProfile.WEB,
    }
    scan_profile = profile_map.get(profile.lower(), ScanProfile.STANDARD)

    console.print(f"\n[bold]Targets:[/]  {', '.join(targets)}")
    console.print(f"[bold]Profile:[/]  {scan_profile.value}")
    console.print(f"[bold]Offline:[/]  {offline}")
    if scan_file:
        console.print(f"[bold]Scan File:[/] {scan_file}")
    console.print()

    # Run scan
    from vulnscanner.core.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator(config)

    try:
        result = asyncio.run(
            orchestrator.run_scan(
                targets=targets,
                profile=scan_profile,
                scan_file=scan_file,
                offline=offline,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/]")
        raise typer.Exit(code=130)
    finally:
        asyncio.run(orchestrator.close())

    # Display summary
    summary = result.summary()
    _display_summary(summary)

    # Display vulnerabilities
    if result.vulnerabilities:
        _display_vulns(result.vulnerabilities)

    # Generate reports
    from vulnscanner.core.reporting.generator import ReportGenerator
    output_dir = output or config.reporting.output_dir
    reporter = ReportGenerator(output_dir=output_dir)
    scan_data = result.to_dict()
    paths = reporter.generate_all(scan_data)

    console.print("\n[bold green]Reports generated:[/]")
    for fmt, path in paths.items():
        console.print(f"  {fmt.upper():>5}: [link=file://{path}]{path}[/link]")

    # Exit code based on findings
    if summary.get("severity", {}).get("critical", 0) > 0:
        raise typer.Exit(code=2)
    if summary.get("severity", {}).get("high", 0) > 0:
        raise typer.Exit(code=1)


# =============================================================================
# CVE lookup
# =============================================================================


@app.command()
def cve(
    cve_id: str = typer.Argument(..., help="CVE identifier (e.g., CVE-2024-12345)"),
    config_file: str | None = typer.Option(None, "--config", help="Path to config.yaml"),
) -> None:
    """Look up a specific CVE across all configured sources."""
    from vulnscanner.core.validators import validate_cve_id, ValidationError

    config = _get_config(config_file)
    _setup_logging(config)

    try:
        cve_id = validate_cve_id(cve_id)
    except ValidationError as exc:
        console.print(f"[red]Invalid CVE format:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]Looking up {cve_id}...[/]\n")

    async def lookup():
        from vulnscanner.core.orchestrator import ScanOrchestrator
        orch = ScanOrchestrator(config)
        records = []
        for source in orch._sources:
            try:
                results = await source.search_cve(cve_id)
                records.extend(results)
            except Exception as exc:
                console.print(f"  [yellow]{source.name}:[/] {exc}")
        await orch.close()
        return records

    records = asyncio.run(lookup())

    if not records:
        console.print(f"[yellow]No results found for {cve_id}[/]")
        return

    # Correlate
    from vulnscanner.core.correlation.engine import CorrelationEngine
    correlated = CorrelationEngine().correlate(records)

    for vuln in correlated:
        _display_vuln_detail(vuln)


# =============================================================================
# Health check
# =============================================================================


@app.command()
def health(
    config_file: str | None = typer.Option(None, "--config", help="Path to config.yaml"),
) -> None:
    """Check health/connectivity of all vulnerability sources."""
    config = _get_config(config_file)
    _setup_logging(config)

    console.print("\n[bold cyan]VulnScanner — Health Check[/]\n")

    from vulnscanner.core.orchestrator import ScanOrchestrator
    orch = ScanOrchestrator(config)
    results = asyncio.run(orch.check_health())
    asyncio.run(orch.close())

    table = Table(title="Source Health")
    table.add_column("Source", style="bold")
    table.add_column("Status")
    table.add_column("Response Time")
    table.add_column("Error")

    for name, data in results.items():
        status = data["status"]
        color = "green" if status == "ok" else "yellow" if status == "rate_limited" else "red"
        rt = f"{data['response_time_ms']:.0f}ms" if data.get("response_time_ms") else "-"
        table.add_row(name, f"[{color}]{status.upper()}[/]", rt, data.get("error") or "-")

    console.print(table)


# =============================================================================
# Sources command
# =============================================================================


@app.command()
def sources(
    config_file: str | None = typer.Option(None, "--config", help="Path to config.yaml"),
) -> None:
    """List all configured vulnerability intelligence sources."""
    config = _get_config(config_file)

    console.print("\n[bold cyan]VulnScanner — Configured Sources[/]\n")

    table = Table()
    table.add_column("Source", style="bold")
    table.add_column("Enabled")
    table.add_column("API/Feed")
    table.add_column("Auth Required")

    source_info = [
        ("NVD", "nvd", "API 2.0", "Optional (API key)"),
        ("CISA KEV", "cisa_kev", "JSON feed", "No"),
        ("OSV", "osv", "REST API", "No"),
        ("EPSS", "epss", "REST API + CSV", "No"),
        ("GHSA", "ghsa", "GraphQL API", "Yes (GitHub PAT)"),
        ("VulnCheck", "vulncheck", "REST API", "Yes (API key)"),
        ("Exploit-DB", "exploitdb", "Git clone", "No"),
        ("Debian Tracker", "debian_tracker", "JSON feed", "No"),
        ("Red Hat", "redhat", "CSAF/VEX API", "No"),
        ("Alpine SecDB", "alpine_secdb", "JSON feed", "No"),
    ]

    for display_name, config_key, api_type, auth in source_info:
        src_conf = config.sources.get(config_key)
        enabled = src_conf.enabled if src_conf else False
        color = "green" if enabled else "dim"
        table.add_row(
            display_name,
            f"[{color}]{'✓' if enabled else '✗'}[/]",
            api_type,
            auth,
        )

    console.print(table)


# =============================================================================
# Config command
# =============================================================================


@app.command()
def config(
    config_file: str | None = typer.Option(None, "--config", help="Path to config.yaml"),
) -> None:
    """Display the current effective configuration (secrets redacted)."""
    cfg = _get_config(config_file)

    console.print("\n[bold cyan]VulnScanner — Current Configuration[/]\n")

    display = cfg.model_dump()
    for key in ("nvd_api_key", "vulncheck_api_key", "github_token"):
        if display.get(key):
            display[key] = "***REDACTED***"

    console.print_json(json.dumps(display, indent=2, default=str))


# =============================================================================
# Search command
# =============================================================================


@app.command()
def search(
    product: str | None = typer.Option(None, "--product", help="Search by product name"),
    vendor: str | None = typer.Option(None, "--vendor", help="Filter by vendor"),
    cpe: str | None = typer.Option(None, "--cpe", help="Search by CPE 2.3 string"),
    config_file: str | None = typer.Option(None, "--config", help="Path to config.yaml"),
) -> None:
    """Search vulnerability databases by product or CPE."""
    config_obj = _get_config(config_file)
    _setup_logging(config_obj)

    if not product and not cpe:
        console.print("[red]Provide --product or --cpe[/]")
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]Searching...[/]\n")

    async def do_search():
        from vulnscanner.core.orchestrator import ScanOrchestrator
        orch = ScanOrchestrator(config_obj)
        records = []
        for source in orch._sources:
            try:
                if cpe and source.supports("search_cpe"):
                    records.extend(await source.search_cpe(cpe))
                elif product and source.supports("search_product"):
                    records.extend(await source.search_product(vendor or "", product))
            except Exception as exc:
                console.print(f"  [yellow]{source.name}:[/] {exc}")
        await orch.close()
        return records

    records = asyncio.run(do_search())

    from vulnscanner.core.correlation.engine import CorrelationEngine
    correlated = CorrelationEngine().correlate(records)

    if not correlated:
        console.print("[yellow]No vulnerabilities found[/]")
        return

    _display_vulns(correlated)


# =============================================================================
# Report command
# =============================================================================


@app.command()
def report(
    scan_json: str = typer.Argument(..., help="Path to scan JSON file"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output directory"),
    config_file: str | None = typer.Option(None, "--config", help="Path to config.yaml"),
) -> None:
    """Generate reports from a previously saved scan JSON."""
    path = Path(scan_json)
    if not path.exists():
        console.print(f"[red]File not found: {scan_json}[/]")
        raise typer.Exit(code=1)

    scan_data = json.loads(path.read_text(encoding="utf-8"))

    from vulnscanner.core.reporting.generator import ReportGenerator
    config_obj = _get_config(config_file)
    output_dir = output or config_obj.reporting.output_dir
    reporter = ReportGenerator(output_dir=output_dir)
    paths = reporter.generate_all(scan_data)

    console.print("\n[bold green]Reports generated:[/]")
    for fmt, p in paths.items():
        console.print(f"  {fmt.upper():>5}: {p}")


# =============================================================================
# Helper display functions
# =============================================================================


def _display_summary(summary: dict) -> None:
    """Display scan summary as a rich panel."""
    severity = summary.get("severity", {})
    lines = [
        f"[bold]Hosts:[/]          {summary.get('total_hosts', 0)}",
        f"[bold]Services:[/]       {summary.get('total_services', 0)}",
        f"[bold]Vulnerabilities:[/] {summary.get('total_vulnerabilities', 0)}",
        "",
        f"[red]Critical:[/] {severity.get('critical', 0)}  "
        f"[yellow]High:[/] {severity.get('high', 0)}  "
        f"[bright_yellow]Medium:[/] {severity.get('medium', 0)}  "
        f"[green]Low:[/] {severity.get('low', 0)}",
        "",
        f"[bold red]KEV:[/]     {summary.get('kev_vulnerabilities', 0)}",
        f"[bold]Exploits:[/] {summary.get('exploit_available', 0)}",
    ]

    errors = summary.get("errors", [])
    if errors:
        lines.append("")
        lines.append("[yellow]Errors:[/]")
        for err in errors[:5]:
            lines.append(f"  • {err}")

    console.print(Panel("\n".join(lines), title="[bold]Scan Summary[/]", border_style="cyan"))


def _display_vulns(vulns: list) -> None:
    """Display vulnerability table."""
    table = Table(title="Vulnerabilities", show_lines=True)
    table.add_column("ID", style="bold cyan", max_width=20)
    table.add_column("Severity", max_width=10)
    table.add_column("CVSS", max_width=6)
    table.add_column("Title", max_width=50)
    table.add_column("KEV", max_width=4)
    table.add_column("EPSS", max_width=8)
    table.add_column("Sources", max_width=20)

    for v in vulns[:50]:  # Cap display
        vid = v.primary_id if hasattr(v, 'primary_id') else v.get('cve_id', '?')
        sev = v.severity.value if hasattr(v, 'severity') else 'unknown'
        cvss = v.max_cvss_score if hasattr(v, 'max_cvss_score') else 0
        title = (v.title or "")[:50] if hasattr(v, 'title') else ""
        kev = "🔴" if (v.kev if hasattr(v, 'kev') else False) else ""
        epss_val = f"{v.epss.score:.3f}" if hasattr(v, 'epss') and v.epss else "-"
        srcs = ", ".join(v.sources) if hasattr(v, 'sources') else ""

        sev_color = {"critical": "red", "high": "yellow", "medium": "bright_yellow",
                     "low": "green"}.get(sev, "dim")

        table.add_row(
            str(vid),
            f"[{sev_color}]{sev.upper()}[/]",
            f"{cvss}" if cvss else "-",
            title,
            kev,
            epss_val,
            srcs,
        )

    console.print(table)


def _display_vuln_detail(vuln) -> None:
    """Display detailed vulnerability information."""
    lines = [
        f"[bold]CVE:[/]        {vuln.cve_id or 'N/A'}",
        f"[bold]GHSA:[/]       {vuln.ghsa_id or 'N/A'}",
        f"[bold]Title:[/]      {vuln.title or 'N/A'}",
        f"[bold]Severity:[/]   {vuln.severity.value.upper()}",
        f"[bold]CVSS:[/]       {vuln.max_cvss_score or 'N/A'}",
    ]

    if vuln.epss:
        lines.append(f"[bold]EPSS:[/]       {vuln.epss.score:.4f} (percentile: {vuln.epss.percentile:.2%})")

    if vuln.kev:
        lines.append(f"[bold red]KEV:[/]        YES — Known exploited in the wild")

    if vuln.exploit_available:
        lines.append(f"[bold yellow]Exploits:[/]   {len(vuln.exploits)} public exploit(s)")

    if vuln.description:
        lines.append(f"\n[bold]Description:[/]\n{vuln.description[:500]}")

    if vuln.fixed_versions:
        lines.append(f"\n[bold green]Fixed in:[/] {', '.join(vuln.fixed_versions[:5])}")

    if vuln.references:
        lines.append(f"\n[bold]References:[/]")
        for ref in vuln.references[:5]:
            if ref:
                lines.append(f"  • {ref}")

    lines.append(f"\n[bold]Sources:[/]    {', '.join(vuln.sources)}")
    lines.append(f"[bold]Confidence:[/] {vuln.confidence:.0%}")

    console.print(Panel("\n".join(lines), title=f"[bold]{vuln.primary_id}[/]", border_style="cyan"))
