"""Report generator — JSON, CSV, and HTML outputs.

Generates scan reports in multiple formats with vulnerability details,
risk assessments, and remediation information.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from vulnscanner.core.logging import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generates scan reports in JSON, CSV, and HTML formats."""

    def __init__(self, output_dir: str = "reports") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(
        self, scan_data: dict[str, Any], base_name: str | None = None
    ) -> dict[str, str]:
        """Generate reports in all formats.

        Args:
            scan_data: Scan result dict from ScanRunResult.to_dict().
            base_name: Base filename (without extension).

        Returns:
            Dict mapping format -> file path.
        """
        if not base_name:
            base_name = f"scan_{datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')}"

        paths: dict[str, str] = {}

        # JSON
        json_path = self._output_dir / f"{base_name}.json"
        self.generate_json(scan_data, str(json_path))
        paths["json"] = str(json_path)

        # CSV
        csv_path = self._output_dir / f"{base_name}.csv"
        self.generate_csv(scan_data, str(csv_path))
        paths["csv"] = str(csv_path)

        # HTML
        html_path = self._output_dir / f"{base_name}.html"
        self.generate_html(scan_data, str(html_path))
        paths["html"] = str(html_path)

        logger.info("reports_generated", paths=paths)
        return paths

    def generate_json(self, scan_data: dict[str, Any], output_path: str) -> None:
        """Generate JSON report."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=2, default=str)

        logger.info("json_report_generated", path=str(path))

    def generate_csv(self, scan_data: dict[str, Any], output_path: str) -> None:
        """Generate CSV report with one row per vulnerability."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        vulns = scan_data.get("vulnerabilities", [])

        headers = [
            "CVE ID", "GHSA ID", "Title", "Severity", "CVSS Score",
            "EPSS Score", "EPSS Percentile", "KEV", "Exploit Available",
            "Vendor", "Product", "Affected Versions", "Fixed Versions",
            "Sources", "Confidence", "References",
        ]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for v in vulns:
                # Get max CVSS
                cvss_scores = v.get("cvss_scores", [])
                max_cvss = max((s.get("base_score", 0) for s in cvss_scores), default=0)

                # EPSS
                epss = v.get("epss") or {}
                epss_score = epss.get("score", "")
                epss_pctl = epss.get("percentile", "")

                # KEV
                kev = "YES" if v.get("kev") else "NO"

                writer.writerow([
                    v.get("cve_id", ""),
                    v.get("ghsa_id", ""),
                    v.get("title", ""),
                    v.get("severity", self._derive_severity(max_cvss)),
                    max_cvss,
                    epss_score,
                    epss_pctl,
                    kev,
                    "YES" if v.get("exploit_available") else "NO",
                    v.get("vendor", ""),
                    v.get("product", ""),
                    "; ".join(v.get("affected_versions", [])[:5]),
                    "; ".join(v.get("fixed_versions", [])[:5]),
                    "; ".join(v.get("sources", [])),
                    v.get("confidence", ""),
                    "; ".join(v.get("references", [])[:3]),
                ])

        logger.info("csv_report_generated", path=str(path), rows=len(vulns))

    def generate_html(self, scan_data: dict[str, Any], output_path: str) -> None:
        """Generate HTML dashboard report."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        summary = scan_data.get("summary", {})
        vulns = scan_data.get("vulnerabilities", [])
        hosts = scan_data.get("hosts", [])
        services = scan_data.get("services", [])
        fingerprints = scan_data.get("fingerprints", [])
        scan_run = scan_data.get("scan_run", {})

        severity = summary.get("severity", {})

        # Sort vulnerabilities by CVSS score descending
        def get_max_cvss(v: dict) -> float:
            scores = v.get("cvss_scores", [])
            return max((s.get("base_score", 0) for s in scores), default=0)

        vulns_sorted = sorted(vulns, key=get_max_cvss, reverse=True)

        html = self._build_html(
            summary=summary,
            vulns=vulns_sorted,
            hosts=hosts,
            services=services,
            fingerprints=fingerprints,
            scan_run=scan_run,
            severity=severity,
        )

        path.write_text(html, encoding="utf-8")
        logger.info("html_report_generated", path=str(path))

    def _build_html(self, **kwargs: Any) -> str:
        """Build the HTML report string."""
        summary = kwargs["summary"]
        vulns = kwargs["vulns"]
        hosts = kwargs["hosts"]
        services = kwargs["services"]
        severity = kwargs["severity"]
        scan_run = kwargs["scan_run"]

        # Build vulnerability rows
        vuln_rows = ""
        for v in vulns:
            cvss_scores = v.get("cvss_scores", [])
            max_cvss = max((s.get("base_score", 0) for s in cvss_scores), default=0)
            sev = self._derive_severity(max_cvss)
            sev_class = f"sev-{sev.lower()}"

            epss = v.get("epss") or {}
            epss_str = f"{epss.get('score', 0):.4f}" if epss.get("score") else "N/A"

            kev_badge = '<span class="badge kev">KEV</span>' if v.get("kev") else ""
            exploit_badge = '<span class="badge exploit">EXPLOIT</span>' if v.get("exploit_available") else ""

            refs = v.get("references", [])[:3]
            refs_html = " ".join(f'<a href="{r}" target="_blank">🔗</a>' for r in refs if r)

            vuln_rows += f"""
            <tr class="{sev_class}">
                <td><code>{v.get('cve_id', v.get('ghsa_id', v.get('osv_id', 'N/A')))}</code></td>
                <td>{v.get('title', '')[:80]}</td>
                <td><span class="severity {sev_class}">{sev}</span></td>
                <td>{max_cvss}</td>
                <td>{epss_str}</td>
                <td>{kev_badge} {exploit_badge}</td>
                <td>{v.get('vendor', '')}</td>
                <td>{v.get('product', '')}</td>
                <td>{'; '.join(v.get('fixed_versions', [])[:3])}</td>
                <td>{refs_html}</td>
            </tr>"""

        # Build host rows
        host_rows = ""
        for h in hosts:
            status_class = "up" if h.get("status") == "up" else "down"
            host_rows += f"""
            <tr>
                <td>{h.get('ip', '')}</td>
                <td>{h.get('hostname', '-')}</td>
                <td><span class="status-{status_class}">{h.get('status', 'unknown')}</span></td>
                <td>{h.get('os_guess', '-')}</td>
            </tr>"""

        # Build service rows
        svc_rows = ""
        for s in services:
            svc_rows += f"""
            <tr>
                <td>{s.get('name', '-')}</td>
                <td>{s.get('product', '-')}</td>
                <td>{s.get('version', '-')}</td>
                <td>{s.get('tunnel', '-')}</td>
                <td><code>{'; '.join(s.get('cpe_raw', []))}</code></td>
            </tr>"""

        # Source status
        sources_status = summary.get("sources_status", {})
        source_badges = ""
        for src, status in sources_status.items():
            cls = "ok" if status == "ok" else "err"
            source_badges += f'<span class="source-badge source-{cls}">{src}: {status.upper()}</span> '

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScanner Report — {scan_run.get('started_at', '')}</title>
<style>
:root {{
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #3b82f6;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #22c55e;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }}
h1 {{ color: var(--accent); margin-bottom: 0.5rem; font-size: 1.8rem; }}
h2 {{ color: var(--text); margin: 2rem 0 1rem; font-size: 1.3rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
.header {{ margin-bottom: 2rem; }}
.header p {{ color: var(--muted); }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; text-align: center; }}
.card .value {{ font-size: 2rem; font-weight: 700; }}
.card .label {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }}
.card.critical .value {{ color: var(--critical); }}
.card.high .value {{ color: var(--high); }}
.card.medium .value {{ color: var(--medium); }}
.card.low .value {{ color: var(--low); }}
.card.kev .value {{ color: #dc2626; }}
table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; margin: 1rem 0; }}
th {{ background: #0f172a; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; padding: 0.8rem; text-align: left; }}
td {{ padding: 0.7rem 0.8rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
tr:hover {{ background: rgba(59,130,246,0.05); }}
code {{ background: rgba(59,130,246,0.1); padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85rem; }}
a {{ color: var(--accent); text-decoration: none; }}
.severity {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
.sev-critical {{ background: rgba(239,68,68,0.2); color: var(--critical); }}
.sev-high {{ background: rgba(249,115,22,0.2); color: var(--high); }}
.sev-medium {{ background: rgba(234,179,8,0.2); color: var(--medium); }}
.sev-low {{ background: rgba(34,197,94,0.2); color: var(--low); }}
.sev-unknown {{ background: rgba(148,163,184,0.2); color: var(--muted); }}
.badge {{ padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.7rem; font-weight: 700; }}
.badge.kev {{ background: rgba(220,38,38,0.2); color: #ef4444; }}
.badge.exploit {{ background: rgba(249,115,22,0.2); color: #f97316; }}
.status-up {{ color: var(--low); }}
.status-down {{ color: var(--muted); }}
.source-badge {{ padding: 0.3rem 0.7rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; display: inline-block; margin: 0.2rem; }}
.source-ok {{ background: rgba(34,197,94,0.15); color: var(--low); }}
.source-err {{ background: rgba(239,68,68,0.15); color: var(--critical); }}
.footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>

<div class="header">
    <h1>🛡️ VulnScanner Report</h1>
    <p>Scan completed: {scan_run.get('completed_at', 'N/A')} | Profile: {scan_run.get('profile', 'standard')}</p>
</div>

<div class="cards">
    <div class="card"><div class="value">{summary.get('total_hosts', 0)}</div><div class="label">Hosts</div></div>
    <div class="card"><div class="value">{summary.get('total_services', 0)}</div><div class="label">Services</div></div>
    <div class="card"><div class="value">{summary.get('total_vulnerabilities', 0)}</div><div class="label">Vulnerabilities</div></div>
    <div class="card critical"><div class="value">{severity.get('critical', 0)}</div><div class="label">Critical</div></div>
    <div class="card high"><div class="value">{severity.get('high', 0)}</div><div class="label">High</div></div>
    <div class="card medium"><div class="value">{severity.get('medium', 0)}</div><div class="label">Medium</div></div>
    <div class="card low"><div class="value">{severity.get('low', 0)}</div><div class="label">Low</div></div>
    <div class="card kev"><div class="value">{summary.get('kev_vulnerabilities', 0)}</div><div class="label">KEV</div></div>
</div>

<h2>Source Status</h2>
<div>{source_badges or '<span class="source-badge source-ok">No sources queried</span>'}</div>

<h2>Discovered Hosts</h2>
<table>
<thead><tr><th>IP</th><th>Hostname</th><th>Status</th><th>OS</th></tr></thead>
<tbody>{host_rows or '<tr><td colspan="4" style="text-align:center;color:var(--muted)">No hosts discovered</td></tr>'}</tbody>
</table>

<h2>Detected Services</h2>
<table>
<thead><tr><th>Service</th><th>Product</th><th>Version</th><th>Tunnel</th><th>CPE</th></tr></thead>
<tbody>{svc_rows or '<tr><td colspan="5" style="text-align:center;color:var(--muted)">No services detected</td></tr>'}</tbody>
</table>

<h2>Vulnerabilities</h2>
<table>
<thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Flags</th><th>Vendor</th><th>Product</th><th>Fix</th><th>Refs</th></tr></thead>
<tbody>{vuln_rows or '<tr><td colspan="10" style="text-align:center;color:var(--muted)">No vulnerabilities found</td></tr>'}</tbody>
</table>

<div class="footer">
    <p>Generated by VulnScanner v{scan_run.get('version', '0.1.0')} — For authorized security assessments only</p>
    <p>⚠️ API keys and sensitive data have been redacted from this report</p>
</div>

</body>
</html>"""

    @staticmethod
    def _derive_severity(cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "CRITICAL"
        if cvss_score >= 7.0:
            return "HIGH"
        if cvss_score >= 4.0:
            return "MEDIUM"
        if cvss_score > 0.0:
            return "LOW"
        return "UNKNOWN"
