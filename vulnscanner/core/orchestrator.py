"""Scan orchestrator — ties all components together.

Coordinates:
  1. Target validation
  2. Nmap scanning
  3. Fingerprint normalization
  4. Vulnerability querying across all sources
  5. Correlation & deduplication
  6. EPSS enrichment
  7. KEV enrichment
  8. Risk scoring
  9. Report generation
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from vulnscanner.core.config import AppConfig
from vulnscanner.core.correlation.engine import CorrelationEngine
from vulnscanner.core.fingerprint.engine import FingerprintEngine
from vulnscanner.core.interfaces import VulnerabilitySource
from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    FingerprintResult,
    Finding,
    ScanProfile,
    ScanRun,
    SourceStatus,
    VulnerabilityRecord,
)
from vulnscanner.core.risk.engine import RiskEngine
from vulnscanner.core.scanner_base import ScanResult
from vulnscanner.core.validators import validate_target
from vulnscanner.integrations.nmap.scanner import NmapScanner
from vulnscanner.sources.epss.source import EPSSSource
from vulnscanner.sources.ghsa.source import GHSASource
from vulnscanner.sources.kev.source import KEVSource
from vulnscanner.sources.nvd.source import NVDSource
from vulnscanner.sources.osv.source import OSVSource

logger = get_logger(__name__)


class ScanOrchestrator:
    """Main scan orchestrator coordinating all framework components."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._scan_run = ScanRun(profile=ScanProfile.STANDARD)

        # Initialize components
        self._nmap = NmapScanner(
            nmap_binary=config.tools.get("nmap", type("", (), {"binary": "nmap"})()).binary
            if "nmap" in config.tools else "nmap",
            timeout=config.tools.get("nmap", type("", (), {"timeout": 600})()).timeout
            if "nmap" in config.tools else 600,
            scan_run_id=self._scan_run.id,
        )
        self._fingerprinter = FingerprintEngine()
        self._correlator = CorrelationEngine()
        self._risk_engine = RiskEngine()

        # Initialize vulnerability sources
        self._sources: list[VulnerabilitySource] = []
        self._init_sources()

        # Concurrency control
        self._semaphore = asyncio.Semaphore(config.max_concurrency)

    def _init_sources(self) -> None:
        """Initialize enabled vulnerability sources."""
        config = self._config

        # NVD
        nvd_conf = config.sources.get("nvd")
        if nvd_conf and nvd_conf.enabled:
            self._nvd = NVDSource(
                api_key=config.nvd_api_key,
                request_delay=nvd_conf.request_delay_s or 6.0,
            )
            self._sources.append(self._nvd)
        else:
            self._nvd = None

        # KEV
        kev_conf = config.sources.get("cisa_kev")
        if kev_conf and kev_conf.enabled:
            self._kev = KEVSource()
            self._sources.append(self._kev)
        else:
            self._kev = None

        # OSV
        osv_conf = config.sources.get("osv")
        if osv_conf and osv_conf.enabled:
            self._osv = OSVSource()
            self._sources.append(self._osv)
        else:
            self._osv = None

        # EPSS
        epss_conf = config.sources.get("epss")
        if epss_conf and epss_conf.enabled:
            self._epss = EPSSSource()
        else:
            self._epss = None

        # GHSA
        ghsa_conf = config.sources.get("ghsa")
        if ghsa_conf and ghsa_conf.enabled:
            self._ghsa = GHSASource(github_token=config.github_token)
            self._sources.append(self._ghsa)
        else:
            self._ghsa = None

    async def run_scan(
        self,
        targets: list[str],
        profile: ScanProfile = ScanProfile.STANDARD,
        scan_file: str | None = None,
        offline: bool = False,
    ) -> ScanRunResult:
        """Execute a complete scan pipeline.

        Args:
            targets: List of raw target strings.
            profile: Scan profile.
            scan_file: Optional Nmap XML file to import instead of scanning.
            offline: If True, skip external API queries.

        Returns:
            ScanRunResult with all findings.
        """
        self._scan_run.profile = profile
        self._scan_run.offline_mode = offline
        start_time = datetime.utcnow()
        self._scan_run.started_at = start_time

        logger.info("scan_started", targets=targets, profile=profile.value, offline=offline)

        # 1. Validate targets
        validated_targets = []
        for raw in targets:
            try:
                spec = validate_target(raw)
                validated_targets.append(spec)
                self._scan_run.targets.append(spec)
            except Exception as exc:
                logger.error("target_validation_failed", target=raw, error=str(exc))
                self._scan_run.errors.append(f"Invalid target: {raw} ({exc})")

        if not validated_targets and not scan_file:
            return ScanRunResult(self._scan_run, [], [], [], [])

        # 2. Discovery (Nmap)
        target_strings = [t.raw for t in validated_targets]
        if scan_file:
            logger.info("importing_scan_file", file=scan_file)
            scan_result = await self._nmap.scan_from_file(scan_file)
        else:
            logger.info("nmap_scan_starting", targets=target_strings, profile=profile.value)
            scan_result = await self._nmap.scan(target_strings, profile)

        if scan_result.has_errors:
            for err in scan_result.errors:
                self._scan_run.errors.append(err)
                logger.error("scan_error", error=err)

        self._scan_run.total_hosts = scan_result.host_count
        self._scan_run.total_ports = scan_result.port_count
        self._scan_run.total_services = scan_result.service_count

        logger.info(
            "discovery_complete",
            hosts=scan_result.host_count,
            ports=scan_result.port_count,
            services=scan_result.service_count,
        )

        # 3. Fingerprint normalization
        fingerprints = self._fingerprinter.fingerprint_services(scan_result.services)
        logger.info("fingerprinting_complete", fingerprints=len(fingerprints))

        # 4. Vulnerability lookup (skip if offline and no local data)
        all_vuln_records: list[VulnerabilityRecord] = []

        if not offline:
            vuln_records = await self._query_vulnerabilities(fingerprints)
            all_vuln_records.extend(vuln_records)

        # 5. Correlation & deduplication
        correlated = self._correlator.correlate(all_vuln_records)
        logger.info("correlation_complete", raw=len(all_vuln_records), correlated=len(correlated))

        # 6. EPSS enrichment
        if self._epss and not offline:
            correlated = await self._enrich_epss(correlated)

        # 7. KEV enrichment
        if self._kev and not offline:
            correlated = await self._enrich_kev(correlated)

        # 8. Risk scoring
        risk_assessments = self._risk_engine.assess_batch(correlated)

        self._scan_run.total_vulnerabilities = len(correlated)
        self._scan_run.completed_at = datetime.utcnow()

        logger.info(
            "scan_completed",
            hosts=self._scan_run.total_hosts,
            services=self._scan_run.total_services,
            vulnerabilities=len(correlated),
            duration=str(self._scan_run.completed_at - start_time),
        )

        return ScanRunResult(
            scan_run=self._scan_run,
            scan_result=scan_result,
            fingerprints=fingerprints,
            vulnerabilities=correlated,
            risk_assessments=risk_assessments,
        )

    async def _query_vulnerabilities(
        self, fingerprints: list[FingerprintResult]
    ) -> list[VulnerabilityRecord]:
        """Query all enabled sources for each fingerprint."""
        all_records: list[VulnerabilityRecord] = []

        for fp in fingerprints:
            tasks = []
            for source in self._sources:
                # Query by CPE if available
                if fp.cpe and source.supports("search_cpe"):
                    tasks.append(self._safe_query(source, "cpe", fp.cpe))
                # Query by product
                elif source.supports("search_product"):
                    tasks.append(self._safe_query(
                        source, "product", fp.vendor, fp.product, fp.version
                    ))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, list):
                        all_records.extend(result)
                    elif isinstance(result, Exception):
                        logger.warning("query_failed", error=str(result))

        return all_records

    async def _safe_query(
        self,
        source: VulnerabilitySource,
        query_type: str,
        *args: Any,
    ) -> list[VulnerabilityRecord]:
        """Execute a source query with concurrency control and error handling."""
        async with self._semaphore:
            try:
                if query_type == "cpe":
                    results = await source.search_cpe(args[0])
                elif query_type == "product":
                    results = await source.search_product(*args)
                elif query_type == "cve":
                    results = await source.search_cve(args[0])
                else:
                    results = []

                self._scan_run.source_statuses[source.name] = SourceStatus.OK
                return results

            except Exception as exc:
                logger.warning(
                    "source_query_failed",
                    source=source.name,
                    query_type=query_type,
                    error=str(exc),
                )
                self._scan_run.source_statuses[source.name] = SourceStatus.ERROR
                return []

    async def _enrich_epss(
        self, vulns: list[VulnerabilityRecord]
    ) -> list[VulnerabilityRecord]:
        """Enrich vulnerabilities with EPSS scores."""
        if not self._epss:
            return vulns

        cve_ids = [v.cve_id for v in vulns if v.cve_id and not v.epss]
        if not cve_ids:
            return vulns

        logger.info("epss_enrichment", cve_count=len(cve_ids))
        scores = await self._epss.get_epss_batch(cve_ids)

        for vuln in vulns:
            if vuln.cve_id and vuln.cve_id in scores:
                vuln.epss = scores[vuln.cve_id]

        return vulns

    async def _enrich_kev(
        self, vulns: list[VulnerabilityRecord]
    ) -> list[VulnerabilityRecord]:
        """Enrich vulnerabilities with KEV status."""
        if not self._kev:
            return vulns

        for vuln in vulns:
            if vuln.cve_id and not vuln.kev:
                kev_entry = await self._kev.is_in_kev(vuln.cve_id)
                if kev_entry:
                    vuln.kev = kev_entry
                    vuln.exploit_available = True
                    if "CISA KEV" not in vuln.sources:
                        vuln.sources.append("CISA KEV")

        return vulns

    async def check_health(self) -> dict[str, Any]:
        """Check health of all configured sources."""
        results = {}
        for source in self._sources:
            health = await source.health_check()
            results[source.name] = {
                "status": health.status.value,
                "response_time_ms": health.response_time_ms,
                "error": health.error_message,
            }
        return results

    async def close(self) -> None:
        """Close all source clients."""
        for source in self._sources:
            if hasattr(source, "close"):
                await source.close()
        if self._epss:
            await self._epss.close()


class ScanRunResult:
    """Container for complete scan results."""

    def __init__(
        self,
        scan_run: ScanRun,
        scan_result: ScanResult | None = None,
        fingerprints: list[FingerprintResult] | None = None,
        vulnerabilities: list[VulnerabilityRecord] | None = None,
        risk_assessments: list | None = None,
    ) -> None:
        self.scan_run = scan_run
        self.scan_result = scan_result
        self.fingerprints = fingerprints or []
        self.vulnerabilities = vulnerabilities or []
        self.risk_assessments = risk_assessments or []

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict for reporting."""
        return {
            "scan_run": self.scan_run.model_dump(mode="json"),
            "hosts": [h.model_dump(mode="json") for h in (self.scan_result.hosts if self.scan_result else [])],
            "ports": [p.model_dump(mode="json") for p in (self.scan_result.ports if self.scan_result else [])],
            "services": [s.model_dump(mode="json") for s in (self.scan_result.services if self.scan_result else [])],
            "fingerprints": [f.model_dump(mode="json") for f in self.fingerprints],
            "vulnerabilities": [v.model_dump(mode="json") for v in self.vulnerabilities],
            "risk_assessments": [r.model_dump(mode="json") for r in self.risk_assessments],
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, Any]:
        """Generate a scan summary."""
        from vulnscanner.core.models import Severity

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for v in self.vulnerabilities:
            sev = v.severity.value
            if sev in severity_counts:
                severity_counts[sev] += 1

        kev_count = sum(1 for v in self.vulnerabilities if v.kev)
        exploit_count = sum(1 for v in self.vulnerabilities if v.exploit_available)

        return {
            "total_hosts": self.scan_run.total_hosts,
            "total_ports": self.scan_run.total_ports,
            "total_services": self.scan_run.total_services,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity": severity_counts,
            "kev_vulnerabilities": kev_count,
            "exploit_available": exploit_count,
            "fingerprints": len(self.fingerprints),
            "sources_status": {k: v.value for k, v in self.scan_run.source_statuses.items()},
            "errors": self.scan_run.errors,
        }
