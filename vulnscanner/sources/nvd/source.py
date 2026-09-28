"""NIST NVD API 2.0 vulnerability source.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Auth: Optional API key (50 req/30s with key, 5 req/30s without)
Rate limit: 6-second recommended delay between requests
License: Public domain (US Government work)
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from vulnscanner.core.http_client import ResilientClient, RateLimitExceeded, SourceUnavailable
from vulnscanner.core.interfaces import VulnerabilitySource
from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    CVSSScore,
    Severity,
    SourceHealth,
    SourceStatus,
    VulnerabilityRecord,
)

logger = get_logger(__name__)

_BASE_URL = "https://services.nvd.nist.gov/rest/json"


class NVDSource(VulnerabilitySource):
    """NIST National Vulnerability Database — API 2.0."""

    def __init__(
        self,
        api_key: str | None = None,
        request_delay: float = 6.0,
        results_per_page: int = 200,
        cache_ttl: float = 86400.0,
    ) -> None:
        self._api_key = api_key
        self._delay = request_delay
        self._results_per_page = results_per_page
        self._cache_ttl = cache_ttl

        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        # Rate: 50 req / 30s with key, 5 req / 30s without
        rate = 50.0 if api_key else 5.0
        self._client = ResilientClient(
            base_url=_BASE_URL,
            rate_limit=rate,
            rate_period=30.0,
            timeout=30.0,
            max_retries=3,
            headers=headers,
        )

    @property
    def name(self) -> str:
        return "NVD"

    @property
    def capabilities(self) -> set[str]:
        return {"search_cve", "search_product", "search_cpe", "get_vuln"}

    async def search_cve(self, cve_id: str) -> list[VulnerabilityRecord]:
        try:
            resp = await self._client.get(
                "/cves/2.0",
                params={"cveId": cve_id},
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                logger.warning("nvd_search_failed", cve=cve_id, status=resp.status_code)
                return []

            data = resp.json()
            await asyncio.sleep(self._delay)
            return self._parse_response(data)

        except (RateLimitExceeded, SourceUnavailable) as exc:
            logger.warning("nvd_unavailable", error=str(exc))
            return []

    async def search_product(
        self, vendor: str, product: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        # NVD API uses keywordSearch for product-based queries
        keyword = f"{vendor} {product}"
        if version:
            keyword += f" {version}"

        try:
            resp = await self._client.get(
                "/cves/2.0",
                params={
                    "keywordSearch": keyword,
                    "resultsPerPage": self._results_per_page,
                },
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            await asyncio.sleep(self._delay)
            return self._parse_response(data)

        except (RateLimitExceeded, SourceUnavailable) as exc:
            logger.warning("nvd_unavailable", error=str(exc))
            return []

    async def search_cpe(self, cpe: str) -> list[VulnerabilityRecord]:
        try:
            resp = await self._client.get(
                "/cves/2.0",
                params={
                    "cpeName": cpe,
                    "resultsPerPage": self._results_per_page,
                },
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            await asyncio.sleep(self._delay)
            return self._parse_response(data)

        except (RateLimitExceeded, SourceUnavailable) as exc:
            logger.warning("nvd_unavailable", error=str(exc))
            return []

    async def search_package(
        self, ecosystem: str, package_name: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        # NVD doesn't have native package ecosystem support — use keyword
        return await self.search_product(ecosystem, package_name, version)

    async def get_vulnerability(self, vuln_id: str) -> VulnerabilityRecord | None:
        results = await self.search_cve(vuln_id)
        return results[0] if results else None

    async def health_check(self) -> SourceHealth:
        try:
            import time
            start = time.monotonic()
            resp = await self._client.get(
                "/cves/2.0",
                params={"cveId": "CVE-2021-44228", "resultsPerPage": 1},
                cache_ttl=0,
            )
            elapsed = (time.monotonic() - start) * 1000

            if resp.status_code == 200:
                return SourceHealth(
                    name=self.name,
                    status=SourceStatus.OK,
                    last_checked=datetime.utcnow(),
                    last_successful=datetime.utcnow(),
                    response_time_ms=elapsed,
                )
            elif resp.status_code == 403:
                return SourceHealth(
                    name=self.name,
                    status=SourceStatus.RATE_LIMITED,
                    last_checked=datetime.utcnow(),
                    response_time_ms=elapsed,
                    error_message="Rate limited (403)",
                )
            else:
                return SourceHealth(
                    name=self.name,
                    status=SourceStatus.ERROR,
                    last_checked=datetime.utcnow(),
                    response_time_ms=elapsed,
                    error_message=f"HTTP {resp.status_code}",
                )
        except Exception as exc:
            return self._unavailable_health(str(exc))

    def _parse_response(self, data: dict[str, Any]) -> list[VulnerabilityRecord]:
        """Parse NVD API 2.0 JSON response into VulnerabilityRecords."""
        records: list[VulnerabilityRecord] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln_wrapper in vulnerabilities:
            cve = vuln_wrapper.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # Description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS scores
            cvss_scores = self._extract_cvss(cve.get("metrics", {}))

            # Affected CPEs
            affected_cpes: list[str] = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            criteria = cpe_match.get("criteria", "")
                            if criteria:
                                affected_cpes.append(criteria)

            # References
            refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

            # Dates
            published = cve.get("published")
            modified = cve.get("lastModified")

            record = VulnerabilityRecord(
                cve_id=cve_id,
                title=cve_id,
                description=description,
                cvss_scores=cvss_scores,
                affected_cpes=affected_cpes,
                published=self._parse_date(published),
                last_modified=self._parse_date(modified),
                references=refs,
                sources=["NVD"],
                source_confidence={"NVD": 0.95},
                confidence=0.90,
            )
            records.append(record)

        return records

    def _extract_cvss(self, metrics: dict[str, Any]) -> list[CVSSScore]:
        """Extract CVSS scores from NVD metrics."""
        scores: list[CVSSScore] = []

        # CVSS v3.1
        for m in metrics.get("cvssMetricV31", []):
            cvss = m.get("cvssData", {})
            scores.append(CVSSScore(
                version="3.1",
                vector_string=cvss.get("vectorString"),
                base_score=cvss.get("baseScore", 0.0),
                severity=self._map_severity(cvss.get("baseSeverity", "")),
                exploitability_score=m.get("exploitabilityScore"),
                impact_score=m.get("impactScore"),
                source="NVD",
            ))

        # CVSS v4.0
        for m in metrics.get("cvssMetricV40", []):
            cvss = m.get("cvssData", {})
            scores.append(CVSSScore(
                version="4.0",
                vector_string=cvss.get("vectorString"),
                base_score=cvss.get("baseScore", 0.0),
                severity=self._map_severity(cvss.get("baseSeverity", "")),
                source="NVD",
            ))

        # CVSS v2 fallback
        if not scores:
            for m in metrics.get("cvssMetricV2", []):
                cvss = m.get("cvssData", {})
                scores.append(CVSSScore(
                    version="2.0",
                    vector_string=cvss.get("vectorString"),
                    base_score=cvss.get("baseScore", 0.0),
                    severity=self._map_severity(m.get("baseSeverity", "")),
                    source="NVD",
                ))

        return scores

    @staticmethod
    def _map_severity(s: str) -> Severity:
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "NONE": Severity.NONE,
        }
        return mapping.get(s.upper(), Severity.UNKNOWN)

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    async def close(self) -> None:
        await self._client.close()
