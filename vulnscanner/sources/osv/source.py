"""OSV.dev vulnerability source.

API: https://api.osv.dev
Endpoints: POST /v1/query, POST /v1/querybatch, GET /v1/vulns/{id}
Auth: None required
Rate limits: None (but use HTTP/2 for large responses)
License: CC BY 4.0
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from vulnscanner.core.http_client import ResilientClient, SourceUnavailable
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

_BASE_URL = "https://api.osv.dev"


class OSVSource(VulnerabilitySource):
    """OSV.dev — Open Source Vulnerabilities database."""

    def __init__(self, cache_ttl: float = 21600.0) -> None:
        self._cache_ttl = cache_ttl
        self._client = ResilientClient(
            base_url=_BASE_URL,
            rate_limit=30.0,
            rate_period=1.0,
            timeout=30.0,
        )

    @property
    def name(self) -> str:
        return "OSV"

    @property
    def capabilities(self) -> set[str]:
        return {"search_cve", "search_package", "get_vuln"}

    async def search_cve(self, cve_id: str) -> list[VulnerabilityRecord]:
        # OSV can look up by CVE alias
        vuln = await self.get_vulnerability(cve_id)
        return [vuln] if vuln else []

    async def search_product(
        self, vendor: str, product: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        # OSV is package-oriented; for generic products use search_package
        return await self.search_package("", product, version)

    async def search_cpe(self, cpe: str) -> list[VulnerabilityRecord]:
        # OSV doesn't support CPE queries directly
        return []

    async def search_package(
        self, ecosystem: str, package_name: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        body: dict[str, Any] = {
            "package": {"name": package_name}
        }
        if ecosystem:
            body["package"]["ecosystem"] = ecosystem
        if version:
            body["version"] = version

        try:
            resp = await self._client.post(
                "/v1/query",
                json=body,
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            return [self._parse_vuln(v) for v in data.get("vulns", []) if v]
        except (SourceUnavailable,) as exc:
            logger.warning("osv_unavailable", error=str(exc))
            return []

    async def get_vulnerability(self, vuln_id: str) -> VulnerabilityRecord | None:
        try:
            resp = await self._client.get(
                f"/v1/vulns/{vuln_id}",
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code == 404:
                return None
            if resp.status_code != 200:
                return None

            return self._parse_vuln(resp.json())
        except (SourceUnavailable,) as exc:
            logger.warning("osv_unavailable", error=str(exc))
            return None

    async def search_batch(
        self, queries: list[dict[str, Any]]
    ) -> list[list[VulnerabilityRecord]]:
        """Batch query multiple packages at once.

        Args:
            queries: List of query dicts (each with 'package' and optionally 'version').

        Returns:
            List of result lists, one per query.
        """
        try:
            resp = await self._client.post(
                "/v1/querybatch",
                json={"queries": queries},
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                return [[] for _ in queries]

            data = resp.json()
            results = []
            for result_set in data.get("results", []):
                vulns = result_set.get("vulns", [])
                results.append([self._parse_vuln(v) for v in vulns if v])
            return results
        except (SourceUnavailable,) as exc:
            logger.warning("osv_batch_unavailable", error=str(exc))
            return [[] for _ in queries]

    async def health_check(self) -> SourceHealth:
        try:
            import time
            start = time.monotonic()
            resp = await self._client.get("/v1/vulns/OSV-2020-1", cache_ttl=0)
            elapsed = (time.monotonic() - start) * 1000

            if resp.status_code == 200:
                return SourceHealth(
                    name=self.name,
                    status=SourceStatus.OK,
                    last_checked=datetime.utcnow(),
                    last_successful=datetime.utcnow(),
                    response_time_ms=elapsed,
                )
            return SourceHealth(
                name=self.name,
                status=SourceStatus.ERROR,
                last_checked=datetime.utcnow(),
                error_message=f"HTTP {resp.status_code}",
            )
        except Exception as exc:
            return self._unavailable_health(str(exc))

    def _parse_vuln(self, data: dict[str, Any]) -> VulnerabilityRecord:
        """Parse an OSV vulnerability JSON into a VulnerabilityRecord."""
        osv_id = data.get("id", "")

        # Extract CVE alias
        cve_id = None
        ghsa_id = None
        for alias in data.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
            elif alias.startswith("GHSA-"):
                ghsa_id = alias

        # Summary / details
        summary = data.get("summary", "")
        details = data.get("details", "")

        # Affected versions
        affected_versions: list[str] = []
        fixed_versions: list[str] = []
        for affected in data.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "introduced" in event:
                        affected_versions.append(f">={event['introduced']}")
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

            # Exact versions
            versions = affected.get("versions", [])
            affected_versions.extend(versions[:20])  # Cap to avoid huge lists

        # CVSS
        cvss_scores: list[CVSSScore] = []
        severity_list = data.get("severity", [])
        for sev in severity_list:
            if sev.get("type") == "CVSS_V3":
                vector = sev.get("score", "")
                # Extract score from vector if possible
                cvss_scores.append(CVSSScore(
                    version="3.1",
                    vector_string=vector,
                    base_score=0.0,  # OSV doesn't always provide numeric score
                    source="OSV",
                ))

        # References
        refs = [r.get("url", "") for r in data.get("references", []) if r.get("url")]

        # Dates
        published = data.get("published")
        modified = data.get("modified")

        return VulnerabilityRecord(
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            osv_id=osv_id,
            title=summary or osv_id,
            description=details or summary,
            cvss_scores=cvss_scores,
            affected_versions=affected_versions[:50],
            fixed_versions=fixed_versions[:20],
            published=self._parse_date(published),
            last_modified=self._parse_date(modified),
            references=refs,
            sources=["OSV"],
            source_confidence={"OSV": 0.85},
            confidence=0.80,
        )

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
