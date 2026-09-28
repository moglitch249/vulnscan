"""FIRST EPSS (Exploit Prediction Scoring System) source.

API: https://api.first.org/data/v1/epss
Bulk CSV: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
Auth: None required
Rate limits: Not documented, use respectfully
License: Public
Model: Currently EPSS v5 (June 2026)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from vulnscanner.core.http_client import ResilientClient, SourceUnavailable
from vulnscanner.core.interfaces import VulnerabilitySource
from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    EPSSScore,
    SourceHealth,
    SourceStatus,
    VulnerabilityRecord,
)

logger = get_logger(__name__)

_API_URL = "https://api.first.org/data/v1/epss"


class EPSSSource(VulnerabilitySource):
    """FIRST EPSS — Exploit Prediction Scoring System."""

    def __init__(self, cache_ttl: float = 86400.0) -> None:
        self._cache_ttl = cache_ttl
        self._client = ResilientClient(
            rate_limit=10.0,
            rate_period=1.0,
            timeout=30.0,
        )

    @property
    def name(self) -> str:
        return "EPSS"

    @property
    def capabilities(self) -> set[str]:
        return {"search_cve", "epss"}

    async def get_epss_score(self, cve_id: str) -> EPSSScore | None:
        """Get EPSS score for a specific CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            EPSSScore or None.
        """
        try:
            resp = await self._client.get(
                _API_URL,
                params={"cve": cve_id},
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            entries = data.get("data", [])
            if not entries:
                return None

            entry = entries[0]
            return EPSSScore(
                score=float(entry.get("epss", 0.0)),
                percentile=float(entry.get("percentile", 0.0)),
                model_version=data.get("model_version"),
                date=datetime.utcnow(),
            )
        except (SourceUnavailable, ValueError) as exc:
            logger.warning("epss_unavailable", error=str(exc))
            return None

    async def get_epss_batch(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Get EPSS scores for multiple CVEs at once.

        Args:
            cve_ids: List of CVE identifiers.

        Returns:
            Dict mapping CVE ID -> EPSSScore.
        """
        if not cve_ids:
            return {}

        # EPSS API supports comma-separated CVEs
        results: dict[str, EPSSScore] = {}

        # Batch in groups of 30
        for i in range(0, len(cve_ids), 30):
            batch = cve_ids[i:i + 30]
            cve_param = ",".join(batch)

            try:
                resp = await self._client.get(
                    _API_URL,
                    params={"cve": cve_param},
                    cache_ttl=self._cache_ttl,
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                for entry in data.get("data", []):
                    cve = entry.get("cve", "")
                    if cve:
                        results[cve] = EPSSScore(
                            score=float(entry.get("epss", 0.0)),
                            percentile=float(entry.get("percentile", 0.0)),
                            model_version=data.get("model_version"),
                            date=datetime.utcnow(),
                        )
            except (SourceUnavailable, ValueError) as exc:
                logger.warning("epss_batch_error", error=str(exc))

        return results

    async def search_cve(self, cve_id: str) -> list[VulnerabilityRecord]:
        epss = await self.get_epss_score(cve_id)
        if not epss:
            return []

        return [VulnerabilityRecord(
            cve_id=cve_id,
            epss=epss,
            sources=["EPSS"],
            source_confidence={"EPSS": 0.90},
            confidence=0.50,  # EPSS alone is just a score, not full vuln data
        )]

    async def search_product(
        self, vendor: str, product: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        return []  # EPSS only supports CVE lookup

    async def search_cpe(self, cpe: str) -> list[VulnerabilityRecord]:
        return []

    async def search_package(
        self, ecosystem: str, package_name: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        return []

    async def get_vulnerability(self, vuln_id: str) -> VulnerabilityRecord | None:
        results = await self.search_cve(vuln_id)
        return results[0] if results else None

    async def health_check(self) -> SourceHealth:
        try:
            import time
            start = time.monotonic()
            resp = await self._client.get(
                _API_URL,
                params={"cve": "CVE-2021-44228"},
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
            return SourceHealth(
                name=self.name,
                status=SourceStatus.ERROR,
                last_checked=datetime.utcnow(),
                error_message=f"HTTP {resp.status_code}",
            )
        except Exception as exc:
            return self._unavailable_health(str(exc))

    async def close(self) -> None:
        await self._client.close()
