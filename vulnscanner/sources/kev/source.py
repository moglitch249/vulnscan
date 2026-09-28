"""CISA Known Exploited Vulnerabilities (KEV) source.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Auth: None required — public JSON feed
Rate limit: None (single JSON download)
License: Public domain (US Government work)
Update frequency: Updated as new KEVs are identified
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from vulnscanner.core.http_client import ResilientClient, SourceUnavailable
from vulnscanner.core.interfaces import VulnerabilitySource
from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    KEVEntry,
    SourceHealth,
    SourceStatus,
    VulnerabilityRecord,
)

logger = get_logger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVSource(VulnerabilitySource):
    """CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, cache_ttl: float = 43200.0) -> None:
        self._cache_ttl = cache_ttl
        self._client = ResilientClient(
            rate_limit=10.0,
            rate_period=1.0,
            timeout=30.0,
        )
        self._catalog: dict[str, dict[str, Any]] | None = None

    @property
    def name(self) -> str:
        return "CISA KEV"

    @property
    def capabilities(self) -> set[str]:
        return {"search_cve", "search_product", "get_vuln", "kev", "bulk_download"}

    async def _ensure_catalog(self) -> dict[str, dict[str, Any]]:
        """Download and cache the full KEV catalog."""
        if self._catalog is not None:
            return self._catalog

        resp = await self._client.get(
            _KEV_URL,
            cache_ttl=self._cache_ttl,
        )
        if resp.status_code != 200:
            logger.warning("kev_download_failed", status=resp.status_code)
            return {}

        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        self._catalog = {}
        for v in vulns:
            cve_id = v.get("cveID", "")
            if cve_id:
                self._catalog[cve_id.upper()] = v

        logger.info("kev_catalog_loaded", count=len(self._catalog))
        return self._catalog

    async def search_cve(self, cve_id: str) -> list[VulnerabilityRecord]:
        catalog = await self._ensure_catalog()
        entry = catalog.get(cve_id.upper())
        if not entry:
            return []

        return [self._to_record(cve_id.upper(), entry)]

    async def search_product(
        self, vendor: str, product: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        catalog = await self._ensure_catalog()
        results = []
        v_lower = vendor.lower()
        p_lower = product.lower()

        for cve_id, entry in catalog.items():
            if (v_lower in entry.get("vendorProject", "").lower() and
                    p_lower in entry.get("product", "").lower()):
                results.append(self._to_record(cve_id, entry))

        return results

    async def search_cpe(self, cpe: str) -> list[VulnerabilityRecord]:
        # KEV doesn't have CPE fields — search by vendor/product extracted from CPE
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor = parts[3].replace("_", " ")
            product = parts[4].replace("_", " ")
            return await self.search_product(vendor, product)
        return []

    async def search_package(
        self, ecosystem: str, package_name: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        return await self.search_product(ecosystem, package_name, version)

    async def get_vulnerability(self, vuln_id: str) -> VulnerabilityRecord | None:
        results = await self.search_cve(vuln_id)
        return results[0] if results else None

    async def is_in_kev(self, cve_id: str) -> KEVEntry | None:
        """Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier.

        Returns:
            KEVEntry if found, None otherwise.
        """
        catalog = await self._ensure_catalog()
        entry = catalog.get(cve_id.upper())
        if not entry:
            return None

        return KEVEntry(
            cve_id=cve_id.upper(),
            vendor_project=entry.get("vendorProject"),
            product=entry.get("product"),
            vulnerability_name=entry.get("vulnerabilityName"),
            date_added=self._parse_date(entry.get("dateAdded")),
            due_date=self._parse_date(entry.get("dueDate")),
            required_action=entry.get("requiredAction"),
            known_ransomware_use=entry.get("knownRansomwareCampaignUse"),
        )

    async def health_check(self) -> SourceHealth:
        try:
            import time
            start = time.monotonic()
            resp = await self._client.get(_KEV_URL, cache_ttl=0)
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

    async def download_offline_data(self, target_dir: str) -> bool:
        """Download KEV catalog for offline use."""
        import json
        from pathlib import Path

        try:
            resp = await self._client.get(_KEV_URL, cache_ttl=0)
            if resp.status_code != 200:
                return False

            path = Path(target_dir) / "kev_catalog.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(resp.text, encoding="utf-8")
            logger.info("kev_offline_saved", path=str(path))
            return True
        except Exception as exc:
            logger.error("kev_offline_failed", error=str(exc))
            return False

    def _to_record(self, cve_id: str, entry: dict[str, Any]) -> VulnerabilityRecord:
        kev = KEVEntry(
            cve_id=cve_id,
            vendor_project=entry.get("vendorProject"),
            product=entry.get("product"),
            vulnerability_name=entry.get("vulnerabilityName"),
            date_added=self._parse_date(entry.get("dateAdded")),
            due_date=self._parse_date(entry.get("dueDate")),
            required_action=entry.get("requiredAction"),
            known_ransomware_use=entry.get("knownRansomwareCampaignUse"),
        )

        return VulnerabilityRecord(
            cve_id=cve_id,
            vendor=entry.get("vendorProject"),
            product=entry.get("product"),
            title=entry.get("vulnerabilityName"),
            description=entry.get("shortDescription", ""),
            kev=kev,
            exploit_available=True,  # KEV = known exploited
            sources=["CISA KEV"],
            source_confidence={"CISA KEV": 1.0},
            confidence=0.95,
            references=[entry.get("notes", "")],
        )

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d")
        except (ValueError, TypeError):
            return None

    async def close(self) -> None:
        await self._client.close()
