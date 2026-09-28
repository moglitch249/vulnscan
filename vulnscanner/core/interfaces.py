"""Abstract base classes for vulnerability intelligence sources.

Every external data source (NVD, CISA KEV, OSV, etc.) implements the
VulnerabilitySource interface so they can be plugged in uniformly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from vulnscanner.core.models import (
    SourceHealth,
    SourceStatus,
    VulnerabilityRecord,
)


class VulnerabilitySource(ABC):
    """Interface that every vulnerability intelligence source must implement.

    Sources are designed as plugins: the correlation engine iterates over
    all registered sources and calls the same interface on each one.
    Sources must handle their own rate limiting, caching, pagination, and
    graceful failure internally.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this source (e.g., 'NVD', 'CISA KEV')."""
        ...

    @property
    @abstractmethod
    def capabilities(self) -> set[str]:
        """Set of capabilities this source supports.

        Standard capability strings:
          - "search_cve"     — lookup by CVE ID
          - "search_product" — lookup by vendor/product
          - "search_cpe"     — lookup by CPE string
          - "search_package" — lookup by ecosystem package name
          - "get_vuln"       — retrieve full vulnerability details
          - "bulk_download"  — supports offline data download
          - "epss"           — provides EPSS scores
          - "kev"            — provides KEV status
          - "exploit_refs"   — provides exploit references
        """
        ...

    @abstractmethod
    async def search_cve(self, cve_id: str) -> list[VulnerabilityRecord]:
        """Search for vulnerabilities by CVE identifier.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            List of matching vulnerability records.
        """
        ...

    @abstractmethod
    async def search_product(
        self,
        vendor: str,
        product: str,
        version: str | None = None,
    ) -> list[VulnerabilityRecord]:
        """Search for vulnerabilities by vendor/product/version.

        Args:
            vendor: Software vendor name.
            product: Product name.
            version: Optional specific version.

        Returns:
            List of matching vulnerability records.
        """
        ...

    @abstractmethod
    async def search_cpe(self, cpe: str) -> list[VulnerabilityRecord]:
        """Search for vulnerabilities by CPE 2.3 string.

        Args:
            cpe: CPE 2.3 formatted string.

        Returns:
            List of matching vulnerability records.
        """
        ...

    @abstractmethod
    async def search_package(
        self,
        ecosystem: str,
        package_name: str,
        version: str | None = None,
    ) -> list[VulnerabilityRecord]:
        """Search for vulnerabilities by package ecosystem identifier.

        Args:
            ecosystem: Package ecosystem (e.g., "PyPI", "npm", "Go").
            package_name: Package name within the ecosystem.
            version: Optional specific version.

        Returns:
            List of matching vulnerability records.
        """
        ...

    @abstractmethod
    async def get_vulnerability(self, vuln_id: str) -> VulnerabilityRecord | None:
        """Retrieve complete details for a single vulnerability.

        Args:
            vuln_id: Vulnerability identifier (CVE, GHSA, OSV, etc.)

        Returns:
            Full vulnerability record, or None if not found.
        """
        ...

    @abstractmethod
    async def health_check(self) -> SourceHealth:
        """Check whether this source is reachable and operational.

        Returns:
            SourceHealth object with current status.
        """
        ...

    # ------------------------------------------------------------------
    # Optional: offline data management
    # ------------------------------------------------------------------

    async def download_offline_data(self, target_dir: str) -> bool:
        """Download data for offline use. Override if source supports it.

        Args:
            target_dir: Directory to store downloaded data.

        Returns:
            True if download succeeded.
        """
        return False

    async def load_offline_data(self, data_dir: str) -> bool:
        """Load previously downloaded offline data. Override if supported.

        Args:
            data_dir: Directory containing offline data.

        Returns:
            True if data loaded successfully.
        """
        return False

    # ------------------------------------------------------------------
    # Helpers (concrete, not abstract)
    # ------------------------------------------------------------------

    def supports(self, capability: str) -> bool:
        """Check whether this source supports a given capability."""
        return capability in self.capabilities

    def _unavailable_health(self, error: str) -> SourceHealth:
        """Create a health object for an unavailable source."""
        from datetime import datetime

        return SourceHealth(
            name=self.name,
            status=SourceStatus.UNAVAILABLE,
            last_checked=datetime.utcnow(),
            error_message=error,
        )


class NotImplementedSource(VulnerabilitySource):
    """Placeholder for sources that cannot be legally/technically implemented.

    Use this when a data source lacks a public API, requires paid access,
    or has licensing restrictions that prevent integration.
    """

    def __init__(self, source_name: str, reason: str) -> None:
        self._name = source_name
        self._reason = reason

    @property
    def name(self) -> str:
        return self._name

    @property
    def capabilities(self) -> set[str]:
        return set()

    @property
    def reason(self) -> str:
        return self._reason

    async def search_cve(self, cve_id: str) -> list[VulnerabilityRecord]:
        return []

    async def search_product(
        self, vendor: str, product: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        return []

    async def search_cpe(self, cpe: str) -> list[VulnerabilityRecord]:
        return []

    async def search_package(
        self, ecosystem: str, package_name: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        return []

    async def get_vulnerability(self, vuln_id: str) -> VulnerabilityRecord | None:
        return None

    async def health_check(self) -> SourceHealth:
        from datetime import datetime

        return SourceHealth(
            name=self.name,
            status=SourceStatus.UNAVAILABLE,
            last_checked=datetime.utcnow(),
            error_message=f"Not implemented: {self._reason}",
        )
