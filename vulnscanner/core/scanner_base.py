"""Abstract base class for scanner integrations (Nmap, httpx, etc.)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from vulnscanner.core.models import (
    DiscoveredHost,
    DiscoveredPort,
    DiscoveredService,
    ScanProfile,
)


class ScannerIntegration(ABC):
    """Interface for external scanner tool integrations.

    Each scanner integration wraps a specific tool (Nmap, httpx, etc.)
    and converts its output into the framework's domain models.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name (e.g., 'nmap', 'httpx')."""
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the external tool binary is installed and accessible."""
        ...

    @abstractmethod
    async def scan(
        self,
        targets: list[str],
        profile: ScanProfile,
        extra_args: list[str] | None = None,
    ) -> ScanResult:
        """Execute a scan against the given targets.

        Args:
            targets: List of IPs, hostnames, or CIDRs.
            profile: Scan profile determining intensity.
            extra_args: Additional tool-specific arguments.

        Returns:
            ScanResult containing discovered hosts, ports, and services.
        """
        ...

    @abstractmethod
    async def parse_output(self, raw_output: str | bytes) -> ScanResult:
        """Parse raw tool output (e.g., Nmap XML) into domain models.

        Args:
            raw_output: Raw output from the scanner tool.

        Returns:
            Parsed ScanResult.
        """
        ...


class ScanResult:
    """Container for results from a single scanner execution."""

    def __init__(
        self,
        scanner_name: str,
        hosts: list[DiscoveredHost] | None = None,
        ports: list[DiscoveredPort] | None = None,
        services: list[DiscoveredService] | None = None,
        raw_output: str | bytes | None = None,
        errors: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.scanner_name = scanner_name
        self.hosts = hosts or []
        self.ports = ports or []
        self.services = services or []
        self.raw_output = raw_output
        self.errors = errors or []
        self.metadata = metadata or {}

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def port_count(self) -> int:
        return len(self.ports)

    @property
    def service_count(self) -> int:
        return len(self.services)

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0
