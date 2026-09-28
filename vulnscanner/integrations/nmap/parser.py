"""Nmap XML output parser.

Parses Nmap's XML output (-oX) into the framework's domain models.
Uses stdlib xml.etree.ElementTree with defusedxml for safe parsing
(prevents XXE and other XML attacks).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import defusedxml.ElementTree as SafeET

from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    DiscoveredHost,
    DiscoveredPort,
    DiscoveredService,
    HostStatus,
    PortState,
    Protocol,
)

logger = get_logger(__name__)


class NmapParseError(Exception):
    """Raised when Nmap XML parsing fails."""


class NmapXMLParser:
    """Parses Nmap XML output into structured domain models."""

    def parse(
        self,
        xml_data: str | bytes,
        scan_run_id: UUID | None = None,
    ) -> NmapParseResult:
        """Parse Nmap XML output.

        Args:
            xml_data: Raw XML string or bytes from nmap -oX.
            scan_run_id: Optional scan run ID to associate results.

        Returns:
            NmapParseResult with hosts, ports, and services.

        Raises:
            NmapParseError: If the XML is malformed or not valid Nmap output.
        """
        try:
            if isinstance(xml_data, bytes):
                xml_data = xml_data.decode("utf-8", errors="replace")

            # Use defusedxml for safe parsing (prevents XXE)
            root = SafeET.fromstring(xml_data)
        except ET.ParseError as exc:
            raise NmapParseError(f"Invalid XML: {exc}") from exc

        if root.tag != "nmaprun":
            raise NmapParseError(
                f"Not a valid Nmap XML document (root tag: {root.tag!r})"
            )

        # Parse metadata
        metadata = self._parse_metadata(root)

        hosts: list[DiscoveredHost] = []
        ports: list[DiscoveredPort] = []
        services: list[DiscoveredService] = []

        for host_elem in root.findall("host"):
            host = self._parse_host(host_elem, scan_run_id)
            if host is None:
                continue

            hosts.append(host)

            # Parse ports and services for this host
            host_ports, host_services = self._parse_ports(host_elem, host.id)
            ports.extend(host_ports)
            services.extend(host_services)

        logger.info(
            "nmap_xml_parsed",
            hosts=len(hosts),
            ports=len(ports),
            services=len(services),
        )

        return NmapParseResult(
            hosts=hosts,
            ports=ports,
            services=services,
            metadata=metadata,
            raw_xml=xml_data,
        )

    def parse_file(
        self,
        file_path: str,
        scan_run_id: UUID | None = None,
    ) -> NmapParseResult:
        """Parse Nmap XML from a file.

        Args:
            file_path: Path to the Nmap XML file.
            scan_run_id: Optional scan run ID.

        Returns:
            NmapParseResult.
        """
        with open(file_path, encoding="utf-8", errors="replace") as f:
            xml_data = f.read()
        return self.parse(xml_data, scan_run_id)

    def _parse_metadata(self, root: ET.Element) -> dict[str, Any]:
        """Extract scan metadata from the nmaprun element."""
        meta: dict[str, Any] = {}
        meta["scanner"] = root.get("scanner", "nmap")
        meta["args"] = root.get("args", "")
        meta["start_time"] = root.get("start", "")
        meta["start_str"] = root.get("startstr", "")
        meta["version"] = root.get("version", "")
        meta["xmloutputversion"] = root.get("xmloutputversion", "")

        # runstats
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                meta["end_time"] = finished.get("time", "")
                meta["elapsed"] = finished.get("elapsed", "")
                meta["exit_status"] = finished.get("exit", "")

            hosts_elem = runstats.find("hosts")
            if hosts_elem is not None:
                meta["hosts_up"] = int(hosts_elem.get("up", "0"))
                meta["hosts_down"] = int(hosts_elem.get("down", "0"))
                meta["hosts_total"] = int(hosts_elem.get("total", "0"))

        return meta

    def _parse_host(
        self,
        host_elem: ET.Element,
        scan_run_id: UUID | None,
    ) -> DiscoveredHost | None:
        """Parse a single <host> element."""
        # Status
        status_elem = host_elem.find("status")
        if status_elem is None:
            return None

        state = status_elem.get("state", "unknown").lower()
        host_status = self._map_host_status(state)

        # IP address
        ip = None
        mac = None
        hostname = None

        for addr in host_elem.findall("address"):
            addr_type = addr.get("addrtype", "")
            if addr_type == "ipv4" or addr_type == "ipv6":
                ip = addr.get("addr")
            elif addr_type == "mac":
                mac = addr.get("addr")

        if ip is None:
            logger.warning("nmap_host_no_ip", element=ET.tostring(host_elem, encoding="unicode")[:200])
            return None

        # Hostname
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")

        # OS detection
        os_guess = None
        os_confidence = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_guess = osmatch.get("name")
                try:
                    os_confidence = int(osmatch.get("accuracy", "0"))
                except (ValueError, TypeError):
                    os_confidence = None

        # Uptime
        start_time = None
        uptime_elem = host_elem.find("uptime")

        host = DiscoveredHost(
            ip=ip,
            hostname=hostname,
            mac_address=mac,
            status=host_status,
            os_guess=os_guess,
            os_confidence=os_confidence,
            scan_run_id=scan_run_id,
        )

        return host

    def _parse_ports(
        self,
        host_elem: ET.Element,
        host_id: UUID,
    ) -> tuple[list[DiscoveredPort], list[DiscoveredService]]:
        """Parse all <port> elements within a <host>."""
        ports_list: list[DiscoveredPort] = []
        services_list: list[DiscoveredService] = []

        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            return ports_list, services_list

        for port_elem in ports_elem.findall("port"):
            port_num_str = port_elem.get("portid", "")
            protocol_str = port_elem.get("protocol", "tcp").lower()

            try:
                port_num = int(port_num_str)
            except (ValueError, TypeError):
                continue

            if port_num < 1 or port_num > 65535:
                continue

            # Port state
            state_elem = port_elem.find("state")
            if state_elem is None:
                continue

            port_state = self._map_port_state(state_elem.get("state", ""))
            reason = state_elem.get("reason")

            # Protocol
            protocol = self._map_protocol(protocol_str)

            port_obj = DiscoveredPort(
                host_id=host_id,
                port=port_num,
                protocol=protocol,
                state=port_state,
                reason=reason,
            )
            ports_list.append(port_obj)

            # Service detection
            service_elem = port_elem.find("service")
            if service_elem is not None:
                service = self._parse_service(service_elem, port_obj.id, host_id)
                if service is not None:
                    services_list.append(service)

        return ports_list, services_list

    def _parse_service(
        self,
        service_elem: ET.Element,
        port_id: UUID,
        host_id: UUID,
    ) -> DiscoveredService | None:
        """Parse a <service> element."""
        name = service_elem.get("name")
        product = service_elem.get("product")
        version = service_elem.get("version")
        extra_info = service_elem.get("extrainfo")
        tunnel = service_elem.get("tunnel")  # e.g., "ssl"
        os_type = service_elem.get("ostype")
        method = service_elem.get("method")

        # Confidence (Nmap uses 1-10)
        conf = None
        conf_str = service_elem.get("conf")
        if conf_str:
            try:
                conf = int(conf_str)
            except (ValueError, TypeError):
                pass

        # CPE elements
        cpe_raw: list[str] = []
        for cpe_elem in service_elem.findall("cpe"):
            if cpe_elem.text:
                cpe_raw.append(cpe_elem.text.strip())

        # Build banner from available info
        banner_parts = []
        if product:
            banner_parts.append(product)
        if version:
            banner_parts.append(version)
        if extra_info:
            banner_parts.append(f"({extra_info})")
        banner = " ".join(banner_parts) if banner_parts else None

        return DiscoveredService(
            port_id=port_id,
            host_id=host_id,
            name=name,
            product=product,
            version=version,
            extra_info=extra_info,
            tunnel=tunnel,
            os_type=os_type,
            banner=banner,
            cpe_raw=cpe_raw,
            confidence=conf,
        )

    @staticmethod
    def _map_host_status(state: str) -> HostStatus:
        mapping = {
            "up": HostStatus.UP,
            "down": HostStatus.DOWN,
        }
        return mapping.get(state, HostStatus.UNKNOWN)

    @staticmethod
    def _map_port_state(state: str) -> PortState:
        mapping = {
            "open": PortState.OPEN,
            "closed": PortState.CLOSED,
            "filtered": PortState.FILTERED,
            "open|filtered": PortState.OPEN_FILTERED,
            "closed|filtered": PortState.CLOSED_FILTERED,
        }
        return mapping.get(state.lower(), PortState.FILTERED)

    @staticmethod
    def _map_protocol(proto: str) -> Protocol:
        mapping = {
            "tcp": Protocol.TCP,
            "udp": Protocol.UDP,
            "sctp": Protocol.SCTP,
        }
        return mapping.get(proto.lower(), Protocol.TCP)


class NmapParseResult:
    """Container for parsed Nmap XML results."""

    def __init__(
        self,
        hosts: list[DiscoveredHost],
        ports: list[DiscoveredPort],
        services: list[DiscoveredService],
        metadata: dict[str, Any],
        raw_xml: str | None = None,
    ) -> None:
        self.hosts = hosts
        self.ports = ports
        self.services = services
        self.metadata = metadata
        self.raw_xml = raw_xml

    @property
    def hosts_up(self) -> list[DiscoveredHost]:
        return [h for h in self.hosts if h.status == HostStatus.UP]

    @property
    def open_ports(self) -> list[DiscoveredPort]:
        return [p for p in self.ports if p.state == PortState.OPEN]

    @property
    def services_with_version(self) -> list[DiscoveredService]:
        return [s for s in self.services if s.version]

    def summary(self) -> dict[str, Any]:
        return {
            "total_hosts": len(self.hosts),
            "hosts_up": len(self.hosts_up),
            "total_ports": len(self.ports),
            "open_ports": len(self.open_ports),
            "services": len(self.services),
            "services_with_version": len(self.services_with_version),
        }
