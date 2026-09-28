"""Input validation utilities.

Validates and classifies user-supplied targets (IPs, CIDRs, hostnames, URLs)
to prevent injection and ensure safe subprocess usage.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from vulnscanner.core.models import TargetSpec

# RFC-compliant hostname regex (no underscores, max 253 chars)
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)

# Basic port range: 1-65535
_PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


class ValidationError(Exception):
    """Raised when user input fails validation."""


def validate_target(raw: str) -> TargetSpec:
    """Classify and validate a raw target string.

    Supports:
      - IPv4 / IPv6 addresses
      - CIDR notation (e.g., 192.168.1.0/24)
      - Hostnames / FQDNs
      - URLs (http:// or https://)

    Args:
        raw: User-supplied target string.

    Returns:
        Validated TargetSpec with target_type set.

    Raises:
        ValidationError: If the input is not a valid target.
    """
    raw = raw.strip()

    if not raw:
        raise ValidationError("Empty target string")

    # Reject obvious injection attempts
    if any(c in raw for c in (";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "\n")):
        raise ValidationError(f"Invalid characters in target: {raw!r}")

    # Try URL first
    if raw.startswith(("http://", "https://")):
        return _validate_url(raw)

    # Try CIDR
    if "/" in raw:
        return _validate_cidr(raw)

    # Try IP address
    try:
        addr = ipaddress.ip_address(raw)
        return TargetSpec(raw=raw, target_type="ip", resolved_ips=[str(addr)])
    except ValueError:
        pass

    # Try hostname
    return _validate_hostname(raw)


def _validate_url(raw: str) -> TargetSpec:
    """Validate a URL target."""
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValidationError(f"URL has no hostname: {raw}")

    # Validate the hostname portion
    hostname = parsed.hostname
    port = parsed.port

    return TargetSpec(
        raw=raw,
        target_type="url",
        hostname=hostname,
        url=raw,
        port_override=[port] if port else None,
    )


def _validate_cidr(raw: str) -> TargetSpec:
    """Validate a CIDR range target."""
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise ValidationError(f"Invalid CIDR notation: {raw}") from exc

    # Sanity check — don't allow huge ranges by default
    if network.num_addresses > 65536:
        raise ValidationError(
            f"CIDR range too large ({network.num_addresses} addresses): {raw}. "
            f"Maximum allowed is /16 (65536 addresses)."
        )

    return TargetSpec(raw=raw, target_type="cidr", cidr=str(network))


def _validate_hostname(raw: str) -> TargetSpec:
    """Validate a hostname / FQDN target."""
    if len(raw) > 253:
        raise ValidationError(f"Hostname too long (max 253 chars): {raw}")

    if not _HOSTNAME_RE.match(raw):
        raise ValidationError(f"Invalid hostname: {raw!r}")

    return TargetSpec(raw=raw, target_type="hostname", hostname=raw)


def validate_port_range(port_str: str) -> list[int]:
    """Validate and expand a port range string.

    Supports: "80", "80,443", "1-1024", "80,443,8000-9000"

    Args:
        port_str: Port specification string.

    Returns:
        Sorted list of port numbers.

    Raises:
        ValidationError: If the port string is invalid.
    """
    if not _PORT_RANGE_RE.match(port_str):
        raise ValidationError(f"Invalid port range: {port_str!r}")

    ports: set[int] = set()
    for part in port_str.split(","):
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if not (1 <= start <= end <= 65535):
                raise ValidationError(f"Port range out of bounds: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValidationError(f"Port out of bounds: {p}")
            ports.add(p)

    return sorted(ports)


def validate_cve_id(cve_id: str) -> str:
    """Validate a CVE identifier format.

    Args:
        cve_id: CVE string (e.g., "CVE-2024-12345").

    Returns:
        Normalized uppercase CVE ID.

    Raises:
        ValidationError: If the format is invalid.
    """
    cve_id = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        raise ValidationError(f"Invalid CVE format: {cve_id!r}")
    return cve_id


def validate_cpe(cpe: str) -> str:
    """Validate a CPE 2.3 formatted string.

    Args:
        cpe: CPE string.

    Returns:
        The validated CPE string.

    Raises:
        ValidationError: If the format is clearly invalid.
    """
    if not cpe.startswith("cpe:2.3:"):
        raise ValidationError(f"CPE must start with 'cpe:2.3:': {cpe!r}")
    parts = cpe.split(":")
    if len(parts) < 5:
        raise ValidationError(f"CPE has too few components: {cpe!r}")
    return cpe
