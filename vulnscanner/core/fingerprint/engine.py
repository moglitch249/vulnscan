"""Software fingerprint normalization engine.

Converts raw service banners and Nmap service detection output into
normalized vendor/product/version identifiers with CPE 2.3 strings,
PURLs, and confidence scores.

Uses:
  - Exact matching against known alias tables
  - Fuzzy matching (Levenshtein distance) for close matches
  - CPE construction from vendor+product+version
  - Configurable confidence thresholds
"""

from __future__ import annotations

import re
from typing import Any

from thefuzz import fuzz

from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    Confidence,
    DiscoveredService,
    FingerprintResult,
)

logger = get_logger(__name__)


# =============================================================================
# Vendor / Product Alias Tables
# =============================================================================
# Maps common Nmap product strings to normalized (vendor, product, cpe_vendor, cpe_product)

_VENDOR_ALIASES: dict[str, str] = {
    "apache": "apache",
    "apache software foundation": "apache",
    "the apache software foundation": "apache",
    "apache foundation": "apache",
    "microsoft": "microsoft",
    "ms": "microsoft",
    "nginx": "nginx",
    "nginx inc": "nginx",
    "f5": "f5",
    "f5 networks": "f5",
    "openssh": "openbsd",
    "openssl": "openssl",
    "openssl project": "openssl",
    "oracle": "oracle",
    "sun": "oracle",
    "sun microsystems": "oracle",
    "ibm": "ibm",
    "google": "google",
    "mozilla": "mozilla",
    "canonical": "canonical",
    "debian": "debian",
    "red hat": "redhat",
    "redhat": "redhat",
    "ubuntu": "canonical",
    "centos": "centos",
    "fedora": "fedoraproject",
    "suse": "suse",
    "opensuse": "opensuse",
    "php": "php",
    "php group": "php",
    "the php group": "php",
    "python": "python",
    "python software foundation": "python",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "node": "nodejs",
    "wordpress": "wordpress",
    "automattic": "wordpress",
    "mysql": "oracle",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "isc": "isc",
    "proftpd": "proftpd",
    "vsftpd": "vsftpd",
    "pure-ftpd": "pureftpd",
    "samba": "samba",
    "samba team": "samba",
    "dovecot": "dovecot",
    "postfix": "postfix",
    "exim": "exim",
    "sendmail": "sendmail",
    "lighttpd": "lighttpd",
    "haproxy": "haproxy",
    "squid": "squid-cache",
    "tomcat": "apache",
    "jetty": "eclipse",
    "eclipse": "eclipse",
    "elastic": "elastic",
    "elasticsearch": "elastic",
    "redis": "redis",
    "mongodb": "mongodb",
    "mongo": "mongodb",
    "docker": "docker",
    "grafana": "grafana",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "jira": "atlassian",
    "atlassian": "atlassian",
    "confluence": "atlassian",
    "bitbucket": "atlassian",
    "cisco": "cisco",
    "juniper": "juniper",
    "fortinet": "fortinet",
    "palo alto": "paloaltonetworks",
    "vmware": "vmware",
    "citrix": "citrix",
}

_PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    # nmap_product_lower -> (cpe_vendor, cpe_product)
    "apache httpd": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "microsoft iis httpd": ("microsoft", "internet_information_services"),
    "iis": ("microsoft", "internet_information_services"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "php": ("php", "php"),
    "python": ("python", "python"),
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "samba": ("samba", "samba"),
    "postfix": ("postfix", "postfix"),
    "dovecot": ("dovecot", "dovecot"),
    "exim": ("exim", "exim"),
    "sendmail": ("sendmail", "sendmail"),
    "bind": ("isc", "bind"),
    "named": ("isc", "bind"),
    "isc bind": ("isc", "bind"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "squid": ("squid-cache", "squid"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "haproxy": ("haproxy", "haproxy"),
    "tomcat": ("apache", "tomcat"),
    "apache tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "jenkins": ("jenkins", "jenkins"),
    "grafana": ("grafana", "grafana"),
    "gitlab": ("gitlab", "gitlab"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "microsoft exchange": ("microsoft", "exchange_server"),
    "exchange": ("microsoft", "exchange_server"),
    "microsoft smb": ("microsoft", "windows"),
    "microsoft windows smb": ("microsoft", "windows"),
    "microsoft windows rpc": ("microsoft", "windows"),
    "microsoft ftpd": ("microsoft", "ftp_service"),
    "microsoft smtp": ("microsoft", "exchange_server"),
    "microsoft sql server": ("microsoft", "sql_server"),
    "mssql": ("microsoft", "sql_server"),
    "vnc": ("realvnc", "vnc"),
    "tightvnc": ("tightvnc", "tightvnc"),
    "cups": ("apple", "cups"),
    "snmp": ("net-snmp", "net-snmp"),
    "net-snmp": ("net-snmp", "net-snmp"),
    "wireguard": ("wireguard", "wireguard"),
    "openvpn": ("openvpn", "openvpn"),
    "strongswan": ("strongswan", "strongswan"),
}


# =============================================================================
# Version Normalization
# =============================================================================

_VERSION_CLEAN_RE = re.compile(r"^[\d]+\.[\d]+(?:\.[\d]+)?(?:\.[\d]+)?")
_VERSION_STRIP_RE = re.compile(r"[^\d.\-_a-zA-Z]")


def normalize_version(raw_version: str | None) -> str:
    """Clean and normalize a version string.

    Examples:
        "2.4.49" -> "2.4.49"
        "7.4p1" -> "7.4p1"
        "8.0.28-0ubuntu0.20.04.3" -> "8.0.28"
        "10.3.34-MariaDB" -> "10.3.34"
    """
    if not raw_version:
        return ""

    raw_version = raw_version.strip()

    # Try to extract the core version number
    match = _VERSION_CLEAN_RE.match(raw_version)
    if match:
        return match.group(0)

    # Fallback: clean common suffixes
    cleaned = raw_version.split("-")[0].split("+")[0].split("~")[0]
    cleaned = _VERSION_STRIP_RE.sub("", cleaned)
    return cleaned or raw_version


# =============================================================================
# CPE Builder
# =============================================================================


def build_cpe(
    vendor: str,
    product: str,
    version: str = "*",
    part: str = "a",
) -> str:
    """Build a CPE 2.3 string.

    Args:
        vendor: Normalized vendor name (lowercase, underscores).
        product: Normalized product name (lowercase, underscores).
        version: Version string or "*" for any.
        part: CPE part — "a" (application), "o" (OS), "h" (hardware).

    Returns:
        CPE 2.3 formatted string.
    """
    # Sanitize for CPE format
    vendor = _cpe_sanitize(vendor)
    product = _cpe_sanitize(product)
    version = _cpe_sanitize(version) if version and version != "*" else "*"

    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _cpe_sanitize(value: str) -> str:
    """Sanitize a string for use in a CPE component."""
    value = value.lower().strip()
    value = re.sub(r"\s+", "_", value)
    value = re.sub(r"[^a-z0-9._\-]", "", value)
    return value or "*"


# =============================================================================
# Fingerprint Engine
# =============================================================================


class FingerprintEngine:
    """Normalizes raw service/software detections into structured fingerprints.

    Supports:
      - Exact matching against alias tables
      - Fuzzy matching for partial matches
      - CPE construction
      - Confidence scoring
    """

    def __init__(
        self,
        fuzzy_threshold: int = 75,
        custom_vendor_aliases: dict[str, str] | None = None,
        custom_product_aliases: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        """Initialize the fingerprint engine.

        Args:
            fuzzy_threshold: Minimum fuzz ratio (0-100) for fuzzy matching.
            custom_vendor_aliases: Additional vendor aliases to merge.
            custom_product_aliases: Additional product aliases to merge.
        """
        self._fuzzy_threshold = fuzzy_threshold
        self._vendor_aliases = {**_VENDOR_ALIASES}
        self._product_aliases = {**_PRODUCT_ALIASES}

        if custom_vendor_aliases:
            self._vendor_aliases.update(custom_vendor_aliases)
        if custom_product_aliases:
            self._product_aliases.update(custom_product_aliases)

    def fingerprint_service(self, service: DiscoveredService) -> FingerprintResult | None:
        """Create a normalized fingerprint from a discovered service.

        Args:
            service: DiscoveredService from Nmap parsing.

        Returns:
            FingerprintResult or None if insufficient data.
        """
        if not service.product and not service.name and not service.cpe_raw:
            return None

        evidence: list[str] = []
        aliases_used: list[str] = []

        # 1. Try Nmap CPE first (highest confidence)
        if service.cpe_raw:
            for cpe_str in service.cpe_raw:
                result = self._from_nmap_cpe(cpe_str, service)
                if result:
                    return result

        # 2. Try exact product match
        raw_input = self._build_raw_input(service)
        product_lower = (service.product or service.name or "").lower().strip()

        if product_lower in self._product_aliases:
            cpe_vendor, cpe_product = self._product_aliases[product_lower]
            version = normalize_version(service.version)
            evidence.append(f"Exact product alias match: '{product_lower}'")
            aliases_used.append(product_lower)

            cpe = build_cpe(cpe_vendor, cpe_product, version) if version else None

            return FingerprintResult(
                vendor=cpe_vendor,
                product=cpe_product,
                version=version,
                cpe=cpe,
                confidence=Confidence.HIGH,
                confidence_score=0.85,
                evidence=evidence,
                raw_input=raw_input,
                aliases_used=aliases_used,
            )

        # 3. Try fuzzy product match
        fuzzy_result = self._fuzzy_match_product(product_lower)
        if fuzzy_result:
            cpe_vendor, cpe_product, score, matched = fuzzy_result
            version = normalize_version(service.version)
            evidence.append(f"Fuzzy product match: '{product_lower}' -> '{matched}' (score={score})")
            aliases_used.append(matched)

            # Confidence based on fuzzy score
            if score >= 90:
                confidence = Confidence.HIGH
                conf_score = 0.80
            elif score >= 80:
                confidence = Confidence.MEDIUM
                conf_score = 0.65
            else:
                confidence = Confidence.LOW
                conf_score = 0.50

            cpe = build_cpe(cpe_vendor, cpe_product, version) if version else None

            return FingerprintResult(
                vendor=cpe_vendor,
                product=cpe_product,
                version=version,
                cpe=cpe,
                confidence=confidence,
                confidence_score=conf_score,
                evidence=evidence,
                raw_input=raw_input,
                aliases_used=aliases_used,
            )

        # 4. Fallback — use raw data with low confidence
        vendor = self._resolve_vendor(product_lower)
        version = normalize_version(service.version)
        evidence.append(f"No alias match — using raw product name: '{product_lower}'")

        product_clean = _cpe_sanitize(product_lower) if product_lower else "unknown"
        cpe = build_cpe(vendor, product_clean, version) if version and vendor != "unknown" else None

        return FingerprintResult(
            vendor=vendor,
            product=product_clean or "unknown",
            version=version,
            cpe=cpe,
            confidence=Confidence.TENTATIVE,
            confidence_score=0.30,
            evidence=evidence,
            raw_input=raw_input,
        )

    def fingerprint_services(
        self, services: list[DiscoveredService]
    ) -> list[FingerprintResult]:
        """Fingerprint multiple services.

        Args:
            services: List of discovered services.

        Returns:
            List of fingerprint results (excluding None results).
        """
        results = []
        for svc in services:
            fp = self.fingerprint_service(svc)
            if fp:
                results.append(fp)

        logger.info(
            "fingerprinting_complete",
            input_services=len(services),
            fingerprints=len(results),
        )
        return results

    def _from_nmap_cpe(
        self, cpe_str: str, service: DiscoveredService
    ) -> FingerprintResult | None:
        """Parse a CPE string provided by Nmap's service detection."""
        # Nmap CPEs can be cpe:/a:vendor:product:version or cpe:2.3:...
        parts = cpe_str.replace("cpe:/", "cpe:2.3:").split(":")

        if len(parts) < 5:
            return None

        # cpe:2.3:part:vendor:product:version:...
        try:
            part = parts[2] if len(parts) > 2 else "a"
            vendor = parts[3] if len(parts) > 3 else ""
            product = parts[4] if len(parts) > 4 else ""
            version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
        except IndexError:
            return None

        if not vendor or not product:
            return None

        # Override version from service detection if available
        if not version and service.version:
            version = normalize_version(service.version)

        # Build proper CPE 2.3
        cpe = build_cpe(vendor, product, version or "*", part)

        return FingerprintResult(
            vendor=vendor,
            product=product,
            version=version or normalize_version(service.version) or "",
            cpe=cpe,
            confidence=Confidence.HIGH,
            confidence_score=0.90,
            evidence=[f"Nmap CPE: {cpe_str}"],
            raw_input=self._build_raw_input(service),
        )

    def _fuzzy_match_product(
        self, product_lower: str
    ) -> tuple[str, str, int, str] | None:
        """Find best fuzzy match in product aliases.

        Returns:
            (cpe_vendor, cpe_product, score, matched_key) or None.
        """
        if not product_lower:
            return None

        best_score = 0
        best_match: tuple[str, str, int, str] | None = None

        for alias, (cpe_vendor, cpe_product) in self._product_aliases.items():
            score = fuzz.ratio(product_lower, alias)
            if score > best_score and score >= self._fuzzy_threshold:
                best_score = score
                best_match = (cpe_vendor, cpe_product, score, alias)

        return best_match

    def _resolve_vendor(self, product_lower: str) -> str:
        """Try to resolve a vendor from vendor aliases."""
        for alias, vendor in self._vendor_aliases.items():
            if alias in product_lower or product_lower in alias:
                return vendor
        return "unknown"

    @staticmethod
    def _build_raw_input(service: DiscoveredService) -> str:
        """Build a human-readable raw input string from service data."""
        parts = []
        if service.product:
            parts.append(service.product)
        if service.version:
            parts.append(service.version)
        if service.extra_info:
            parts.append(f"({service.extra_info})")
        if not parts and service.name:
            parts.append(service.name)
        return " ".join(parts)
