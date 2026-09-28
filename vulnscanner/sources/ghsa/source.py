"""GitHub Security Advisories (GHSA) source.

API: https://api.github.com/graphql (GraphQL)
Auth: Personal Access Token (PAT) recommended — 5000 req/hr
Rate limits: 5000 requests/hour with token
License: GitHub terms
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

_GRAPHQL_URL = "https://api.github.com/graphql"

_QUERY_BY_CVE = """
query($cveId: String!) {
  securityAdvisories(identifier: {type: CVE, value: $cveId}, first: 5) {
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      cvss { vectorString score }
      identifiers { type value }
      references { url }
      vulnerabilities(first: 20) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
"""

_QUERY_BY_GHSA = """
query($ghsaId: String!) {
  securityAdvisory(ghsaId: $ghsaId) {
    ghsaId
    summary
    description
    severity
    publishedAt
    updatedAt
    cvss { vectorString score }
    identifiers { type value }
    references { url }
    vulnerabilities(first: 20) {
      nodes {
        package { name ecosystem }
        vulnerableVersionRange
        firstPatchedVersion { identifier }
      }
    }
  }
}
"""

_QUERY_BY_PACKAGE = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
  securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 20) {
    nodes {
      advisory {
        ghsaId
        summary
        description
        severity
        publishedAt
        updatedAt
        cvss { vectorString score }
        identifiers { type value }
        references { url }
      }
      package { name ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""

# Map ecosystem names to GitHub's enum values
_ECOSYSTEM_MAP: dict[str, str] = {
    "pypi": "PIP",
    "pip": "PIP",
    "npm": "NPM",
    "go": "GO",
    "maven": "MAVEN",
    "nuget": "NUGET",
    "rubygems": "RUBYGEMS",
    "rust": "RUST",
    "crates.io": "RUST",
    "composer": "COMPOSER",
    "pub": "PUB",
    "erlang": "ERLANG",
    "actions": "ACTIONS",
    "swift": "SWIFT",
}


class GHSASource(VulnerabilitySource):
    """GitHub Security Advisories — GraphQL API."""

    def __init__(
        self,
        github_token: str | None = None,
        cache_ttl: float = 43200.0,
    ) -> None:
        self._token = github_token
        self._cache_ttl = cache_ttl

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if github_token:
            headers["Authorization"] = f"bearer {github_token}"

        self._client = ResilientClient(
            rate_limit=80.0,  # ~5000/hr = ~83/min
            rate_period=60.0,
            timeout=30.0,
            headers=headers,
        )

    @property
    def name(self) -> str:
        return "GHSA"

    @property
    def capabilities(self) -> set[str]:
        return {"search_cve", "search_package", "get_vuln"}

    async def search_cve(self, cve_id: str) -> list[VulnerabilityRecord]:
        if not self._token:
            logger.warning("ghsa_no_token", msg="GITHUB_TOKEN not set, skipping GHSA")
            return []

        try:
            resp = await self._client.post(
                _GRAPHQL_URL,
                json={"query": _QUERY_BY_CVE, "variables": {"cveId": cve_id}},
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            advisories = (data.get("data", {})
                          .get("securityAdvisories", {})
                          .get("nodes", []))
            return [self._parse_advisory(a) for a in advisories if a]
        except (SourceUnavailable,) as exc:
            logger.warning("ghsa_unavailable", error=str(exc))
            return []

    async def search_product(
        self, vendor: str, product: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        # Try common ecosystems
        return await self.search_package("", product, version)

    async def search_cpe(self, cpe: str) -> list[VulnerabilityRecord]:
        return []  # GHSA doesn't support CPE

    async def search_package(
        self, ecosystem: str, package_name: str, version: str | None = None
    ) -> list[VulnerabilityRecord]:
        if not self._token:
            return []

        gh_eco = _ECOSYSTEM_MAP.get(ecosystem.lower(), "")
        if not gh_eco:
            return []

        try:
            resp = await self._client.post(
                _GRAPHQL_URL,
                json={
                    "query": _QUERY_BY_PACKAGE,
                    "variables": {"ecosystem": gh_eco, "package": package_name},
                },
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            nodes = (data.get("data", {})
                     .get("securityVulnerabilities", {})
                     .get("nodes", []))

            results = []
            for node in nodes:
                advisory = node.get("advisory", {})
                record = self._parse_advisory(advisory)
                # Add package-specific info
                pkg = node.get("package", {})
                if pkg:
                    record.product = pkg.get("name")
                vuln_range = node.get("vulnerableVersionRange")
                if vuln_range:
                    record.affected_versions.append(vuln_range)
                fix = node.get("firstPatchedVersion", {})
                if fix and fix.get("identifier"):
                    record.fixed_versions.append(fix["identifier"])
                results.append(record)

            return results
        except (SourceUnavailable,) as exc:
            logger.warning("ghsa_unavailable", error=str(exc))
            return []

    async def get_vulnerability(self, vuln_id: str) -> VulnerabilityRecord | None:
        if vuln_id.startswith("CVE-"):
            results = await self.search_cve(vuln_id)
            return results[0] if results else None

        if vuln_id.startswith("GHSA-"):
            return await self._get_by_ghsa(vuln_id)

        return None

    async def _get_by_ghsa(self, ghsa_id: str) -> VulnerabilityRecord | None:
        if not self._token:
            return None

        try:
            resp = await self._client.post(
                _GRAPHQL_URL,
                json={"query": _QUERY_BY_GHSA, "variables": {"ghsaId": ghsa_id}},
                cache_ttl=self._cache_ttl,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            advisory = data.get("data", {}).get("securityAdvisory")
            if not advisory:
                return None

            return self._parse_advisory(advisory)
        except (SourceUnavailable,) as exc:
            logger.warning("ghsa_unavailable", error=str(exc))
            return None

    async def health_check(self) -> SourceHealth:
        if not self._token:
            return SourceHealth(
                name=self.name,
                status=SourceStatus.AUTH_REQUIRED,
                last_checked=datetime.utcnow(),
                error_message="GITHUB_TOKEN not configured",
            )
        try:
            import time
            start = time.monotonic()
            resp = await self._client.post(
                _GRAPHQL_URL,
                json={"query": "{ viewer { login } }"},
                cache_ttl=0,
            )
            elapsed = (time.monotonic() - start) * 1000

            if resp.status_code == 200:
                remaining = resp.headers.get("X-RateLimit-Remaining")
                return SourceHealth(
                    name=self.name,
                    status=SourceStatus.OK,
                    last_checked=datetime.utcnow(),
                    last_successful=datetime.utcnow(),
                    response_time_ms=elapsed,
                    rate_limit_remaining=int(remaining) if remaining else None,
                )
            return SourceHealth(
                name=self.name,
                status=SourceStatus.ERROR,
                last_checked=datetime.utcnow(),
                error_message=f"HTTP {resp.status_code}",
            )
        except Exception as exc:
            return self._unavailable_health(str(exc))

    def _parse_advisory(self, advisory: dict[str, Any]) -> VulnerabilityRecord:
        ghsa_id = advisory.get("ghsaId", "")
        cve_id = None

        for ident in advisory.get("identifiers", []):
            if ident.get("type") == "CVE":
                cve_id = ident.get("value")

        # CVSS
        cvss_scores: list[CVSSScore] = []
        cvss_data = advisory.get("cvss", {})
        if cvss_data and cvss_data.get("score"):
            cvss_scores.append(CVSSScore(
                version="3.1",
                vector_string=cvss_data.get("vectorString"),
                base_score=float(cvss_data.get("score", 0.0)),
                severity=self._map_severity(advisory.get("severity", "")),
                source="GHSA",
            ))

        # Affected / Fixed
        affected: list[str] = []
        fixed: list[str] = []
        for vuln in advisory.get("vulnerabilities", {}).get("nodes", []):
            vr = vuln.get("vulnerableVersionRange")
            if vr:
                affected.append(vr)
            fpv = vuln.get("firstPatchedVersion", {})
            if fpv and fpv.get("identifier"):
                fixed.append(fpv["identifier"])

        refs = [r.get("url", "") for r in advisory.get("references", []) if r.get("url")]

        return VulnerabilityRecord(
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            title=advisory.get("summary", ghsa_id),
            description=advisory.get("description", ""),
            cvss_scores=cvss_scores,
            affected_versions=affected,
            fixed_versions=fixed,
            published=self._parse_date(advisory.get("publishedAt")),
            last_modified=self._parse_date(advisory.get("updatedAt")),
            references=refs,
            sources=["GHSA"],
            source_confidence={"GHSA": 0.90},
            confidence=0.85,
        )

    @staticmethod
    def _map_severity(s: str) -> Severity:
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "LOW": Severity.LOW,
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
