"""Core domain models for VulnScanner.

All data structures used across the framework are defined here as Pydantic
models to ensure validation, serialization, and type safety.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Enumerations
# =============================================================================


class ScanProfile(str, Enum):
    """Predefined scan intensity profiles."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    WEB = "web"


class Severity(str, Enum):
    """Standardized severity levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Protocol(str, Enum):
    """Network protocols."""

    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class HostStatus(str, Enum):
    """Host liveness status."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class PortState(str, Enum):
    """Port state from scanning."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class Confidence(str, Enum):
    """Confidence level for fingerprint / correlation results."""

    EXACT = "exact"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


class SourceStatus(str, Enum):
    """Status of a vulnerability source during a scan run."""

    OK = "ok"
    RATE_LIMITED = "rate_limited"
    UNAVAILABLE = "unavailable"
    AUTH_REQUIRED = "auth_required"
    ERROR = "error"
    DISABLED = "disabled"
    OFFLINE = "offline"


# =============================================================================
# Target Models
# =============================================================================


class TargetSpec(BaseModel):
    """A single scan target (IP, hostname, CIDR, or URL)."""

    raw: str = Field(description="Original target string as provided by user")
    target_type: str = Field(description="ip | hostname | cidr | url")
    resolved_ips: list[str] = Field(default_factory=list)
    hostname: str | None = None
    url: str | None = None
    cidr: str | None = None
    port_override: list[int] | None = None

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, v: str) -> str:
        allowed = {"ip", "hostname", "cidr", "url"}
        if v not in allowed:
            msg = f"target_type must be one of {allowed}, got '{v}'"
            raise ValueError(msg)
        return v


# =============================================================================
# Discovery Models
# =============================================================================


class DiscoveredHost(BaseModel):
    """A host found during network discovery."""

    id: UUID = Field(default_factory=uuid4)
    ip: str
    hostname: str | None = None
    mac_address: str | None = None
    status: HostStatus = HostStatus.UNKNOWN
    os_guess: str | None = None
    os_confidence: int | None = None  # 0-100
    scan_run_id: UUID | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class DiscoveredPort(BaseModel):
    """A port found on a discovered host."""

    id: UUID = Field(default_factory=uuid4)
    host_id: UUID
    port: int = Field(ge=1, le=65535)
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.OPEN
    reason: str | None = None


class DiscoveredService(BaseModel):
    """A service running on a discovered port."""

    id: UUID = Field(default_factory=uuid4)
    port_id: UUID
    host_id: UUID
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    tunnel: str | None = None  # e.g., "ssl"
    os_type: str | None = None
    banner: str | None = None
    cpe_raw: list[str] = Field(default_factory=list)
    confidence: int | None = None  # 0-10 Nmap confidence


# =============================================================================
# Fingerprint Models
# =============================================================================


class FingerprintResult(BaseModel):
    """Normalized software fingerprint with CPE and PURL."""

    id: UUID = Field(default_factory=uuid4)
    vendor: str
    product: str
    version: str
    cpe: str | None = None  # CPE 2.3 URI
    purl: str | None = None  # Package URL
    confidence: Confidence = Confidence.MEDIUM
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.5)
    evidence: list[str] = Field(default_factory=list)
    raw_input: str | None = None
    aliases_used: list[str] = Field(default_factory=list)

    @property
    def display_name(self) -> str:
        return f"{self.vendor} {self.product} {self.version}"


# =============================================================================
# Vulnerability Models
# =============================================================================


class CVSSScore(BaseModel):
    """CVSS score data."""

    version: str  # "3.1", "4.0", etc.
    vector_string: str | None = None
    base_score: float = Field(ge=0.0, le=10.0)
    severity: Severity = Severity.UNKNOWN
    exploitability_score: float | None = None
    impact_score: float | None = None
    source: str | None = None


class EPSSScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) data."""

    score: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)
    model_version: str | None = None
    date: datetime | None = None


class KEVEntry(BaseModel):
    """CISA Known Exploited Vulnerability entry."""

    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: datetime | None = None
    due_date: datetime | None = None
    required_action: str | None = None
    known_ransomware_use: str | None = None


class ExploitReference(BaseModel):
    """A reference to a public exploit."""

    source: str  # "exploit-db", "github", "metasploit", etc.
    id: str | None = None
    url: str | None = None
    description: str | None = None
    published: datetime | None = None
    verified: bool | None = None


class VulnerabilityRecord(BaseModel):
    """A fully correlated vulnerability with evidence from multiple sources.

    This is the central output object — every vulnerability finding
    is normalized into this schema before reporting.
    """

    id: UUID = Field(default_factory=uuid4)
    cve_id: str | None = None
    ghsa_id: str | None = None
    osv_id: str | None = None
    vendor_advisory_ids: list[str] = Field(default_factory=list)

    # Affected software
    vendor: str | None = None
    product: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    affected_cpes: list[str] = Field(default_factory=list)

    # Description
    title: str | None = None
    description: str | None = None

    # Scoring
    cvss_scores: list[CVSSScore] = Field(default_factory=list)
    epss: EPSSScore | None = None
    kev: KEVEntry | None = None

    # Exploits
    exploits: list[ExploitReference] = Field(default_factory=list)
    exploit_available: bool = False

    # Metadata
    published: datetime | None = None
    last_modified: datetime | None = None
    references: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    source_confidence: dict[str, float] = Field(default_factory=dict)

    # Correlation
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    correlation_evidence: list[str] = Field(default_factory=list)

    @property
    def primary_id(self) -> str:
        """Return the best available identifier."""
        return self.cve_id or self.ghsa_id or self.osv_id or str(self.id)

    @property
    def max_cvss_score(self) -> float | None:
        """Return the highest CVSS base score across all versions."""
        if not self.cvss_scores:
            return None
        return max(s.base_score for s in self.cvss_scores)

    @property
    def severity(self) -> Severity:
        """Derive severity from the highest CVSS score."""
        score = self.max_cvss_score
        if score is None:
            return Severity.UNKNOWN
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW
        return Severity.NONE

    def dedup_key(self) -> str:
        """Generate a deduplication key from available identifiers."""
        parts = [
            self.cve_id or "",
            self.ghsa_id or "",
            self.osv_id or "",
            self.vendor or "",
            self.product or "",
        ]
        raw = "|".join(parts).lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# =============================================================================
# Risk Models
# =============================================================================


class RiskFactor(BaseModel):
    """A single factor contributing to the risk score."""

    name: str
    value: float
    weight: float
    description: str
    evidence: str | None = None


class RiskAssessment(BaseModel):
    """Transparent, explainable risk assessment for a vulnerability finding."""

    vulnerability_id: UUID
    risk_score: float = Field(ge=0.0, le=100.0)
    factors: list[RiskFactor] = Field(default_factory=list)
    explanation: str | None = None

    @property
    def risk_level(self) -> Severity:
        if self.risk_score >= 90:
            return Severity.CRITICAL
        if self.risk_score >= 70:
            return Severity.HIGH
        if self.risk_score >= 40:
            return Severity.MEDIUM
        if self.risk_score > 0:
            return Severity.LOW
        return Severity.NONE


# =============================================================================
# Scan Run Models
# =============================================================================


class ScanRun(BaseModel):
    """Metadata for a complete scan execution."""

    id: UUID = Field(default_factory=uuid4)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    profile: ScanProfile = ScanProfile.STANDARD
    targets: list[TargetSpec] = Field(default_factory=list)
    source_statuses: dict[str, SourceStatus] = Field(default_factory=dict)
    total_hosts: int = 0
    total_ports: int = 0
    total_services: int = 0
    total_vulnerabilities: int = 0
    offline_mode: bool = False
    errors: list[str] = Field(default_factory=list)
    version: str = "0.1.0"


class Finding(BaseModel):
    """Links a vulnerability to a specific host/service discovered in a scan."""

    id: UUID = Field(default_factory=uuid4)
    scan_run_id: UUID
    host_id: UUID
    port_id: UUID | None = None
    service_id: UUID | None = None
    fingerprint_id: UUID | None = None
    vulnerability_id: UUID
    risk_assessment_id: UUID | None = None
    found_at: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Source Health Models
# =============================================================================


class SourceHealth(BaseModel):
    """Health status of a vulnerability intelligence source."""

    name: str
    status: SourceStatus
    last_checked: datetime | None = None
    last_successful: datetime | None = None
    response_time_ms: float | None = None
    error_message: str | None = None
    rate_limit_remaining: int | None = None
    cache_age_hours: float | None = None


# =============================================================================
# Cache Models
# =============================================================================


class CacheEntry(BaseModel):
    """Metadata for a cached API response."""

    key: str
    source: str
    fetched_at: datetime = Field(default_factory=datetime.utcnow)
    ttl_hours: float
    data_hash: str | None = None
    size_bytes: int | None = None

    @property
    def is_expired(self) -> bool:
        from datetime import timedelta

        if self.ttl_hours <= 0:
            return False
        return datetime.utcnow() > self.fetched_at + timedelta(hours=self.ttl_hours)
