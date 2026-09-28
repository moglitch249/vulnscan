"""Tests for core domain models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from vulnscanner.core.models import (
    CVSSScore,
    CacheEntry,
    Confidence,
    DiscoveredHost,
    DiscoveredPort,
    DiscoveredService,
    EPSSScore,
    FingerprintResult,
    Finding,
    HostStatus,
    KEVEntry,
    PortState,
    Protocol,
    RiskAssessment,
    RiskFactor,
    ScanProfile,
    ScanRun,
    Severity,
    SourceStatus,
    TargetSpec,
    VulnerabilityRecord,
)


class TestTargetSpec:
    def test_valid_ip_target(self) -> None:
        ts = TargetSpec(raw="192.168.1.1", target_type="ip")
        assert ts.target_type == "ip"

    def test_valid_cidr_target(self) -> None:
        ts = TargetSpec(raw="10.0.0.0/24", target_type="cidr", cidr="10.0.0.0/24")
        assert ts.cidr == "10.0.0.0/24"

    def test_valid_url_target(self) -> None:
        ts = TargetSpec(
            raw="https://example.com", target_type="url", url="https://example.com"
        )
        assert ts.url == "https://example.com"

    def test_invalid_target_type_raises(self) -> None:
        with pytest.raises(PydanticValidationError):
            TargetSpec(raw="x", target_type="ftp")


class TestDiscoveredHost:
    def test_defaults(self) -> None:
        host = DiscoveredHost(ip="10.0.0.1")
        assert host.status == HostStatus.UNKNOWN
        assert host.id is not None


class TestDiscoveredPort:
    def test_port_bounds(self) -> None:
        from uuid import uuid4
        port = DiscoveredPort(host_id=uuid4(), port=443)
        assert port.port == 443

    def test_invalid_port_raises(self) -> None:
        from uuid import uuid4
        with pytest.raises(PydanticValidationError):
            DiscoveredPort(host_id=uuid4(), port=0)

        with pytest.raises(PydanticValidationError):
            DiscoveredPort(host_id=uuid4(), port=70000)


class TestFingerprintResult:
    def test_display_name(self) -> None:
        fp = FingerprintResult(vendor="Apache", product="HTTP Server", version="2.4.49")
        assert fp.display_name == "Apache HTTP Server 2.4.49"

    def test_confidence_score_bounds(self) -> None:
        with pytest.raises(PydanticValidationError):
            FingerprintResult(
                vendor="x", product="y", version="1.0", confidence_score=1.5
            )


class TestVulnerabilityRecord:
    def test_primary_id_cve(self) -> None:
        vr = VulnerabilityRecord(cve_id="CVE-2024-12345")
        assert vr.primary_id == "CVE-2024-12345"

    def test_primary_id_ghsa_fallback(self) -> None:
        vr = VulnerabilityRecord(ghsa_id="GHSA-xxxx-yyyy-zzzz")
        assert vr.primary_id == "GHSA-xxxx-yyyy-zzzz"

    def test_primary_id_uuid_fallback(self) -> None:
        vr = VulnerabilityRecord()
        assert len(vr.primary_id) > 0

    def test_severity_critical(self) -> None:
        vr = VulnerabilityRecord(
            cvss_scores=[CVSSScore(version="3.1", base_score=9.8)]
        )
        assert vr.severity == Severity.CRITICAL

    def test_severity_high(self) -> None:
        vr = VulnerabilityRecord(
            cvss_scores=[CVSSScore(version="3.1", base_score=7.5)]
        )
        assert vr.severity == Severity.HIGH

    def test_severity_medium(self) -> None:
        vr = VulnerabilityRecord(
            cvss_scores=[CVSSScore(version="3.1", base_score=5.0)]
        )
        assert vr.severity == Severity.MEDIUM

    def test_severity_low(self) -> None:
        vr = VulnerabilityRecord(
            cvss_scores=[CVSSScore(version="3.1", base_score=2.0)]
        )
        assert vr.severity == Severity.LOW

    def test_severity_unknown_no_scores(self) -> None:
        vr = VulnerabilityRecord()
        assert vr.severity == Severity.UNKNOWN

    def test_max_cvss_selects_highest(self) -> None:
        vr = VulnerabilityRecord(
            cvss_scores=[
                CVSSScore(version="3.1", base_score=5.0),
                CVSSScore(version="4.0", base_score=8.1),
            ]
        )
        assert vr.max_cvss_score == 8.1

    def test_dedup_key_deterministic(self) -> None:
        vr1 = VulnerabilityRecord(cve_id="CVE-2024-1111", vendor="Apache")
        vr2 = VulnerabilityRecord(cve_id="CVE-2024-1111", vendor="Apache")
        assert vr1.dedup_key() == vr2.dedup_key()

    def test_dedup_key_differs(self) -> None:
        vr1 = VulnerabilityRecord(cve_id="CVE-2024-1111")
        vr2 = VulnerabilityRecord(cve_id="CVE-2024-2222")
        assert vr1.dedup_key() != vr2.dedup_key()


class TestRiskAssessment:
    def test_risk_level_critical(self) -> None:
        from uuid import uuid4
        ra = RiskAssessment(vulnerability_id=uuid4(), risk_score=95.0)
        assert ra.risk_level == Severity.CRITICAL

    def test_risk_level_low(self) -> None:
        from uuid import uuid4
        ra = RiskAssessment(vulnerability_id=uuid4(), risk_score=15.0)
        assert ra.risk_level == Severity.LOW


class TestCacheEntry:
    def test_is_expired(self) -> None:
        from datetime import datetime, timedelta

        old = CacheEntry(
            key="test",
            source="nvd",
            fetched_at=datetime.utcnow() - timedelta(hours=25),
            ttl_hours=24.0,
        )
        assert old.is_expired

    def test_not_expired(self) -> None:
        entry = CacheEntry(key="test", source="nvd", ttl_hours=24.0)
        assert not entry.is_expired


class TestEnums:
    def test_scan_profiles(self) -> None:
        assert ScanProfile.QUICK.value == "quick"
        assert ScanProfile.DEEP.value == "deep"

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"

    def test_source_status(self) -> None:
        assert SourceStatus.RATE_LIMITED.value == "rate_limited"
