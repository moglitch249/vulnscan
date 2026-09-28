"""Tests for input validators."""

from __future__ import annotations

import pytest

from vulnscanner.core.validators import (
    ValidationError,
    validate_cpe,
    validate_cve_id,
    validate_port_range,
    validate_target,
)


class TestValidateTarget:
    def test_ipv4(self) -> None:
        ts = validate_target("192.168.1.1")
        assert ts.target_type == "ip"
        assert ts.resolved_ips == ["192.168.1.1"]

    def test_ipv6(self) -> None:
        ts = validate_target("::1")
        assert ts.target_type == "ip"

    def test_cidr(self) -> None:
        ts = validate_target("10.0.0.0/24")
        assert ts.target_type == "cidr"
        assert ts.cidr == "10.0.0.0/24"

    def test_hostname(self) -> None:
        ts = validate_target("example.com")
        assert ts.target_type == "hostname"
        assert ts.hostname == "example.com"

    def test_url_http(self) -> None:
        ts = validate_target("http://example.com/path")
        assert ts.target_type == "url"
        assert ts.url == "http://example.com/path"

    def test_url_https_with_port(self) -> None:
        ts = validate_target("https://example.com:8443")
        assert ts.target_type == "url"
        assert ts.port_override == [8443]

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="Empty"):
            validate_target("")

    def test_injection_semicolon(self) -> None:
        with pytest.raises(ValidationError, match="Invalid characters"):
            validate_target("192.168.1.1; rm -rf /")

    def test_injection_pipe(self) -> None:
        with pytest.raises(ValidationError, match="Invalid characters"):
            validate_target("10.0.0.1 | whoami")

    def test_injection_backtick(self) -> None:
        with pytest.raises(ValidationError, match="Invalid characters"):
            validate_target("`whoami`")

    def test_injection_dollar(self) -> None:
        with pytest.raises(ValidationError, match="Invalid characters"):
            validate_target("$(command)")

    def test_cidr_too_large(self) -> None:
        with pytest.raises(ValidationError, match="too large"):
            validate_target("10.0.0.0/8")

    def test_invalid_hostname(self) -> None:
        with pytest.raises(ValidationError, match="Invalid hostname"):
            validate_target("-invalid.com")

    def test_hostname_too_long(self) -> None:
        long = "a" * 254
        with pytest.raises(ValidationError, match="too long"):
            validate_target(long)


class TestValidatePortRange:
    def test_single_port(self) -> None:
        assert validate_port_range("80") == [80]

    def test_multiple_ports(self) -> None:
        assert validate_port_range("80,443,8080") == [80, 443, 8080]

    def test_port_range(self) -> None:
        ports = validate_port_range("1-5")
        assert ports == [1, 2, 3, 4, 5]

    def test_mixed(self) -> None:
        ports = validate_port_range("22,80,8000-8002")
        assert ports == [22, 80, 8000, 8001, 8002]

    def test_invalid_format(self) -> None:
        with pytest.raises(ValidationError, match="Invalid port range"):
            validate_port_range("abc")

    def test_port_zero(self) -> None:
        with pytest.raises(ValidationError, match="out of bounds"):
            validate_port_range("0")

    def test_port_too_high(self) -> None:
        with pytest.raises(ValidationError, match="out of bounds"):
            validate_port_range("70000")


class TestValidateCveId:
    def test_valid_cve(self) -> None:
        assert validate_cve_id("CVE-2024-12345") == "CVE-2024-12345"

    def test_lowercase_normalized(self) -> None:
        assert validate_cve_id("cve-2024-12345") == "CVE-2024-12345"

    def test_invalid_format(self) -> None:
        with pytest.raises(ValidationError, match="Invalid CVE"):
            validate_cve_id("NOT-A-CVE")

    def test_short_id(self) -> None:
        with pytest.raises(ValidationError, match="Invalid CVE"):
            validate_cve_id("CVE-2024-12")  # need at least 4 digits


class TestValidateCpe:
    def test_valid_cpe(self) -> None:
        cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        assert validate_cpe(cpe) == cpe

    def test_invalid_prefix(self) -> None:
        with pytest.raises(ValidationError, match="must start with"):
            validate_cpe("cpe:2.2:a:apache:http_server")

    def test_too_few_parts(self) -> None:
        with pytest.raises(ValidationError, match="too few"):
            validate_cpe("cpe:2.3:a")
