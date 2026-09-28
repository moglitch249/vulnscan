"""Tests for the VulnerabilitySource interface and NotImplementedSource."""

from __future__ import annotations

import pytest

from vulnscanner.core.interfaces import NotImplementedSource, VulnerabilitySource
from vulnscanner.core.models import SourceStatus


class TestNotImplementedSource:
    @pytest.fixture
    def source(self) -> NotImplementedSource:
        return NotImplementedSource(
            source_name="TestSource",
            reason="No public API available",
        )

    def test_name(self, source: NotImplementedSource) -> None:
        assert source.name == "TestSource"

    def test_capabilities_empty(self, source: NotImplementedSource) -> None:
        assert source.capabilities == set()

    def test_supports_nothing(self, source: NotImplementedSource) -> None:
        assert not source.supports("search_cve")
        assert not source.supports("anything")

    @pytest.mark.asyncio
    async def test_search_cve_returns_empty(self, source: NotImplementedSource) -> None:
        result = await source.search_cve("CVE-2024-12345")
        assert result == []

    @pytest.mark.asyncio
    async def test_search_product_returns_empty(self, source: NotImplementedSource) -> None:
        result = await source.search_product("apache", "httpd")
        assert result == []

    @pytest.mark.asyncio
    async def test_search_cpe_returns_empty(self, source: NotImplementedSource) -> None:
        result = await source.search_cpe("cpe:2.3:a:apache:http_server:*")
        assert result == []

    @pytest.mark.asyncio
    async def test_search_package_returns_empty(self, source: NotImplementedSource) -> None:
        result = await source.search_package("PyPI", "requests")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_vulnerability_returns_none(self, source: NotImplementedSource) -> None:
        result = await source.get_vulnerability("CVE-2024-12345")
        assert result is None

    @pytest.mark.asyncio
    async def test_health_check_unavailable(self, source: NotImplementedSource) -> None:
        health = await source.health_check()
        assert health.status == SourceStatus.UNAVAILABLE
        assert "No public API" in (health.error_message or "")

    @pytest.mark.asyncio
    async def test_download_offline_returns_false(self, source: NotImplementedSource) -> None:
        result = await source.download_offline_data("/tmp/test")
        assert result is False

    def test_reason_property(self, source: NotImplementedSource) -> None:
        assert source.reason == "No public API available"
