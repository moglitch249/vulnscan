"""Resilient HTTP client with rate limiting, retry, caching, and timeouts.

This module provides a shared async HTTP client used by all vulnerability
sources. It wraps httpx with:
  - Per-source rate limiting (via aiolimiter)
  - Exponential backoff retry
  - Response caching
  - Configurable timeouts
  - Graceful failure (never crashes the entire scan)
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import httpx
from aiolimiter import AsyncLimiter

from vulnscanner.core.logging import get_logger

logger = get_logger(__name__)


class RateLimitExceeded(Exception):
    """Raised when a source's rate limit is exhausted after retries."""


class SourceUnavailable(Exception):
    """Raised when a source is unreachable after retries."""


class ResilientClient:
    """Async HTTP client with built-in resilience.

    Each vulnerability source should create its own ResilientClient instance
    with source-specific rate limits and timeouts.
    """

    def __init__(
        self,
        *,
        base_url: str = "",
        rate_limit: float = 10.0,
        rate_period: float = 1.0,
        timeout: float = 30.0,
        max_retries: int = 3,
        user_agent: str = "VulnScanner/0.1.0",
        headers: dict[str, str] | None = None,
        cache_enabled: bool = True,
    ) -> None:
        """Initialize the resilient HTTP client.

        Args:
            base_url: Base URL prepended to all requests.
            rate_limit: Maximum requests allowed per rate_period seconds.
            rate_period: Time window (seconds) for rate limiting.
            timeout: Request timeout in seconds.
            max_retries: Maximum retry attempts on transient failures.
            user_agent: User-Agent header value.
            headers: Additional default headers.
            cache_enabled: Whether to use in-memory response caching.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._limiter = AsyncLimiter(rate_limit, rate_period)
        self._cache: dict[str, tuple[float, Any]] = {}
        self._cache_enabled = cache_enabled

        default_headers = {"User-Agent": user_agent}
        if headers:
            default_headers.update(headers)

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout),
            headers=default_headers,
            follow_redirects=True,
        )

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache_ttl: float = 300.0,
    ) -> httpx.Response:
        """Perform a rate-limited, retrying GET request.

        Args:
            path: URL path (appended to base_url).
            params: Query parameters.
            headers: Additional request headers.
            cache_ttl: Cache TTL in seconds. Set to 0 to skip cache.

        Returns:
            httpx.Response on success.

        Raises:
            RateLimitExceeded: If rate limited after all retries.
            SourceUnavailable: If the source is unreachable.
        """
        cache_key = self._cache_key("GET", path, params)

        # Check cache
        if self._cache_enabled and cache_ttl > 0:
            cached = self._cache.get(cache_key)
            if cached and (time.monotonic() - cached[0]) < cache_ttl:
                logger.debug("cache_hit", path=path)
                return cached[1]

        return await self._request_with_retry(
            "GET", path, params=params, headers=headers, cache_key=cache_key,
            cache_ttl=cache_ttl,
        )

    async def post(
        self,
        path: str,
        json: Any | None = None,
        data: Any | None = None,
        headers: dict[str, str] | None = None,
        cache_ttl: float = 0.0,
    ) -> httpx.Response:
        """Perform a rate-limited, retrying POST request.

        Args:
            path: URL path.
            json: JSON body.
            data: Form data.
            headers: Additional request headers.
            cache_ttl: Cache TTL in seconds (0 = no caching).

        Returns:
            httpx.Response on success.
        """
        cache_key = self._cache_key("POST", path, json or data)

        if self._cache_enabled and cache_ttl > 0:
            cached = self._cache.get(cache_key)
            if cached and (time.monotonic() - cached[0]) < cache_ttl:
                logger.debug("cache_hit", path=path)
                return cached[1]

        return await self._request_with_retry(
            "POST", path, json=json, data=data, headers=headers,
            cache_key=cache_key, cache_ttl=cache_ttl,
        )

    async def _request_with_retry(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        data: Any | None = None,
        headers: dict[str, str] | None = None,
        cache_key: str = "",
        cache_ttl: float = 0.0,
    ) -> httpx.Response:
        """Execute an HTTP request with rate limiting and exponential backoff."""
        last_error: Exception | None = None

        for attempt in range(1, self._max_retries + 1):
            # Respect rate limit
            await self._limiter.acquire()

            try:
                response = await self._client.request(
                    method,
                    path,
                    params=params,
                    json=json,
                    data=data,
                    headers=headers,
                )

                # Handle rate limiting responses
                if response.status_code == 429:
                    retry_after = float(response.headers.get("Retry-After", "60"))
                    logger.warning(
                        "rate_limited",
                        path=path,
                        attempt=attempt,
                        retry_after=retry_after,
                    )
                    if attempt < self._max_retries:
                        await asyncio.sleep(min(retry_after, 120))
                        continue
                    raise RateLimitExceeded(
                        f"Rate limited after {self._max_retries} attempts: {path}"
                    )

                # Handle server errors with retry
                if response.status_code >= 500:
                    logger.warning(
                        "server_error",
                        path=path,
                        status=response.status_code,
                        attempt=attempt,
                    )
                    if attempt < self._max_retries:
                        backoff = 2 ** attempt
                        await asyncio.sleep(backoff)
                        continue
                    raise SourceUnavailable(
                        f"Server error {response.status_code} after retries: {path}"
                    )

                # Success — cache if applicable
                if self._cache_enabled and cache_ttl > 0 and response.status_code < 400:
                    self._cache[cache_key] = (time.monotonic(), response)

                return response

            except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError) as exc:
                last_error = exc
                logger.warning(
                    "request_failed",
                    path=path,
                    error=str(exc),
                    attempt=attempt,
                )
                if attempt < self._max_retries:
                    backoff = 2 ** attempt
                    await asyncio.sleep(backoff)
                    continue

        raise SourceUnavailable(
            f"Source unavailable after {self._max_retries} attempts: {path}"
        ) from last_error

    def _cache_key(self, method: str, path: str, params: Any = None) -> str:
        """Generate a deterministic cache key."""
        raw = f"{method}:{self._base_url}/{path}:{params}"
        return hashlib.sha256(raw.encode()).hexdigest()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> ResilientClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
