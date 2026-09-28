"""Configuration loading and validation.

Loads settings from config.yaml and .env, merges them, and exposes a
typed AppConfig object used throughout the application.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field


# =============================================================================
# Configuration Sections
# =============================================================================


class DatabaseConfig(BaseModel):
    backend: str = "sqlite"
    sqlite_path: str = "data/vulnscanner.db"
    postgresql_dsn: str | None = None


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"
    file: str = "logs/vulnscanner.log"
    max_size_mb: int = 50
    backup_count: int = 5


class ScanProfileConfig(BaseModel):
    description: str = ""
    nmap_args: list[str] = Field(default_factory=list)
    port_discovery: bool = True
    service_detection: bool = True
    os_detection: bool = False
    vuln_lookup: bool = True
    http_fingerprint: bool = False
    max_targets: int = 256


class SourceConfig(BaseModel):
    """Generic configuration for a vulnerability source."""

    enabled: bool = True
    base_url: str | None = None
    feed_url: str | None = None
    api_url: str | None = None
    graphql_url: str | None = None
    json_url: str | None = None
    csaf_url: str | None = None
    git_repo: str | None = None
    local_path: str | None = None
    rate_limit_per_30s: int | None = None
    rate_limit_per_min: int | None = None
    rate_limit_per_hour: int | None = None
    request_delay_s: float | None = None
    results_per_page: int | None = None
    cache_ttl_hours: float = 24.0
    versions: list[str] | None = None
    osv_ecosystem: str | None = None
    query_endpoint: str | None = None
    querybatch_endpoint: str | None = None
    vuln_endpoint: str | None = None
    bulk_csv_url: str | None = None


class ToolConfig(BaseModel):
    """Configuration for an external scanner tool."""

    enabled: bool = False
    binary: str = ""
    timeout: int = 600


class ReportingConfig(BaseModel):
    output_dir: str = "reports"
    formats: list[str] = Field(default_factory=lambda: ["json", "html", "csv"])
    html_template: str = "templates/report.html.j2"
    redact_api_keys: bool = True
    include_evidence: bool = True
    include_raw_data: bool = False


class CacheConfig(BaseModel):
    enabled: bool = True
    backend: str = "sqlite"
    ttl_default_hours: float = 24.0
    max_size_mb: int = 500
    cleanup_interval_hours: float = 48.0


# =============================================================================
# Root Configuration
# =============================================================================


class AppConfig(BaseModel):
    """Root application configuration — the single source of truth."""

    # Scanner metadata
    name: str = "vulnscanner"
    version: str = "0.1.0"
    max_concurrency: int = 10
    http_timeout: int = 30
    max_retries: int = 3
    user_agent: str = "VulnScanner/0.1.0 (Defensive Security Research)"

    # Sections
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    profiles: dict[str, ScanProfileConfig] = Field(default_factory=dict)
    sources: dict[str, SourceConfig] = Field(default_factory=dict)
    tools: dict[str, ToolConfig] = Field(default_factory=dict)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)

    # API keys (loaded from .env, never hardcoded)
    nvd_api_key: str | None = None
    vulncheck_api_key: str | None = None
    github_token: str | None = None

    # Offline mode
    offline_data_path: str = "data/offline"


# =============================================================================
# Loader
# =============================================================================


def load_config(
    config_path: str | Path | None = None,
    env_path: str | Path | None = None,
) -> AppConfig:
    """Load and merge configuration from YAML file and environment variables.

    Priority (highest first):
      1. Environment variables
      2. .env file
      3. config.yaml

    Args:
        config_path: Path to config.yaml. Defaults to ./config.yaml.
        env_path: Path to .env file. Defaults to ./.env.

    Returns:
        Validated AppConfig instance.
    """
    # 1. Load .env
    env_file = Path(env_path) if env_path else Path(".env")
    if env_file.exists():
        load_dotenv(env_file)

    # 2. Load YAML
    yaml_path = Path(config_path) if config_path else Path("config.yaml")
    yaml_data: dict[str, Any] = {}
    if yaml_path.exists():
        with open(yaml_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
            if isinstance(raw, dict):
                # Flatten "scanner" top-level key if present
                scanner_block = raw.pop("scanner", {})
                yaml_data = {**scanner_block, **raw}

    # 3. Inject env-var secrets
    yaml_data["nvd_api_key"] = os.getenv("NVD_API_KEY") or yaml_data.get("nvd_api_key")
    yaml_data["vulncheck_api_key"] = (
        os.getenv("VULNCHECK_API_KEY") or yaml_data.get("vulncheck_api_key")
    )
    yaml_data["github_token"] = os.getenv("GITHUB_TOKEN") or yaml_data.get("github_token")

    # Concurrency from env
    max_conc = os.getenv("MAX_CONCURRENCY")
    if max_conc:
        yaml_data["max_concurrency"] = int(max_conc)

    # Database path from env
    db_path = os.getenv("DATABASE_PATH")
    if db_path:
        yaml_data.setdefault("database", {})["sqlite_path"] = db_path

    # Log level from env
    log_level = os.getenv("LOG_LEVEL")
    if log_level:
        yaml_data.setdefault("logging", {})["level"] = log_level

    # Offline data path from env
    offline = os.getenv("OFFLINE_DATA_PATH")
    if offline:
        yaml_data["offline_data_path"] = offline

    return AppConfig(**yaml_data)
