"""Tests for configuration loading."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from vulnscanner.core.config import AppConfig, load_config


class TestLoadConfig:
    def test_default_config_without_files(self, tmp_path: Path) -> None:
        """Loading with no files should return defaults."""
        cfg = load_config(
            config_path=tmp_path / "nonexistent.yaml",
            env_path=tmp_path / "nonexistent.env",
        )
        assert isinstance(cfg, AppConfig)
        assert cfg.name == "vulnscanner"
        assert cfg.max_concurrency == 10

    def test_yaml_loading(self, tmp_path: Path) -> None:
        """YAML values should be loaded."""
        yaml_content = {
            "scanner": {"name": "test-scanner", "max_concurrency": 5},
            "database": {"backend": "sqlite", "sqlite_path": "test.db"},
        }
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml.dump(yaml_content))

        cfg = load_config(config_path=yaml_path, env_path=tmp_path / "no.env")
        assert cfg.name == "test-scanner"
        assert cfg.max_concurrency == 5
        assert cfg.database.sqlite_path == "test.db"

    def test_env_overrides_yaml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables should override YAML."""
        yaml_content = {"scanner": {"max_concurrency": 5}}
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml.dump(yaml_content))

        monkeypatch.setenv("MAX_CONCURRENCY", "20")

        cfg = load_config(config_path=yaml_path, env_path=tmp_path / "no.env")
        assert cfg.max_concurrency == 20

    def test_secrets_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """API keys should come from environment variables."""
        monkeypatch.setenv("NVD_API_KEY", "test-nvd-key")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")

        cfg = load_config(
            config_path=tmp_path / "no.yaml", env_path=tmp_path / "no.env"
        )
        assert cfg.nvd_api_key == "test-nvd-key"
        assert cfg.github_token == "ghp_test"

    def test_profiles_loading(self, tmp_path: Path) -> None:
        """Scan profiles should load from YAML."""
        yaml_content = {
            "profiles": {
                "quick": {
                    "description": "Fast scan",
                    "nmap_args": ["-sn"],
                    "port_discovery": False,
                }
            }
        }
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml.dump(yaml_content))

        cfg = load_config(config_path=yaml_path, env_path=tmp_path / "no.env")
        assert "quick" in cfg.profiles
        assert cfg.profiles["quick"].nmap_args == ["-sn"]

    def test_sources_loading(self, tmp_path: Path) -> None:
        """Vulnerability source configs should load from YAML."""
        yaml_content = {
            "sources": {
                "nvd": {
                    "enabled": True,
                    "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    "cache_ttl_hours": 48,
                }
            }
        }
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(yaml.dump(yaml_content))

        cfg = load_config(config_path=yaml_path, env_path=tmp_path / "no.env")
        assert "nvd" in cfg.sources
        assert cfg.sources["nvd"].cache_ttl_hours == 48
