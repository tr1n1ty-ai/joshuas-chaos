"""Tests for core/config.py."""

import textwrap
from pathlib import Path

import pytest

from joshuas_chaos.core.config import ConfigError, load_config
from joshuas_chaos.core.models import AppConfig


@pytest.mark.unit
class TestLoadConfig:
    def test_successful_load(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            textwrap.dedent("""\
                allowed_accounts:
                  - "123456789012"
                allowed_regions:
                  - "us-east-1"
                impact_mode: "low"
                resource_safety:
                  required_tag_key: "AttackLab"
                  required_tag_value: "true"
                  allowed_name_prefix: "AttackLab"
                modules:
                  s3_versioning_recovery:
                    enabled: true
            """)
        )
        config = load_config(cfg_file)
        assert isinstance(config, AppConfig)
        assert config.allowed_accounts == ["123456789012"]
        assert config.allowed_regions == ["us-east-1"]
        assert config.impact_mode == "low"
        assert config.resource_safety.required_tag_key == "AttackLab"
        assert config.resource_safety.allowed_name_prefix == "AttackLab"

    def test_missing_file_raises_config_error(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.yaml"
        with pytest.raises(ConfigError, match="not found"):
            load_config(missing)

    def test_malformed_yaml_raises_config_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "config.yaml"
        bad_file.write_text("key: [unclosed bracket\n")
        with pytest.raises(ConfigError, match="Malformed YAML"):
            load_config(bad_file)

    def test_non_mapping_yaml_raises_config_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "config.yaml"
        bad_file.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="Expected a YAML mapping"):
            load_config(bad_file)

    def test_missing_required_key_raises_config_error(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            textwrap.dedent("""\
                allowed_accounts:
                  - "123456789012"
                # missing: allowed_regions, impact_mode, resource_safety, modules
            """)
        )
        with pytest.raises(ConfigError, match="Missing required config keys"):
            load_config(cfg_file)

    def test_missing_resource_safety_subkey_raises_config_error(
        self, tmp_path: Path
    ) -> None:
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            textwrap.dedent("""\
                allowed_accounts:
                  - "123456789012"
                allowed_regions:
                  - "us-east-1"
                impact_mode: "low"
                resource_safety:
                  required_tag_key: "AttackLab"
                  # missing: required_tag_value, allowed_name_prefix
                modules: {}
            """)
        )
        with pytest.raises(ConfigError, match="Missing required resource_safety keys"):
            load_config(cfg_file)

    def test_allowed_accounts_not_list_raises_config_error(
        self, tmp_path: Path
    ) -> None:
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            textwrap.dedent("""\
                allowed_accounts: "not-a-list"
                allowed_regions:
                  - "us-east-1"
                impact_mode: "low"
                resource_safety:
                  required_tag_key: "AttackLab"
                  required_tag_value: "true"
                  allowed_name_prefix: "AttackLab"
                modules: {}
            """)
        )
        with pytest.raises(ConfigError, match="must be a list"):
            load_config(cfg_file)

    def test_modules_values_accessible(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            textwrap.dedent("""\
                allowed_accounts:
                  - "111111111111"
                allowed_regions:
                  - "us-west-2"
                impact_mode: "low"
                resource_safety:
                  required_tag_key: "AttackLab"
                  required_tag_value: "true"
                  allowed_name_prefix: "AttackLab"
                modules:
                  s3_versioning_recovery:
                    enabled: true
                    approved_buckets:
                      - "mytest-bucket"
            """)
        )
        config = load_config(cfg_file)
        s3_cfg = config.modules.get("s3_versioning_recovery", {})
        assert s3_cfg.get("enabled") is True
        assert "mytest-bucket" in s3_cfg.get("approved_buckets", [])
