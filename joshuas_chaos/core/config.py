"""Configuration loading and validation for the chaos engineering framework."""

from pathlib import Path

import yaml

from joshuas_chaos.core.models import AppConfig, ResourceSafetyConfig


class ConfigError(Exception):
    """Raised when config is missing, malformed, or incomplete."""


_DEFAULT_CONFIG_PATH = Path(__file__).parents[2] / "config.yaml"

_REQUIRED_TOP_LEVEL_KEYS = frozenset(
    {"allowed_accounts", "allowed_regions", "impact_mode", "resource_safety", "modules"}
)
_REQUIRED_SAFETY_KEYS = frozenset(
    {"required_tag_key", "required_tag_value", "allowed_name_prefix"}
)


def load_config(path: Path | None = None) -> AppConfig:
    """Load and validate config.yaml.

    Fails closed (raises ConfigError) if the file is missing or malformed.
    """
    config_path = path or _DEFAULT_CONFIG_PATH

    if not config_path.exists():
        raise ConfigError(
            f"Configuration file not found: {config_path}. "
            "Please create config.yaml before running."
        )

    try:
        raw = yaml.safe_load(config_path.read_text())
    except yaml.YAMLError as exc:
        raise ConfigError(f"Malformed YAML in {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(
            f"Expected a YAML mapping at the top level of {config_path}, got {type(raw).__name__}"
        )

    missing = _REQUIRED_TOP_LEVEL_KEYS - raw.keys()
    if missing:
        raise ConfigError(
            f"Missing required config keys in {config_path}: {sorted(missing)}"
        )

    # Validate resource_safety sub-section
    safety_raw = raw.get("resource_safety")
    if not isinstance(safety_raw, dict):
        raise ConfigError("'resource_safety' must be a mapping in config.yaml")

    missing_safety = _REQUIRED_SAFETY_KEYS - safety_raw.keys()
    if missing_safety:
        raise ConfigError(
            f"Missing required resource_safety keys: {sorted(missing_safety)}"
        )

    # Validate list fields
    for list_field in ("allowed_accounts", "allowed_regions"):
        if not isinstance(raw[list_field], list):
            raise ConfigError(f"'{list_field}' must be a list in config.yaml")

    if not isinstance(raw.get("modules"), dict):
        raise ConfigError("'modules' must be a mapping in config.yaml")

    resource_safety = ResourceSafetyConfig(
        required_tag_key=str(safety_raw["required_tag_key"]),
        required_tag_value=str(safety_raw["required_tag_value"]),
        allowed_name_prefix=str(safety_raw["allowed_name_prefix"]),
    )

    return AppConfig(
        allowed_accounts=[str(a) for a in raw["allowed_accounts"]],
        allowed_regions=[str(r) for r in raw["allowed_regions"]],
        impact_mode=str(raw["impact_mode"]),
        resource_safety=resource_safety,
        modules=raw["modules"],
    )
