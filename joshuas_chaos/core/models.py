"""Data models for the chaos engineering framework."""

from dataclasses import dataclass, field


@dataclass
class ResourceSafetyConfig:
    required_tag_key: str
    required_tag_value: str
    allowed_name_prefix: str


@dataclass
class AppConfig:
    allowed_accounts: list[str]
    allowed_regions: list[str]
    impact_mode: str
    resource_safety: ResourceSafetyConfig
    modules: dict[str, dict]


@dataclass
class ModuleResult:
    module: str
    mode: str  # "dry-run" | "execute" | "cleanup"
    account_id: str
    principal_arn: str
    region: str
    risk_summary: str
    required_permissions: list[str]
    observed_permissions: list[str]
    aws_api_calls: list[str]
    cloudtrail_events: list[str]
    findings: list[str]
    detections: list[str]
    cleanup_required: bool
    safe_to_execute: bool
    errors: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class CallerIdentity:
    account_id: str
    user_id: str
    arn: str
