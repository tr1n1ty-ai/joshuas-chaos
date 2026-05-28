"""Safety checks and enforcement for the chaos engineering framework."""

import logging

from joshuas_chaos.core.models import AppConfig, CallerIdentity

logger = logging.getLogger("joshuas_chaos")


class SafetyError(Exception):
    """Raised when a safety check fails. Always fail closed."""


class SafetyChecker:
    """Enforces all safety invariants for the framework.

    All checks raise SafetyError on failure — never silently pass.
    """

    def __init__(self, config: AppConfig, identity: CallerIdentity) -> None:
        self._config = config
        self._identity = identity

    def assert_account_allowed(self) -> None:
        """Raise SafetyError if the current account is not in the allowlist."""
        account_id = self._identity.account_id
        if account_id not in self._config.allowed_accounts:
            raise SafetyError(
                f"Account '{account_id}' is not in the allowed_accounts list. "
                f"Allowed: {self._config.allowed_accounts}. "
                "Add this account to config.yaml only if it is an authorized lab account."
            )
        logger.info("Account %s is in allowlist.", account_id)

    def assert_region_allowed(self, region: str) -> None:
        """Raise SafetyError if the given region is not in the allowlist."""
        if region not in self._config.allowed_regions:
            raise SafetyError(
                f"Region '{region}' is not in the allowed_regions list. "
                f"Allowed: {self._config.allowed_regions}."
            )
        logger.info("Region %s is in allowlist.", region)

    def assert_resource_safe(
        self, resource_name: str, tags: dict[str, str]
    ) -> None:
        """Raise SafetyError if the resource does not meet lab-safety requirements.

        A resource is safe if it meets AT LEAST ONE of:
          1. Its name starts with the configured allowed_name_prefix (default: 'AttackLab')
          2. It has the required tag key=value (default: AttackLab=true)
        """
        prefix = self._config.resource_safety.allowed_name_prefix
        tag_key = self._config.resource_safety.required_tag_key
        tag_val = self._config.resource_safety.required_tag_value

        has_prefix = resource_name.startswith(prefix)
        has_tag = tags.get(tag_key, "").lower() == tag_val.lower()

        if not has_prefix and not has_tag:
            raise SafetyError(
                f"Resource '{resource_name}' does not meet lab-safety requirements. "
                f"Resource must either start with '{prefix}' OR have tag {tag_key}={tag_val}. "
                "Only execute against authorized AttackLab resources."
            )
        logger.info(
            "Resource '%s' passed safety check (has_prefix=%s, has_tag=%s).",
            resource_name,
            has_prefix,
            has_tag,
        )

    def assert_execute_flags(
        self,
        execute: bool,
        confirm_account: str,
        i_understand: bool,
    ) -> None:
        """Raise SafetyError unless all three execute flags are satisfied.

        All of the following must be true:
          1. execute=True
          2. confirm_account matches the current account ID
          3. i_understand=True
        """
        if not execute:
            raise SafetyError(
                "Execute mode requires --execute flag. "
                "Dry-run mode is the default."
            )
        if not i_understand:
            raise SafetyError(
                "Execute mode requires --i-understand-this-is-authorized flag. "
                "This confirms you understand this tool is for authorized lab use only."
            )
        if confirm_account != self._identity.account_id:
            raise SafetyError(
                f"--confirm-account '{confirm_account}' does not match "
                f"current account '{self._identity.account_id}'. "
                "You must explicitly confirm the target account ID."
            )
        logger.info(
            "Execute flags validated for account %s.", self._identity.account_id
        )
