"""Tests for core/safety.py."""

import pytest

from joshuas_chaos.core.models import AppConfig, CallerIdentity, ResourceSafetyConfig
from joshuas_chaos.core.safety import SafetyChecker, SafetyError

_SENTINEL = object()


def _make_config(
    allowed_accounts: list[str] | None = None,
    allowed_regions: list[str] | None = None,
) -> AppConfig:
    return AppConfig(
        allowed_accounts=["123456789012"] if allowed_accounts is None else allowed_accounts,
        allowed_regions=["us-east-1"] if allowed_regions is None else allowed_regions,
        impact_mode="low",
        resource_safety=ResourceSafetyConfig(
            required_tag_key="AttackLab",
            required_tag_value="true",
            allowed_name_prefix="AttackLab",
        ),
        modules={},
    )


def _make_identity(account_id: str = "123456789012") -> CallerIdentity:
    return CallerIdentity(
        account_id=account_id,
        user_id="AIDAEXAMPLE",
        arn=f"arn:aws:iam::{account_id}:user/test",
    )


@pytest.mark.unit
class TestAssertAccountAllowed:
    def test_account_in_allowlist_passes(self) -> None:
        config = _make_config(allowed_accounts=["123456789012"])
        identity = _make_identity("123456789012")
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()  # should not raise

    def test_account_not_in_allowlist_raises(self) -> None:
        config = _make_config(allowed_accounts=["123456789012"])
        identity = _make_identity("999999999999")
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError, match="not in the allowed_accounts"):
            checker.assert_account_allowed()

    def test_empty_allowlist_raises(self) -> None:
        config = _make_config(allowed_accounts=[])
        identity = _make_identity("123456789012")
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError):
            checker.assert_account_allowed()


@pytest.mark.unit
class TestAssertRegionAllowed:
    def test_region_in_allowlist_passes(self) -> None:
        config = _make_config(allowed_regions=["us-east-1", "us-west-2"])
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_region_allowed("us-east-1")  # should not raise
        checker.assert_region_allowed("us-west-2")  # should not raise

    def test_region_not_in_allowlist_raises(self) -> None:
        config = _make_config(allowed_regions=["us-east-1"])
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError, match="not in the allowed_regions"):
            checker.assert_region_allowed("eu-west-1")


@pytest.mark.unit
class TestAssertExecuteFlags:
    def test_all_three_flags_correct_passes(self) -> None:
        config = _make_config()
        identity = _make_identity("123456789012")
        checker = SafetyChecker(config, identity)
        checker.assert_execute_flags(
            execute=True,
            confirm_account="123456789012",
            i_understand=True,
        )  # should not raise

    def test_execute_false_raises(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError, match="--execute"):
            checker.assert_execute_flags(
                execute=False,
                confirm_account="123456789012",
                i_understand=True,
            )

    def test_i_understand_false_raises(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError, match="i-understand"):
            checker.assert_execute_flags(
                execute=True,
                confirm_account="123456789012",
                i_understand=False,
            )

    def test_wrong_account_raises(self) -> None:
        config = _make_config()
        identity = _make_identity("123456789012")
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError, match="does not match"):
            checker.assert_execute_flags(
                execute=True,
                confirm_account="999999999999",
                i_understand=True,
            )

    def test_missing_execute_flag_raises(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError):
            checker.assert_execute_flags(
                execute=True,
                confirm_account="",
                i_understand=True,
            )


@pytest.mark.unit
class TestAssertResourceSafe:
    def test_resource_with_attack_lab_tag_passes(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_resource_safe("my-bucket", {"AttackLab": "true"})  # no raise

    def test_resource_with_attack_lab_prefix_passes(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_resource_safe("AttackLabFooBucket", {})  # no raise

    def test_resource_with_prefix_and_tag_passes(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_resource_safe("AttackLabBucket", {"AttackLab": "true"})  # no raise

    def test_resource_without_tag_and_wrong_name_raises(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError, match="does not meet lab-safety"):
            checker.assert_resource_safe("prod-important-bucket", {})

    def test_resource_with_wrong_tag_value_raises(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        with pytest.raises(SafetyError):
            checker.assert_resource_safe("my-bucket", {"AttackLab": "false"})

    def test_resource_tag_case_insensitive(self) -> None:
        config = _make_config()
        identity = _make_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_resource_safe("my-bucket", {"AttackLab": "True"})  # should pass
