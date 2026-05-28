"""Tests for modules/s3_versioning_recovery using botocore Stubber."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.stub import Stubber

from joshuas_chaos.core.models import AppConfig, CallerIdentity, ResourceSafetyConfig
from joshuas_chaos.modules.s3_versioning_recovery.module import S3VersioningRecoveryModule


def _make_config(approved_buckets: list[str] | None = None) -> AppConfig:
    return AppConfig(
        allowed_accounts=["123456789012"],
        allowed_regions=["us-east-1"],
        impact_mode="low",
        resource_safety=ResourceSafetyConfig(
            required_tag_key="AttackLab",
            required_tag_value="true",
            allowed_name_prefix="AttackLab",
        ),
        modules={
            "s3_versioning_recovery": {
                "enabled": True,
                "approved_buckets": approved_buckets or [],
            }
        },
    )


def _make_identity() -> CallerIdentity:
    return CallerIdentity(
        account_id="123456789012",
        user_id="AIDAEXAMPLE",
        arn="arn:aws:iam::123456789012:user/test",
    )


def _make_context(s3_client) -> MagicMock:
    """Return a mock AWSContext that returns the given s3 client."""
    context = MagicMock()
    context.region = "us-east-1"
    context.get_caller_identity.return_value = _make_identity()
    context.get_client.return_value = s3_client
    return context


@pytest.mark.unit
class TestS3VersioningRecoveryDryRun:
    def test_dry_run_does_not_modify_buckets(self) -> None:
        """Dry run must not call PutBucketVersioning."""
        import boto3

        s3_client = boto3.client("s3", region_name="us-east-1")
        stubber = Stubber(s3_client)

        stubber.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "my-bucket", "CreationDate": "2024-01-01"}]},
        )
        stubber.add_response(
            "get_bucket_versioning",
            {"Status": "Enabled"},
            expected_params={"Bucket": "my-bucket"},
        )
        stubber.add_response(
            "get_bucket_tagging",
            {"TagSet": []},
            expected_params={"Bucket": "my-bucket"},
        )

        module = S3VersioningRecoveryModule()
        config = _make_config()
        context = _make_context(s3_client)

        with stubber:
            result = module.dry_run(context, config)

        # Must not have any PutBucketVersioning in api_calls
        assert not any("PutBucketVersioning" in call for call in result.aws_api_calls)
        assert result.mode == "dry-run"

    def test_dry_run_returns_versioning_status(self) -> None:
        import boto3

        s3_client = boto3.client("s3", region_name="us-east-1")
        stubber = Stubber(s3_client)

        stubber.add_response(
            "list_buckets",
            {
                "Buckets": [
                    {"Name": "bucket-enabled", "CreationDate": "2024-01-01"},
                    {"Name": "bucket-suspended", "CreationDate": "2024-01-01"},
                ]
            },
        )
        stubber.add_response(
            "get_bucket_versioning",
            {"Status": "Enabled"},
            expected_params={"Bucket": "bucket-enabled"},
        )
        stubber.add_response(
            "get_bucket_versioning",
            {"Status": "Suspended"},
            expected_params={"Bucket": "bucket-suspended"},
        )
        stubber.add_response(
            "get_bucket_tagging",
            {"TagSet": []},
            expected_params={"Bucket": "bucket-enabled"},
        )
        stubber.add_response(
            "get_bucket_tagging",
            {"TagSet": []},
            expected_params={"Bucket": "bucket-suspended"},
        )

        module = S3VersioningRecoveryModule()
        config = _make_config()
        context = _make_context(s3_client)

        with stubber:
            result = module.dry_run(context, config)

        assert result.mode == "dry-run"
        findings_text = " ".join(result.findings)
        assert "bucket-suspended" in findings_text or "WITHOUT versioning" in findings_text


@pytest.mark.unit
class TestS3VersioningRecoveryExecute:
    def test_execute_refuses_untagged_buckets(self) -> None:
        """Execute must not modify buckets that don't pass safety checks."""
        import boto3

        s3_client = boto3.client("s3", region_name="us-east-1")
        stubber = Stubber(s3_client)

        # Only a non-AttackLab bucket
        stubber.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "prod-real-bucket", "CreationDate": "2024-01-01"}]},
        )
        stubber.add_response(
            "get_bucket_tagging",
            {"TagSet": []},  # No AttackLab tag
            expected_params={"Bucket": "prod-real-bucket"},
        )

        module = S3VersioningRecoveryModule()
        config = _make_config()
        context = _make_context(s3_client)

        with stubber:
            result = module.execute(context, config)

        # Should report no targets found
        assert result.mode == "execute"
        findings_text = " ".join(result.findings)
        assert "No AttackLab" in findings_text or "No action taken" in findings_text
        # PutBucketVersioning must NOT appear in api_calls
        assert not any("PutBucketVersioning" in call for call in result.aws_api_calls)

    def test_execute_targets_attacklab_tagged_bucket(self) -> None:
        """Execute should modify AttackLab-tagged buckets."""
        import boto3

        s3_client = boto3.client("s3", region_name="us-east-1")
        stubber = Stubber(s3_client)

        stubber.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "AttackLabTestBucket", "CreationDate": "2024-01-01"}]},
        )
        stubber.add_response(
            "get_bucket_tagging",
            {"TagSet": [{"Key": "AttackLab", "Value": "true"}]},
            expected_params={"Bucket": "AttackLabTestBucket"},
        )
        # Safety re-check in execute
        stubber.add_response(
            "get_bucket_tagging",
            {"TagSet": [{"Key": "AttackLab", "Value": "true"}]},
            expected_params={"Bucket": "AttackLabTestBucket"},
        )
        stubber.add_response(
            "get_bucket_versioning",
            {"Status": "Enabled"},
            expected_params={"Bucket": "AttackLabTestBucket"},
        )
        # Suspend
        stubber.add_response(
            "put_bucket_versioning",
            {},
            expected_params={
                "Bucket": "AttackLabTestBucket",
                "VersioningConfiguration": {"Status": "Suspended"},
            },
        )
        # Re-enable
        stubber.add_response(
            "put_bucket_versioning",
            {},
            expected_params={
                "Bucket": "AttackLabTestBucket",
                "VersioningConfiguration": {"Status": "Enabled"},
            },
        )

        module = S3VersioningRecoveryModule()
        config = _make_config()
        context = _make_context(s3_client)

        # Patch sleep to avoid waiting during tests
        with stubber, patch("joshuas_chaos.modules.s3_versioning_recovery.module.time.sleep"):
            result = module.execute(context, config)

        assert result.mode == "execute"
        findings_text = " ".join(result.findings)
        assert "Suspended" in findings_text or "CHAOS" in findings_text


@pytest.mark.unit
class TestS3VersioningRecoveryCleanup:
    def test_cleanup_is_idempotent(self) -> None:
        """Calling cleanup twice should not raise and should be safe."""
        import boto3

        module = S3VersioningRecoveryModule()
        config = _make_config()

        def make_stubbed_context():
            s3_client = boto3.client("s3", region_name="us-east-1")
            stubber = Stubber(s3_client)
            stubber.add_response(
                "list_buckets",
                {"Buckets": []},
            )
            ctx = _make_context(s3_client)
            return ctx, stubber

        ctx1, stub1 = make_stubbed_context()
        with stub1:
            result1 = module.cleanup(ctx1, config)
        assert result1.mode == "cleanup"

        # Call again — should still succeed
        ctx2, stub2 = make_stubbed_context()
        with stub2:
            result2 = module.cleanup(ctx2, config)
        assert result2.mode == "cleanup"
        assert result2.cleanup_required is False

    def test_cleanup_re_enables_suspended_bucket(self) -> None:
        import boto3

        s3_client = boto3.client("s3", region_name="us-east-1")
        stubber = Stubber(s3_client)

        stubber.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "AttackLabBucket", "CreationDate": "2024-01-01"}]},
        )
        stubber.add_response(
            "get_bucket_tagging",
            {"TagSet": [{"Key": "AttackLab", "Value": "true"}]},
            expected_params={"Bucket": "AttackLabBucket"},
        )
        stubber.add_response(
            "get_bucket_versioning",
            {"Status": "Suspended"},
            expected_params={"Bucket": "AttackLabBucket"},
        )
        stubber.add_response(
            "put_bucket_versioning",
            {},
            expected_params={
                "Bucket": "AttackLabBucket",
                "VersioningConfiguration": {"Status": "Enabled"},
            },
        )

        module = S3VersioningRecoveryModule()
        config = _make_config()
        context = _make_context(s3_client)

        with stubber:
            result = module.cleanup(context, config)

        assert result.mode == "cleanup"
        assert any("Re-enabled" in f or "CLEANUP" in f for f in result.findings)


@pytest.mark.unit
class TestS3VersioningRecoveryAccessDenied:
    def test_access_denied_on_list_buckets_handled_gracefully(self) -> None:
        import boto3

        s3_client = boto3.client("s3", region_name="us-east-1")
        stubber = Stubber(s3_client)

        stubber.add_client_error(
            "list_buckets",
            service_error_code="AccessDenied",
            http_status_code=403,
        )

        module = S3VersioningRecoveryModule()
        config = _make_config()
        context = _make_context(s3_client)

        with stubber:
            result = module.dry_run(context, config)

        # Should return a result with errors, not raise
        assert result.mode == "dry-run"
        assert len(result.errors) > 0 or "denied" in " ".join(result.findings).lower()
