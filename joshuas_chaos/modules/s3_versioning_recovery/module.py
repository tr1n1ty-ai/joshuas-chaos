"""S3 Bucket Versioning Recovery Module.

Chaos phase: Suspend versioning on AttackLab-tagged buckets.
Recovery phase: Re-enable versioning on all affected buckets.
"""

import logging
import time
from datetime import UTC, datetime

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_CHAOS_WAIT_SECONDS = 5  # Short wait in lab; configurable


class S3VersioningRecoveryModule(ChaosModule):
    name = "s3_versioning_recovery"
    description = (
        "Suspend S3 versioning on AttackLab-tagged buckets, then verify "
        "detection and re-enable (data-protection chaos scenario)."
    )
    category = "data-protection"
    required_permissions = [
        "s3:ListBuckets",
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning",
        "s3:GetBucketTagging",
    ]
    cloudtrail_events = [
        "ListBuckets",
        "GetBucketVersioning",
        "PutBucketVersioning",
        "GetBucketTagging",
    ]
    mitre_attack = ["T1485", "T1486"]
    destructive = False  # versioning can always be re-enabled
    reversible = True

    def _list_all_buckets(self, s3) -> list[str]:
        """Return names of all S3 buckets in the account."""
        response = s3.list_buckets()
        return [b["Name"] for b in response.get("Buckets", [])]

    def _get_versioning_status(self, s3, bucket: str) -> str:
        """Return 'Enabled', 'Suspended', or 'Never' for a bucket."""
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket)
            return resp.get("Status", "Never")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "AccessDenied":
                return "AccessDenied"
            return f"Error:{code}"

    def _get_bucket_tags(self, s3, bucket: str) -> dict[str, str]:
        """Return the tags for a bucket, or empty dict on failure."""
        try:
            resp = s3.get_bucket_tagging(Bucket=bucket)
            return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
        except botocore.exceptions.ClientError:
            return {}

    def _is_lab_safe(self, bucket: str, tags: dict[str, str], config: AppConfig) -> bool:
        """Return True if the bucket passes safety checks."""
        prefix = config.resource_safety.allowed_name_prefix
        tag_key = config.resource_safety.required_tag_key
        tag_val = config.resource_safety.required_tag_value
        return bucket.startswith(prefix) or tags.get(tag_key, "").lower() == tag_val.lower()

    def _is_approved(self, bucket: str, config: AppConfig) -> bool:
        """Return True if the bucket is in the approved_buckets config list."""
        module_cfg = config.modules.get("s3_versioning_recovery", {})
        approved = module_cfg.get("approved_buckets", [])
        return bucket in (approved or [])

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []

        try:
            buckets = self._list_all_buckets(s3)
            findings.append(f"Found {len(buckets)} S3 bucket(s) in account.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"s3:ListBuckets failed: {code}")
            buckets = []

        lab_buckets = []
        for bucket in buckets:
            tags = self._get_bucket_tags(s3, bucket)
            if self._is_lab_safe(bucket, tags, config) or self._is_approved(bucket, config):
                lab_buckets.append(bucket)

        if lab_buckets:
            findings.append(f"Lab-safe target buckets: {lab_buckets}")
        else:
            findings.append(
                "No AttackLab-tagged or approved buckets found. "
                "Execute will have no targets."
            )

        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Low — read-only check of bucket inventory and tags.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=["s3:ListBuckets", "s3:GetBucketTagging"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """List all buckets and their versioning status. No modifications."""
        identity = context.get_caller_identity()
        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            buckets = self._list_all_buckets(s3)
            api_calls.append("s3:ListBuckets")
            findings.append(f"Total S3 buckets: {len(buckets)}")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"s3:ListBuckets denied: {code}")
            return ModuleResult(
                module=self.name,
                mode="dry-run",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="Could not enumerate buckets — check IAM permissions.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=errors,
            )

        versioning_summary: dict[str, str] = {}
        for bucket in buckets:
            status = self._get_versioning_status(s3, bucket)
            api_calls.append(f"s3:GetBucketVersioning ({bucket})")
            versioning_summary[bucket] = status

        not_enabled = [b for b, s in versioning_summary.items() if s != "Enabled"]
        enabled = [b for b, s in versioning_summary.items() if s == "Enabled"]

        if not_enabled:
            findings.append(
                f"Buckets WITHOUT versioning enabled ({len(not_enabled)}): {not_enabled}"
            )
        else:
            findings.append("All buckets have versioning enabled.")

        findings.append(f"Buckets with versioning enabled: {len(enabled)}")

        # Identify which would be targeted in execute
        would_target = []
        for bucket in buckets:
            tags = self._get_bucket_tags(s3, bucket)
            api_calls.append(f"s3:GetBucketTagging ({bucket})")
            if self._is_lab_safe(bucket, tags, config) or self._is_approved(bucket, config):
                would_target.append(bucket)

        if would_target:
            findings.append(
                f"[DRY-RUN] Would target in execute mode: {would_target}"
            )
        else:
            findings.append(
                "[DRY-RUN] No AttackLab-tagged or approved buckets found to target."
            )

        detections = [
            "CloudTrail: PutBucketVersioning with Status=Suspended on AttackLab bucket",
            "Config Rule: s3-bucket-versioning-enabled (will trigger non-compliance)",
            "Security Hub: [S3.14] S3 general purpose buckets should have versioning enabled",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                "Observation only. Would suspend versioning on AttackLab-tagged buckets "
                "and re-enable after detection window."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(would_target),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Suspend versioning on AttackLab-tagged buckets, wait, then re-enable."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []
        affected: list[str] = []

        try:
            buckets = self._list_all_buckets(s3)
            api_calls.append("s3:ListBuckets")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"s3:ListBuckets failed: {code}")
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="Failed to list buckets.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=errors,
            )

        targets = []
        for bucket in buckets:
            tags = self._get_bucket_tags(s3, bucket)
            api_calls.append(f"s3:GetBucketTagging ({bucket})")
            if self._is_lab_safe(bucket, tags, config) or self._is_approved(bucket, config):
                targets.append(bucket)

        if not targets:
            findings.append(
                "No AttackLab-tagged or approved buckets found. No action taken."
            )
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No lab-safe targets found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=True,
                errors=errors,
            )

        # Phase 1: Suspend versioning
        for bucket in targets:
            try:
                checker.assert_resource_safe(
                    bucket,
                    self._get_bucket_tags(s3, bucket),
                )
                status = self._get_versioning_status(s3, bucket)
                api_calls.append(f"s3:GetBucketVersioning ({bucket})")

                if status == "Enabled":
                    suspend_time = datetime.now(tz=UTC).isoformat()
                    s3.put_bucket_versioning(
                        Bucket=bucket,
                        VersioningConfiguration={"Status": "Suspended"},
                    )
                    api_calls.append(f"s3:PutBucketVersioning ({bucket}, Suspended)")
                    findings.append(
                        f"[CHAOS] Suspended versioning on '{bucket}' at {suspend_time}"
                    )
                    affected.append(bucket)
                else:
                    findings.append(
                        f"Skipping '{bucket}' — versioning was not Enabled (status={status})"
                    )
            except Exception as exc:
                errors.append(f"Failed to suspend versioning on '{bucket}': {exc}")
                logger.error("execute: suspend failed for %s: %s", bucket, exc)

        if affected:
            findings.append(
                f"Waiting {_CHAOS_WAIT_SECONDS}s for detection window..."
            )
            time.sleep(_CHAOS_WAIT_SECONDS)

            # Phase 2: Re-enable versioning (immediate remediation)
            for bucket in affected:
                try:
                    re_enable_time = datetime.now(tz=UTC).isoformat()
                    s3.put_bucket_versioning(
                        Bucket=bucket,
                        VersioningConfiguration={"Status": "Enabled"},
                    )
                    api_calls.append(f"s3:PutBucketVersioning ({bucket}, Enabled)")
                    findings.append(
                        f"[REMEDIATION] Re-enabled versioning on '{bucket}' at {re_enable_time}"
                    )
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "Unknown")
                    errors.append(
                        f"Failed to re-enable versioning on '{bucket}': {code}"
                    )

        detections = [
            "CloudTrail: PutBucketVersioning Status=Suspended",
            "AWS Config: s3-bucket-versioning-enabled rule triggers NON_COMPLIANT",
            "Security Hub finding S3.14",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Suspended versioning on {len(affected)} bucket(s), then re-enabled."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["s3:ListBuckets", "s3:GetBucketVersioning", "s3:PutBucketVersioning"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=bool(errors),
            safe_to_execute=True,
            errors=errors,
            metadata={"affected_buckets": affected},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Re-enable versioning on all AttackLab-tagged buckets. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()

        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            buckets = self._list_all_buckets(s3)
            api_calls.append("s3:ListBuckets")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            return ModuleResult(
                module=self.name,
                mode="cleanup",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="Failed to list buckets during cleanup.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=[],
                detections=[],
                cleanup_required=True,
                safe_to_execute=False,
                errors=[f"s3:ListBuckets failed: {code}"],
            )

        remediated: list[str] = []
        for bucket in buckets:
            tags = self._get_bucket_tags(s3, bucket)
            api_calls.append(f"s3:GetBucketTagging ({bucket})")
            if not (self._is_lab_safe(bucket, tags, config) or self._is_approved(bucket, config)):
                continue

            status = self._get_versioning_status(s3, bucket)
            api_calls.append(f"s3:GetBucketVersioning ({bucket})")

            if status != "Enabled":
                try:
                    s3.put_bucket_versioning(
                        Bucket=bucket,
                        VersioningConfiguration={"Status": "Enabled"},
                    )
                    api_calls.append(f"s3:PutBucketVersioning ({bucket}, Enabled)")
                    findings.append(f"[CLEANUP] Re-enabled versioning on '{bucket}'")
                    remediated.append(bucket)
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "Unknown")
                    if code == "AccessDenied":
                        errors.append(f"AccessDenied re-enabling versioning on '{bucket}'")
                    else:
                        errors.append(f"Error re-enabling versioning on '{bucket}': {code}")
            else:
                findings.append(f"'{bucket}' versioning already Enabled — no action needed.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Cleanup complete. Re-enabled versioning on {len(remediated)} bucket(s).",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = S3VersioningRecoveryModule()
