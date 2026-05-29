"""CloudTrail Lifecycle Rule Module.

Dry-run ONLY: Detect if principal can add S3 lifecycle rules to CloudTrail log buckets
to auto-delete logs. Maps to Stratus Red Team aws.defense-evasion.cloudtrail-lifecycle-rule.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class CloudTrailLifecycleRuleModule(ChaosModule):
    name = "cloudtrail_lifecycle_rule"
    description = (
        "Detect if principal can add S3 lifecycle rules to CloudTrail log buckets to "
        "auto-delete logs. Dry-run only. Maps to Stratus Red Team "
        "aws.defense-evasion.cloudtrail-lifecycle-rule."
    )
    category = "defense-evasion"
    required_permissions = [
        "cloudtrail:DescribeTrails",
        "s3:GetBucketLifecycleConfiguration",
        "s3:PutLifecycleConfiguration",
    ]
    cloudtrail_events = ["DescribeTrails", "GetBucketLifecycleConfiguration", "PutLifecycleConfiguration"]
    mitre_attack = ["T1562.008"]
    destructive = False
    reversible = True

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Read-only check for S3 lifecycle rule manipulation on CloudTrail buckets.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate CloudTrail buckets and check lifecycle permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check PutLifecycleConfiguration permission and inspect CloudTrail log buckets."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ct = context.get_client("cloudtrail")
        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check PutLifecycleConfiguration permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["s3:PutLifecycleConfiguration"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        put_perm: bool | None = perm_results.get("s3:PutLifecycleConfiguration")

        # Enumerate trails and extract buckets
        trails: list[dict] = []
        try:
            resp = ct.describe_trails(includeShadowTrails=False)
            api_calls.append("cloudtrail:DescribeTrails")
            trails = resp.get("trailList", [])
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"cloudtrail:DescribeTrails failed: {code}")

        buckets_seen: set[str] = set()
        for trail in trails:
            bucket = trail.get("S3BucketName", "")
            if not bucket or bucket in buckets_seen:
                continue
            buckets_seen.add(bucket)

            findings.append(f"CloudTrail log bucket: '{bucket}'")

            if put_perm is True:
                findings.append(
                    f"[CRITICAL] Principal can add S3 lifecycle rules to CloudTrail bucket "
                    f"'{bucket}' to auto-expire logs"
                )
            elif put_perm is None:
                findings.append(
                    f"[UNKNOWN] s3:PutLifecycleConfiguration permission on bucket '{bucket}' "
                    "could not be determined"
                )

            # Check existing lifecycle rules
            try:
                lc_resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
                api_calls.append("s3:GetBucketLifecycleConfiguration")
                rules = lc_resp.get("Rules", [])
                if rules:
                    findings.append(
                        f"  Existing lifecycle rules on '{bucket}': {len(rules)} rule(s)"
                    )
                    for rule in rules:
                        rule_id = rule.get("ID", "unknown")
                        status = rule.get("Status", "unknown")
                        expiration = rule.get("Expiration", {})
                        findings.append(
                            f"    Rule '{rule_id}' (status={status}) "
                            f"expiration={expiration}"
                        )
                else:
                    findings.append(f"  No existing lifecycle rules on '{bucket}'.")
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "NoSuchLifecycleConfiguration":
                    findings.append(f"  No lifecycle configuration on '{bucket}'.")
                    api_calls.append("s3:GetBucketLifecycleConfiguration")
                elif code in ("AccessDenied", "AccessDeniedException"):
                    errors.append(
                        f"s3:GetBucketLifecycleConfiguration for '{bucket}' — AccessDenied"
                    )
                else:
                    errors.append(
                        f"s3:GetBucketLifecycleConfiguration for '{bucket}' failed: {code}"
                    )

        findings.append(f"Total unique CloudTrail log buckets found: {len(buckets_seen)}")

        detections = [
            "CloudTrail: PutBucketLifecycle S3 event",
            "AWS Config: s3-bucket-logging-enabled rule",
            "Security Hub: [S3.4] S3 buckets should have server-side encryption enabled",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(buckets_seen)} CloudTrail log bucket(s). "
                f"PutLifecycleConfiguration permission: "
                f"{'confirmed' if put_perm is True else 'unknown' if put_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["s3:PutLifecycleConfiguration"] if put_perm is True else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "trail_count": len(trails),
                "bucket_count": len(buckets_seen),
                "put_lifecycle_permission": put_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "cloudtrail_lifecycle_rule is dry-run only. "
            "Adding S3 lifecycle rules to CloudTrail buckets is prohibited by the safety policy of this framework."
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — this module is dry-run only.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["No state was modified — this module is dry-run only."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = CloudTrailLifecycleRuleModule()
