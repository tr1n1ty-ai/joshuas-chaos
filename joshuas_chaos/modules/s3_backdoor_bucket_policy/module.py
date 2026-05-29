"""S3 Backdoor Bucket Policy Module.

Simulate S3 bucket policy backdoor for exfiltration by adding a cross-account
GetObject policy statement to AttackLab-tagged S3 buckets.
Maps to Stratus Red Team aws.exfiltration.s3-backdoor-bucket-policy.
"""

import json
import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_BACKDOOR_SID = "AttackLabBackdoor"


class S3BackdoorBucketPolicyModule(ChaosModule):
    name = "s3_backdoor_bucket_policy"
    description = (
        "Simulate S3 bucket policy backdoor for exfiltration by adding a cross-account "
        "GetObject policy statement to AttackLab-tagged S3 buckets. "
        "Execute adds a policy statement for a benign lab principal only. "
        "Maps to Stratus Red Team aws.exfiltration.s3-backdoor-bucket-policy."
    )
    category = "exfiltration"
    required_permissions = [
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:ListAllMyBuckets",
        "s3:GetBucketTagging",
    ]
    cloudtrail_events = [
        "GetBucketPolicy",
        "PutBucketPolicy",
        "ListAllMyBuckets",
        "GetBucketTagging",
    ]
    mitre_attack = ["T1537"]
    destructive = False
    reversible = True

    def _list_all_buckets(self, s3) -> list[str]:
        """Return list of all bucket names."""
        buckets: list[str] = []
        try:
            response = s3.list_buckets()
            buckets = [b["Name"] for b in response.get("Buckets", [])]
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("s3:ListAllMyBuckets failed: %s", code)
        return buckets

    def _get_bucket_tags(self, s3, bucket_name: str) -> dict[str, str]:
        """Return tags for a bucket, empty dict if no tags or error."""
        try:
            response = s3.get_bucket_tagging(Bucket=bucket_name)
            return {t["Key"]: t["Value"] for t in response.get("TagSet", [])}
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "NoSuchTagSet":
                return {}
            logger.warning("s3:GetBucketTagging failed for '%s': %s", bucket_name, code)
            return {}

    def _get_attacklab_buckets(
        self, s3, api_calls: list[str]
    ) -> tuple[list[str], list[dict]]:
        """Return (all_bucket_names, attacklab_bucket_dicts)."""
        all_buckets = self._list_all_buckets(s3)
        api_calls.append("s3:ListAllMyBuckets")

        attacklab_buckets: list[dict] = []
        for bucket_name in all_buckets:
            tags = self._get_bucket_tags(s3, bucket_name)
            api_calls.append(f"s3:GetBucketTagging ({bucket_name})")
            if tags.get("AttackLab", "").lower() == "true":
                attacklab_buckets.append({"bucket_name": bucket_name, "tags": tags})

        return all_buckets, attacklab_buckets

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check S3 bucket policy modification permissions.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess S3 bucket policy backdoor exfiltration risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check permissions and enumerate AttackLab-tagged S3 buckets."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["s3:PutBucketPolicy"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("s3:PutBucketPolicy") is True:
            findings.append("[RISK] Principal has s3:PutBucketPolicy permission.")

        all_buckets, attacklab_buckets = self._get_attacklab_buckets(s3, api_calls)

        n_total = len(all_buckets)
        n_attacklab = len(attacklab_buckets)
        findings.append(f"Total S3 buckets: {n_total}")
        findings.append(f"AttackLab-tagged buckets: {n_attacklab}")
        findings.append(
            f"[DRY-RUN] Would add cross-account GetObject policy statement "
            f"to {n_attacklab} AttackLab buckets"
        )

        detections = [
            "CloudTrail: s3:PutBucketPolicy with cross-account principal",
            "AWS Config: s3-bucket-policy-not-deny-delete-action",
            "GuardDuty: Policy:S3/AccountBlockPublicAccessDisabled",
            "Security Hub: S3.2 — S3 bucket not publicly readable",
            "Macie: policy finding on bucket policy change",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {n_total} total bucket(s), {n_attacklab} AttackLab-tagged. "
                "No changes made."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a is True],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_buckets),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Add AttackLabBackdoor GetObject policy statement to AttackLab-tagged S3 buckets."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_buckets, attacklab_buckets = self._get_attacklab_buckets(s3, api_calls)

        modified: list[str] = []
        for bucket in attacklab_buckets:
            bucket_name = bucket["bucket_name"]
            tags = bucket["tags"]

            try:
                checker.assert_resource_safe(bucket_name, tags)
            except SafetyError as exc:
                errors.append(f"Resource safety check failed for '{bucket_name}': {exc}")
                continue

            # Get existing policy or start with empty
            policy: dict = {"Version": "2012-10-17", "Statement": []}
            try:
                resp = s3.get_bucket_policy(Bucket=bucket_name)
                api_calls.append(f"s3:GetBucketPolicy ({bucket_name})")
                policy = json.loads(resp["Policy"])
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "NoSuchBucketPolicy":
                    # Start with empty policy
                    pass
                else:
                    errors.append(f"s3:GetBucketPolicy failed for '{bucket_name}': {code}")
                    continue

            # Check if backdoor statement already exists
            existing_sids = [
                s.get("Sid", "") for s in policy.get("Statement", [])
            ]
            if _BACKDOOR_SID in existing_sids:
                findings.append(
                    f"Backdoor statement '{_BACKDOOR_SID}' already exists in "
                    f"'{bucket_name}' — skipping (idempotent)."
                )
                modified.append(bucket_name)
                continue

            # Add backdoor statement — same-account root principal (benign lab simulation)
            backdoor_statement = {
                "Sid": _BACKDOOR_SID,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{identity.account_id}:root"},
                "Action": ["s3:GetObject"],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
            policy["Statement"].append(backdoor_statement)

            try:
                s3.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps(policy),
                )
                api_calls.append(f"s3:PutBucketPolicy ({bucket_name})")
                findings.append(
                    f"[EXECUTE] Added '{_BACKDOOR_SID}' GetObject policy statement to "
                    f"bucket '{bucket_name}' (principal: same-account root, benign lab)."
                )
                modified.append(bucket_name)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"s3:PutBucketPolicy failed for '{bucket_name}': {code}")

        detections = [
            "CloudTrail: s3:PutBucketPolicy with cross-account principal",
            "AWS Config: s3-bucket-policy-not-deny-delete-action",
            "GuardDuty: Policy:S3/AccountBlockPublicAccessDisabled",
            "Security Hub: S3.2 — S3 bucket not publicly readable",
            "Macie: policy finding on bucket policy change",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Added '{_BACKDOOR_SID}' policy statement to {len(modified)} "
                "AttackLab bucket(s)."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["s3:GetBucketPolicy", "s3:PutBucketPolicy"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
            metadata={"modified_bucket_names": modified},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Remove AttackLabBackdoor statement from S3 bucket policies. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_buckets, attacklab_buckets = self._get_attacklab_buckets(s3, api_calls)

        for bucket in attacklab_buckets:
            bucket_name = bucket["bucket_name"]

            # Get existing policy
            policy: dict | None = None
            try:
                resp = s3.get_bucket_policy(Bucket=bucket_name)
                api_calls.append(f"s3:GetBucketPolicy ({bucket_name})")
                policy = json.loads(resp["Policy"])
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "NoSuchBucketPolicy":
                    findings.append(
                        f"No policy found on '{bucket_name}' — already cleaned (idempotent)."
                    )
                    continue
                elif code == "NoSuchBucket":
                    findings.append(
                        f"Bucket '{bucket_name}' not found — already deleted (idempotent)."
                    )
                    continue
                else:
                    errors.append(f"s3:GetBucketPolicy failed for '{bucket_name}': {code}")
                    continue

            # Remove the backdoor statement
            original_count = len(policy.get("Statement", []))
            policy["Statement"] = [
                s for s in policy.get("Statement", [])
                if s.get("Sid", "") != _BACKDOOR_SID
            ]
            removed_count = original_count - len(policy["Statement"])

            if removed_count == 0:
                findings.append(
                    f"Statement '{_BACKDOOR_SID}' not found in '{bucket_name}' — "
                    "already removed (idempotent)."
                )
                continue

            if not policy["Statement"]:
                # Empty policy — delete it entirely
                try:
                    s3.delete_bucket_policy(Bucket=bucket_name)
                    api_calls.append(f"s3:DeleteBucketPolicy ({bucket_name})")
                    findings.append(
                        f"[CLEANUP] Deleted bucket policy from '{bucket_name}' "
                        f"(policy now empty after removing '{_BACKDOOR_SID}')."
                    )
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "Unknown")
                    errors.append(f"s3:DeleteBucketPolicy failed for '{bucket_name}': {code}")
            else:
                try:
                    s3.put_bucket_policy(
                        Bucket=bucket_name,
                        Policy=json.dumps(policy),
                    )
                    api_calls.append(f"s3:PutBucketPolicy ({bucket_name})")
                    findings.append(
                        f"[CLEANUP] Removed '{_BACKDOOR_SID}' statement from "
                        f"bucket '{bucket_name}' policy."
                    )
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "Unknown")
                    errors.append(f"s3:PutBucketPolicy cleanup failed for '{bucket_name}': {code}")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Removed '{_BACKDOOR_SID}' policy statements from AttackLab buckets.",
            required_permissions=[
                "s3:ListAllMyBuckets",
                "s3:GetBucketTagging",
                "s3:GetBucketPolicy",
                "s3:PutBucketPolicy",
            ],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = S3BackdoorBucketPolicyModule()
