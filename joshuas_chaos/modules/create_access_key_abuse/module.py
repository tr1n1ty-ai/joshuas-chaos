"""Create Access Key Abuse Module.

Simulates iam:CreateAccessKey abuse on AttackLab IAM users.
Secret access key is never printed or logged.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_STATE_KEY = "created_access_key_ids"  # stored in metadata for cleanup


class CreateAccessKeyAbuseModule(ChaosModule):
    name = "create_access_key_abuse"
    description = (
        "Simulate iam:CreateAccessKey abuse by creating a test key on an "
        "AttackLab IAM user. Secret key is never exposed."
    )
    category = "credential-access"
    required_permissions = [
        "iam:CreateAccessKey",
        "iam:ListUsers",
        "iam:DeleteAccessKey",
        "iam:ListAccessKeys",
    ]
    cloudtrail_events = [
        "CreateAccessKey",
        "DeleteAccessKey",
        "ListUsers",
        "ListAccessKeys",
    ]
    mitre_attack = ["T1098.001"]
    destructive = False
    reversible = True

    _created_keys: dict[str, str]  # username -> access_key_id

    def __init__(self) -> None:
        self._created_keys = {}

    def _list_attacklab_users(self, iam) -> list[str]:
        """Return IAM usernames starting with 'AttackLab'."""
        users = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    if user["UserName"].startswith("AttackLab"):
                        users.append(user["UserName"])
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("list_users failed: %s", code)
        return users

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        iam = context.get_client("iam")
        attacklab_users = self._list_attacklab_users(iam)
        findings = [f"AttackLab IAM users found: {attacklab_users or 'none'}"]
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Read-only check for AttackLab IAM users.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=["iam:ListUsers"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=bool(attacklab_users),
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check if iam:CreateAccessKey is possible; list AttackLab users."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        iam = context.get_client("iam")

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["iam:CreateAccessKey"],
        )

        attacklab_users = self._list_attacklab_users(iam)
        findings: list[str] = []

        if perm_results.get("iam:CreateAccessKey"):
            findings.append(
                f"[RISK] Principal '{identity.arn}' can call iam:CreateAccessKey"
            )
        else:
            findings.append("iam:CreateAccessKey not permitted for this principal.")

        if attacklab_users:
            findings.append(f"[DRY-RUN] Would create test key for users: {attacklab_users}")
        else:
            findings.append(
                "No AttackLab-prefixed IAM users found. "
                "Create a user named 'AttackLabTestUser' to use this module."
            )

        detections = [
            "CloudTrail: CreateAccessKey event for IAM user",
            "GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            "Security Hub: [IAM.3] IAM users' access keys should be rotated every 90 days",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed CreateAccessKey risk. No changes made.",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:CreateAccessKey"] if perm_results.get("iam:CreateAccessKey") else [],
            aws_api_calls=["iam:SimulatePrincipalPolicy", "iam:ListUsers"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_users),
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Create a test access key for AttackLab IAM users only.

        The SecretAccessKey is never stored, logged, or printed.
        The AccessKeyId is tracked for cleanup.
        """
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []
        created_keys: dict[str, str] = {}

        attacklab_users = self._list_attacklab_users(iam)
        api_calls.append("iam:ListUsers")

        if not attacklab_users:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab IAM users found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-prefixed IAM users found. No action taken."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=True,
                errors=[],
            )

        for username in attacklab_users:
            try:
                checker.assert_resource_safe(username, {})
                response = iam.create_access_key(UserName=username)
                api_calls.append(f"iam:CreateAccessKey ({username})")
                key_id = response["AccessKey"]["AccessKeyId"]
                # NEVER log or store the SecretAccessKey
                created_keys[username] = key_id
                self._created_keys[username] = key_id
                findings.append(
                    f"[EXECUTE] Created access key ID {key_id} for user '{username}'. "
                    "SecretAccessKey NOT stored or logged."
                )
            except Exception as exc:
                errors.append(f"Failed to create key for '{username}': {exc}")
                logger.error("create_access_key failed for %s: %s", username, exc)

        detections = [
            "CloudTrail: CreateAccessKey event",
            "Security Hub: [IAM.3] access key created event",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Created test access keys for {len(created_keys)} AttackLab user(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:CreateAccessKey"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
            metadata={"created_key_ids": created_keys},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Delete all test access keys created by execute. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Re-discover AttackLab users and delete any keys we may have created
        attacklab_users = self._list_attacklab_users(iam)
        api_calls.append("iam:ListUsers")

        for username in attacklab_users:
            try:
                resp = iam.list_access_keys(UserName=username)
                api_calls.append(f"iam:ListAccessKeys ({username})")
                for key_meta in resp.get("AccessKeyMetadata", []):
                    key_id = key_meta["AccessKeyId"]
                    # Only delete keys we created (tracked in _created_keys)
                    if key_id in self._created_keys.values():
                        iam.delete_access_key(UserName=username, AccessKeyId=key_id)
                        api_calls.append(f"iam:DeleteAccessKey ({username}, {key_id})")
                        findings.append(f"[CLEANUP] Deleted access key {key_id} for '{username}'")
                        # Remove from tracking
                        self._created_keys = {
                            k: v for k, v in self._created_keys.items() if v != key_id
                        }
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "NoSuchEntity":
                    findings.append(f"Key for '{username}' already deleted — idempotent.")
                else:
                    errors.append(f"Cleanup failed for '{username}': {code}")

        if not findings:
            findings.append("No tracked access keys to clean up.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Cleanup complete — test access keys deleted.",
            required_permissions=["iam:ListAccessKeys", "iam:DeleteAccessKey"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = CreateAccessKeyAbuseModule()
