"""IAM Create User Login Profile Module.

Simulate persistence by creating a console login profile for existing
AttackLab IAM users. Password is never logged.
Maps to Stratus Red Team aws.persistence.iam-create-user-login-profile.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_TEST_PASSWORD = "AttackLab-Test-P@ssw0rd-2024!"


class IAMCreateUserLoginProfileModule(ChaosModule):
    name = "iam_create_user_login_profile"
    description = (
        "Simulate persistence by creating a console login profile for an existing AttackLab "
        "IAM user. Execute creates/updates a login profile with a known test password. "
        "Password is logged as [REDACTED]. "
        "Maps to Stratus Red Team aws.persistence.iam-create-user-login-profile."
    )
    category = "persistence"
    required_permissions = [
        "iam:ListUsers",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:DeleteLoginProfile",
        "iam:GetLoginProfile",
    ]
    cloudtrail_events = [
        "ListUsers",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "DeleteLoginProfile",
        "GetLoginProfile",
    ]
    mitre_attack = ["T1078.004"]
    destructive = False
    reversible = True

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
            logger.warning("iam:ListUsers failed: %s", code)
        return users

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        iam = context.get_client("iam")
        users = self._list_attacklab_users(iam)
        findings = [f"AttackLab-prefixed IAM users found: {users or 'none'}"]
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for AttackLab IAM users to create login profiles.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=["iam:ListUsers"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=bool(users),
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check iam:CreateLoginProfile permission and count target users."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        iam = context.get_client("iam")
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["iam:CreateLoginProfile"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        users = self._list_attacklab_users(iam)
        n = len(users)

        if perm_results.get("iam:CreateLoginProfile") is True:
            findings.append("[RISK] Principal can call iam:CreateLoginProfile.")
        elif simulation_available:
            findings.append("iam:CreateLoginProfile not permitted for this principal.")

        findings.append(
            f"[DRY-RUN] Would create/update console login profile for {n} AttackLab-prefixed users."
        )

        detections = [
            "CloudTrail: iam:CreateLoginProfile or iam:UpdateLoginProfile",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "AWS Config: iam-user-no-policies-check",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {n} AttackLab-prefixed users for login profile creation.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, v in perm_results.items() if v is True],
            aws_api_calls=["iam:SimulatePrincipalPolicy", "iam:ListUsers"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(users),
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Create or update console login profiles for AttackLab-prefixed users."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        users = self._list_attacklab_users(iam)
        api_calls.append("iam:ListUsers")

        if not users:
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

        for user_name in users:
            checker.assert_resource_safe(user_name, {})

            try:
                iam.create_login_profile(
                    UserName=user_name,
                    Password=_TEST_PASSWORD,
                    PasswordResetRequired=False,
                )
                api_calls.append(f"iam:CreateLoginProfile ({user_name})")
                findings.append(
                    f"[EXECUTE] Created login profile for '{user_name}'. Password: [REDACTED]."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "EntityAlreadyExists":
                    # Profile exists — update it
                    try:
                        iam.update_login_profile(
                            UserName=user_name,
                            Password=_TEST_PASSWORD,
                            PasswordResetRequired=False,
                        )
                        api_calls.append(f"iam:UpdateLoginProfile ({user_name})")
                        findings.append(
                            f"[EXECUTE] Updated existing login profile for '{user_name}'. Password: [REDACTED]."
                        )
                    except botocore.exceptions.ClientError as exc2:
                        code2 = exc2.response.get("Error", {}).get("Code", "Unknown")
                        errors.append(f"iam:UpdateLoginProfile failed for '{user_name}': {code2}")
                else:
                    errors.append(f"iam:CreateLoginProfile failed for '{user_name}': {code}")

        detections = [
            "CloudTrail: iam:CreateLoginProfile or iam:UpdateLoginProfile",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "AWS Config: iam-user-no-policies-check",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Created/updated console login profiles for {len(users)} AttackLab user(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:CreateLoginProfile"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Delete console login profiles for AttackLab-prefixed users. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        users = self._list_attacklab_users(iam)
        api_calls.append("iam:ListUsers")

        for user_name in users:
            try:
                iam.delete_login_profile(UserName=user_name)
                api_calls.append(f"iam:DeleteLoginProfile ({user_name})")
                findings.append(f"[CLEANUP] Deleted login profile for '{user_name}'.")
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("NoSuchEntityException", "NoSuchEntity"):
                    findings.append(
                        f"Login profile for '{user_name}' not found — idempotent."
                    )
                else:
                    errors.append(f"iam:DeleteLoginProfile failed for '{user_name}': {code}")

        if not findings:
            findings.append("No AttackLab users found for login profile cleanup.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Console login profiles deleted for AttackLab users.",
            required_permissions=["iam:ListUsers", "iam:DeleteLoginProfile"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = IAMCreateUserLoginProfileModule()
