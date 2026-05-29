"""IAM Update Login Profile Module.

Simulate privilege escalation by updating the console login profile password
of AttackLab-prefixed IAM users that already have a login profile.
The new password is never logged. Cleanup restores a known test password.
Maps to Stratus Red Team aws.privilege-escalation.iam-update-login-profile.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_NEW_PASSWORD = "AttackLab-Escalated-P@ssw0rd-2024!"
_CLEANUP_PASSWORD = "AttackLab-Restored-P@ssw0rd-2024!"


class IAMUpdateLoginProfileModule(ChaosModule):
    name = "iam_update_login_profile"
    description = (
        "Simulate privilege escalation by updating the console login profile password "
        "of AttackLab-prefixed IAM users that already have a login profile. "
        "The new password is never logged. Cleanup restores a known test password. "
        "Maps to Stratus Red Team aws.privilege-escalation.iam-update-login-profile."
    )
    category = "privilege-escalation"
    required_permissions = [
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:UpdateLoginProfile",
    ]
    cloudtrail_events = [
        "ListUsers",
        "GetLoginProfile",
        "UpdateLoginProfile",
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

    def _has_login_profile(self, iam, user_name: str) -> bool:
        """Return True if the user has an existing login profile, False otherwise."""
        try:
            iam.get_login_profile(UserName=user_name)
            return True
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("NoSuchEntityException", "NoSuchEntity"):
                return False
            raise

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for AttackLab IAM users with existing login profiles.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess iam:UpdateLoginProfile risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check iam:UpdateLoginProfile permission and count target users with login profiles."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        iam = context.get_client("iam")
        findings: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["iam:UpdateLoginProfile"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("iam:UpdateLoginProfile") is True:
            findings.append("[RISK] Principal can call iam:UpdateLoginProfile.")
        elif simulation_available:
            findings.append("iam:UpdateLoginProfile not permitted for this principal.")

        attacklab_users = self._list_attacklab_users(iam)
        api_calls.append("iam:ListUsers")
        total_attacklab = len(attacklab_users)

        users_with_profile: list[str] = []
        for user_name in attacklab_users:
            api_calls.append(f"iam:GetLoginProfile ({user_name})")
            if self._has_login_profile(iam, user_name):
                users_with_profile.append(user_name)

        n = len(users_with_profile)

        findings.append(
            f"[DRY-RUN] Would call iam:UpdateLoginProfile on {n} AttackLab users "
            f"with existing login profiles (out of {total_attacklab} total AttackLab users)."
        )
        findings.append(
            "Note: UpdateLoginProfile on an account with elevated privileges = effective account takeover."
        )

        detections = [
            "CloudTrail: iam:UpdateLoginProfile (especially on high-privilege users)",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "AWS Config: iam-user-no-policies-check",
            "Security Hub: IAM.9 — MFA should be enabled for the root user",
            "UEBA: unexpected password change for IAM user",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {n} AttackLab users with existing login profiles "
                f"(targets for iam:UpdateLoginProfile)."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, v in perm_results.items() if v is True],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(users_with_profile),
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Update console login profile passwords for AttackLab users that have existing profiles."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []
        updated_users: list[str] = []

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

        for user_name in attacklab_users:
            try:
                checker.assert_resource_safe(user_name, {})
            except SafetyError as exc:
                findings.append(f"[SKIP] Skipping '{user_name}': {exc}")
                continue

            # Check if login profile exists — skip if not
            api_calls.append(f"iam:GetLoginProfile ({user_name})")
            try:
                iam.get_login_profile(UserName=user_name)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("NoSuchEntityException", "NoSuchEntity"):
                    findings.append(
                        f"No login profile for '{user_name}' — skipping (nothing to update)."
                    )
                    continue
                errors.append(f"iam:GetLoginProfile failed for '{user_name}': {code}")
                continue

            # Update the login profile password
            try:
                iam.update_login_profile(
                    UserName=user_name,
                    Password=_NEW_PASSWORD,
                    PasswordResetRequired=False,
                )
                api_calls.append(f"iam:UpdateLoginProfile ({user_name})")
                findings.append(
                    f"[EXECUTE] Updated login profile password for '{user_name}'. New password: [REDACTED]."
                )
                updated_users.append(user_name)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"iam:UpdateLoginProfile failed for '{user_name}': {code}")

        detections = [
            "CloudTrail: iam:UpdateLoginProfile (especially on high-privilege users)",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "AWS Config: iam-user-no-policies-check",
            "Security Hub: IAM.9 — MFA should be enabled for the root user",
            "UEBA: unexpected password change for IAM user",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Updated console login profile passwords for {len(updated_users)} "
                "AttackLab user(s) with existing login profiles."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["iam:UpdateLoginProfile"] if updated_users else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=bool(updated_users),
            safe_to_execute=True,
            errors=errors,
            metadata={"updated_users": updated_users},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Restore login profile passwords for AttackLab users to a known test state. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        attacklab_users = self._list_attacklab_users(iam)
        api_calls.append("iam:ListUsers")

        for user_name in attacklab_users:
            # Check profile exists before attempting update
            api_calls.append(f"iam:GetLoginProfile ({user_name})")
            try:
                iam.get_login_profile(UserName=user_name)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("NoSuchEntityException", "NoSuchEntity"):
                    findings.append(
                        f"No login profile for '{user_name}' — idempotent, nothing to restore."
                    )
                    continue
                errors.append(f"iam:GetLoginProfile failed for '{user_name}': {code}")
                continue

            # Restore to cleanup password with PasswordResetRequired=True
            try:
                iam.update_login_profile(
                    UserName=user_name,
                    Password=_CLEANUP_PASSWORD,
                    PasswordResetRequired=True,
                )
                api_calls.append(f"iam:UpdateLoginProfile ({user_name})")
                findings.append(
                    f"[CLEANUP] Restored login profile password for '{user_name}' "
                    "(PasswordResetRequired=True). Password: [REDACTED]."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("NoSuchEntityException", "NoSuchEntity"):
                    findings.append(
                        f"Login profile for '{user_name}' not found — idempotent."
                    )
                else:
                    errors.append(f"iam:UpdateLoginProfile failed for '{user_name}': {code}")

        if not findings:
            findings.append("No AttackLab users found for login profile cleanup.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Restored login profile passwords for AttackLab users (PasswordResetRequired=True).",
            required_permissions=["iam:ListUsers", "iam:GetLoginProfile", "iam:UpdateLoginProfile"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = IAMUpdateLoginProfileModule()
