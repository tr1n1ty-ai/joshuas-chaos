"""Console Login Without MFA Module.

Dry-run ONLY: Enumerate IAM users with console access (login profile) but no MFA device.
Maps to Stratus Red Team aws.initial-access.console-login-without-mfa.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class ConsoleLoginWithoutMFAModule(ChaosModule):
    name = "console_login_without_mfa"
    description = (
        "Enumerate IAM users with console access (login profile) but no MFA device. "
        "These accounts are susceptible to password-only console login. "
        "Dry-run only. Maps to Stratus Red Team aws.initial-access.console-login-without-mfa."
    )
    category = "initial-access"
    required_permissions = [
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
    ]
    cloudtrail_events = ["ListUsers", "GetLoginProfile", "ListMFADevices"]
    mitre_attack = ["T1078.004"]
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
            risk_summary="Read-only enumeration of IAM users with console access lacking MFA.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate IAM users and their MFA status."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate IAM users and identify those with console access but no MFA."""
        identity = context.get_caller_identity()
        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Enumerate all IAM users via paginator
        all_users: list[dict] = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                api_calls.append("iam:ListUsers")
                all_users.extend(page.get("Users", []))
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"iam:ListUsers failed: {code}")

        no_mfa: list[dict] = []
        has_mfa: list[dict] = []
        no_console: list[str] = []

        for user in all_users:
            username = user.get("UserName", "unknown")
            password_last_used = user.get("PasswordLastUsed")

            # Check if user has a console login profile
            has_console = False
            try:
                iam.get_login_profile(UserName=username)
                api_calls.append("iam:GetLoginProfile")
                has_console = True
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "NoSuchEntityException":
                    # No login profile — skip MFA check
                    no_console.append(username)
                    api_calls.append("iam:GetLoginProfile")
                    continue
                elif code in ("AccessDenied", "AccessDeniedException"):
                    errors.append(f"iam:GetLoginProfile for '{username}' — AccessDenied")
                    continue
                else:
                    errors.append(f"iam:GetLoginProfile for '{username}' failed: {code}")
                    continue

            if not has_console:
                no_console.append(username)
                continue

            # Check MFA devices for users with console access
            mfa_devices: list[dict] = []
            try:
                mfa_resp = iam.list_mfa_devices(UserName=username)
                api_calls.append("iam:ListMFADevices")
                mfa_devices = mfa_resp.get("MFADevices", [])
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("AccessDenied", "AccessDeniedException"):
                    errors.append(f"iam:ListMFADevices for '{username}' — AccessDenied")
                else:
                    errors.append(f"iam:ListMFADevices for '{username}' failed: {code}")

            user_entry = {
                "username": username,
                "password_last_used": str(password_last_used) if password_last_used else "never",
                "mfa_device_count": len(mfa_devices),
            }

            if mfa_devices:
                has_mfa.append(user_entry)
            else:
                no_mfa.append(user_entry)

        # Build findings
        if no_mfa:
            vulnerable_names = [u["username"] for u in no_mfa]
            findings.append(
                f"[CRITICAL] {len(no_mfa)} IAM user(s) have console access without MFA: "
                f"{vulnerable_names}"
            )
            for user_entry in no_mfa:
                findings.append(
                    f"  Vulnerable: '{user_entry['username']}' | "
                    f"PasswordLastUsed: {user_entry['password_last_used']}"
                )
        else:
            findings.append("No IAM users with console access and missing MFA found.")

        if has_mfa:
            findings.append(
                f"[INFO] {len(has_mfa)} IAM user(s) have console access with MFA enabled"
            )

        findings.append(f"Total IAM users examined: {len(all_users)}")
        findings.append(f"Users without console access: {len(no_console)}")

        detections = [
            "CloudTrail: ConsoleLogin event without MFA",
            "AWS Config rule: iam-user-mfa-enabled",
            "Security Hub: [IAM.5] MFA should be enabled for all IAM users with console password",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"{len(no_mfa)} IAM user(s) with console access lack MFA "
                f"(vulnerable to password-only login)."
                if no_mfa
                else "All IAM users with console access have MFA enabled."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "total_users": len(all_users),
                "no_mfa_count": len(no_mfa),
                "has_mfa_count": len(has_mfa),
                "no_console_count": len(no_console),
                "vulnerable_users": [u["username"] for u in no_mfa],
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "console_login_without_mfa is dry-run only. "
            "Performing console login attacks is prohibited by the safety policy of this framework."
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


MODULE = ConsoleLoginWithoutMFAModule()
