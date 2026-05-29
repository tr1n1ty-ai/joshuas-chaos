"""IAM Create Admin User Module.

Simulate persistence via admin IAM user creation.
Creates AttackLabBackdoorUser with AdministratorAccess policy attached.
Maps to Stratus Red Team aws.persistence.iam-create-admin-user.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_USER_NAME = "AttackLabBackdoorUser"
_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


class IAMCreateAdminUserModule(ChaosModule):
    name = "iam_create_admin_user"
    description = (
        "Simulate persistence via admin IAM user creation. Creates AttackLabBackdoorUser "
        "with AdministratorAccess policy attached. Cleanup detaches policy and deletes user. "
        "Maps to Stratus Red Team aws.persistence.iam-create-admin-user."
    )
    category = "persistence"
    required_permissions = [
        "iam:CreateUser",
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy",
        "iam:DeleteUser",
        "iam:TagUser",
    ]
    cloudtrail_events = ["CreateUser", "AttachUserPolicy", "DetachUserPolicy", "DeleteUser"]
    mitre_attack = ["T1136.003"]
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
            risk_summary="Check permissions to create backdoor admin IAM user.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess iam:CreateUser + AdministratorAccess risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check iam:CreateUser + iam:AttachUserPolicy permissions."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["iam:CreateUser", "iam:AttachUserPolicy"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("iam:CreateUser") is True:
            findings.append("[RISK] Principal can call iam:CreateUser.")
        elif simulation_available:
            findings.append("iam:CreateUser not permitted for this principal.")

        if perm_results.get("iam:AttachUserPolicy") is True:
            findings.append("[RISK] Principal can call iam:AttachUserPolicy.")
        elif simulation_available:
            findings.append("iam:AttachUserPolicy not permitted for this principal.")

        findings.append(
            f"[DRY-RUN] Would create IAM user '{_USER_NAME}' with AdministratorAccess."
        )

        detections = [
            "CloudTrail: iam:CreateUser + iam:AttachUserPolicy with AdministratorAccess",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "AWS Config: iam-user-no-policies-check",
            "Security Hub: IAM.2 — IAM users should not have IAM policies attached",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed admin user creation risk. No changes made.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, v in perm_results.items() if v is True],
            aws_api_calls=["iam:SimulatePrincipalPolicy"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Create AttackLabBackdoorUser and attach AdministratorAccess."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_USER_NAME, {})

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Create user
        try:
            iam.create_user(
                UserName=_USER_NAME,
                Tags=[{"Key": "AttackLab", "Value": "true"}],
            )
            api_calls.append(f"iam:CreateUser ({_USER_NAME})")
            findings.append(f"[EXECUTE] Created IAM user '{_USER_NAME}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "EntityAlreadyExists":
                findings.append(f"IAM user '{_USER_NAME}' already exists — idempotent.")
                api_calls.append(f"iam:CreateUser ({_USER_NAME}) [already existed]")
            else:
                errors.append(f"iam:CreateUser failed: {code}")

        # Attach AdministratorAccess
        try:
            iam.attach_user_policy(
                UserName=_USER_NAME,
                PolicyArn=_POLICY_ARN,
            )
            api_calls.append(f"iam:AttachUserPolicy ({_USER_NAME}, AdministratorAccess)")
            findings.append(
                f"[EXECUTE] Attached AdministratorAccess policy to user '{_USER_NAME}'."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"iam:AttachUserPolicy failed: {code}")

        detections = [
            "CloudTrail: iam:CreateUser + iam:AttachUserPolicy with AdministratorAccess",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "AWS Config: iam-user-no-policies-check",
            "Security Hub: IAM.2 — IAM users should not have IAM policies attached",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Created backdoor admin IAM user '{_USER_NAME}'.",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:CreateUser", "iam:AttachUserPolicy"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detach policy and delete AttackLabBackdoorUser. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Detach policy
        try:
            iam.detach_user_policy(
                UserName=_USER_NAME,
                PolicyArn=_POLICY_ARN,
            )
            api_calls.append(f"iam:DetachUserPolicy ({_USER_NAME})")
            findings.append(f"[CLEANUP] Detached AdministratorAccess from '{_USER_NAME}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("NoSuchEntityException", "NoSuchEntity"):
                findings.append(
                    f"Policy not attached to '{_USER_NAME}' — idempotent."
                )
            else:
                errors.append(f"iam:DetachUserPolicy failed: {code}")

        # Delete user
        try:
            iam.delete_user(UserName=_USER_NAME)
            api_calls.append(f"iam:DeleteUser ({_USER_NAME})")
            findings.append(f"[CLEANUP] Deleted IAM user '{_USER_NAME}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("NoSuchEntityException", "NoSuchEntity"):
                findings.append(f"IAM user '{_USER_NAME}' not found — idempotent.")
            elif code == "DeleteConflict":
                errors.append(
                    f"iam:DeleteUser failed for '{_USER_NAME}' — DeleteConflict: "
                    "User may have additional credentials — delete them manually before retrying cleanup."
                )
            else:
                errors.append(f"iam:DeleteUser failed: {code}")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Backdoor admin user '{_USER_NAME}' cleanup complete.",
            required_permissions=["iam:DetachUserPolicy", "iam:DeleteUser"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = IAMCreateAdminUserModule()
