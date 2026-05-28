"""IAM Self-Escalation Detection Module.

Dry-run ONLY: Detects if the calling principal has risky IAM escalation permissions.
"""

import logging

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_RISKY_PERMISSIONS = [
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:AddUserToGroup",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachGroupPolicy",
]


class IAMSelfEscalationModule(ChaosModule):
    name = "iam_self_escalation"
    description = (
        "Detect if the calling principal has IAM permissions that could allow "
        "privilege escalation. Dry-run only."
    )
    category = "privilege-escalation"
    required_permissions = [
        "iam:SimulatePrincipalPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
    ]
    cloudtrail_events = ["SimulatePrincipalPolicy"]
    mitre_attack = ["T1098"]
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
            risk_summary="Read-only IAM permission check. No changes.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Module ready. Run dry-run to assess escalation risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check if the principal has risky IAM escalation permissions."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=_RISKY_PERMISSIONS,
            resource="*",
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        risky_allowed: list[str] = []
        for action, allowed in perm_results.items():
            if allowed:
                risky_allowed.append(action)
                findings.append(
                    f"[HIGH RISK] Principal '{identity.arn}' has permission: {action}"
                )

        if not risky_allowed:
            findings.append(
                "No risky IAM escalation permissions detected for the calling principal."
            )

        observed = [p for p, allowed in perm_results.items() if allowed]

        detections = [
            "CloudTrail: iam:AttachRolePolicy / iam:PutRolePolicy on own role",
            "CloudTrail: iam:CreatePolicyVersion with default version set",
            "GuardDuty: Policy:IAMUser/RootCredentialUsage (if root)",
            "IAM Access Analyzer: overly-permissive policy findings",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Principal has {len(risky_allowed)} risky IAM escalation permission(s)."
                if risky_allowed
                else "No risky IAM escalation permissions detected."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=observed,
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,  # dry-run only module
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "iam_self_escalation is a dry-run only module. "
            "It performs no modifications to avoid uncontrolled privilege escalation."
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — this module makes no changes.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["No state was created by this module."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = IAMSelfEscalationModule()
