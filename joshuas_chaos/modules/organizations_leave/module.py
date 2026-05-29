"""Organizations Leave Module.

Dry-run ONLY: Detect if account is in an AWS Organization and if principal has
organizations:LeaveOrganization permission.
Maps to Stratus Red Team aws.defense-evasion.organizations-leave.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class OrganizationsLeaveModule(ChaosModule):
    name = "organizations_leave"
    description = (
        "Detect if account is in an AWS Organization and if principal has "
        "organizations:LeaveOrganization permission. Dry-run only. Maps to Stratus Red Team "
        "aws.defense-evasion.organizations-leave."
    )
    category = "defense-evasion"
    required_permissions = [
        "organizations:DescribeOrganization",
        "organizations:LeaveOrganization",
    ]
    cloudtrail_events = ["DescribeOrganization", "LeaveOrganization"]
    mitre_attack = ["T1562"]
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
            risk_summary="Read-only check for AWS Organizations membership and leave capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to check organization membership and LeaveOrganization permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check LeaveOrganization permission and organization membership."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check LeaveOrganization permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["organizations:LeaveOrganization"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        leave_perm: bool | None = perm_results.get("organizations:LeaveOrganization")

        # Try to describe the organization
        org_id: str | None = None
        master_account_id: str | None = None
        feature_set: str | None = None
        in_org = False

        try:
            orgs = context.get_client("organizations")
            resp = orgs.describe_organization()
            api_calls.append("organizations:DescribeOrganization")
            org = resp.get("Organization", {})
            org_id = org.get("Id")
            master_account_id = org.get("MasterAccountId")
            feature_set = org.get("FeatureSet")
            in_org = True

            findings.append(f"Organization ID: {org_id}")
            findings.append(f"Master Account ID: {master_account_id}")
            findings.append(f"Feature Set: {feature_set}")

        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in (
                "AWSOrganizationsNotInUseException",
                "AccessDenied",
                "AccessDeniedException",
            ):
                findings.append(
                    "Account is not part of an AWS Organization or access denied — "
                    "technique not applicable"
                )
            else:
                errors.append(f"organizations:DescribeOrganization failed: {code}")

        if in_org and org_id:
            if leave_perm is True:
                findings.append(
                    f"[CRITICAL] Principal can remove this account from organization '{org_id}' — "
                    "would remove SCP guardrails and shared security tooling"
                )
            elif leave_perm is None:
                findings.append(
                    "[UNKNOWN] organizations:LeaveOrganization permission could not be determined"
                )
            else:
                findings.append(
                    f"[INFO] Principal does not have organizations:LeaveOrganization — "
                    f"account '{identity.account_id}' is protected in org '{org_id}'"
                )
        elif not in_org:
            findings.append(
                "Account is not part of an AWS Organization — technique not applicable"
            )

        detections = [
            "CloudTrail: LeaveOrganization event",
            "AWS Organizations: organization-level CloudTrail",
            "Security Hub: Organizations findings",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Account is in org '{org_id}'. "
                f"LeaveOrganization permission: "
                f"{'confirmed — CRITICAL' if leave_perm is True else 'unknown' if leave_perm is None else 'denied'}."
                if in_org
                else "Account is not in an AWS Organization — technique not applicable."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=(
                ["organizations:LeaveOrganization"] if leave_perm is True else []
            ),
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "in_organization": in_org,
                "org_id": org_id,
                "master_account_id": master_account_id,
                "feature_set": feature_set,
                "leave_permission": leave_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "organizations_leave is dry-run only. "
            "Leaving an AWS Organization is prohibited by the safety policy of this framework."
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


MODULE = OrganizationsLeaveModule()
