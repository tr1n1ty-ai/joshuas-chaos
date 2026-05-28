"""PassRole + CloudFormation Abuse Module.

Detect cloudformation:CreateStack AND iam:PassRole.
Execute: Create a harmless tagged test CloudFormation stack (output only, no resources with permissions).
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_STACK_NAME = "AttackLabPassRoleCFNTest"
_TEMPLATE = """{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "AttackLab PassRole CloudFormation test - benign output only",
  "Outputs": {
    "TestOutput": {
      "Description": "AttackLab passrole_cloudformation test",
      "Value": "AttackLab-CFN-PassRole-Test-Benign"
    }
  }
}"""


class PassRoleCloudFormationModule(ChaosModule):
    name = "passrole_cloudformation"
    description = (
        "Detect cloudformation:CreateStack + iam:PassRole risk and simulate "
        "by creating a harmless AttackLab CloudFormation stack (outputs only)."
    )
    category = "privilege-escalation"
    required_permissions = [
        "cloudformation:CreateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
        "iam:PassRole",
    ]
    cloudtrail_events = [
        "CreateStack",
        "DeleteStack",
        "DescribeStacks",
    ]
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
            risk_summary="Check cloudformation:CreateStack + iam:PassRole.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess PassRole + CloudFormation risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detect cloudformation:CreateStack AND iam:PassRole."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["cloudformation:CreateStack", "iam:PassRole"],
        )

        has_cfn = perm_results.get("cloudformation:CreateStack", False)
        has_pass = perm_results.get("iam:PassRole", False)

        if has_cfn and has_pass:
            findings.append(
                "[HIGH RISK] Principal has cloudformation:CreateStack AND iam:PassRole. "
                "Can create a stack that provisions resources with a passed role."
            )
        elif has_cfn:
            findings.append("[MEDIUM] Principal has cloudformation:CreateStack but not iam:PassRole.")
        elif has_pass:
            findings.append("[LOW] Principal has iam:PassRole but not cloudformation:CreateStack.")
        else:
            findings.append("No cloudformation:CreateStack or iam:PassRole permissions detected.")

        findings.append(
            f"[DRY-RUN] Would create stack '{_STACK_NAME}' with output-only template (no resource permissions)."
        )

        detections = [
            "CloudTrail: cloudformation:CreateStack with roleARN parameter",
            "CloudTrail: iam:PassRole for cloudformation.amazonaws.com",
            "CloudFormation drift detection",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed PassRole + CloudFormation risk.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=["iam:SimulatePrincipalPolicy"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Create a harmless tagged CloudFormation stack."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_STACK_NAME, {})

        cfn = context.get_client("cloudformation")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            cfn.create_stack(
                StackName=_STACK_NAME,
                TemplateBody=_TEMPLATE,
                Tags=[{"Key": "AttackLab", "Value": "true"}],
                OnFailure="ROLLBACK",
            )
            api_calls.append(f"cloudformation:CreateStack ({_STACK_NAME})")
            findings.append(
                f"[EXECUTE] Created CloudFormation stack '{_STACK_NAME}'. "
                "Template: output-only, no resources with permissions."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "AlreadyExistsException":
                findings.append(f"Stack '{_STACK_NAME}' already exists.")
            else:
                errors.append(f"cloudformation:CreateStack failed: {code}")

        detections = [
            "CloudTrail: cloudformation:CreateStack",
            "CloudTrail: iam:PassRole for cloudformation.amazonaws.com",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Created benign CloudFormation stack '{_STACK_NAME}'.",
            required_permissions=self.required_permissions,
            observed_permissions=["cloudformation:CreateStack"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Delete the AttackLab CloudFormation stack. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        cfn = context.get_client("cloudformation")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            cfn.delete_stack(StackName=_STACK_NAME)
            api_calls.append(f"cloudformation:DeleteStack ({_STACK_NAME})")
            findings.append(f"[CLEANUP] Deleted CloudFormation stack '{_STACK_NAME}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("ValidationError", "StackNotFoundException"):
                findings.append(f"Stack '{_STACK_NAME}' not found — already deleted (idempotent).")
            else:
                errors.append(f"cloudformation:DeleteStack failed: {code}")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="CloudFormation stack deleted.",
            required_permissions=["cloudformation:DeleteStack"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = PassRoleCloudFormationModule()
