"""PassRole + Lambda Abuse Module.

Dry-run: Detect iam:PassRole + lambda permissions.
Execute: Create a benign AttackLab Lambda that calls sts:GetCallerIdentity only.
Cleanup: Delete the Lambda.
"""

import io
import logging
import zipfile

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_FUNCTION_NAME = "AttackLabPassRoleLambdaTest"
_RUNTIME = "python3.12"
_HANDLER = "handler.lambda_handler"

# Benign Lambda that ONLY calls sts:GetCallerIdentity
_LAMBDA_CODE = '''
import boto3
import json

def lambda_handler(event, context):
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    return {
        "statusCode": 200,
        "body": json.dumps({
            "account": identity["Account"],
            "arn": identity["Arn"],
            "message": "AttackLab passrole test - benign sts:GetCallerIdentity only"
        })
    }
'''.strip()


def _build_lambda_zip() -> bytes:
    """Build an in-memory zip containing the Lambda handler code."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _LAMBDA_CODE)
    return buf.getvalue()


class PassRoleLambdaModule(ChaosModule):
    name = "passrole_lambda"
    description = (
        "Detect iam:PassRole + Lambda permission combinations, then simulate "
        "by creating a benign AttackLab Lambda function (sts:GetCallerIdentity only)."
    )
    category = "privilege-escalation"
    required_permissions = [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
    ]
    cloudtrail_events = [
        "CreateFunction20150331",
        "InvokeFunction",
        "DeleteFunction20150331",
        "GetFunction20150331",
    ]
    mitre_attack = ["T1098", "T1610"]
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
            risk_summary="Check iam:PassRole + Lambda permissions.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess PassRole + Lambda escalation risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detect iam:PassRole AND lambda:CreateFunction/UpdateFunctionCode/InvokeFunction."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []

        actions_to_check = [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:UpdateFunctionCode",
            "lambda:InvokeFunction",
        ]
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=actions_to_check,
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        has_passrole = perm_results.get("iam:PassRole") is True
        has_lambda = any(
            perm_results.get(p) is True
            for p in ["lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction"]
        )

        if has_passrole and has_lambda:
            findings.append(
                "[HIGH RISK] Principal has iam:PassRole AND Lambda permissions. "
                "Can create Lambda with privileged role."
            )
        elif has_passrole:
            findings.append("[MEDIUM] Principal has iam:PassRole but no Lambda write permissions.")
        elif has_lambda:
            findings.append("[LOW] Principal has Lambda permissions but not iam:PassRole.")
        elif simulation_available:
            findings.append("No iam:PassRole or Lambda permissions detected.")

        findings.append(
            f"[DRY-RUN] Would create '{_FUNCTION_NAME}' with benign sts:GetCallerIdentity code."
        )

        detections = [
            "CloudTrail: lambda:CreateFunction with role ARN",
            "CloudTrail: iam:PassRole for Lambda service",
            "GuardDuty: Behavior:Lambda/NetworkActivity",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed PassRole + Lambda risk. No changes made.",
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
        """Create AttackLab Lambda function with benign sts:GetCallerIdentity code."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_FUNCTION_NAME, {})

        lam = context.get_client("lambda")
        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Find an AttackLab execution role to pass
        role_arn: str | None = None
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    if role["RoleName"].startswith("AttackLab"):
                        role_arn = role["Arn"]
                        break
                if role_arn:
                    break
            api_calls.append("iam:ListRoles")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"iam:ListRoles failed: {code}")

        if not role_arn:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab IAM role found to pass to Lambda.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-prefixed IAM role found. Create 'AttackLabLambdaRole' first."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=errors,
            )

        zip_bytes = _build_lambda_zip()

        try:
            lam.create_function(
                FunctionName=_FUNCTION_NAME,
                Runtime=_RUNTIME,
                Role=role_arn,
                Handler=_HANDLER,
                Code={"ZipFile": zip_bytes},
                Description="AttackLab PassRole test — benign sts:GetCallerIdentity only",
                Timeout=10,
                Tags={"AttackLab": "true"},
            )
            api_calls.append(f"lambda:CreateFunction ({_FUNCTION_NAME})")
            findings.append(
                f"[EXECUTE] Created Lambda function '{_FUNCTION_NAME}' "
                f"with role '{role_arn}'. Code: sts:GetCallerIdentity only."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "ResourceConflictException":
                findings.append(
                    f"Lambda '{_FUNCTION_NAME}' already exists — already deployed."
                )
            else:
                errors.append(f"lambda:CreateFunction failed: {code}")

        detections = [
            "CloudTrail: lambda:CreateFunction with new role ARN",
            "CloudTrail: iam:PassRole for lambda.amazonaws.com",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Created benign Lambda '{_FUNCTION_NAME}' with passed role.",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:PassRole", "lambda:CreateFunction"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Delete the AttackLab Lambda function. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        lam = context.get_client("lambda")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            lam.delete_function(FunctionName=_FUNCTION_NAME)
            api_calls.append(f"lambda:DeleteFunction ({_FUNCTION_NAME})")
            findings.append(f"[CLEANUP] Deleted Lambda function '{_FUNCTION_NAME}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "ResourceNotFoundException":
                findings.append(f"Lambda '{_FUNCTION_NAME}' not found — already deleted (idempotent).")
            else:
                errors.append(f"lambda:DeleteFunction failed: {code}")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Lambda function deleted.",
            required_permissions=["lambda:DeleteFunction"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = PassRoleLambdaModule()
