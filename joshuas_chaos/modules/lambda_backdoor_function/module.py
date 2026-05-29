"""Lambda Backdoor Function Module.

Simulate Lambda function backdoor by adding a resource-based policy
allowing the current account to invoke AttackLab Lambda functions.
Maps to Stratus Red Team aws.persistence.lambda-backdoor-function.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_STATEMENT_ID = "AttackLabBackdoorInvoke"


class LambdaBackdoorFunctionModule(ChaosModule):
    name = "lambda_backdoor_function"
    description = (
        "Simulate Lambda function backdoor by adding a resource-based policy allowing "
        "the current account to invoke AttackLab Lambda functions. "
        "Maps to Stratus Red Team aws.persistence.lambda-backdoor-function."
    )
    category = "persistence"
    required_permissions = [
        "lambda:ListFunctions",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:GetPolicy",
    ]
    cloudtrail_events = [
        "ListFunctions20150331",
        "AddPermission20150331",
        "RemovePermission20150331",
    ]
    mitre_attack = ["T1525"]
    destructive = False
    reversible = True

    def _list_attacklab_functions(self, lam) -> list[str]:
        """Return Lambda function names starting with 'AttackLab'."""
        functions = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for func in page.get("Functions", []):
                    if func["FunctionName"].startswith("AttackLab"):
                        functions.append(func["FunctionName"])
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("lambda:ListFunctions failed: %s", code)
        return functions

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        lam = context.get_client("lambda")
        functions = self._list_attacklab_functions(lam)
        findings = [f"AttackLab-prefixed Lambda functions found: {functions or 'none'}"]
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for AttackLab Lambda functions for backdoor permission.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=["lambda:ListFunctions"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=bool(functions),
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check lambda:AddPermission and count AttackLab functions."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        lam = context.get_client("lambda")
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["lambda:AddPermission"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        functions = self._list_attacklab_functions(lam)
        n = len(functions)

        if perm_results.get("lambda:AddPermission") is True:
            findings.append("[RISK] Principal can call lambda:AddPermission.")
        elif simulation_available:
            findings.append("lambda:AddPermission not permitted for this principal.")

        findings.append(
            f"[DRY-RUN] Would add invoke permission statement to {n} AttackLab Lambda functions."
        )

        detections = [
            "CloudTrail: lambda:AddPermission with cross-account principal",
            "GuardDuty: Policy:Lambda/FunctionPublicAccess",
            "AWS Config: lambda-function-public-access-prohibited",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {n} AttackLab Lambda functions for potential backdoor.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, v in perm_results.items() if v is True],
            aws_api_calls=["iam:SimulatePrincipalPolicy", "lambda:ListFunctions"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(functions),
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Add invoke permission statement to AttackLab Lambda functions."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        lam = context.get_client("lambda")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        functions = self._list_attacklab_functions(lam)
        api_calls.append("lambda:ListFunctions")

        if not functions:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab Lambda functions found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-prefixed Lambda functions found. No action taken."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=True,
                errors=[],
            )

        for fn_name in functions:
            checker.assert_resource_safe(fn_name, {})

            try:
                lam.add_permission(
                    FunctionName=fn_name,
                    StatementId=_STATEMENT_ID,
                    Action="lambda:InvokeFunction",
                    Principal=f"arn:aws:iam::{identity.account_id}:root",
                )
                api_calls.append(f"lambda:AddPermission ({fn_name})")
                findings.append(
                    f"[EXECUTE] Added invoke permission statement '{_STATEMENT_ID}' to function '{fn_name}'."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "ResourceConflictException":
                    findings.append(
                        f"Permission statement '{_STATEMENT_ID}' already exists on '{fn_name}' — idempotent."
                    )
                else:
                    errors.append(f"lambda:AddPermission failed for '{fn_name}': {code}")

        detections = [
            "CloudTrail: lambda:AddPermission with cross-account principal",
            "GuardDuty: Policy:Lambda/FunctionPublicAccess",
            "AWS Config: lambda-function-public-access-prohibited",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Added backdoor invoke permission to {len(functions)} AttackLab Lambda(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["lambda:AddPermission"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Remove backdoor invoke permission from AttackLab Lambda functions. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        lam = context.get_client("lambda")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        functions = self._list_attacklab_functions(lam)
        api_calls.append("lambda:ListFunctions")

        for fn_name in functions:
            try:
                lam.remove_permission(
                    FunctionName=fn_name,
                    StatementId=_STATEMENT_ID,
                )
                api_calls.append(f"lambda:RemovePermission ({fn_name})")
                findings.append(
                    f"[CLEANUP] Removed permission statement '{_STATEMENT_ID}' from function '{fn_name}'."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "ResourceNotFoundException":
                    findings.append(
                        f"Permission statement '{_STATEMENT_ID}' not found on '{fn_name}' — idempotent."
                    )
                else:
                    errors.append(f"lambda:RemovePermission failed for '{fn_name}': {code}")

        if not findings:
            findings.append("No AttackLab Lambda functions found for cleanup.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Backdoor invoke permissions removed from AttackLab Lambda functions.",
            required_permissions=["lambda:ListFunctions", "lambda:RemovePermission"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = LambdaBackdoorFunctionModule()
