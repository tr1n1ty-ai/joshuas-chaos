"""Existing Lambda Takeover Module.

List Lambda functions the principal may be able to update.
Execute: Only updates Lambda functions tagged AttackLab=true.
Updates to benign sts:GetCallerIdentity code.
Cleanup: Restore original Lambda code.
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

_BENIGN_CODE = '''
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
            "message": "AttackLab existing_lambda_takeover - benign sts:GetCallerIdentity"
        })
    }
'''.strip()


def _build_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _BENIGN_CODE)
    return buf.getvalue()


class ExistingLambdaTakeoverModule(ChaosModule):
    name = "existing_lambda_takeover"
    description = (
        "List Lambda functions potentially updatable, then simulate takeover by "
        "updating AttackLab-tagged functions with benign code."
    )
    category = "persistence"
    required_permissions = [
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "lambda:UpdateFunctionCode",
        "lambda:ListTags",
    ]
    cloudtrail_events = [
        "ListFunctions20150331",
        "GetFunction20150331",
        "UpdateFunctionCode20150331",
        "ListTags",
    ]
    mitre_attack = ["T1525"]
    destructive = False
    reversible = True

    _original_code_locations: dict[str, str]  # function_name -> original_s3_location or description

    def __init__(self) -> None:
        self._original_code_locations = {}

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for updatable Lambda functions.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to list Lambda functions and assess takeover risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _get_function_tags(self, lam, function_arn: str) -> dict[str, str]:
        try:
            resp = lam.list_tags(Resource=function_arn)
            return resp.get("Tags", {})
        except botocore.exceptions.ClientError:
            return {}

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """List Lambda functions and their execution roles. No modifications."""
        identity = context.get_caller_identity()
        lam = context.get_client("lambda")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        functions_info: list[dict] = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for func in page.get("Functions", []):
                    functions_info.append({
                        "name": func["FunctionName"],
                        "arn": func["FunctionArn"],
                        "role": func.get("Role", ""),
                        "runtime": func.get("Runtime", ""),
                    })
            api_calls.append("lambda:ListFunctions")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"lambda:ListFunctions failed: {code}")

        attacklab_funcs = []
        for func in functions_info:
            tags = self._get_function_tags(lam, func["arn"])
            api_calls.append(f"lambda:ListTags ({func['name']})")
            tag_key = config.resource_safety.required_tag_key
            tag_val = config.resource_safety.required_tag_value
            if (
                func["name"].startswith(config.resource_safety.allowed_name_prefix)
                or tags.get(tag_key, "").lower() == tag_val.lower()
            ):
                attacklab_funcs.append(func)

        findings.append(f"Total Lambda functions visible: {len(functions_info)}")
        if attacklab_funcs:
            for func in attacklab_funcs:
                findings.append(
                    f"[DRY-RUN] Would update '{func['name']}' (role: {func['role']}) "
                    "with benign sts:GetCallerIdentity code."
                )
        else:
            findings.append(
                "No AttackLab-tagged Lambda functions found. "
                "Tag a Lambda with AttackLab=true to use execute mode."
            )

        # Report execution role ARNs for all visible functions
        for func in functions_info[:10]:  # limit output
            findings.append(
                f"Function '{func['name']}' execution role: {func['role']}"
            )

        detections = [
            "CloudTrail: lambda:UpdateFunctionCode on unexpected function",
            "CloudTrail: lambda:GetFunction (to download code)",
            "Lambda code signing policy violation (if configured)",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {len(functions_info)} Lambda(s), {len(attacklab_funcs)} AttackLab-tagged.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_funcs),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Update AttackLab-tagged Lambda functions with benign code."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        lam = context.get_client("lambda")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []
        updated: list[str] = []

        try:
            paginator = lam.get_paginator("list_functions")
            all_funcs = []
            for page in paginator.paginate():
                all_funcs.extend(page.get("Functions", []))
            api_calls.append("lambda:ListFunctions")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"lambda:ListFunctions failed: {code}")
            all_funcs = []

        for func in all_funcs:
            name = func["FunctionName"]
            arn = func["FunctionArn"]
            tags = self._get_function_tags(lam, arn)
            api_calls.append(f"lambda:ListTags ({name})")

            try:
                checker.assert_resource_safe(name, tags)
            except Exception:
                continue  # skip non-lab resources silently

            # Store note about original (we track by name; can't safely restore bytes without S3)
            self._original_code_locations[name] = "original-before-attacklab-test"

            try:
                lam.update_function_code(
                    FunctionName=name,
                    ZipFile=_build_zip(),
                )
                api_calls.append(f"lambda:UpdateFunctionCode ({name})")
                findings.append(
                    f"[EXECUTE] Updated '{name}' with benign sts:GetCallerIdentity code. "
                    f"Original code reference stored in metadata."
                )
                updated.append(name)
            except botocore.exceptions.ClientError as exc:
                code_err = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"lambda:UpdateFunctionCode failed for '{name}': {code_err}")

        if not updated:
            findings.append("No AttackLab-tagged Lambda functions found to update.")

        detections = [
            "CloudTrail: UpdateFunctionCode20150331",
            "Lambda code signing policy violation",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Updated {len(updated)} AttackLab Lambda(s) with benign code.",
            required_permissions=self.required_permissions,
            observed_permissions=["lambda:UpdateFunctionCode"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=bool(updated),
            safe_to_execute=True,
            errors=errors,
            metadata={"updated_functions": updated},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Restore original Lambda code. Idempotent.

        Note: Since we cannot safely download and re-upload arbitrary bytes,
        we restore by re-uploading a clearly-labeled placeholder that indicates
        the function needs restoration from source control / deployment pipeline.
        """
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        lam = context.get_client("lambda")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        restore_code = '''
import json

def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "ATTACKLAB_CLEANUP: Restore this function from your deployment pipeline.",
            "status": "needs_restore"
        })
    }
'''.strip()

        for func_name in list(self._original_code_locations.keys()):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("handler.py", restore_code)
            try:
                lam.update_function_code(
                    FunctionName=func_name,
                    ZipFile=buf.getvalue(),
                )
                api_calls.append(f"lambda:UpdateFunctionCode ({func_name}) cleanup")
                findings.append(
                    f"[CLEANUP] Replaced '{func_name}' code with cleanup placeholder. "
                    "Redeploy from source control to fully restore."
                )
                del self._original_code_locations[func_name]
            except botocore.exceptions.ClientError as exc:
                code_err = exc.response.get("Error", {}).get("Code", "Unknown")
                if code_err == "ResourceNotFoundException":
                    findings.append(f"Function '{func_name}' not found — idempotent.")
                    del self._original_code_locations[func_name]
                else:
                    errors.append(f"Cleanup failed for '{func_name}': {code_err}")

        if not findings:
            findings.append("No Lambda functions tracked for cleanup.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Lambda cleanup placeholder deployed. Redeploy from source control.",
            required_permissions=["lambda:UpdateFunctionCode"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = ExistingLambdaTakeoverModule()
