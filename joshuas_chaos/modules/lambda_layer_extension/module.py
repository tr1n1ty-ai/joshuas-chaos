"""Lambda Layer Extension Module.

Simulate Lambda layer persistence by publishing a benign AttackLab Lambda layer
and attaching it to AttackLab-prefixed Lambda functions.
Maps to Stratus Red Team aws.persistence.lambda-layer-extension.
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

_LAYER_NAME = "AttackLabExtensionLayer"
_EXT_SCRIPT = "#!/bin/sh\necho AttackLab layer extension test"


def _build_layer_zip() -> bytes:
    """Build an in-memory zip containing the extension shell script."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("extensions/attacklab-ext")
        info.external_attr = 0o755 << 16  # executable
        zf.writestr(info, _EXT_SCRIPT)
    return buf.getvalue()


class LambdaLayerExtensionModule(ChaosModule):
    name = "lambda_layer_extension"
    description = (
        "Simulate Lambda layer persistence by publishing a benign AttackLab Lambda layer "
        "and attaching it to AttackLab-prefixed Lambda functions. "
        "Maps to Stratus Red Team aws.persistence.lambda-layer-extension."
    )
    category = "persistence"
    required_permissions = [
        "lambda:ListFunctions",
        "lambda:PublishLayerVersion",
        "lambda:UpdateFunctionConfiguration",
        "lambda:DeleteLayerVersion",
        "lambda:GetLayerVersion",
        "lambda:ListLayerVersions",
    ]
    cloudtrail_events = [
        "ListFunctions20150331",
        "PublishLayerVersion20181031",
        "UpdateFunctionConfiguration20150331",
        "DeleteLayerVersion20181031",
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
            risk_summary="Check for AttackLab Lambda functions for layer extension attack.",
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
        """Check lambda:PublishLayerVersion and count AttackLab functions."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        lam = context.get_client("lambda")
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["lambda:PublishLayerVersion"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        functions = self._list_attacklab_functions(lam)
        n = len(functions)

        if perm_results.get("lambda:PublishLayerVersion") is True:
            findings.append("[RISK] Principal can call lambda:PublishLayerVersion.")
        elif simulation_available:
            findings.append("lambda:PublishLayerVersion not permitted for this principal.")

        findings.append(
            f"[DRY-RUN] Would publish layer '{_LAYER_NAME}' and attach to {n} AttackLab functions."
        )

        detections = [
            "CloudTrail: lambda:PublishLayerVersion + lambda:UpdateFunctionConfiguration",
            "GuardDuty: Execution:Lambda/MaliciousLambdaLayer",
            "AWS Config: monitor lambda layer changes via CloudTrail",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {n} AttackLab Lambda functions for potential layer extension.",
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
        """Publish AttackLabExtensionLayer and attach to AttackLab Lambda functions."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_LAYER_NAME, {})

        lam = context.get_client("lambda")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Build and publish layer
        zip_bytes = _build_layer_zip()
        layer_arn: str | None = None

        try:
            resp = lam.publish_layer_version(
                LayerName=_LAYER_NAME,
                Content={"ZipFile": zip_bytes},
                Description="AttackLab layer extension test — benign",
            )
            layer_arn = resp["LayerVersionArn"]
            api_calls.append(f"lambda:PublishLayerVersion ({_LAYER_NAME})")
            findings.append(
                f"[EXECUTE] Published layer '{_LAYER_NAME}'. ARN: {layer_arn}."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"lambda:PublishLayerVersion failed: {code}")

        if not layer_arn:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="Layer publication failed — no functions updated.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=True,
                errors=errors,
            )

        # Attach layer to AttackLab functions
        functions = self._list_attacklab_functions(lam)
        api_calls.append("lambda:ListFunctions")
        attached = []

        for fn_name in functions:
            checker.assert_resource_safe(fn_name, {})

            try:
                lam.update_function_configuration(
                    FunctionName=fn_name,
                    Layers=[layer_arn],
                )
                api_calls.append(f"lambda:UpdateFunctionConfiguration ({fn_name})")
                findings.append(
                    f"[EXECUTE] Attached layer '{_LAYER_NAME}' to function '{fn_name}'."
                )
                attached.append(fn_name)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"lambda:UpdateFunctionConfiguration failed for '{fn_name}': {code}")

        if not functions:
            findings.append(
                "No AttackLab-prefixed Lambda functions found to attach layer to."
            )

        detections = [
            "CloudTrail: lambda:PublishLayerVersion + lambda:UpdateFunctionConfiguration",
            "GuardDuty: Execution:Lambda/MaliciousLambdaLayer",
            "AWS Config: monitor lambda layer changes via CloudTrail",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Published '{_LAYER_NAME}' and attached to {len(attached)} function(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["lambda:PublishLayerVersion", "lambda:UpdateFunctionConfiguration"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
            metadata={"layer_version_arn": layer_arn, "attached_functions": attached},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Delete all versions of AttackLabExtensionLayer and detach from functions. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        lam = context.get_client("lambda")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Detach layer from AttackLab functions
        functions = self._list_attacklab_functions(lam)
        api_calls.append("lambda:ListFunctions")

        for fn_name in functions:
            try:
                lam.update_function_configuration(
                    FunctionName=fn_name,
                    Layers=[],
                )
                api_calls.append(f"lambda:UpdateFunctionConfiguration ({fn_name}) detach")
                findings.append(f"[CLEANUP] Detached all layers from function '{fn_name}'.")
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "ResourceNotFoundException":
                    findings.append(f"Function '{fn_name}' not found — idempotent.")
                else:
                    errors.append(f"lambda:UpdateFunctionConfiguration failed for '{fn_name}': {code}")

        # Delete all versions of the layer
        try:
            paginator = lam.get_paginator("list_layer_versions")
            for page in paginator.paginate(LayerName=_LAYER_NAME):
                for version in page.get("LayerVersions", []):
                    version_number = version["Version"]
                    try:
                        lam.delete_layer_version(
                            LayerName=_LAYER_NAME,
                            VersionNumber=version_number,
                        )
                        api_calls.append(f"lambda:DeleteLayerVersion ({_LAYER_NAME} v{version_number})")
                        findings.append(
                            f"[CLEANUP] Deleted layer '{_LAYER_NAME}' version {version_number}."
                        )
                    except botocore.exceptions.ClientError as exc:
                        code = exc.response.get("Error", {}).get("Code", "Unknown")
                        if code == "ResourceNotFoundException":
                            findings.append(
                                f"Layer '{_LAYER_NAME}' v{version_number} not found — idempotent."
                            )
                        else:
                            errors.append(
                                f"lambda:DeleteLayerVersion failed for v{version_number}: {code}"
                            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "ResourceNotFoundException":
                findings.append(f"Layer '{_LAYER_NAME}' not found — idempotent.")
            else:
                errors.append(f"lambda:ListLayerVersions failed: {code}")

        if not findings:
            findings.append(f"Layer '{_LAYER_NAME}' not found — nothing to clean up.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Layer '{_LAYER_NAME}' versions deleted and detached from functions.",
            required_permissions=["lambda:ListLayerVersions", "lambda:DeleteLayerVersion", "lambda:UpdateFunctionConfiguration"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = LambdaLayerExtensionModule()
