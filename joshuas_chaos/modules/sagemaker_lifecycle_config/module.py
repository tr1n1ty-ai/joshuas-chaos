"""SageMaker Lifecycle Config Abuse Module.

Dry-run: Detect CreateNotebookInstanceLifecycleConfig permission.
Execute: Create a benign AttackLab lifecycle config with an echo-only script.
Cleanup: Delete the lifecycle config.

Maps to Stratus Red Team aws.execution.sagemaker-lifecycle-config-execution.
"""

import base64
import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_CONFIG_NAME = "AttackLabLifecycleConfigTest"

# Benign on-start script — only echoes a marker message
_BENIGN_SCRIPT = "#!/bin/bash\necho AttackLab lifecycle config test - benign"


def _b64(s: str) -> str:
    """Base64-encode a string (SageMaker requires base64 scripts)."""
    return base64.b64encode(s.encode()).decode()


class SageMakerLifecycleConfigModule(ChaosModule):
    name = "sagemaker_lifecycle_config"
    description = (
        "Simulate SageMaker lifecycle configuration abuse. Execute creates a benign "
        "AttackLab lifecycle config with an echo-only script. "
        "Maps to Stratus Red Team aws.execution.sagemaker-lifecycle-config-execution."
    )
    category = "execution"
    required_permissions = [
        "sagemaker:ListNotebookInstances",
        "sagemaker:CreateNotebookInstanceLifecycleConfig",
        "sagemaker:DeleteNotebookInstanceLifecycleConfig",
        "sagemaker:ListNotebookInstanceLifecycleConfigs",
    ]
    cloudtrail_events = [
        "CreateNotebookInstanceLifecycleConfig",
        "DeleteNotebookInstanceLifecycleConfig",
        "ListNotebookInstances",
    ]
    mitre_attack = ["T1059", "T1578"]
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
            risk_summary="Check SageMaker lifecycle config abuse prerequisites.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess SageMaker lifecycle config abuse risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detect CreateNotebookInstanceLifecycleConfig permissions and enumerate notebooks."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        sm = context.get_client("sagemaker")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=[
                "sagemaker:CreateNotebookInstanceLifecycleConfig",
                "sagemaker:ListNotebookInstances",
            ],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        has_create = perm_results.get("sagemaker:CreateNotebookInstanceLifecycleConfig") is True
        if has_create:
            findings.append(
                "[HIGH RISK] Principal has CreateNotebookInstanceLifecycleConfig. "
                "Can inject code that runs when a SageMaker notebook starts."
            )
        elif perm_results.get("sagemaker:CreateNotebookInstanceLifecycleConfig") is False:
            findings.append("[OK] Principal does not have CreateNotebookInstanceLifecycleConfig.")

        # Enumerate notebook instances
        notebooks: list[dict] = []
        try:
            paginator = sm.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for nb in page.get("NotebookInstances", []):
                    name = nb.get("NotebookInstanceName", "")
                    status = nb.get("NotebookInstanceStatus", "Unknown")
                    notebooks.append({"name": name, "status": status})
            api_calls.append("sagemaker:ListNotebookInstances")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"sagemaker:ListNotebookInstances failed: {code}")

        findings.append(f"SageMaker notebook instances visible: {len(notebooks)}")

        tag_prefix = config.resource_safety.allowed_name_prefix
        attacklab_notebooks = [n for n in notebooks if n["name"].startswith(tag_prefix)]
        findings.append(
            f"[DRY-RUN] Would create lifecycle config '{_CONFIG_NAME}' "
            "with benign echo-only on-start script."
        )
        if attacklab_notebooks:
            findings.append(
                f"AttackLab notebooks that could be targeted: "
                f"{[n['name'] for n in attacklab_notebooks]}"
            )

        detections = [
            "CloudTrail: sagemaker:CreateNotebookInstanceLifecycleConfig",
            "CloudTrail: sagemaker:UpdateNotebookInstance (lifecycle config change)",
            "SageMaker audit logs: lifecycle script execution on notebook start",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(notebooks)} notebook(s). "
                f"CreateNotebookInstanceLifecycleConfig: "
                f"{'confirmed' if has_create else 'not detected'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Create a benign AttackLab lifecycle config (echo only)."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_CONFIG_NAME, {})

        sm = context.get_client("sagemaker")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            sm.create_notebook_instance_lifecycle_config(
                NotebookInstanceLifecycleConfigName=_CONFIG_NAME,
                OnStart=[{"Content": _b64(_BENIGN_SCRIPT)}],
            )
            api_calls.append(f"sagemaker:CreateNotebookInstanceLifecycleConfig ({_CONFIG_NAME})")
            findings.append(
                f"[EXECUTE] Created lifecycle config '{_CONFIG_NAME}' "
                "with benign echo-only on-start script."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "ResourceInUse":
                findings.append(f"Lifecycle config '{_CONFIG_NAME}' already exists.")
            else:
                errors.append(f"sagemaker:CreateNotebookInstanceLifecycleConfig failed: {code}")

        detections = [
            "CloudTrail: sagemaker:CreateNotebookInstanceLifecycleConfig",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Created lifecycle config '{_CONFIG_NAME}' with benign script.",
            required_permissions=self.required_permissions,
            observed_permissions=["sagemaker:CreateNotebookInstanceLifecycleConfig"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Delete the AttackLab lifecycle config. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        sm = context.get_client("sagemaker")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            sm.delete_notebook_instance_lifecycle_config(
                NotebookInstanceLifecycleConfigName=_CONFIG_NAME
            )
            api_calls.append(
                f"sagemaker:DeleteNotebookInstanceLifecycleConfig ({_CONFIG_NAME})"
            )
            findings.append(f"[CLEANUP] Deleted lifecycle config '{_CONFIG_NAME}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("ResourceNotFound", "ValidationException"):
                findings.append(
                    f"Lifecycle config '{_CONFIG_NAME}' not found — already deleted (idempotent)."
                )
            else:
                errors.append(
                    f"sagemaker:DeleteNotebookInstanceLifecycleConfig failed: {code}"
                )

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Lifecycle config deleted.",
            required_permissions=["sagemaker:DeleteNotebookInstanceLifecycleConfig"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = SageMakerLifecycleConfigModule()
