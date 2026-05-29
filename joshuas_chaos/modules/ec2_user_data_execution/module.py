"""EC2 User Data Execution Module.

Simulate code execution via EC2 user data modification on a stopped AttackLab instance.
Execute sets a benign user data script (prints hostname) on a stopped AttackLab instance.
Cleanup restores the original user data.

Maps to Stratus Red Team aws.execution.ec2-user-data (Execution + Privilege Escalation).
"""

import base64
import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.masking import mask_string
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_BENIGN_USER_DATA = (
    "#!/bin/bash\n"
    "echo \"AttackLab user-data execution test - benign\" > /tmp/attacklab_test.txt\n"
    "hostname >> /tmp/attacklab_test.txt"
)


class EC2UserDataExecutionModule(ChaosModule):
    name = "ec2_user_data_execution"
    description = (
        "Simulate code execution via EC2 user data modification on a stopped AttackLab instance. "
        "Execute sets a benign user data script (prints hostname) on a stopped AttackLab instance. "
        "Maps to Stratus Red Team aws.execution.ec2-user-data (Execution + Privilege Escalation)."
    )
    category = "execution"
    required_permissions = [
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceAttribute",
        "ec2:DescribeInstanceAttribute",
    ]
    cloudtrail_events = [
        "DescribeInstances",
        "ModifyInstanceAttribute",
        "DescribeInstanceAttribute",
    ]
    mitre_attack = ["T1059.004", "T1078.004"]
    destructive = False
    reversible = True

    _original_user_data: dict[str, str]

    def __init__(self) -> None:
        self._original_user_data = {}

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                "Check for ec2:ModifyInstanceAttribute permission and "
                "stopped AttackLab-tagged instances."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=[
                "Run dry-run to check ModifyInstanceAttribute permission "
                "and enumerate stopped AttackLab instances."
            ],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _get_stopped_attacklab_instances(self, ec2, config: AppConfig) -> list[dict]:
        """Return EC2 instances tagged AttackLab=true that are stopped."""
        tag_key = config.resource_safety.required_tag_key
        tag_val = config.resource_safety.required_tag_value
        instances: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[
                    {"Name": f"tag:{tag_key}", "Values": [tag_val]},
                    {"Name": "instance-state-name", "Values": ["stopped"]},
                ]
            ):
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        instances.append({
                            "instance_id": inst["InstanceId"],
                            "state": inst.get("State", {}).get("Name", "unknown"),
                            "tags": tags,
                        })
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ec2:DescribeInstances failed: %s", code)
        return instances

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check ModifyInstanceAttribute permission and find stopped AttackLab instances."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2:ModifyInstanceAttribute"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        modify_perm: bool | None = perm_results.get("ec2:ModifyInstanceAttribute")

        if modify_perm is True:
            findings.append(
                "[HIGH RISK] Principal can modify EC2 user data on stopped instances — "
                "code executes as root on next start"
            )
        elif modify_perm is None:
            findings.append(
                "[UNKNOWN] ec2:ModifyInstanceAttribute permission could not be determined — "
                "treat as potential risk."
            )

        stopped_instances = self._get_stopped_attacklab_instances(ec2, config)
        api_calls.append("ec2:DescribeInstances")
        n = len(stopped_instances)

        if stopped_instances:
            findings.append(
                f"Stopped AttackLab instances found: "
                f"{[i['instance_id'] for i in stopped_instances]}"
            )
        else:
            findings.append("No stopped AttackLab-tagged EC2 instances found.")

        findings.append(
            f"[DRY-RUN] Would set benign user data on {n} stopped AttackLab instance(s)"
        )
        findings.append(
            "Note: user data runs as root/SYSTEM on instance start — "
            "equivalent to RCE with highest privilege."
        )

        detections = [
            "CloudTrail: ModifyInstanceAttribute event",
            "GuardDuty: no specific finding — detection gap for user data modification",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"ModifyInstanceAttribute permission: "
                f"{'confirmed' if modify_perm is True else 'unknown' if modify_perm is None else 'denied'}. "
                f"Stopped AttackLab instances: {n}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(stopped_instances),
            errors=errors,
            metadata={
                "stopped_attacklab_instance_ids": [i["instance_id"] for i in stopped_instances],
                "modify_instance_attribute_permission": modify_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Set benign user data on stopped AttackLab-tagged instances."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        stopped_instances = self._get_stopped_attacklab_instances(ec2, config)
        api_calls.append("ec2:DescribeInstances")

        if not stopped_instances:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No stopped AttackLab instances found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=[
                    "No stopped AttackLab instances found. "
                    "Stop an instance tagged AttackLab=true to use this module."
                ],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        new_user_data_b64 = base64.b64encode(_BENIGN_USER_DATA.encode()).decode()

        for inst in stopped_instances:
            instance_id = inst["instance_id"]

            # Backup current user data
            original_b64 = ""
            try:
                attr_resp = ec2.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute="userData",
                )
                api_calls.append(f"ec2:DescribeInstanceAttribute ({instance_id})")
                user_data_val = attr_resp.get("UserData", {})
                original_b64 = user_data_val.get("Value", "") or ""
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "AccessDenied":
                    errors.append(
                        f"ec2:DescribeInstanceAttribute denied for '{instance_id}': {code}"
                    )
                    continue
                else:
                    errors.append(
                        f"ec2:DescribeInstanceAttribute failed for '{instance_id}': {code}"
                    )
                    continue

            # Store masked original user data
            if original_b64:
                try:
                    decoded = base64.b64decode(original_b64).decode("utf-8", errors="replace")
                    masked = mask_string(decoded)
                except Exception:
                    masked = "[non-UTF-8 user data]"
            else:
                masked = ""
            self._original_user_data[instance_id] = original_b64

            # Set new benign user data
            try:
                ec2.modify_instance_attribute(
                    InstanceId=instance_id,
                    UserData={"Value": new_user_data_b64},
                )
                api_calls.append(f"ec2:ModifyInstanceAttribute ({instance_id})")
                findings.append(
                    f"[EXECUTE] Set benign user data on stopped instance '{instance_id}'. "
                    f"Original user data backed up (masked: {masked!r}). "
                    "Note: does NOT start the instance — only modifies the attribute."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(
                    f"ec2:ModifyInstanceAttribute failed for '{instance_id}': {code}"
                )
                # Remove from backup if we didn't succeed
                self._original_user_data.pop(instance_id, None)

        detections = [
            "CloudTrail: ModifyInstanceAttribute event",
            "GuardDuty: no specific finding — detection gap for user data modification",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Set benign user data on {len(self._original_user_data)} instance(s). "
                "Original user data backed up for cleanup."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[
                "ec2:ModifyInstanceAttribute",
                "ec2:DescribeInstanceAttribute",
            ],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=bool(self._original_user_data),
            safe_to_execute=True,
            errors=errors,
            metadata={"modified_instance_ids": list(self._original_user_data.keys())},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Restore original user data on modified instances. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        if not self._original_user_data:
            findings.append("No user data backups recorded — nothing to restore (idempotent).")
            return ModuleResult(
                module=self.name,
                mode="cleanup",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No state to clean up.",
                required_permissions=["ec2:ModifyInstanceAttribute"],
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=True,
                errors=errors,
            )

        for instance_id, original_b64 in list(self._original_user_data.items()):
            try:
                ec2.modify_instance_attribute(
                    InstanceId=instance_id,
                    UserData={"Value": original_b64},
                )
                api_calls.append(f"ec2:ModifyInstanceAttribute ({instance_id})")
                findings.append(
                    f"[CLEANUP] Restored original user data on instance '{instance_id}'."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
                    findings.append(
                        f"Instance '{instance_id}' not found — "
                        "may have been terminated (idempotent)."
                    )
                else:
                    errors.append(
                        f"ec2:ModifyInstanceAttribute restore failed for '{instance_id}': {code}"
                    )

        self._original_user_data = {}

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Original user data restored on all modified instances.",
            required_permissions=["ec2:ModifyInstanceAttribute"],
            observed_permissions=["ec2:ModifyInstanceAttribute"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = EC2UserDataExecutionModule()
