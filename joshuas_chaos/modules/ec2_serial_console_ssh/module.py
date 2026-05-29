"""EC2 Serial Console SSH Module.

Simulate EC2 Serial Console lateral movement by assessing account-level serial console
access status and enumerating AttackLab instances that would be affected.
Dry-run only — serial console enable/disable requires account-level changes.

Maps to Stratus Red Team aws.lateral-movement.ec2-serial-console-ssh.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class EC2SerialConsoleSshModule(ChaosModule):
    name = "ec2_serial_console_ssh"
    description = (
        "Simulate EC2 Serial Console lateral movement by enabling serial console access "
        "at the account level and pushing an SSH key to AttackLab instances. "
        "Dry-run only — serial console enable/disable requires account-level changes. "
        "Maps to Stratus Red Team aws.lateral-movement.ec2-serial-console-ssh."
    )
    category = "lateral-movement"
    required_permissions = [
        "ec2:DescribeInstances",
        "ec2:GetSerialConsoleAccessStatus",
        "ec2:EnableSerialConsoleAccess",
        "ec2:SendSerialConsoleSSHPublicKey",
        "ec2:DisableSerialConsoleAccess",
    ]
    cloudtrail_events = [
        "DescribeInstances",
        "GetSerialConsoleAccessStatus",
        "EnableSerialConsoleAccess",
        "SendSerialConsoleSSHPublicKey",
        "DisableSerialConsoleAccess",
    ]
    mitre_attack = ["T1021.004"]
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
            risk_summary=(
                "Check for ec2:EnableSerialConsoleAccess and ec2:SendSerialConsoleSSHPublicKey "
                "permissions, and assess current account-level serial console status."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=[
                "Run dry-run to check serial console permissions and current account-level status."
            ],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate serial console status and AttackLab instances, assess risk."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check key permissions
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=[
                "ec2:EnableSerialConsoleAccess",
                "ec2:SendSerialConsoleSSHPublicKey",
            ],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        enable_perm: bool | None = perm_results.get("ec2:EnableSerialConsoleAccess")
        send_key_perm: bool | None = perm_results.get("ec2:SendSerialConsoleSSHPublicKey")

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if enable_perm is True:
            findings.append(
                "[RISK] Principal has ec2:EnableSerialConsoleAccess permission."
            )
        elif enable_perm is None and simulation_available:
            findings.append(
                "[UNKNOWN] ec2:EnableSerialConsoleAccess permission could not be determined."
            )

        if send_key_perm is True:
            findings.append(
                "[RISK] Principal has ec2:SendSerialConsoleSSHPublicKey permission."
            )
        elif send_key_perm is None and simulation_available:
            findings.append(
                "[UNKNOWN] ec2:SendSerialConsoleSSHPublicKey permission could not be determined."
            )

        # Check current serial console access status
        serial_console_enabled: bool | None = None
        try:
            resp = ec2.get_serial_console_access_status()
            serial_console_enabled = resp.get("SerialConsoleAccessEnabled", False)
            api_calls.append("ec2:GetSerialConsoleAccessStatus")
            status_str = "ENABLED" if serial_console_enabled else "disabled"
            findings.append(
                f"Current account-level serial console access status: {status_str}"
            )
            if serial_console_enabled:
                findings.append(
                    "[HIGH RISK] Serial console access is already enabled at account level"
                )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ec2:GetSerialConsoleAccessStatus failed: {code}")

        # Enumerate running AttackLab instances
        tag_key = config.resource_safety.required_tag_key
        tag_val = config.resource_safety.required_tag_value
        running_attacklab: list[dict] = []

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        state = inst.get("State", {}).get("Name", "unknown")
                        is_attacklab = tags.get(tag_key, "").lower() == tag_val.lower()
                        if is_attacklab and state == "running":
                            running_attacklab.append({
                                "instance_id": inst["InstanceId"],
                                "tags": tags,
                            })
            api_calls.append("ec2:DescribeInstances")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ec2:DescribeInstances failed: {code}")

        n = len(running_attacklab)
        findings.append(f"Running AttackLab EC2 instances found: {n}")

        findings.append(
            f"[DRY-RUN] Would enable serial console access and push SSH key to {n} AttackLab instances"
        )
        findings.append(
            "Note: serial console access is account-level, not per-instance — broader blast radius."
        )

        detections = [
            "CloudTrail: ec2:EnableSerialConsoleAccess (account-level event)",
            "CloudTrail: ec2:SendSerialConsoleSSHPublicKey",
            "GuardDuty: no specific finding for serial console",
            "AWS Config: monitor ec2:EnableSerialConsoleAccess via CloudTrail rule",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Serial console access currently "
                f"{'enabled' if serial_console_enabled else 'disabled' if serial_console_enabled is False else 'unknown'}. "
                f"Running AttackLab instances found: {n}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a is True],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,  # dry-run only module
            errors=errors,
            metadata={
                "serial_console_enabled": serial_console_enabled,
                "running_attacklab_instance_ids": [i["instance_id"] for i in running_attacklab],
                "running_attacklab_count": n,
                "enable_serial_console_permission": enable_perm,
                "send_serial_console_ssh_key_permission": send_key_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Not implemented — enabling serial console access is account-level."""
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Execute not implemented: account-level change cannot be safely scoped to AttackLab resources.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=[
                "Execute not implemented: ec2:EnableSerialConsoleAccess is an account-level "
                "change that cannot be safely scoped to AttackLab resources. "
                "Use dry-run to assess current status."
            ],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """No-op: execute is not implemented, no state was created."""
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


MODULE = EC2SerialConsoleSshModule()
