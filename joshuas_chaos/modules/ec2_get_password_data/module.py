"""EC2 Get Password Data Module.

Dry-run ONLY: Detect if principal has ec2:GetPasswordData permission and enumerate
Windows EC2 instances whose encrypted Administrator password could be retrieved.
Maps to Stratus Red Team aws.credential-access.ec2-get-password-data.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class EC2GetPasswordDataModule(ChaosModule):
    name = "ec2_get_password_data"
    description = (
        "Detect if principal has ec2:GetPasswordData permission and enumerate Windows EC2 "
        "instances whose encrypted Administrator password could be retrieved. "
        "Dry-run only. Maps to Stratus Red Team aws.credential-access.ec2-get-password-data."
    )
    category = "credential-access"
    required_permissions = ["ec2:DescribeInstances", "ec2:GetPasswordData"]
    cloudtrail_events = ["DescribeInstances", "GetPasswordData"]
    mitre_attack = ["T1552.005"]
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
            risk_summary="Read-only check for EC2 GetPasswordData capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate Windows instances and check GetPasswordData permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate Windows EC2 instances and check GetPasswordData permission."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check GetPasswordData permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2:GetPasswordData"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        get_pwd_perm: bool | None = perm_results.get("ec2:GetPasswordData")

        if get_pwd_perm is True:
            findings.append(
                "[RISK] Principal has ec2:GetPasswordData — can retrieve encrypted Windows "
                "Administrator password for instances launched with a known key pair"
            )
        elif get_pwd_perm is None:
            findings.append(
                "[UNKNOWN] ec2:GetPasswordData permission could not be determined"
            )

        # Enumerate Windows instances
        windows_instances: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "platform", "Values": ["windows"]}]
            ):
                api_calls.append("ec2:DescribeInstances")
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        instance_id = inst["InstanceId"]
                        state = inst.get("State", {}).get("Name", "unknown")
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        windows_instances.append({
                            "instance_id": instance_id,
                            "state": state,
                            "tags": tags,
                        })
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("AccessDenied", "AccessDeniedException"):
                errors.append("ec2:DescribeInstances — AccessDenied.")
            else:
                errors.append(f"ec2:DescribeInstances failed: {code}")

        findings.append(f"Windows EC2 instances found: {len(windows_instances)}")
        for inst in windows_instances:
            findings.append(
                f"  Instance '{inst['instance_id']}' (state={inst['state']})"
            )

        if windows_instances:
            findings.append(
                "[NOTE] Retrieving password data requires the private key used at launch to "
                "decrypt the ciphertext. Useful for lateral movement to Windows workloads."
            )
        else:
            findings.append("No Windows instances found in this region.")

        detections = [
            "CloudTrail: GetPasswordData events",
            "GuardDuty: CredentialAccess:EC2/Unusualpasswordreset",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(windows_instances)} Windows instance(s). "
                f"GetPasswordData permission: "
                f"{'confirmed' if get_pwd_perm is True else 'unknown' if get_pwd_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ec2:GetPasswordData"] if get_pwd_perm is True else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "windows_instance_ids": [i["instance_id"] for i in windows_instances],
                "get_password_data_permission": get_pwd_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "ec2_get_password_data is dry-run only. "
            "Retrieving EC2 password data is credential access that could expose real "
            "credentials even in lab environments."
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


MODULE = EC2GetPasswordDataModule()
