"""SSM SendCommand Abuse Module.

List SSM managed instances and assess SendCommand risk.
Execute: Only target EC2 instances tagged AttackLab=true.
Allowed commands: whoami, hostname ONLY.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

# STRICTLY limited to these benign commands only
_ALLOWED_COMMANDS = ["whoami", "hostname"]
_SSM_DOCUMENT = "AWS-RunShellScript"


class SSMSendCommandAbuseModule(ChaosModule):
    name = "ssm_sendcommand_abuse"
    description = (
        "List SSM managed instances and assess SendCommand risk. "
        "Execute sends only 'whoami' and 'hostname' to AttackLab-tagged instances."
    )
    category = "execution"
    required_permissions = [
        "ssm:DescribeInstanceInformation",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ec2:DescribeInstances",
    ]
    cloudtrail_events = [
        "DescribeInstanceInformation",
        "SendCommand",
        "GetCommandInvocation",
    ]
    mitre_attack = ["T1651"]
    destructive = False
    reversible = True

    _command_ids: list[str]

    def __init__(self) -> None:
        self._command_ids = []

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for SSM managed instances.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to list SSM managed instances."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _get_attacklab_instances(self, ec2, config: AppConfig) -> list[dict]:
        """Return EC2 instance info for instances tagged AttackLab=true."""
        tag_key = config.resource_safety.required_tag_key
        tag_val = config.resource_safety.required_tag_value
        instances: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": f"tag:{tag_key}", "Values": [tag_val]}]
            ):
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        instances.append({
                            "instance_id": inst["InstanceId"],
                            "state": inst.get("State", {}).get("Name", "unknown"),
                        })
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ec2:DescribeInstances failed: %s", code)
        return instances

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """List SSM managed instances and assess SendCommand risk."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ssm = context.get_client("ssm")
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ssm:SendCommand"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        if perm_results.get("ssm:SendCommand"):
            findings.append("[RISK] Principal has ssm:SendCommand permission.")

        # List SSM managed instances
        managed_instances: list[str] = []
        try:
            paginator = ssm.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                for info in page.get("InstanceInformationList", []):
                    managed_instances.append(info.get("InstanceId", ""))
            api_calls.append("ssm:DescribeInstanceInformation")
            findings.append(f"SSM managed instances: {len(managed_instances)}")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ssm:DescribeInstanceInformation failed: {code}")

        attacklab_instances = self._get_attacklab_instances(ec2, config)
        api_calls.append("ec2:DescribeInstances")
        if attacklab_instances:
            findings.append(
                f"[DRY-RUN] Would send 'whoami' and 'hostname' to AttackLab instances: "
                f"{[i['instance_id'] for i in attacklab_instances]}"
            )
        else:
            findings.append("No AttackLab-tagged EC2 instances found.")

        detections = [
            "CloudTrail: ssm:SendCommand",
            "SSM Session Manager logs",
            "CloudWatch: SSM-RunShellScript output",
            "GuardDuty: Execution:EC2/SuspiciousCommand",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {len(managed_instances)} SSM managed instances.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_instances),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Send whoami and hostname to AttackLab-tagged instances only."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ssm = context.get_client("ssm")
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        attacklab_instances = self._get_attacklab_instances(ec2, config)
        api_calls.append("ec2:DescribeInstances")

        if not attacklab_instances:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab-tagged instances found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-tagged EC2 instances found."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        instance_ids = [i["instance_id"] for i in attacklab_instances if i["state"] == "running"]

        if not instance_ids:
            findings.append("AttackLab instances found but none are running.")
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No running AttackLab instances.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        # STRICTLY limited to whoami and hostname only
        for instance_id in instance_ids:
            try:
                resp = ssm.send_command(
                    InstanceIds=[instance_id],
                    DocumentName=_SSM_DOCUMENT,
                    Parameters={"commands": _ALLOWED_COMMANDS},
                    Comment="AttackLab ssm_sendcommand_abuse test - whoami/hostname only",
                    TimeoutSeconds=30,
                )
                cmd_id = resp["Command"]["CommandId"]
                self._command_ids.append(cmd_id)
                api_calls.append(f"ssm:SendCommand ({instance_id})")
                findings.append(
                    f"[EXECUTE] Sent commands {_ALLOWED_COMMANDS} to instance '{instance_id}'. "
                    f"Command ID: {cmd_id}"
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"ssm:SendCommand failed for '{instance_id}': {code}")

        detections = [
            "CloudTrail: ssm:SendCommand",
            "CloudWatch: /aws/ssm/AWS-RunShellScript output log",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Sent benign commands to {len(instance_ids)} instance(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["ssm:SendCommand"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={"command_ids": self._command_ids},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        findings = [
            "SSM commands complete on their own — no cleanup needed.",
            f"Command IDs: {self._command_ids or 'none'}",
        ]
        self._command_ids = []
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required for SSM commands.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=[],
        )


MODULE = SSMSendCommandAbuseModule()
