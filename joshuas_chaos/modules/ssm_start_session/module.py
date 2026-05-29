"""SSM Start Session Module.

Detect if principal has ssm:StartSession permission and enumerate SSM-managed instances
that could be targeted for interactive shell access.  Dry-run only.

Maps to Stratus Red Team aws.execution.ssm-start-session.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class SSMStartSessionModule(ChaosModule):
    name = "ssm_start_session"
    description = (
        "Detect if principal has ssm:StartSession permission and enumerate SSM-managed instances "
        "that could be targeted for interactive shell access. Dry-run only. "
        "Maps to Stratus Red Team aws.execution.ssm-start-session."
    )
    category = "execution"
    required_permissions = [
        "ssm:DescribeInstanceInformation",
        "ssm:StartSession",
        "ec2:DescribeInstances",
    ]
    cloudtrail_events = [
        "DescribeInstanceInformation",
        "StartSession",
        "DescribeInstances",
    ]
    mitre_attack = ["T1021.007"]
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
                "Check for ssm:StartSession permission and enumerate SSM-managed instances."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=[
                "Run dry-run to check ssm:StartSession permission "
                "and enumerate SSM-managed instances."
            ],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate SSM-managed instances and assess StartSession risk."""
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
            actions=["ssm:StartSession"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        start_session_perm: bool | None = perm_results.get("ssm:StartSession")

        # Enumerate SSM-managed instances
        ssm_instances: list[dict] = []
        try:
            paginator = ssm.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                for info in page.get("InstanceInformationList", []):
                    ssm_instances.append({
                        "instance_id": info.get("InstanceId", ""),
                        "ping_status": info.get("PingStatus", "unknown"),
                        "platform_type": info.get("PlatformType", "unknown"),
                        "platform_name": info.get("PlatformName", ""),
                        "agent_version": info.get("AgentVersion", ""),
                    })
            api_calls.append("ssm:DescribeInstanceInformation")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ssm:DescribeInstanceInformation failed: {code}")

        # Enumerate EC2 instances to enrich with tags
        ec2_tag_map: dict[str, dict] = {}
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        iid = inst["InstanceId"]
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        name = tags.get("Name", "")
                        is_attacklab = tags.get("AttackLab", "").lower() == "true"
                        ec2_tag_map[iid] = {
                            "name": name,
                            "is_attacklab": is_attacklab,
                            "tags": tags,
                        }
            api_calls.append("ec2:DescribeInstances")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ec2:DescribeInstances failed: {code}")

        # Permission finding
        n = len(ssm_instances)
        if start_session_perm is True:
            findings.append(
                f"[CRITICAL] Principal has ssm:StartSession — can open interactive shell "
                f"sessions on {n} SSM-managed instance(s) without SSH keys or network access"
            )
        elif start_session_perm is None:
            findings.append(
                "[UNKNOWN] ssm:StartSession permission could not be determined — "
                "treat as potential risk."
            )

        findings.append(
            "Note: StartSession bypasses security groups, NACLs, and bastion hosts — "
            "direct shell access via SSM tunneling."
        )

        # List instances with enrichment
        attacklab_count = 0
        for inst in ssm_instances:
            iid = inst["instance_id"]
            ping = inst["ping_status"]
            platform = inst["platform_type"]
            ec2_info = ec2_tag_map.get(iid, {})
            name = ec2_info.get("name", "")
            is_attacklab = ec2_info.get("is_attacklab", False)

            if is_attacklab:
                attacklab_count += 1
                label = " [AttackLab]"
            else:
                label = ""

            findings.append(
                f"  SSM instance: '{iid}'{label} | name={name!r} | "
                f"platform={platform} | ping={ping}"
            )

        if attacklab_count:
            findings.append(
                f"AttackLab-tagged instances among SSM targets: {attacklab_count}"
            )

        detections = [
            "CloudTrail: ssm:StartSession events",
            "SSM Session Manager logs (if enabled): full session transcript",
            "GuardDuty: no specific finding for SSM sessions",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"StartSession permission: "
                f"{'confirmed' if start_session_perm is True else 'unknown' if start_session_perm is None else 'denied'}. "
                f"SSM-managed instances found: {n}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,  # dry-run only module
            errors=errors,
            metadata={
                "ssm_managed_instance_ids": [i["instance_id"] for i in ssm_instances],
                "ssm_managed_count": n,
                "attacklab_ssm_count": attacklab_count,
                "start_session_permission": start_session_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "ssm_start_session is dry-run only. "
            "Interactive shell sessions cannot be safely automated — "
            "use the AWS console or CLI to initiate sessions manually."
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


MODULE = SSMStartSessionModule()
