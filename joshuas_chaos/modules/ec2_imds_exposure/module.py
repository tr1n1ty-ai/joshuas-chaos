"""EC2 IMDS Exposure Module.

Dry-run ONLY.
Check EC2 instance metadata options using describe_instances paginator.
Report instances where HttpTokens is 'optional' (IMDSv1 enabled).
Does NOT query IMDS credentials.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class EC2IMDSExposureModule(ChaosModule):
    name = "ec2_imds_exposure"
    description = (
        "Check EC2 instances for IMDSv1 exposure (HttpTokens=optional). "
        "Dry-run only — does NOT query IMDS or credentials."
    )
    category = "credential-access"
    required_permissions = [
        "ec2:DescribeInstances",
    ]
    cloudtrail_events = [
        "DescribeInstances",
    ]
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
            risk_summary="Read-only check of EC2 instance IMDS configuration.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to check for IMDSv1-enabled instances."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,  # dry-run only
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate EC2 instances and flag those with IMDSv1 enabled."""
        identity = context.get_caller_identity()
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        imdsv1_instances: list[dict] = []
        imdsv2_instances: list[dict] = []
        total = 0

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                api_calls.append("ec2:DescribeInstances")
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        total += 1
                        instance_id = inst["InstanceId"]
                        state = inst.get("State", {}).get("Name", "unknown")
                        meta_opts = inst.get("MetadataOptions", {})
                        http_tokens = meta_opts.get("HttpTokens", "optional")
                        imds_state = meta_opts.get("State", "unknown")

                        entry = {
                            "instance_id": instance_id,
                            "state": state,
                            "http_tokens": http_tokens,
                            "imds_state": imds_state,
                        }

                        if http_tokens == "optional":
                            imdsv1_instances.append(entry)
                        else:
                            imdsv2_instances.append(entry)

        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "AccessDenied":
                errors.append("ec2:DescribeInstances — AccessDenied.")
            else:
                errors.append(f"ec2:DescribeInstances failed: {code}")

        findings.append(f"Total EC2 instances examined: {total}")
        findings.append(f"IMDSv1-enabled (HttpTokens=optional): {len(imdsv1_instances)}")
        findings.append(f"IMDSv2-required (HttpTokens=required): {len(imdsv2_instances)}")

        for inst in imdsv1_instances:
            findings.append(
                f"[FINDING] Instance '{inst['instance_id']}' (state={inst['state']}) "
                "has IMDSv1 ENABLED — credentials accessible without token."
            )

        if not imdsv1_instances:
            findings.append("All visible instances are configured for IMDSv2 only.")

        detections = [
            "CloudTrail: DescribeInstances enumeration from unexpected principal",
            "AWS Config: ec2-imdsv2-check rule (flags optional instances)",
            "Security Hub: [EC2.8] EC2 instances should use IMDSv2",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"{len(imdsv1_instances)} instance(s) with IMDSv1 enabled (SSRF risk)."
                if imdsv1_instances
                else "No IMDSv1 instances found."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,  # dry-run only module
            errors=errors,
            metadata={
                "imdsv1_instances": [i["instance_id"] for i in imdsv1_instances],
                "imdsv2_instances": [i["instance_id"] for i in imdsv2_instances],
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "ec2_imds_exposure is a dry-run only module. "
            "It does not query IMDS endpoints or retrieve credentials."
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — module makes no changes.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["No state created by this module."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = EC2IMDSExposureModule()
