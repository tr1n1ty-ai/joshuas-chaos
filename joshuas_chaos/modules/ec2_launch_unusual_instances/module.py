"""EC2 Launch Unusual Instances Module.

Simulate launching unusual EC2 instance types (large GPU/compute) that attackers use
for crypto-mining or ML workloads.  Execute phase launches a single t3.micro (NOT the
GPU types used in real attacks) tagged AttackLab=true in an AttackLab-tagged subnet.

Maps to Stratus Red Team aws.execution.ec2-launch-unusual-instances.
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

_INSTANCE_TYPE = "t3.micro"  # Lab safety — real Stratus uses p2.xlarge (GPU)
_INSTANCE_NAME = "AttackLabUnusualInstanceTest"
_USER_DATA_SCRIPT = "#!/bin/bash\necho AttackLab unusual instance test"


class EC2LaunchUnusualInstancesModule(ChaosModule):
    name = "ec2_launch_unusual_instances"
    description = (
        "Simulate launching unusual EC2 instance types (large GPU/compute instances) "
        "that attackers use for crypto-mining or ML workloads. "
        "Execute launches a single t3.micro tagged AttackLab=true in an AttackLab-tagged subnet. "
        "Maps to Stratus Red Team aws.execution.ec2-launch-unusual-instances."
    )
    category = "execution"
    required_permissions = [
        "ec2:RunInstances",
        "ec2:DescribeInstances",
        "ec2:DescribeSubnets",
        "ec2:TerminateInstances",
    ]
    cloudtrail_events = ["RunInstances", "DescribeInstances", "TerminateInstances"]
    mitre_attack = ["T1578.002"]
    destructive = False
    reversible = True

    _launched_instance_ids: list[str]

    def __init__(self) -> None:
        self._launched_instance_ids = []

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for ec2:RunInstances permission and AttackLab-tagged subnets.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to check RunInstances permission and enumerate lab subnets."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _get_attacklab_subnets(self, ec2) -> list[dict]:
        """Return subnets tagged AttackLab=true."""
        subnets: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_subnets")
            for page in paginator.paginate(
                Filters=[{"Name": "tag:AttackLab", "Values": ["true"]}]
            ):
                for subnet in page.get("Subnets", []):
                    subnets.append({
                        "subnet_id": subnet["SubnetId"],
                        "vpc_id": subnet.get("VpcId", "unknown"),
                        "availability_zone": subnet.get("AvailabilityZone", "unknown"),
                    })
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ec2:DescribeSubnets failed: %s", code)
        return subnets

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check RunInstances permission and enumerate AttackLab subnets."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2:RunInstances"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        run_perm: bool | None = perm_results.get("ec2:RunInstances")

        if run_perm is True:
            findings.append(
                "[RISK] Principal has ec2:RunInstances — can launch arbitrary instance types "
                "including GPU instances used for crypto-mining (p3, p4, g4) or large compute "
                "(c5n, hpc6a)"
            )
        elif run_perm is None:
            findings.append(
                "[UNKNOWN] ec2:RunInstances permission could not be determined — "
                "treat as potential risk."
            )

        # Find AttackLab-tagged subnets
        subnets = self._get_attacklab_subnets(ec2)
        api_calls.append("ec2:DescribeSubnets")

        if subnets:
            findings.append(
                f"AttackLab-tagged subnets available for execute mode: "
                f"{[s['subnet_id'] for s in subnets]}"
            )
        else:
            findings.append(
                "No AttackLab-tagged subnets found — execute mode will require a subnet "
                "tagged AttackLab=true."
            )

        findings.append(
            f"[DRY-RUN] Would launch a single {_INSTANCE_TYPE} tagged AttackLab=true "
            "in an AttackLab subnet"
        )
        findings.append(
            "Note: real Stratus technique launches p2.xlarge (GPU) — this framework uses "
            f"{_INSTANCE_TYPE} for lab safety."
        )

        detections = [
            "CloudTrail: RunInstances with unusual instance types",
            "GuardDuty: CryptoCurrency:EC2/BitcoinTool.B or Execution:EC2/SuspiciousCommand",
            "Cost anomaly detection: sudden spike in EC2 spend",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"RunInstances permission: "
                f"{'confirmed' if run_perm is True else 'unknown' if run_perm is None else 'denied'}. "
                f"AttackLab subnets found: {len(subnets)}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(subnets),
            errors=errors,
            metadata={
                "attacklab_subnet_ids": [s["subnet_id"] for s in subnets],
                "run_instances_permission": run_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Launch a single t3.micro in an AttackLab-tagged subnet."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        subnets = self._get_attacklab_subnets(ec2)
        api_calls.append("ec2:DescribeSubnets")

        if not subnets:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab-tagged subnet found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=[
                    "No AttackLab-tagged subnet found. "
                    "Create a subnet tagged AttackLab=true to use this module."
                ],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        subnet_id = subnets[0]["subnet_id"]
        user_data_b64 = base64.b64encode(_USER_DATA_SCRIPT.encode()).decode()

        try:
            resp = ec2.run_instances(
                ImageId="resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2",
                InstanceType=_INSTANCE_TYPE,
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                UserData=user_data_b64,
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "AttackLab", "Value": "true"},
                            {"Key": "Name", "Value": _INSTANCE_NAME},
                        ],
                    }
                ],
                # No key pair — SSM access only
                MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            )
            api_calls.append("ec2:RunInstances")
            instances = resp.get("Instances", [])
            for inst in instances:
                iid = inst["InstanceId"]
                self._launched_instance_ids.append(iid)
                findings.append(
                    f"[EXECUTE] Launched {_INSTANCE_TYPE} instance '{iid}' "
                    f"in subnet '{subnet_id}' tagged AttackLab=true, Name={_INSTANCE_NAME}."
                )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ec2:RunInstances failed: {code}")

        detections = [
            "CloudTrail: RunInstances with unusual instance types",
            "GuardDuty: CryptoCurrency:EC2/BitcoinTool.B or Execution:EC2/SuspiciousCommand",
            "Cost anomaly detection: sudden spike in EC2 spend",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Launched {len(self._launched_instance_ids)} {_INSTANCE_TYPE} instance(s) "
                "tagged AttackLab=true."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ec2:RunInstances"] if self._launched_instance_ids else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=bool(self._launched_instance_ids),
            safe_to_execute=True,
            errors=errors,
            metadata={"launched_instance_ids": list(self._launched_instance_ids)},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Terminate AttackLabUnusualInstanceTest instances. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Find instances tagged Name=AttackLabUnusualInstanceTest that are not terminated
        target_ids: list[str] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[
                    {"Name": "tag:Name", "Values": [_INSTANCE_NAME]},
                    {
                        "Name": "instance-state-name",
                        "Values": ["pending", "running", "stopping", "stopped"],
                    },
                ]
            ):
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        target_ids.append(inst["InstanceId"])
            api_calls.append("ec2:DescribeInstances")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ec2:DescribeInstances failed: {code}")

        if not target_ids:
            findings.append(
                f"No non-terminated instances with Name={_INSTANCE_NAME} found — "
                "already terminated (idempotent)."
            )
            self._launched_instance_ids = []
            return ModuleResult(
                module=self.name,
                mode="cleanup",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No instances to terminate — already cleaned up.",
                required_permissions=["ec2:TerminateInstances"],
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=True,
                errors=errors,
            )

        try:
            ec2.terminate_instances(InstanceIds=target_ids)
            api_calls.append(f"ec2:TerminateInstances ({target_ids})")
            findings.append(f"[CLEANUP] Terminated instances: {target_ids}")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "InvalidInstanceID.NotFound":
                findings.append("Instances not found — already terminated (idempotent).")
            else:
                errors.append(f"ec2:TerminateInstances failed: {code}")

        self._launched_instance_ids = []

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Terminated {len(target_ids)} AttackLab instance(s).",
            required_permissions=["ec2:TerminateInstances"],
            observed_permissions=["ec2:TerminateInstances"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = EC2LaunchUnusualInstancesModule()
