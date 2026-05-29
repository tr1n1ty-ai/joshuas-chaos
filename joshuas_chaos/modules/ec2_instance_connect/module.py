"""EC2 Instance Connect Module.

Simulate EC2 Instance Connect lateral movement by pushing a temporary SSH public key
to AttackLab-tagged EC2 instances. The key is ephemeral (60s TTL) and never used.

Maps to Stratus Red Team aws.lateral-movement.ec2-instance-connect.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

# Valid RSA public key for testing — never used to establish a connection.
# Key is ephemeral: EC2 Instance Connect auto-expires keys after 60 seconds.
_TEST_SSH_PUBLIC_KEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2a7PUE9GpFf3aBLrzA3p1bqH3OvHLfGIq"
    "JN0Jp/s7mJOLh9CwFJP7a9fYFzMSm2bT5UJxaO6uGQ9mEVcAF8QjO0Bv/wHZpDlb5oJQ2R"
    "vTNLfMRkdI1wG7TBjEKCHt2s8pXrD6OhNvFqM0l4iKMZoW3vfXkBGz3IZ1G9Hc0JQMo3Xp"
    "YG2nKTzDsP4M8UNLjPWdR6b1v0pBKYGzJbWkQlM2HrFfYUv6WlKdMXhZr5bVL4Qp9CIoTN"
    "XlBZGQNpRB0VbOUJvM3cxY8hRpKFAQbNZL2gTdWQ9OXiEM4vJ7LnCb6ZrFoY2xH8fPeQMXl"
    "tWIJGT5B8qK3HoVzE2J0mN9RfDsU1YPbGQK6wOX4iLRIE1vRcJoMH9TzNPlKlW0sFXBDkQ"
    "Pj3GsL8= attacklab-test-key"
)


class EC2InstanceConnectModule(ChaosModule):
    name = "ec2_instance_connect"
    description = (
        "Simulate EC2 Instance Connect lateral movement by pushing a temporary SSH public key "
        "to AttackLab-tagged EC2 instances. The key is ephemeral (60s TTL) and never used. "
        "Maps to Stratus Red Team aws.lateral-movement.ec2-instance-connect."
    )
    category = "lateral-movement"
    required_permissions = [
        "ec2:DescribeInstances",
        "ec2-instance-connect:SendSSHPublicKey",
    ]
    cloudtrail_events = [
        "DescribeInstances",
        "SendSSHPublicKey",
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
                "Check for ec2-instance-connect:SendSSHPublicKey permission "
                "and enumerate running AttackLab EC2 instances."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=[
                "Run dry-run to check ec2-instance-connect:SendSSHPublicKey permission "
                "and enumerate running AttackLab instances."
            ],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate running AttackLab instances and assess EC2 Instance Connect risk."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check ec2-instance-connect:SendSSHPublicKey permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2-instance-connect:SendSSHPublicKey"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        send_key_perm: bool | None = perm_results.get("ec2-instance-connect:SendSSHPublicKey")

        if send_key_perm is True:
            findings.append(
                "[RISK] Principal has ec2-instance-connect:SendSSHPublicKey permission."
            )
        elif send_key_perm is None:
            findings.append(
                "[UNKNOWN] ec2-instance-connect:SendSSHPublicKey permission could not be "
                "determined — treat as potential risk."
            )

        # Enumerate AttackLab-tagged running instances
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
                                "az": inst.get("Placement", {}).get("AvailabilityZone", ""),
                                "tags": tags,
                            })
            api_calls.append("ec2:DescribeInstances")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ec2:DescribeInstances failed: {code}")

        n = len(running_attacklab)
        findings.append(f"Running AttackLab EC2 instances found: {n}")

        findings.append(
            f"[DRY-RUN] Would push ephemeral SSH public key to {n} running AttackLab "
            "instances via ec2-instance-connect:SendSSHPublicKey (60s TTL, key never used)"
        )
        findings.append(
            "Note: EC2 Instance Connect bypasses permanent SSH key management — "
            "key auto-expires after 60 seconds."
        )

        detections = [
            "CloudTrail: ec2-instance-connect:SendSSHPublicKey",
            "VPC Flow Logs: subsequent SSH connection on port 22",
            "GuardDuty: UnauthorizedAccess:EC2/SSHBruteForce (if connection attempted)",
            "AWS Config: ec2-instance-connect audit via CloudTrail",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"SendSSHPublicKey permission: "
                f"{'confirmed' if send_key_perm is True else 'unknown' if send_key_perm is None else 'denied'}. "
                f"Running AttackLab instances found: {n}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a is True],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={
                "running_attacklab_instance_ids": [i["instance_id"] for i in running_attacklab],
                "running_attacklab_count": n,
                "send_ssh_public_key_permission": send_key_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Push a throwaway SSH public key to running AttackLab instances via EC2 Instance Connect."""
        identity = context.get_caller_identity()
        safety = SafetyChecker(config, identity)
        safety.assert_account_allowed()
        safety.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        eic = context.get_client("ec2-instance-connect")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []
        pushed_instance_ids: list[str] = []

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
                                "az": inst.get("Placement", {}).get("AvailabilityZone", ""),
                                "tags": tags,
                            })
            api_calls.append("ec2:DescribeInstances")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ec2:DescribeInstances failed: {code}")

        if not running_attacklab:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No running AttackLab instances found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No running AttackLab-tagged EC2 instances found."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=errors,
            )

        for inst in running_attacklab:
            instance_id = inst["instance_id"]
            az = inst["az"]
            tags = inst["tags"]
            instance_name = tags.get("Name", instance_id)

            # Per-resource safety check — skip on SafetyError
            try:
                safety.assert_resource_safe(instance_name, tags)
            except SafetyError as exc:
                findings.append(
                    f"[SKIPPED] '{instance_id}' (name={instance_name!r}): {exc}"
                )
                continue

            try:
                eic.send_ssh_public_key(
                    InstanceId=instance_id,
                    InstanceOSUser="ec2-user",
                    SSHPublicKey=_TEST_SSH_PUBLIC_KEY,
                    AvailabilityZone=az,
                )
                api_calls.append(f"ec2-instance-connect:SendSSHPublicKey ({instance_id})")
                pushed_instance_ids.append(instance_id)
                findings.append(
                    f"[EXECUTE] Pushed ephemeral SSH public key to '{instance_id}' "
                    f"(az={az}, os_user=ec2-user). Key expires in 60 seconds and was "
                    "never used to establish a connection."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(
                    f"ec2-instance-connect:SendSSHPublicKey failed for '{instance_id}': {code}"
                )

        findings.append(
            f"EC2 Instance Connect keys pushed to {len(pushed_instance_ids)} instance(s). "
            "Keys expire automatically after 60 seconds — no cleanup required."
        )

        detections = [
            "CloudTrail: ec2-instance-connect:SendSSHPublicKey",
            "VPC Flow Logs: subsequent SSH connection on port 22",
            "GuardDuty: UnauthorizedAccess:EC2/SSHBruteForce (if connection attempted)",
            "AWS Config: ec2-instance-connect audit via CloudTrail",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Pushed ephemeral SSH public key to {len(pushed_instance_ids)} instance(s) "
                "via EC2 Instance Connect. Keys expire in 60 seconds and were never used."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ec2-instance-connect:SendSSHPublicKey"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={
                "pushed_instance_ids": pushed_instance_ids,
                "key_ttl_seconds": 60,
            },
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """No-op: EC2 Instance Connect keys expire automatically after 60 seconds."""
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — EC2 Instance Connect keys expire automatically after 60 seconds.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=[
                "No cleanup required — EC2 Instance Connect keys expire automatically after 60 seconds."
            ],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = EC2InstanceConnectModule()
