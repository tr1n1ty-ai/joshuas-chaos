"""EC2 Security Group Open Port Module.

Simulate exfiltration by opening TCP 4444 (0.0.0.0/0) on AttackLab-tagged
security groups. Maps to Stratus Red Team aws.exfiltration.ec2-security-group-open-port.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_OPEN_PORT = 4444
_CIDR = "0.0.0.0/0"
_IP_PERMISSIONS = [
    {
        "IpProtocol": "tcp",
        "FromPort": _OPEN_PORT,
        "ToPort": _OPEN_PORT,
        "IpRanges": [{"CidrIp": _CIDR, "Description": "AttackLab exfil test"}],
    }
]


class EC2SecurityGroupOpenPortModule(ChaosModule):
    name = "ec2_security_group_open_port"
    description = (
        "Simulate EC2 security group exfiltration by adding an inbound rule that opens "
        "a high port (TCP 4444) to 0.0.0.0/0 on AttackLab-tagged security groups. "
        "Maps to Stratus Red Team aws.exfiltration.ec2-security-group-open-port."
    )
    category = "exfiltration"
    required_permissions = [
        "ec2:DescribeSecurityGroups",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
    ]
    cloudtrail_events = [
        "DescribeSecurityGroups",
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
    ]
    mitre_attack = ["T1048"]
    destructive = False
    reversible = True

    def _get_attacklab_security_groups(self, ec2) -> list[dict]:
        """Return security groups tagged AttackLab=true."""
        groups: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate(
                Filters=[{"Name": "tag:AttackLab", "Values": ["true"]}]
            ):
                for sg in page.get("SecurityGroups", []):
                    tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
                    groups.append({
                        "group_id": sg["GroupId"],
                        "group_name": sg.get("GroupName", sg["GroupId"]),
                        "tags": tags,
                    })
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ec2:DescribeSecurityGroups failed: %s", code)
        return groups

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check EC2 security group ingress rule modification permissions.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess security group open port exfiltration risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check permissions and count AttackLab-tagged security groups."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2:AuthorizeSecurityGroupIngress"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("ec2:AuthorizeSecurityGroupIngress") is True:
            findings.append("[RISK] Principal has ec2:AuthorizeSecurityGroupIngress permission.")

        groups = self._get_attacklab_security_groups(ec2)
        api_calls.append("ec2:DescribeSecurityGroups")

        n = len(groups)
        findings.append(f"AttackLab-tagged security groups found: {n}")
        findings.append(
            f"[DRY-RUN] Would add TCP {_OPEN_PORT} ingress rule ({_CIDR}) "
            f"to {n} AttackLab security groups"
        )

        detections = [
            "CloudTrail: ec2:AuthorizeSecurityGroupIngress with 0.0.0.0/0 source",
            "GuardDuty: Recon:EC2/PortProbeUnprotectedPort",
            "AWS Config: restricted-common-ports rule violation",
            "Security Hub: CIS AWS Foundations 4.1 — unrestricted inbound",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {n} AttackLab security group(s). No changes made.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a is True],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(groups),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Add TCP 4444 ingress rule to AttackLab-tagged security groups."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        groups = self._get_attacklab_security_groups(ec2)
        api_calls.append("ec2:DescribeSecurityGroups")

        modified: list[str] = []
        for sg in groups:
            group_id = sg["group_id"]
            group_name = sg["group_name"]
            tags = sg["tags"]

            try:
                checker.assert_resource_safe(group_name, tags)
            except SafetyError as exc:
                errors.append(f"Resource safety check failed for '{group_name}': {exc}")
                continue

            try:
                ec2.authorize_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=_IP_PERMISSIONS,
                )
                api_calls.append(f"ec2:AuthorizeSecurityGroupIngress ({group_id})")
                findings.append(
                    f"[EXECUTE] Added TCP {_OPEN_PORT} ingress rule ({_CIDR}) "
                    f"to security group '{group_id}' ({group_name})."
                )
                modified.append(group_id)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "InvalidPermission.Duplicate":
                    findings.append(
                        f"TCP {_OPEN_PORT} ingress rule already exists on '{group_id}' — "
                        "already present (idempotent)."
                    )
                    modified.append(group_id)
                else:
                    errors.append(
                        f"ec2:AuthorizeSecurityGroupIngress failed for '{group_id}': {code}"
                    )

        detections = [
            "CloudTrail: ec2:AuthorizeSecurityGroupIngress with 0.0.0.0/0 source",
            "GuardDuty: Recon:EC2/PortProbeUnprotectedPort",
            "AWS Config: restricted-common-ports rule violation",
            "Security Hub: CIS AWS Foundations 4.1 — unrestricted inbound",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Added TCP {_OPEN_PORT} ingress rule to {len(modified)} security group(s)."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ec2:AuthorizeSecurityGroupIngress"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
            metadata={"modified_group_ids": modified},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Revoke the TCP 4444 ingress rule from AttackLab security groups. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        groups = self._get_attacklab_security_groups(ec2)
        api_calls.append("ec2:DescribeSecurityGroups")

        for sg in groups:
            group_id = sg["group_id"]
            group_name = sg["group_name"]

            try:
                ec2.revoke_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=_IP_PERMISSIONS,
                )
                api_calls.append(f"ec2:RevokeSecurityGroupIngress ({group_id})")
                findings.append(
                    f"[CLEANUP] Revoked TCP {_OPEN_PORT} ingress rule from "
                    f"security group '{group_id}' ({group_name})."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "InvalidPermission.NotFound":
                    findings.append(
                        f"TCP {_OPEN_PORT} ingress rule not found on '{group_id}' — "
                        "already removed (idempotent)."
                    )
                else:
                    errors.append(
                        f"ec2:RevokeSecurityGroupIngress failed for '{group_id}': {code}"
                    )

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Revoked TCP 4444 ingress rules from AttackLab security groups.",
            required_permissions=["ec2:DescribeSecurityGroups", "ec2:RevokeSecurityGroupIngress"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = EC2SecurityGroupOpenPortModule()
