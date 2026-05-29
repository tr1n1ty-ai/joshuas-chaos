"""EC2 Share EBS Snapshot Module.

Simulate EBS snapshot exfiltration by making AttackLab-tagged snapshots public.
Maps to Stratus Red Team aws.exfiltration.ec2-share-ebs-snapshot.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class EC2ShareEBSSnapshotModule(ChaosModule):
    name = "ec2_share_ebs_snapshot"
    description = (
        "Simulate EBS snapshot exfiltration by making AttackLab-tagged snapshots public. "
        "Execute calls ec2:ModifySnapshotAttribute to add 'all' group to createVolumePermission. "
        "Maps to Stratus Red Team aws.exfiltration.ec2-share-ebs-snapshot."
    )
    category = "exfiltration"
    required_permissions = [
        "ec2:DescribeSnapshots",
        "ec2:ModifySnapshotAttribute",
    ]
    cloudtrail_events = [
        "DescribeSnapshots",
        "ModifySnapshotAttribute",
    ]
    mitre_attack = ["T1537"]
    destructive = False
    reversible = True

    def _get_attacklab_snapshots(self, ec2) -> tuple[list[dict], list[dict]]:
        """Return (all_snapshots, attacklab_snapshots) owned by self."""
        all_snapshots: list[dict] = []
        attacklab_snapshots: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snap in page.get("Snapshots", []):
                    snap_id = snap["SnapshotId"]
                    description = snap.get("Description", snap_id)
                    tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
                    all_snapshots.append(
                        {"snapshot_id": snap_id, "description": description, "tags": tags}
                    )
                    if tags.get("AttackLab", "").lower() == "true":
                        attacklab_snapshots.append(
                            {"snapshot_id": snap_id, "description": description, "tags": tags}
                        )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ec2:DescribeSnapshots failed: %s", code)
        return all_snapshots, attacklab_snapshots

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check EBS snapshot attribute modification permissions.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess EBS snapshot sharing exfiltration risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check permissions and enumerate AttackLab-tagged EBS snapshots."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2:ModifySnapshotAttribute"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("ec2:ModifySnapshotAttribute") is True:
            findings.append("[RISK] Principal has ec2:ModifySnapshotAttribute permission.")

        all_snapshots, attacklab_snapshots = self._get_attacklab_snapshots(ec2)
        api_calls.append("ec2:DescribeSnapshots")

        n_total = len(all_snapshots)
        n_attacklab = len(attacklab_snapshots)
        findings.append(f"Total snapshots visible (owned by self): {n_total}")
        findings.append(f"AttackLab-tagged snapshots: {n_attacklab}")
        findings.append(
            f"[DRY-RUN] Would make {n_attacklab} AttackLab snapshots public "
            "via ModifySnapshotAttribute"
        )

        detections = [
            "CloudTrail: ec2:ModifySnapshotAttribute with Group=all",
            "AWS Config: ec2-snapshot-public rule",
            "GuardDuty: Policy:EC2/ExposedAccessKeys (similar pattern)",
            "Security Hub: AWS Foundational Security Best Practices EC2.1",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {n_total} total snapshot(s), {n_attacklab} AttackLab-tagged. "
                "No changes made."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a is True],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_snapshots),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Make AttackLab-tagged EBS snapshots public via createVolumePermission."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_snapshots, attacklab_snapshots = self._get_attacklab_snapshots(ec2)
        api_calls.append("ec2:DescribeSnapshots")

        modified: list[str] = []
        for snap in attacklab_snapshots:
            snap_id = snap["snapshot_id"]
            description = snap["description"]
            tags = snap["tags"]

            try:
                checker.assert_resource_safe(description, tags)
            except SafetyError as exc:
                errors.append(f"Resource safety check failed for '{snap_id}': {exc}")
                continue

            try:
                ec2.modify_snapshot_attribute(
                    SnapshotId=snap_id,
                    Attribute="createVolumePermission",
                    OperationType="add",
                    GroupNames=["all"],
                )
                api_calls.append(f"ec2:ModifySnapshotAttribute ({snap_id})")
                findings.append(
                    f"[EXECUTE] Made snapshot '{snap_id}' public via "
                    "createVolumePermission Group=all."
                )
                modified.append(snap_id)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"ec2:ModifySnapshotAttribute failed for '{snap_id}': {code}")

        detections = [
            "CloudTrail: ec2:ModifySnapshotAttribute with Group=all",
            "AWS Config: ec2-snapshot-public rule",
            "GuardDuty: Policy:EC2/ExposedAccessKeys (similar pattern)",
            "Security Hub: AWS Foundational Security Best Practices EC2.1",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Made {len(modified)} AttackLab EBS snapshot(s) public.",
            required_permissions=self.required_permissions,
            observed_permissions=["ec2:ModifySnapshotAttribute"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
            metadata={"modified_snapshot_ids": modified},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Remove public createVolumePermission from AttackLab snapshots. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_snapshots, attacklab_snapshots = self._get_attacklab_snapshots(ec2)
        api_calls.append("ec2:DescribeSnapshots")

        for snap in attacklab_snapshots:
            snap_id = snap["snapshot_id"]

            try:
                ec2.modify_snapshot_attribute(
                    SnapshotId=snap_id,
                    Attribute="createVolumePermission",
                    OperationType="remove",
                    GroupNames=["all"],
                )
                api_calls.append(f"ec2:ModifySnapshotAttribute ({snap_id})")
                findings.append(
                    f"[CLEANUP] Removed public createVolumePermission from snapshot '{snap_id}'."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "InvalidSnapshot.NotFound":
                    findings.append(
                        f"Snapshot '{snap_id}' not found — already removed or deleted (idempotent)."
                    )
                else:
                    errors.append(
                        f"ec2:ModifySnapshotAttribute cleanup failed for '{snap_id}': {code}"
                    )

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Removed public createVolumePermission from AttackLab snapshots.",
            required_permissions=["ec2:DescribeSnapshots", "ec2:ModifySnapshotAttribute"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = EC2ShareEBSSnapshotModule()
