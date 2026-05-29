"""RDS Share Snapshot Module.

Simulate RDS snapshot exfiltration by making AttackLab-tagged DB snapshots public.
Maps to Stratus Red Team aws.exfiltration.rds-share-snapshot.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class RDSShareSnapshotModule(ChaosModule):
    name = "rds_share_snapshot"
    description = (
        "Simulate RDS snapshot exfiltration by making AttackLab-tagged DB snapshots public. "
        "Execute calls rds:ModifyDBSnapshotAttribute to add 'all' attribute. "
        "Maps to Stratus Red Team aws.exfiltration.rds-share-snapshot."
    )
    category = "exfiltration"
    required_permissions = [
        "rds:DescribeDBSnapshots",
        "rds:ModifyDBSnapshotAttribute",
        "rds:DescribeDBSnapshotAttributes",
    ]
    cloudtrail_events = [
        "DescribeDBSnapshots",
        "ModifyDBSnapshotAttribute",
    ]
    mitre_attack = ["T1537"]
    destructive = False
    reversible = True

    def _get_attacklab_db_snapshots(self, rds) -> tuple[list[dict], list[dict]]:
        """Return (all_manual_snapshots, attacklab_snapshots)."""
        all_snapshots: list[dict] = []
        attacklab_snapshots: list[dict] = []
        try:
            paginator = rds.get_paginator("describe_db_snapshots")
            for page in paginator.paginate(SnapshotType="manual"):
                for snap in page.get("DBSnapshots", []):
                    snap_id = snap["DBSnapshotIdentifier"]
                    tags = {t["Key"]: t["Value"] for t in snap.get("TagList", [])}
                    all_snapshots.append({"snapshot_id": snap_id, "tags": tags})
                    if tags.get("AttackLab", "").lower() == "true":
                        attacklab_snapshots.append({"snapshot_id": snap_id, "tags": tags})
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("rds:DescribeDBSnapshots failed: %s", code)
        return all_snapshots, attacklab_snapshots

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check RDS DB snapshot attribute modification permissions.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess RDS snapshot sharing exfiltration risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check permissions and enumerate AttackLab-tagged RDS snapshots."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        rds = context.get_client("rds")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["rds:ModifyDBSnapshotAttribute"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("rds:ModifyDBSnapshotAttribute") is True:
            findings.append("[RISK] Principal has rds:ModifyDBSnapshotAttribute permission.")

        all_snapshots, attacklab_snapshots = self._get_attacklab_db_snapshots(rds)
        api_calls.append("rds:DescribeDBSnapshots")

        n_total = len(all_snapshots)
        n_attacklab = len(attacklab_snapshots)
        findings.append(f"Total manual RDS snapshots: {n_total}")
        findings.append(f"AttackLab-tagged RDS snapshots: {n_attacklab}")
        findings.append(
            f"[DRY-RUN] Would share {n_attacklab} AttackLab snapshots publicly "
            "via rds:ModifyDBSnapshotAttribute"
        )

        detections = [
            "CloudTrail: rds:ModifyDBSnapshotAttribute with restore=all",
            "GuardDuty: Policy:RDS/DBSnapshotPublic",
            "AWS Config: rds-snapshot-public rule",
            "Security Hub: RDS.1 — RDS snapshot not public",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {n_total} manual RDS snapshot(s), {n_attacklab} AttackLab-tagged. "
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
        """Make AttackLab-tagged RDS snapshots publicly restorable."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        rds = context.get_client("rds")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_snapshots, attacklab_snapshots = self._get_attacklab_db_snapshots(rds)
        api_calls.append("rds:DescribeDBSnapshots")

        modified: list[str] = []
        for snap in attacklab_snapshots:
            snap_id = snap["snapshot_id"]
            tags = snap["tags"]

            try:
                checker.assert_resource_safe(snap_id, tags)
            except SafetyError as exc:
                errors.append(f"Resource safety check failed for '{snap_id}': {exc}")
                continue

            try:
                rds.modify_db_snapshot_attribute(
                    DBSnapshotIdentifier=snap_id,
                    AttributeName="restore",
                    ValuesToAdd=["all"],
                )
                api_calls.append(f"rds:ModifyDBSnapshotAttribute ({snap_id})")
                findings.append(
                    f"[EXECUTE] Made RDS snapshot '{snap_id}' publicly restorable "
                    "via AttributeName=restore ValuesToAdd=['all']."
                )
                modified.append(snap_id)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"rds:ModifyDBSnapshotAttribute failed for '{snap_id}': {code}")

        detections = [
            "CloudTrail: rds:ModifyDBSnapshotAttribute with restore=all",
            "GuardDuty: Policy:RDS/DBSnapshotPublic",
            "AWS Config: rds-snapshot-public rule",
            "Security Hub: RDS.1 — RDS snapshot not public",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Made {len(modified)} AttackLab RDS snapshot(s) publicly restorable.",
            required_permissions=self.required_permissions,
            observed_permissions=["rds:ModifyDBSnapshotAttribute"],
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
        """Remove public restore attribute from AttackLab RDS snapshots. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        rds = context.get_client("rds")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_snapshots, attacklab_snapshots = self._get_attacklab_db_snapshots(rds)
        api_calls.append("rds:DescribeDBSnapshots")

        for snap in attacklab_snapshots:
            snap_id = snap["snapshot_id"]

            try:
                rds.modify_db_snapshot_attribute(
                    DBSnapshotIdentifier=snap_id,
                    AttributeName="restore",
                    ValuesToRemove=["all"],
                )
                api_calls.append(f"rds:ModifyDBSnapshotAttribute ({snap_id})")
                findings.append(
                    f"[CLEANUP] Removed public restore attribute from RDS snapshot '{snap_id}'."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "DBSnapshotNotFound":
                    findings.append(
                        f"RDS snapshot '{snap_id}' not found — "
                        "already removed or deleted (idempotent)."
                    )
                else:
                    errors.append(
                        f"rds:ModifyDBSnapshotAttribute cleanup failed for '{snap_id}': {code}"
                    )

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Removed public restore attribute from AttackLab RDS snapshots.",
            required_permissions=["rds:DescribeDBSnapshots", "rds:ModifyDBSnapshotAttribute"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = RDSShareSnapshotModule()
