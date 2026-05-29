"""VPC Remove Flow Logs Module.

Dry-run ONLY: Detect if principal can delete VPC Flow Logs.
Maps to Stratus Red Team aws.defense-evasion.vpc-remove-flow-logs.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class VPCRemoveFlowLogsModule(ChaosModule):
    name = "vpc_remove_flow_logs"
    description = (
        "Detect if principal can delete VPC Flow Logs. "
        "Dry-run only. Maps to Stratus Red Team aws.defense-evasion.vpc-remove-flow-logs."
    )
    category = "defense-evasion"
    required_permissions = [
        "ec2:DescribeFlowLogs",
        "ec2:DeleteFlowLogs",
    ]
    cloudtrail_events = ["DescribeFlowLogs", "DeleteFlowLogs"]
    mitre_attack = ["T1562.008"]
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
            risk_summary="Read-only check for VPC Flow Log deletion capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate VPC flow logs and check delete permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check DeleteFlowLogs permission and enumerate all VPC flow logs."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check DeleteFlowLogs permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2:DeleteFlowLogs"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        delete_perm: bool | None = perm_results.get("ec2:DeleteFlowLogs")

        # Enumerate all flow logs via paginator
        flow_logs: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_flow_logs")
            for page in paginator.paginate():
                api_calls.append("ec2:DescribeFlowLogs")
                flow_logs.extend(page.get("FlowLogs", []))
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("AccessDenied", "AccessDeniedException"):
                errors.append("ec2:DescribeFlowLogs — AccessDenied")
            else:
                errors.append(f"ec2:DescribeFlowLogs failed: {code}")

        active_count = 0
        for fl in flow_logs:
            fl_id = fl.get("FlowLogId", "unknown")
            resource_id = fl.get("ResourceId", "unknown")
            dest_type = fl.get("LogDestinationType", "unknown")
            log_status = fl.get("FlowLogStatus", "unknown")
            deliver_status = fl.get("DeliverLogsStatus", "unknown")

            if log_status == "ACTIVE":
                active_count += 1

            findings.append(
                f"FlowLog: '{fl_id}' | Resource: {resource_id} | "
                f"Destination: {dest_type} | Status: {log_status} | "
                f"DeliverStatus: {deliver_status}"
            )

        findings.append(f"Total VPC flow logs: {len(flow_logs)}")
        findings.append(f"Active flow logs: {active_count}")

        if delete_perm is True:
            findings.append(
                f"[CRITICAL] Principal can delete {len(flow_logs)} VPC flow log(s) — "
                "removes network traffic visibility"
            )
        elif delete_perm is None:
            findings.append(
                "[UNKNOWN] ec2:DeleteFlowLogs permission could not be determined"
            )

        detections = [
            "CloudTrail: DeleteFlowLogs event",
            "AWS Config: vpc-flow-logs-enabled rule",
            "Security Hub: [EC2.6] VPC flow logging should be enabled for all VPCs",
            "GuardDuty: network anomaly detections (reduced baseline after log deletion)",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(flow_logs)} VPC flow log(s) ({active_count} active). "
                f"DeleteFlowLogs permission: "
                f"{'confirmed' if delete_perm is True else 'unknown' if delete_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ec2:DeleteFlowLogs"] if delete_perm is True else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "flow_log_count": len(flow_logs),
                "active_count": active_count,
                "delete_permission": delete_perm,
                "flow_log_ids": [fl.get("FlowLogId") for fl in flow_logs],
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "vpc_remove_flow_logs is dry-run only. "
            "Deleting VPC Flow Logs is prohibited by the safety policy of this framework."
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


MODULE = VPCRemoveFlowLogsModule()
