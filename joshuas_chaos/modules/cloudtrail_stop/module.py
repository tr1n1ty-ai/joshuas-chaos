"""CloudTrail Stop Module.

Dry-run ONLY: Detect if principal has cloudtrail:StopLogging permission.
Maps to Stratus Red Team aws.defense-evasion.cloudtrail-stop.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class CloudTrailStopModule(ChaosModule):
    name = "cloudtrail_stop"
    description = (
        "Detect if principal has cloudtrail:StopLogging permission. "
        "Dry-run only. Maps to Stratus Red Team aws.defense-evasion.cloudtrail-stop."
    )
    category = "defense-evasion"
    required_permissions = [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:StopLogging",
    ]
    cloudtrail_events = ["DescribeTrails", "GetTrailStatus", "StopLogging"]
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
            risk_summary="Read-only check for CloudTrail stop logging capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate trails and check StopLogging permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check StopLogging permission and enumerate trail logging status."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ct = context.get_client("cloudtrail")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check StopLogging permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["cloudtrail:StopLogging"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        stop_perm: bool | None = perm_results.get("cloudtrail:StopLogging")

        if stop_perm is True:
            findings.append(
                "[CRITICAL] Principal has cloudtrail:StopLogging — can halt all CloudTrail logging"
            )
        elif stop_perm is None:
            findings.append(
                "[UNKNOWN] cloudtrail:StopLogging permission could not be determined"
            )

        # Enumerate trails in current region
        trails: list[dict] = []
        try:
            resp = ct.describe_trails(includeShadowTrails=False)
            api_calls.append("cloudtrail:DescribeTrails")
            trails = resp.get("trailList", [])
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"cloudtrail:DescribeTrails failed: {code}")

        logging_count = 0
        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", "unknown")
            is_logging = False

            try:
                status_resp = ct.get_trail_status(Name=trail_arn)
                api_calls.append("cloudtrail:GetTrailStatus")
                is_logging = status_resp.get("IsLogging", False)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"cloudtrail:GetTrailStatus for '{trail_name}' failed: {code}")

            if is_logging:
                logging_count += 1

            findings.append(
                f"Trail: '{trail_name}' | ARN: {trail_arn} | IsLogging: {is_logging}"
            )

        findings.append(f"Total trails in region: {len(trails)}")
        findings.append(f"Trails currently logging: {logging_count}")

        detections = [
            "GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled",
            "CloudTrail: StopLogging event",
            "AWS Config: cloudtrail-enabled rule",
            "Security Hub: [CloudTrail.1] CloudTrail should be enabled and configured",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(trails)} trail(s) ({logging_count} logging). "
                f"StopLogging permission: "
                f"{'confirmed' if stop_perm is True else 'unknown' if stop_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["cloudtrail:StopLogging"] if stop_perm is True else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "trail_count": len(trails),
                "logging_count": logging_count,
                "stop_logging_permission": stop_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "cloudtrail_stop is dry-run only. "
            "Stopping CloudTrail logging is prohibited by the safety policy of this framework."
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


MODULE = CloudTrailStopModule()
