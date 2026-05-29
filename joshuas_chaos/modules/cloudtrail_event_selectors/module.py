"""CloudTrail Event Selectors Module.

Dry-run ONLY: Detect if principal can disable CloudTrail logging via event selectors.
Maps to Stratus Red Team aws.defense-evasion.cloudtrail-event-selectors.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class CloudTrailEventSelectorsModule(ChaosModule):
    name = "cloudtrail_event_selectors"
    description = (
        "Detect if principal can disable CloudTrail logging via event selectors. "
        "Dry-run only. Maps to Stratus Red Team aws.defense-evasion.cloudtrail-event-selectors."
    )
    category = "defense-evasion"
    required_permissions = [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:PutEventSelectors",
    ]
    cloudtrail_events = ["DescribeTrails", "GetEventSelectors", "PutEventSelectors"]
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
            risk_summary="Read-only check for CloudTrail event selector manipulation capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate trails and check PutEventSelectors permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check PutEventSelectors permission and enumerate current event selectors."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ct = context.get_client("cloudtrail")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check PutEventSelectors permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["cloudtrail:PutEventSelectors"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        put_perm: bool | None = perm_results.get("cloudtrail:PutEventSelectors")

        if put_perm is True:
            findings.append(
                "[CRITICAL] Principal can modify event selectors to exclude all management events, "
                "effectively blinding CloudTrail"
            )
        elif put_perm is None:
            findings.append(
                "[UNKNOWN] cloudtrail:PutEventSelectors permission could not be determined"
            )

        # Enumerate trails
        trails: list[dict] = []
        try:
            resp = ct.describe_trails(includeShadowTrails=False)
            api_calls.append("cloudtrail:DescribeTrails")
            trails = resp.get("trailList", [])
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"cloudtrail:DescribeTrails failed: {code}")

        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", "unknown")

            try:
                sel_resp = ct.get_event_selectors(TrailName=trail_arn)
                api_calls.append("cloudtrail:GetEventSelectors")
                selectors = sel_resp.get("EventSelectors", [])
                read_write_types = [s.get("ReadWriteType", "unknown") for s in selectors]
                findings.append(
                    f"Trail: '{trail_name}' | ReadWriteType(s): {read_write_types}"
                )
                findings.append(
                    "  Note: attacker sets ReadWriteType=None or uses advanced selectors "
                    "excluding all events"
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(
                    f"cloudtrail:GetEventSelectors for '{trail_name}' failed: {code}"
                )

        findings.append(f"Total trails enumerated: {len(trails)}")

        detections = [
            "CloudTrail: PutEventSelectors event",
            "AWS Config: cloudtrail-enabled rule (detects logging gaps)",
            "Security Hub: [CloudTrail.1] CloudTrail should be enabled and configured",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(trails)} trail(s). "
                f"PutEventSelectors permission: "
                f"{'confirmed' if put_perm is True else 'unknown' if put_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["cloudtrail:PutEventSelectors"] if put_perm is True else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "trail_count": len(trails),
                "put_event_selectors_permission": put_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "cloudtrail_event_selectors is dry-run only. "
            "Modifying CloudTrail event selectors is prohibited by the safety policy of this framework."
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


MODULE = CloudTrailEventSelectorsModule()
