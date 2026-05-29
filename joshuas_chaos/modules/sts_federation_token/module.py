"""STS Federation Token Module.

Simulate STS federation token persistence by calling sts:GetFederationToken
to obtain long-lived temporary credentials.
Secret access key is never logged.
Maps to Stratus Red Team aws.persistence.sts-federation-token.
"""

import json
import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class STSFederationTokenModule(ChaosModule):
    name = "sts_federation_token"
    description = (
        "Simulate STS federation token persistence by calling sts:GetFederationToken "
        "to obtain long-lived temporary credentials. Token ARN is logged; secret is [REDACTED]. "
        "Maps to Stratus Red Team aws.persistence.sts-federation-token."
    )
    category = "persistence"
    required_permissions = ["sts:GetFederationToken"]
    cloudtrail_events = ["GetFederationToken"]
    mitre_attack = ["T1548.005"]
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
            risk_summary="Check sts:GetFederationToken permission for persistence simulation.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess sts:GetFederationToken federation token risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check sts:GetFederationToken permission."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["sts:GetFederationToken"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("sts:GetFederationToken") is True:
            findings.append("[RISK] Principal can call sts:GetFederationToken.")
        elif simulation_available:
            findings.append("sts:GetFederationToken not permitted for this principal.")

        findings.append(
            "[DRY-RUN] Would call sts:GetFederationToken to obtain 12-hour temporary credentials for persistence."
        )

        detections = [
            "CloudTrail: sts:GetFederationToken",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "UEBA: unusual GetFederationToken call from non-federation service",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed sts:GetFederationToken risk. No changes made.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, v in perm_results.items() if v is True],
            aws_api_calls=["iam:SimulatePrincipalPolicy"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Call sts:GetFederationToken and log token ID. Secret is never logged."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        sts = context.get_client("sts")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        session_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:GetCallerIdentity",
                    "Resource": "*",
                }
            ],
        })

        try:
            resp = sts.get_federation_token(
                Name="AttackLabFederationToken",
                DurationSeconds=43200,  # 12 hours
                Policy=session_policy,
            )
            api_calls.append("sts:GetFederationToken")
            credentials = resp["Credentials"]
            key_id = credentials["AccessKeyId"]
            expiration = credentials["Expiration"]
            # NEVER log SecretAccessKey or SessionToken
            findings.append(
                f"[EXECUTE] Obtained federation token. "
                f"AccessKeyId: {key_id}. "
                f"Expiration: {expiration}. "
                "Secret: [REDACTED]."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"sts:GetFederationToken failed: {code}")

        detections = [
            "CloudTrail: sts:GetFederationToken",
            "GuardDuty: Persistence:IAMUser/UserPermissions",
            "UEBA: unusual GetFederationToken call from non-federation service",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Obtained 12-hour STS federation token. Token expires automatically.",
            required_permissions=self.required_permissions,
            observed_permissions=["sts:GetFederationToken"] if not errors else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """No-op — federation token expires automatically after 12 hours."""
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — federation token expires automatically.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Federation token expires automatically after 12 hours. No cleanup needed."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = STSFederationTokenModule()
