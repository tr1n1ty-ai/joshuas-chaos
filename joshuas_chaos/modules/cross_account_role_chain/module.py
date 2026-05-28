"""Cross-Account Role Chain Module.

Map sts:AssumeRole paths from config.modules.cross_account_role_chain.allowed_role_arns.
Does NOT brute-force accounts. Does NOT enumerate outside allowlisted accounts.
Output graph JSON showing role chain.
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


class CrossAccountRoleChainModule(ChaosModule):
    name = "cross_account_role_chain"
    description = (
        "Map cross-account sts:AssumeRole paths from explicitly configured role ARNs only. "
        "Does NOT brute-force or enumerate outside the allowlist."
    )
    category = "lateral-movement"
    required_permissions = [
        "sts:AssumeRole",
        "iam:GetRole",
    ]
    cloudtrail_events = [
        "AssumeRole",
        "GetRole",
    ]
    mitre_attack = ["T1550.001"]
    destructive = False
    reversible = True

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        module_cfg = config.modules.get("cross_account_role_chain", {})
        allowed_roles = module_cfg.get("allowed_role_arns", []) or []
        findings = [
            f"Configured allowed_role_arns: {allowed_roles or 'none — configure in config.yaml'}"
        ]
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check configured role ARNs for cross-account chaining.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=bool(allowed_roles),
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Map assume-role paths for explicitly configured ARNs only."""
        identity = context.get_caller_identity()
        module_cfg = config.modules.get("cross_account_role_chain", {})
        allowed_roles: list[str] = module_cfg.get("allowed_role_arns", []) or []

        findings: list[str] = []
        api_calls: list[str] = []
        errors: list[str] = []

        if not allowed_roles:
            findings.append(
                "No allowed_role_arns configured in config.yaml. "
                "Add role ARNs to modules.cross_account_role_chain.allowed_role_arns."
            )
            return ModuleResult(
                module=self.name,
                mode="dry-run",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No role ARNs configured.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=[],
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
            )

        # Validate that all configured ARNs are in allowlisted accounts
        for role_arn in allowed_roles:
            try:
                account_in_arn = role_arn.split(":")[4]
            except IndexError:
                errors.append(f"Invalid ARN format: {role_arn}")
                continue

            if account_in_arn not in config.allowed_accounts:
                errors.append(
                    f"Role ARN '{role_arn}' is in account '{account_in_arn}' "
                    "which is NOT in allowed_accounts. Skipping."
                )
                continue

            findings.append(
                f"[DRY-RUN] Would attempt sts:AssumeRole for '{role_arn}' "
                f"(account {account_in_arn} is in allowlist)."
            )

        # Build role chain graph (dry-run: just document, don't assume)
        chain_graph = {
            "source": identity.arn,
            "targets": [
                {
                    "role_arn": arn,
                    "account": arn.split(":")[4] if ":" in arn else "unknown",
                    "status": "would_attempt" if arn.split(":")[4] in config.allowed_accounts else "blocked",
                }
                for arn in allowed_roles
                if len(arn.split(":")) > 4
            ],
        }

        findings.append(
            f"[DRY-RUN] Role chain graph: {json.dumps(chain_graph, indent=2)}"
        )

        detections = [
            "CloudTrail: sts:AssumeRole cross-account",
            "CloudTrail: unusual role assumption patterns",
            "GuardDuty: Policy:IAMUser/RootCredentialUsage (if root assumed)",
            "IAM Access Analyzer: cross-account access findings",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Mapped {len(allowed_roles)} configured role chain target(s).",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(allowed_roles),
            errors=errors,
            metadata={"role_chain_graph": chain_graph},
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Attempt sts:AssumeRole for each allowlisted role ARN. Builds role chain."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        module_cfg = config.modules.get("cross_account_role_chain", {})
        allowed_roles: list[str] = module_cfg.get("allowed_role_arns", []) or []

        if not allowed_roles:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No allowed_role_arns configured.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=[],
                cloudtrail_events=self.cloudtrail_events,
                findings=["No role ARNs configured in config.yaml."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        sts = context.get_client("sts")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []
        assumed: list[dict] = []

        for role_arn in allowed_roles:
            try:
                account_in_arn = role_arn.split(":")[4]
            except IndexError:
                errors.append(f"Invalid ARN: {role_arn}")
                continue

            if account_in_arn not in config.allowed_accounts:
                errors.append(
                    f"Blocked: '{role_arn}' is in non-allowlisted account '{account_in_arn}'."
                )
                continue

            try:
                resp = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="AttackLabCrossAccountTest",
                    DurationSeconds=900,
                )
                api_calls.append(f"sts:AssumeRole ({role_arn})")
                assumed_arn = resp["AssumedRoleUser"]["Arn"]
                # Credentials are NOT stored or logged
                findings.append(
                    f"[EXECUTE] Successfully assumed role '{role_arn}'. "
                    f"Assumed ARN: {assumed_arn}. "
                    "Credentials NOT stored or logged."
                )
                assumed.append({"role_arn": role_arn, "assumed_arn": assumed_arn})
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "AccessDenied":
                    findings.append(f"AccessDenied assuming role '{role_arn}'.")
                else:
                    errors.append(f"sts:AssumeRole failed for '{role_arn}': {code}")

        detections = [
            "CloudTrail: sts:AssumeRole cross-account",
            "IAM Access Analyzer: cross-account role access",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Successfully assumed {len(assumed)} cross-account role(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["sts:AssumeRole"] if assumed else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={"assumed_roles": assumed},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — STS sessions expire automatically.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["STS sessions expire in 15 minutes (900s). No persistent state created."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = CrossAccountRoleChainModule()
