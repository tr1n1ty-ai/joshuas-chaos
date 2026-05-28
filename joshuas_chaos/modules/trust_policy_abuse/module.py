"""Trust Policy Abuse Module.

Targets the AttackLabTrustRole IAM role only.
Backs up trust policy, adds a benign test condition, then restores original.
"""

import json
import logging
from datetime import UTC, datetime

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_TARGET_ROLE = "AttackLabTrustRole"
_BENIGN_CONDITION_KEY = "aws:RequestedRegion"
_BENIGN_CONDITION_VALUE = "us-east-1"


class TrustPolicyAbuseModule(ChaosModule):
    name = "trust_policy_abuse"
    description = (
        "Detect and simulate iam:UpdateAssumeRolePolicy abuse on AttackLabTrustRole. "
        "Backs up original policy before any modification."
    )
    category = "privilege-escalation"
    required_permissions = [
        "iam:UpdateAssumeRolePolicy",
        "iam:GetRole",
    ]
    cloudtrail_events = [
        "UpdateAssumeRolePolicy",
        "GetRole",
    ]
    mitre_attack = ["T1098.003"]
    destructive = False
    reversible = True

    _original_policy: dict | None = None

    def __init__(self) -> None:
        self._original_policy = None

    def _get_role(self, iam) -> dict | None:
        try:
            response = iam.get_role(RoleName=_TARGET_ROLE)
            return response["Role"]
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "NoSuchEntity":
                return None
            logger.warning("get_role failed: %s", code)
            return None

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        iam = context.get_client("iam")
        role = self._get_role(iam)
        findings = []

        if role:
            findings.append(f"Target role '{_TARGET_ROLE}' found. ARN: {role.get('Arn')}")
        else:
            findings.append(
                f"Target role '{_TARGET_ROLE}' not found. "
                "Create an IAM role named 'AttackLabTrustRole' to use this module."
            )

        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Checked for AttackLabTrustRole existence.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=["iam:GetRole"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=role is not None,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detect if iam:UpdateAssumeRolePolicy is possible."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        iam = context.get_client("iam")
        findings: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["iam:UpdateAssumeRolePolicy", "iam:GetRole"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        if perm_results.get("iam:UpdateAssumeRolePolicy"):
            findings.append(
                "[RISK] Principal has iam:UpdateAssumeRolePolicy — can modify trust policies."
            )
        else:
            findings.append("iam:UpdateAssumeRolePolicy not permitted.")

        role = self._get_role(iam)
        api_calls.append("iam:GetRole")

        if role:
            import urllib.parse
            raw_policy = role.get("AssumeRolePolicyDocument", {})
            if isinstance(raw_policy, str):
                try:
                    raw_policy = json.loads(urllib.parse.unquote(raw_policy))
                except (json.JSONDecodeError, ValueError):
                    pass
            findings.append(
                f"[DRY-RUN] Target role '{_TARGET_ROLE}' found. "
                f"Current trust policy has {len(raw_policy.get('Statement', []))} statement(s)."
            )
            findings.append(
                f"[DRY-RUN] Would add benign condition "
                f"'{_BENIGN_CONDITION_KEY}={_BENIGN_CONDITION_VALUE}' to trust policy."
            )
        else:
            findings.append(
                f"Role '{_TARGET_ROLE}' not found. Execute would have no target."
            )

        detections = [
            "CloudTrail: UpdateAssumeRolePolicy",
            "IAM Access Analyzer: Changed trust policy",
            "Security Hub: [IAM.1] IAM policies should not allow full '*' administrative privileges",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed trust policy abuse risk. No changes made.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=role is not None,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Backup and modify trust policy on AttackLabTrustRole with benign condition."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_TARGET_ROLE, {})

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        role = self._get_role(iam)
        api_calls.append("iam:GetRole")

        if not role:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary=f"Role '{_TARGET_ROLE}' not found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=[f"Role '{_TARGET_ROLE}' does not exist. No action taken."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        import urllib.parse
        raw_policy = role.get("AssumeRolePolicyDocument", {})
        if isinstance(raw_policy, str):
            try:
                original_policy = json.loads(urllib.parse.unquote(raw_policy))
            except (json.JSONDecodeError, ValueError):
                original_policy = {}
        else:
            original_policy = raw_policy

        self._original_policy = original_policy
        backup_json = json.dumps(original_policy, indent=2)
        findings.append(f"[BACKUP] Original trust policy backed up ({len(backup_json)} chars).")

        # Add benign condition to each statement
        modified_policy = json.loads(json.dumps(original_policy))  # deep copy
        for stmt in modified_policy.get("Statement", []):
            cond = stmt.setdefault("Condition", {})
            cond.setdefault("StringEquals", {})[_BENIGN_CONDITION_KEY] = _BENIGN_CONDITION_VALUE

        modify_time = datetime.now(tz=UTC).isoformat()
        try:
            iam.update_assume_role_policy(
                RoleName=_TARGET_ROLE,
                PolicyDocument=json.dumps(modified_policy),
            )
            api_calls.append(f"iam:UpdateAssumeRolePolicy ({_TARGET_ROLE})")
            findings.append(
                f"[EXECUTE] Modified trust policy on '{_TARGET_ROLE}' at {modify_time}. "
                f"Added benign condition {_BENIGN_CONDITION_KEY}={_BENIGN_CONDITION_VALUE}."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"UpdateAssumeRolePolicy failed: {code}")

        detections = [
            "CloudTrail: UpdateAssumeRolePolicy on AttackLabTrustRole",
            "IAM Access Analyzer: trust policy modification alert",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Modified AttackLabTrustRole trust policy with benign condition.",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:GetRole", "iam:UpdateAssumeRolePolicy"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
            metadata={"original_policy": original_policy},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Restore original trust policy on AttackLabTrustRole. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        if self._original_policy is None:
            # Try to detect if it still has our test condition
            role = self._get_role(iam)
            if not role:
                return ModuleResult(
                    module=self.name,
                    mode="cleanup",
                    account_id=identity.account_id,
                    principal_arn=identity.arn,
                    region=context.region,
                    risk_summary="Role not found during cleanup.",
                    required_permissions=["iam:GetRole"],
                    observed_permissions=[],
                    aws_api_calls=["iam:GetRole"],
                    cloudtrail_events=self.cloudtrail_events,
                    findings=["AttackLabTrustRole not found — nothing to clean up."],
                    detections=[],
                    cleanup_required=False,
                    safe_to_execute=True,
                    errors=[],
                )
            findings.append(
                "No original policy backup in memory. "
                "Cannot restore — run execute first to create a backup."
            )
            return ModuleResult(
                module=self.name,
                mode="cleanup",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No backup available for restoration.",
                required_permissions=["iam:UpdateAssumeRolePolicy"],
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=True,
                safe_to_execute=False,
                errors=["No original policy backup available."],
            )

        try:
            iam.update_assume_role_policy(
                RoleName=_TARGET_ROLE,
                PolicyDocument=json.dumps(self._original_policy),
            )
            api_calls.append(f"iam:UpdateAssumeRolePolicy ({_TARGET_ROLE})")
            findings.append(f"[CLEANUP] Restored original trust policy on '{_TARGET_ROLE}'.")
            self._original_policy = None
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "NoSuchEntity":
                findings.append(f"Role '{_TARGET_ROLE}' no longer exists — cleanup is idempotent.")
                self._original_policy = None
            else:
                errors.append(f"Restore failed: {code}")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Trust policy restored.",
            required_permissions=["iam:UpdateAssumeRolePolicy"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = TrustPolicyAbuseModule()
