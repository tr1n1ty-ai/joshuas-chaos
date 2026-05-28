"""Secrets Manager Data Access Module.

dry_run: Check if ListSecrets / GetSecretValue access appears possible.
execute: Only read secrets tagged AttackLab=true. MASK secret values completely.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class SecretsManagerDataAccessModule(ChaosModule):
    name = "secretsmanager_data_access"
    description = (
        "Assess Secrets Manager data access risk. Execute reads only AttackLab-tagged "
        "secrets — all secret values are fully masked in output."
    )
    category = "credential-access"
    required_permissions = [
        "secretsmanager:ListSecrets",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
    ]
    cloudtrail_events = [
        "ListSecrets",
        "GetSecretValue",
        "DescribeSecret",
    ]
    mitre_attack = ["T1555"]
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
            risk_summary="Check Secrets Manager access risk.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess Secrets Manager data access risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _list_secrets(self, sm, config: AppConfig) -> tuple[list[dict], list[dict]]:
        """Return (all_secrets, attacklab_secrets) as lists of dicts with name+arn."""
        tag_key = config.resource_safety.required_tag_key
        tag_val = config.resource_safety.required_tag_value
        prefix = config.resource_safety.allowed_name_prefix
        all_secrets: list[dict] = []
        attacklab_secrets: list[dict] = []

        try:
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    name = secret.get("Name", "")
                    arn = secret.get("ARN", "")
                    tags = {t["Key"]: t["Value"] for t in secret.get("Tags", [])}
                    all_secrets.append({"name": name, "arn": arn})
                    has_prefix = name.startswith(prefix)
                    has_tag = tags.get(tag_key, "").lower() == tag_val.lower()
                    if has_prefix or has_tag:
                        attacklab_secrets.append({"name": name, "arn": arn, "tags": tags})
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("secretsmanager:ListSecrets failed: %s", code)

        return all_secrets, attacklab_secrets

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check ListSecrets / GetSecretValue access possibility."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        sm = context.get_client("secretsmanager")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["secretsmanager:ListSecrets", "secretsmanager:GetSecretValue"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        if perm_results.get("secretsmanager:ListSecrets"):
            findings.append("[RISK] Principal has secretsmanager:ListSecrets")
        if perm_results.get("secretsmanager:GetSecretValue"):
            findings.append("[HIGH RISK] Principal has secretsmanager:GetSecretValue")

        all_secrets, attacklab_secrets = self._list_secrets(sm, config)
        api_calls.append("secretsmanager:ListSecrets")

        findings.append(f"Total secrets visible: {len(all_secrets)}")
        if attacklab_secrets:
            findings.append(
                f"[DRY-RUN] Would attempt GetSecretValue for AttackLab-tagged secrets: "
                f"{[s['name'] for s in attacklab_secrets]}"
            )
        else:
            findings.append("No AttackLab-tagged secrets found for execute mode.")

        detections = [
            "CloudTrail: secretsmanager:GetSecretValue",
            "CloudTrail: secretsmanager:ListSecrets",
            "Secrets Manager resource policy access alert",
            "GuardDuty: CredentialAccess:SecretsManager/SuspiciousGetSecretValueAPI",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {len(all_secrets)} secret(s), {len(attacklab_secrets)} AttackLab-tagged.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_secrets),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Read AttackLab-tagged secrets. ALL secret values are masked in output."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        sm = context.get_client("secretsmanager")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_secrets, attacklab_secrets = self._list_secrets(sm, config)
        api_calls.append("secretsmanager:ListSecrets")

        if not attacklab_secrets:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab-tagged secrets found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-tagged secrets found."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=True,
                errors=[],
            )

        accessed: list[str] = []
        for secret in attacklab_secrets:
            name = secret["name"]
            tags = secret.get("tags", {})
            try:
                checker.assert_resource_safe(name, tags)
            except SafetyError as exc:
                errors.append(f"Resource safety check failed for '{name}': {exc}")
                continue
            try:
                resp = sm.get_secret_value(SecretId=name)
                api_calls.append(f"secretsmanager:GetSecretValue ({name})")
                # ALWAYS mask the actual secret value — never log or store it
                secret_type = "SecretString" if "SecretString" in resp else "SecretBinary"
                findings.append(
                    f"[EXECUTE] Accessed secret '{name}' (type={secret_type}). "
                    "Value: [REDACTED — not stored or logged]"
                )
                accessed.append(name)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "AccessDeniedException":
                    errors.append(f"AccessDenied for secret '{name}'")
                else:
                    errors.append(f"GetSecretValue failed for '{name}': {code}")

        detections = [
            "CloudTrail: secretsmanager:GetSecretValue",
            "GuardDuty: CredentialAccess:SecretsManager/SuspiciousGetSecretValueAPI",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Accessed {len(accessed)} AttackLab secret(s). Values are [REDACTED].",
            required_permissions=self.required_permissions,
            observed_permissions=["secretsmanager:GetSecretValue"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={"accessed_secret_names": accessed},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — read-only access.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["No state was modified by this module."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = SecretsManagerDataAccessModule()
