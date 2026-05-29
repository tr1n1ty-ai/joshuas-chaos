"""Secrets Manager Batch Retrieve Module.

Simulate batch Secrets Manager credential access using BatchGetSecretValue API.
Execute reads only AttackLab-tagged secrets in batch — all values fully masked.
Maps to Stratus Red Team aws.credential-access.secretsmanager-batch-retrieve-secrets.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class SecretsManagerBatchRetrieveModule(ChaosModule):
    name = "secretsmanager_batch_retrieve"
    description = (
        "Simulate batch Secrets Manager credential access using BatchGetSecretValue API. "
        "Execute reads only AttackLab-tagged secrets in batch — all values fully masked. "
        "Maps to Stratus Red Team aws.credential-access.secretsmanager-batch-retrieve-secrets."
    )
    category = "credential-access"
    required_permissions = [
        "secretsmanager:ListSecrets",
        "secretsmanager:BatchGetSecretValue",
        "secretsmanager:GetSecretValue",
    ]
    cloudtrail_events = ["ListSecrets", "BatchGetSecretValue", "GetSecretValue"]
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
            risk_summary="Check for batch Secrets Manager credential access capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate secrets and check BatchGetSecretValue permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _list_all_and_attacklab_secrets(
        self, sm, config: AppConfig
    ) -> tuple[list[dict], list[dict]]:
        """Return (all_secrets, attacklab_secrets) lists."""
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
        """Check BatchGetSecretValue access and enumerate targetable secrets."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        sm = context.get_client("secretsmanager")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check BatchGetSecretValue permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["secretsmanager:BatchGetSecretValue"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        batch_perm: bool | None = perm_results.get("secretsmanager:BatchGetSecretValue")

        if batch_perm is True:
            findings.append(
                "[HIGH RISK] Principal has BatchGetSecretValue — can retrieve all accessible "
                "secrets in a single API call, generating minimal CloudTrail noise"
            )
            findings.append(
                "[KEY INSIGHT] BatchGetSecretValue generates a single CloudTrail event "
                "regardless of secret count — much harder to detect at scale than "
                "individual GetSecretValue calls"
            )
        elif batch_perm is None:
            findings.append(
                "[UNKNOWN] secretsmanager:BatchGetSecretValue permission could not be determined"
            )

        all_secrets, attacklab_secrets = self._list_all_and_attacklab_secrets(sm, config)
        api_calls.append("secretsmanager:ListSecrets")

        findings.append(f"Total secrets visible: {len(all_secrets)}")
        findings.append(f"AttackLab-tagged secrets: {len(attacklab_secrets)}")

        n = len(attacklab_secrets)
        findings.append(
            f"[DRY-RUN] Would batch-retrieve {n} AttackLab-tagged secret(s)"
        )
        if attacklab_secrets:
            findings.append(
                f"Target secret names: {[s['name'] for s in attacklab_secrets]}"
            )

        detections = [
            "CloudTrail: BatchGetSecretValue (single event regardless of secret count)",
            "GuardDuty: CredentialAccess:SecretsManager/SuspiciousGetSecretValueAPI",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(all_secrets)} secret(s), {len(attacklab_secrets)} AttackLab-tagged. "
                f"BatchGetSecretValue permission: "
                f"{'confirmed' if batch_perm is True else 'unknown' if batch_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["secretsmanager:BatchGetSecretValue"] if batch_perm is True else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_secrets),
            errors=errors,
            metadata={
                "total_secrets": len(all_secrets),
                "attacklab_secrets": [s["name"] for s in attacklab_secrets],
                "batch_get_permission": batch_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Batch-retrieve AttackLab-tagged secrets. ALL values are masked in output."""
        identity = context.get_caller_identity()
        safety = SafetyChecker(config, identity)
        safety.assert_account_allowed()
        safety.assert_region_allowed(context.region)

        sm = context.get_client("secretsmanager")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_secrets, attacklab_secrets = self._list_all_and_attacklab_secrets(sm, config)
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

        # Validate resources against safety checker
        safe_secrets: list[dict] = []
        for secret in attacklab_secrets:
            try:
                safety.assert_resource_safe(secret["name"], secret.get("tags", {}))
                safe_secrets.append(secret)
            except SafetyError as exc:
                errors.append(f"Resource safety check failed for '{secret['name']}': {exc}")

        accessed_names: list[str] = []
        secret_arns = [s["arn"] for s in safe_secrets]

        # Try BatchGetSecretValue first; fall back to individual GetSecretValue
        batch_succeeded = False
        if secret_arns:
            try:
                resp = sm.batch_get_secret_value(SecretIdList=secret_arns)
                api_calls.append("secretsmanager:BatchGetSecretValue")
                batch_succeeded = True
                for entry in resp.get("SecretValues", []):
                    name = entry.get("Name", "")
                    # Determine type but NEVER store or log the actual value
                    secret_type = "SecretString" if "SecretString" in entry else "SecretBinary"
                    # Immediately discard value — assign to throwaway var to be explicit
                    _ = entry.pop("SecretString", None)
                    _ = entry.pop("SecretBinary", None)
                    findings.append(
                        f"[EXECUTE] BatchGetSecretValue — secret '{name}' "
                        f"(type={secret_type}). Value: [REDACTED — not stored or logged]"
                    )
                    accessed_names.append(name)
                for err_entry in resp.get("Errors", []):
                    errors.append(
                        f"BatchGetSecretValue error for '{err_entry.get('SecretId', '?')}': "
                        f"{err_entry.get('ErrorCode', 'Unknown')}"
                    )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("AccessDenied", "AccessDeniedException",
                            "InvalidRequestException", "UnrecognizedClientException"):
                    logger.warning(
                        "BatchGetSecretValue not available (%s) — falling back to GetSecretValue",
                        code,
                    )
                else:
                    errors.append(f"BatchGetSecretValue failed: {code}")

        # Fallback: individual GetSecretValue per secret
        if not batch_succeeded and safe_secrets:
            for secret in safe_secrets:
                name = secret["name"]
                try:
                    resp = sm.get_secret_value(SecretId=name)
                    api_calls.append(f"secretsmanager:GetSecretValue ({name})")
                    secret_type = "SecretString" if "SecretString" in resp else "SecretBinary"
                    # Immediately discard value
                    _ = resp.pop("SecretString", None)
                    _ = resp.pop("SecretBinary", None)
                    findings.append(
                        f"[EXECUTE] GetSecretValue (fallback) — secret '{name}' "
                        f"(type={secret_type}). Value: [REDACTED — not stored or logged]"
                    )
                    accessed_names.append(name)
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "Unknown")
                    if code in ("AccessDenied", "AccessDeniedException"):
                        errors.append(f"AccessDenied for secret '{name}'")
                    else:
                        errors.append(f"GetSecretValue failed for '{name}': {code}")

        detections = [
            "CloudTrail: BatchGetSecretValue (single event regardless of secret count)",
            "GuardDuty: CredentialAccess:SecretsManager/SuspiciousGetSecretValueAPI",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Batch-retrieved {len(accessed_names)} AttackLab secret(s). "
                "Values are [REDACTED]."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=(
                ["secretsmanager:BatchGetSecretValue"]
                if batch_succeeded
                else ["secretsmanager:GetSecretValue"]
            ),
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={"accessed_secret_names": accessed_names},
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


MODULE = SecretsManagerBatchRetrieveModule()
