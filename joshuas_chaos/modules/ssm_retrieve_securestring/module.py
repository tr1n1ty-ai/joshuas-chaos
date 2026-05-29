"""SSM Retrieve SecureString Module.

Simulate SSM Parameter Store credential access by retrieving SecureString parameters
tagged AttackLab=true with decryption. All parameter values are fully masked.
Maps to Stratus Red Team aws.credential-access.ssm-retrieve-securestring-parameters.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

# SSM GetParameters API accepts at most 10 parameter names per call
_SSM_BATCH_SIZE = 10


class SSMRetrieveSecureStringModule(ChaosModule):
    name = "ssm_retrieve_securestring"
    description = (
        "Simulate SSM Parameter Store credential access by retrieving SecureString parameters "
        "tagged AttackLab=true with decryption. All parameter values are fully masked. "
        "Maps to Stratus Red Team aws.credential-access.ssm-retrieve-securestring-parameters."
    )
    category = "credential-access"
    required_permissions = [
        "ssm:DescribeParameters",
        "ssm:GetParameters",
        "ssm:GetParameter",
        "kms:Decrypt",
    ]
    cloudtrail_events = ["DescribeParameters", "GetParameters", "Decrypt"]
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
            risk_summary="Check for SSM Parameter Store SecureString retrieval capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate SecureString parameters and check GetParameters permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _describe_secure_parameters(
        self, ssm, config: AppConfig
    ) -> tuple[list[dict], list[dict]]:
        """Return (all_secure_params, attacklab_params).

        Filters DescribeParameters to Type=SecureString.
        AttackLab params are those with name prefix or AttackLab tag (if tag listing available).
        Note: SSM parameter tags require ssm:ListTagsForResource — if unavailable, filter
        by name prefix only.
        """
        prefix = config.resource_safety.allowed_name_prefix
        tag_key = config.resource_safety.required_tag_key
        tag_val = config.resource_safety.required_tag_value

        all_secure: list[dict] = []
        attacklab: list[dict] = []

        try:
            paginator = ssm.get_paginator("describe_parameters")
            for page in paginator.paginate(
                ParameterFilters=[{"Key": "Type", "Values": ["SecureString"]}]
            ):
                for param in page.get("Parameters", []):
                    name = param.get("Name", "")
                    param_type = param.get("Type", "SecureString")
                    all_secure.append({"name": name, "type": param_type, "tags": {}})
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ssm:DescribeParameters failed: %s", code)
            return all_secure, attacklab

        # Attempt to enrich with tags via ListTagsForResource; fall back to name-prefix filter
        for param in all_secure:
            name = param["name"]
            tags: dict[str, str] = {}
            try:
                tag_resp = ssm.list_tags_for_resource(
                    ResourceType="Parameter",
                    ResourceId=name,
                )
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagList", [])}
                param["tags"] = tags
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code not in ("AccessDenied", "AccessDeniedException"):
                    logger.debug("ssm:ListTagsForResource failed for '%s': %s", name, code)
                # Fall through — name-prefix check will still apply

            has_prefix = name.startswith(f"/{prefix}") or name.startswith(prefix)
            has_tag = tags.get(tag_key, "").lower() == tag_val.lower()
            if has_prefix or has_tag:
                attacklab.append(param)

        return all_secure, attacklab

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate SecureString parameters and assess retrieval risk."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ssm = context.get_client("ssm")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check GetParameters permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ssm:GetParameters"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        get_params_perm: bool | None = perm_results.get("ssm:GetParameters")

        if get_params_perm is True:
            findings.append(
                "[HIGH RISK] Principal can retrieve SecureString parameters with decryption "
                "— may expose database passwords, API keys, and other secrets"
            )
        elif get_params_perm is None:
            findings.append(
                "[UNKNOWN] ssm:GetParameters permission could not be determined"
            )

        all_secure, attacklab_params = self._describe_secure_parameters(ssm, config)
        api_calls.append("ssm:DescribeParameters")

        findings.append(f"Total SecureString parameters visible: {len(all_secure)}")
        findings.append(f"AttackLab-tagged SecureString parameters: {len(attacklab_params)}")

        n = len(attacklab_params)
        findings.append(
            f"[DRY-RUN] Would retrieve {n} AttackLab SecureString parameter(s) "
            "with WithDecryption=True"
        )
        if attacklab_params:
            findings.append(
                f"Target parameter names: {[p['name'] for p in attacklab_params]}"
            )

        detections = [
            "CloudTrail: GetParameters with WithDecryption=true",
            "CloudTrail: kms:Decrypt event for each KMS-encrypted parameter",
            "AWS Config: ssm-document-not-public",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(all_secure)} SecureString parameter(s), "
                f"{n} AttackLab-tagged. "
                f"GetParameters permission: "
                f"{'confirmed' if get_params_perm is True else 'unknown' if get_params_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ssm:GetParameters"] if get_params_perm is True else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_params),
            errors=errors,
            metadata={
                "total_secure_params": len(all_secure),
                "attacklab_param_names": [p["name"] for p in attacklab_params],
                "get_parameters_permission": get_params_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Retrieve AttackLab SecureString parameters with decryption. Values are masked."""
        identity = context.get_caller_identity()
        safety = SafetyChecker(config, identity)
        safety.assert_account_allowed()
        safety.assert_region_allowed(context.region)

        ssm = context.get_client("ssm")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_secure, attacklab_params = self._describe_secure_parameters(ssm, config)
        api_calls.append("ssm:DescribeParameters")

        if not attacklab_params:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab SecureString parameters found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-tagged SecureString parameters found."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=True,
                errors=[],
            )

        # Validate each resource against safety checker before touching it
        safe_params: list[dict] = []
        for param in attacklab_params:
            try:
                safety.assert_resource_safe(param["name"], param.get("tags", {}))
                safe_params.append(param)
            except SafetyError as exc:
                errors.append(f"Resource safety check failed for '{param['name']}': {exc}")

        accessed_names: list[str] = []

        # Batch by _SSM_BATCH_SIZE (API limit is 10 names per call)
        for i in range(0, len(safe_params), _SSM_BATCH_SIZE):
            batch = safe_params[i: i + _SSM_BATCH_SIZE]
            batch_names = [p["name"] for p in batch]
            try:
                resp = ssm.get_parameters(
                    Names=batch_names,
                    WithDecryption=True,
                )
                api_calls.append(
                    f"ssm:GetParameters (batch {i // _SSM_BATCH_SIZE + 1}, "
                    f"{len(batch_names)} params, WithDecryption=True)"
                )
                for param_entry in resp.get("Parameters", []):
                    param_name = param_entry.get("Name", "")
                    param_type = param_entry.get("Type", "SecureString")
                    # IMMEDIATELY discard value — never stored or logged
                    _ = param_entry.pop("Value", None)
                    findings.append(
                        f"[EXECUTE] Retrieved parameter '{param_name}' "
                        f"(type={param_type}, WithDecryption=True). "
                        "Value: [REDACTED — not stored or logged]"
                    )
                    accessed_names.append(param_name)
                for invalid_name in resp.get("InvalidParameters", []):
                    errors.append(
                        f"Parameter '{invalid_name}' returned as InvalidParameters "
                        "(may not exist or be inaccessible)"
                    )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("AccessDenied", "AccessDeniedException"):
                    errors.append(
                        f"AccessDenied for ssm:GetParameters batch {batch_names}"
                    )
                else:
                    errors.append(
                        f"ssm:GetParameters failed for batch {batch_names}: {code}"
                    )

        detections = [
            "CloudTrail: GetParameters with WithDecryption=true",
            "CloudTrail: kms:Decrypt event for each KMS-encrypted parameter",
            "AWS Config: ssm-document-not-public",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Retrieved {len(accessed_names)} AttackLab SecureString parameter(s). "
                "Values are [REDACTED]."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ssm:GetParameters", "kms:Decrypt"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={"accessed_param_names": accessed_names},
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


MODULE = SSMRetrieveSecureStringModule()
