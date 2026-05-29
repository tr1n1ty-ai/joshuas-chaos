"""DNS Delete Logs Module.

Dry-run ONLY: Detect if principal can delete Route53 Resolver DNS query log configurations.
Maps to Stratus Red Team aws.defense-evasion.dns-delete-logs.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class DNSDeleteLogsModule(ChaosModule):
    name = "dns_delete_logs"
    description = (
        "Detect if principal can delete Route53 Resolver DNS query log configurations. "
        "Dry-run only. Maps to Stratus Red Team aws.defense-evasion.dns-delete-logs."
    )
    category = "defense-evasion"
    required_permissions = [
        "route53resolver:ListResolverQueryLogConfigs",
        "route53resolver:DeleteResolverQueryLogConfig",
    ]
    cloudtrail_events = ["ListResolverQueryLogConfigs", "DeleteResolverQueryLogConfig"]
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
            risk_summary="Read-only check for DNS query log deletion capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate DNS query log configs and check delete permissions."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check DeleteResolverQueryLogConfig permission and enumerate log configs."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check DeleteResolverQueryLogConfig permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["route53resolver:DeleteResolverQueryLogConfig"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        delete_perm: bool | None = perm_results.get("route53resolver:DeleteResolverQueryLogConfig")

        configs: list[dict] = []
        try:
            r53resolver = context.get_client("route53resolver")

            # Use paginator if available, otherwise direct call
            try:
                paginator = r53resolver.get_paginator("list_resolver_query_log_configs")
                for page in paginator.paginate():
                    api_calls.append("route53resolver:ListResolverQueryLogConfigs")
                    configs.extend(page.get("ResolverQueryLogConfigs", []))
            except botocore.exceptions.OperationNotPageableError:
                resp = r53resolver.list_resolver_query_log_configs()
                api_calls.append("route53resolver:ListResolverQueryLogConfigs")
                configs = resp.get("ResolverQueryLogConfigs", [])

        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("AccessDenied", "AccessDeniedException"):
                errors.append("route53resolver:ListResolverQueryLogConfigs — AccessDenied")
            else:
                errors.append(f"route53resolver:ListResolverQueryLogConfigs failed: {code}")
        except Exception as exc:
            # Route53 Resolver may not be available in all regions
            errors.append(
                f"route53resolver service unavailable or error in this region: {exc}"
            )

        findings.append(f"DNS query log configurations found: {len(configs)}")

        for cfg in configs:
            cfg_id = cfg.get("Id", "unknown")
            cfg_name = cfg.get("Name", "unknown")
            association_count = cfg.get("AssociationCount", 0)
            status = cfg.get("Status", "unknown")
            findings.append(
                f"Config: '{cfg_name}' | ID: {cfg_id} | "
                f"Associations: {association_count} | Status: {status}"
            )

        if delete_perm is True:
            findings.append(
                f"[HIGH RISK] Principal can delete DNS query log configurations"
            )
            findings.append(
                "Note: loss of DNS logs removes visibility into domain lookups from VPC resources"
            )
        elif delete_perm is None:
            findings.append(
                "[UNKNOWN] route53resolver:DeleteResolverQueryLogConfig permission "
                "could not be determined"
            )

        detections = [
            "CloudTrail: DeleteResolverQueryLogConfig event",
            "AWS Config: vpc-flow-logs-enabled rule (DNS logging gap)",
            "Security Hub: Route53 Resolver query logging findings",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(configs)} DNS query log config(s). "
                f"DeleteResolverQueryLogConfig permission: "
                f"{'confirmed' if delete_perm is True else 'unknown' if delete_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=(
                ["route53resolver:DeleteResolverQueryLogConfig"] if delete_perm is True else []
            ),
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "config_count": len(configs),
                "delete_permission": delete_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "dns_delete_logs is dry-run only. "
            "Deleting Route53 Resolver DNS query log configurations is prohibited "
            "by the safety policy of this framework."
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


MODULE = DNSDeleteLogsModule()
