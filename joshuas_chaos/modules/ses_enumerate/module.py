"""SES Enumerate Module.

Enumerate SES (Simple Email Service) configuration including verified identities,
sending limits, and account-level settings. Read-only.

Maps to Stratus Red Team aws.discovery.ses-enumerate.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class SESEnumerateModule(ChaosModule):
    name = "ses_enumerate"
    description = (
        "Enumerate SES (Simple Email Service) configuration including verified identities, "
        "sending limits, and account-level settings. Read-only. "
        "Maps to Stratus Red Team aws.discovery.ses-enumerate."
    )
    category = "discovery"
    required_permissions = [
        "ses:GetAccountSendingEnabled",
        "ses:GetSendQuota",
        "ses:ListIdentities",
        "ses:GetIdentityVerificationAttributes",
    ]
    cloudtrail_events = [
        "GetAccountSendingEnabled",
        "GetSendQuota",
        "ListIdentities",
        "GetIdentityVerificationAttributes",
    ]
    mitre_attack = ["T1087.004"]
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
            risk_summary="Check SES enumeration capability.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate SES configuration."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _enumerate_ses(
        self,
        context: AWSContext,
        config: AppConfig,
        mode: str,
    ) -> ModuleResult:
        """Shared enumeration logic used by both dry_run and execute (read-only)."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ses = context.get_client("ses")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check ListIdentities permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ses:ListIdentities"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        # --- GetSendQuota ---
        max_24h: float = 0.0
        max_rate: float = 0.0
        sent_last_24h: float = 0.0
        quota_ok = False
        try:
            quota_resp = ses.get_send_quota()
            api_calls.append("ses:GetSendQuota")
            max_24h = quota_resp.get("Max24HourSend", 0.0)
            max_rate = quota_resp.get("MaxSendRate", 0.0)
            sent_last_24h = quota_resp.get("SentLast24Hours", 0.0)
            quota_ok = True
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "AccessDenied":
                errors.append("ses:GetSendQuota denied: AccessDenied")
            else:
                errors.append(f"ses:GetSendQuota failed: {code}")

        # --- GetAccountSendingEnabled ---
        sending_enabled: bool | None = None
        try:
            enabled_resp = ses.get_account_sending_enabled()
            api_calls.append("ses:GetAccountSendingEnabled")
            sending_enabled = enabled_resp.get("Enabled", False)
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code == "AccessDenied":
                errors.append("ses:GetAccountSendingEnabled denied: AccessDenied")
            else:
                errors.append(f"ses:GetAccountSendingEnabled failed: {code}")

        findings.append(
            f"SES sending enabled: "
            f"{'yes' if sending_enabled is True else 'no' if sending_enabled is False else 'unknown'}"
        )
        if quota_ok:
            findings.append(
                f"Send quota: max {max_24h:.0f} emails/24h, "
                f"max rate {max_rate:.1f}/sec, "
                f"sent last 24h: {sent_last_24h:.0f}"
            )

        # --- ListIdentities (paginated) ---
        identities: list[str] = []
        try:
            paginator = ses.get_paginator("list_identities")
            for page in paginator.paginate():
                identities.extend(page.get("Identities", []))
            api_calls.append("ses:ListIdentities")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in ("AccessDenied", "NotSupportedForSandbox"):
                errors.append(f"ses:ListIdentities failed: {code}")
            elif "InvalidClientTokenId" in code or "OptInRequired" in code:
                # SES not available in this region
                findings.append("SES not configured in this region/account")
                return ModuleResult(
                    module=self.name,
                    mode=mode,
                    account_id=identity.account_id,
                    principal_arn=identity.arn,
                    region=context.region,
                    risk_summary="SES not configured in this region/account.",
                    required_permissions=self.required_permissions,
                    observed_permissions=[],
                    aws_api_calls=api_calls,
                    cloudtrail_events=self.cloudtrail_events,
                    findings=findings,
                    detections=[],
                    cleanup_required=False,
                    safe_to_execute=True,
                    errors=errors,
                )
            else:
                errors.append(f"ses:ListIdentities failed: {code}")
        except Exception as exc:
            # Catch broad exceptions for regions that don't support SES v1
            err_str = str(exc)
            if "endpoint" in err_str.lower() or "not supported" in err_str.lower():
                findings.append("SES not configured in this region/account")
                return ModuleResult(
                    module=self.name,
                    mode=mode,
                    account_id=identity.account_id,
                    principal_arn=identity.arn,
                    region=context.region,
                    risk_summary="SES not configured in this region/account.",
                    required_permissions=self.required_permissions,
                    observed_permissions=[],
                    aws_api_calls=api_calls,
                    cloudtrail_events=self.cloudtrail_events,
                    findings=findings,
                    detections=[],
                    cleanup_required=False,
                    safe_to_execute=True,
                    errors=errors,
                )
            raise

        if not identities:
            findings.append("SES not configured in this region/account")
        else:
            findings.append(f"SES verified identities found: {len(identities)}")

            # --- GetIdentityVerificationAttributes (batch up to 100) ---
            batch_size = 100
            for batch_start in range(0, len(identities), batch_size):
                batch = identities[batch_start: batch_start + batch_size]
                try:
                    attr_resp = ses.get_identity_verification_attributes(
                        Identities=batch
                    )
                    api_calls.append("ses:GetIdentityVerificationAttributes")
                    attrs = attr_resp.get("VerificationAttributes", {})
                    for identity_name in batch:
                        verification = attrs.get(identity_name, {})
                        status = verification.get("VerificationStatus", "Unknown")
                        findings.append(
                            f"  Identity: '{identity_name}' — verification status: {status}"
                        )
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "Unknown")
                    errors.append(
                        f"ses:GetIdentityVerificationAttributes failed: {code}"
                    )

        if sending_enabled is True and quota_ok and max_24h > 0:
            findings.append(
                f"[RISK] SES is enabled with {max_24h:.0f} email/24h quota — could be abused "
                "for phishing or spam if principal gains ses:SendEmail"
            )

        detections = [
            "CloudTrail: SES enumeration events are low-signal individually but unusual in bulk",
            "GuardDuty: no specific finding for SES enumeration",
        ]

        list_perm: bool | None = perm_results.get("ses:ListIdentities")
        observed = [p for p, a in perm_results.items() if a]

        return ModuleResult(
            module=self.name,
            mode=mode,
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"SES {'enabled' if sending_enabled else 'disabled/unknown'}, "
                f"{len(identities)} verified identities found. "
                f"ListIdentities permission: "
                f"{'confirmed' if list_perm is True else 'unknown' if list_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=observed,
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={
                "sending_enabled": sending_enabled,
                "max_24h_send": max_24h,
                "max_send_rate": max_rate,
                "sent_last_24h": sent_last_24h,
                "identity_count": len(identities),
                "identities": identities,
            },
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate SES configuration — identical to execute (read-only)."""
        return self._enumerate_ses(context, config, mode="dry-run")

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate SES configuration — identical to dry_run (read-only)."""
        return self._enumerate_ses(context, config, mode="execute")

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — this module is read-only.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["No state was modified — this module is read-only."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = SESEnumerateModule()
