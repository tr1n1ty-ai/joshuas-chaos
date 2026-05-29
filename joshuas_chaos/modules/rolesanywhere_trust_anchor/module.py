"""Roles Anywhere Trust Anchor Module.

Simulate IAM Roles Anywhere persistence by creating an AttackLab trust anchor
with a self-signed certificate.
Maps to Stratus Red Team aws.persistence.rolesanywhere-create-trust-anchor.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_ANCHOR_NAME = "AttackLabTrustAnchor"

_SELF_SIGNED_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o4qne60TB3wolGfRs1TP7LIGY5XxPBZKBqCFa4pEBNFRlNfClTTQMvBMuexuinz2
kM6XWKXL6S5DFaZaDiD8u9aLJhHQx6ZJDV9RDkaHLJo+tHOHKAIRfQ9JNWQ3LJe
Fh5MXhNHFOK6JB6Lm8P+mJv3PxVHjnxHCBNQ9AoYxlR+tRDSbTPpRkGIOVRfY5l
ZfBNvGJfxSjpS5raSPgbPMHOMEeSmXVLNhxk6MFTxLBR2KsODMJ9Af1iSGYiYsSO
D2a4P6A8fOk2N/uu+q+NF5u6dBgjZGiUqxHHHvl8UNI+EMnRkDa8HzKn0YDtHpNg
Q5ZkMjmBZCiJ5T0/iQMXAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAA==
-----END CERTIFICATE-----"""


class RolesAnywhereTrustAnchorModule(ChaosModule):
    name = "rolesanywhere_trust_anchor"
    description = (
        "Simulate IAM Roles Anywhere persistence by creating an AttackLab trust anchor "
        "with a self-signed certificate. Cleanup deletes the trust anchor. "
        "Maps to Stratus Red Team aws.persistence.rolesanywhere-create-trust-anchor."
    )
    category = "persistence"
    required_permissions = [
        "rolesanywhere:CreateTrustAnchor",
        "rolesanywhere:DeleteTrustAnchor",
        "rolesanywhere:ListTrustAnchors",
    ]
    cloudtrail_events = [
        "CreateTrustAnchor",
        "DeleteTrustAnchor",
        "ListTrustAnchors",
    ]
    mitre_attack = ["T1556"]
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
            risk_summary="Check rolesanywhere:CreateTrustAnchor permission.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess Roles Anywhere trust anchor creation risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check rolesanywhere:CreateTrustAnchor and list existing trust anchors."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ra = context.get_client("rolesanywhere")
        findings: list[str] = []
        api_calls = ["iam:SimulatePrincipalPolicy"]

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["rolesanywhere:CreateTrustAnchor"],
        )

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("rolesanywhere:CreateTrustAnchor") is True:
            findings.append("[RISK] Principal can call rolesanywhere:CreateTrustAnchor.")
        elif simulation_available:
            findings.append("rolesanywhere:CreateTrustAnchor not permitted for this principal.")

        # Try to list existing trust anchors
        existing_count = 0
        try:
            resp = ra.list_trust_anchors()
            api_calls.append("rolesanywhere:ListTrustAnchors")
            existing_count = len(resp.get("trustAnchors", []))
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("rolesanywhere:ListTrustAnchors failed: %s", code)

        findings.append(
            f"Existing trust anchors in account: {existing_count}."
        )
        findings.append(
            f"[DRY-RUN] Would create Roles Anywhere trust anchor '{_ANCHOR_NAME}' with self-signed certificate."
        )

        detections = [
            "CloudTrail: rolesanywhere:CreateTrustAnchor",
            "GuardDuty: no specific finding — monitor via CloudTrail",
            "AWS Config: custom rule for rolesanywhere trust anchor changes",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {existing_count} existing trust anchors. Would create '{_ANCHOR_NAME}'.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, v in perm_results.items() if v is True],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Create AttackLabTrustAnchor with self-signed certificate."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_ANCHOR_NAME, {})

        ra = context.get_client("rolesanywhere")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            resp = ra.create_trust_anchor(
                name=_ANCHOR_NAME,
                source={
                    "sourceData": {"x509CertificateData": _SELF_SIGNED_CERT_PEM},
                    "sourceType": "CERTIFICATE_BUNDLE",
                },
                tags=[{"key": "AttackLab", "value": "true"}],
            )
            api_calls.append(f"rolesanywhere:CreateTrustAnchor ({_ANCHOR_NAME})")
            anchor_id = resp.get("trustAnchor", {}).get("trustAnchorId", "unknown")
            findings.append(
                f"[EXECUTE] Created Roles Anywhere trust anchor '{_ANCHOR_NAME}'. "
                f"TrustAnchorId: {anchor_id}."
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"rolesanywhere:CreateTrustAnchor failed: {code}")

        detections = [
            "CloudTrail: rolesanywhere:CreateTrustAnchor",
            "GuardDuty: no specific finding — monitor via CloudTrail",
            "AWS Config: custom rule for rolesanywhere trust anchor changes",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Created Roles Anywhere trust anchor '{_ANCHOR_NAME}'.",
            required_permissions=self.required_permissions,
            observed_permissions=["rolesanywhere:CreateTrustAnchor"] if not errors else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Delete the AttackLabTrustAnchor. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ra = context.get_client("rolesanywhere")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Find the trust anchor by name
        anchor_id: str | None = None
        try:
            resp = ra.list_trust_anchors()
            api_calls.append("rolesanywhere:ListTrustAnchors")
            for anchor in resp.get("trustAnchors", []):
                if anchor.get("name") == _ANCHOR_NAME:
                    anchor_id = anchor.get("trustAnchorId")
                    break
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"rolesanywhere:ListTrustAnchors failed: {code}")

        if not anchor_id:
            findings.append(
                f"Trust anchor '{_ANCHOR_NAME}' not found — already deleted (idempotent)."
            )
        else:
            try:
                ra.delete_trust_anchor(trustAnchorId=anchor_id)
                api_calls.append(f"rolesanywhere:DeleteTrustAnchor ({anchor_id})")
                findings.append(
                    f"[CLEANUP] Deleted trust anchor '{_ANCHOR_NAME}' (id: {anchor_id})."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "ResourceNotFoundException":
                    findings.append(
                        f"Trust anchor '{_ANCHOR_NAME}' not found — idempotent."
                    )
                else:
                    errors.append(f"rolesanywhere:DeleteTrustAnchor failed: {code}")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Trust anchor '{_ANCHOR_NAME}' cleanup complete.",
            required_permissions=["rolesanywhere:ListTrustAnchors", "rolesanywhere:DeleteTrustAnchor"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = RolesAnywhereTrustAnchorModule()
