"""S3 Ransomware Detection Module.

Dry-run ONLY: Assess S3 ransomware susceptibility by checking versioning, MFA delete,
and relevant IAM permissions.
Covers Stratus Red Team aws.impact.s3-ransomware-* techniques.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_BUCKET_SCAN_LIMIT = 50


class S3RansomwareDetectionModule(ChaosModule):
    name = "s3_ransomware_detection"
    description = (
        "Assess S3 ransomware susceptibility: checks for s3:DeleteObject, s3:PutObject, "
        "and s3:GetObject permissions, versioning status, and MFA delete configuration. "
        "Dry-run only. Covers Stratus Red Team aws.impact.s3-ransomware-* techniques."
    )
    category = "impact"
    required_permissions = [
        "s3:ListBuckets",
        "s3:GetBucketVersioning",
        "s3:GetBucketLocation",
        "s3:DeleteObject",
        "s3:PutObject",
    ]
    cloudtrail_events = ["ListBuckets", "GetBucketVersioning", "DeleteObject", "PutObject"]
    mitre_attack = ["T1485", "T1486"]
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
            risk_summary="Read-only assessment of S3 ransomware susceptibility.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate S3 buckets and assess ransomware risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Assess S3 ransomware susceptibility across all visible buckets."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        s3 = context.get_client("s3")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check DeleteObject and PutObject permissions
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["s3:DeleteObject", "s3:PutObject"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        delete_perm: bool | None = perm_results.get("s3:DeleteObject")
        put_perm: bool | None = perm_results.get("s3:PutObject")

        # List buckets
        buckets: list[str] = []
        try:
            resp = s3.list_buckets()
            api_calls.append("s3:ListBuckets")
            buckets = [b["Name"] for b in resp.get("Buckets", [])]
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"s3:ListBuckets failed: {code}")

        # Categorize buckets
        no_versioning: list[str] = []
        versioning_no_mfa: list[str] = []
        protected: list[str] = []

        scan_limit = min(len(buckets), _BUCKET_SCAN_LIMIT)
        if len(buckets) > _BUCKET_SCAN_LIMIT:
            findings.append(
                f"[INFO] {len(buckets)} buckets found — scanning first {_BUCKET_SCAN_LIMIT} "
                "to avoid memory issues."
            )

        for bucket in buckets[:scan_limit]:
            try:
                ver_resp = s3.get_bucket_versioning(Bucket=bucket)
                api_calls.append("s3:GetBucketVersioning")
                versioning_status = ver_resp.get("Status", "")
                mfa_delete = ver_resp.get("MFADelete", "")

                if versioning_status != "Enabled":
                    no_versioning.append(bucket)
                elif mfa_delete != "Enabled":
                    versioning_no_mfa.append(bucket)
                else:
                    protected.append(bucket)

            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("AccessDenied", "AccessDeniedException"):
                    errors.append(f"s3:GetBucketVersioning for '{bucket}' — AccessDenied")
                else:
                    errors.append(f"s3:GetBucketVersioning for '{bucket}' failed: {code}")

        # Build findings
        if no_versioning:
            findings.append(
                f"[CRITICAL] {len(no_versioning)} bucket(s) have NO versioning enabled — "
                "objects cannot be recovered after deletion (batch/individual ransomware)"
            )
            for b in no_versioning:
                findings.append(f"  No versioning: '{b}'")

        if versioning_no_mfa:
            findings.append(
                f"[HIGH] {len(versioning_no_mfa)} bucket(s) have versioning but no MFA delete — "
                "versions can be purged (client-side encryption ransomware)"
            )
            for b in versioning_no_mfa:
                findings.append(f"  Versioning w/o MFA delete: '{b}'")

        if protected:
            findings.append(
                f"[INFO] {len(protected)} bucket(s) are protected with versioning + MFA delete"
            )

        if delete_perm is True:
            findings.append(
                "[RISK] Principal has s3:DeleteObject — "
                "can execute individual/batch deletion ransomware"
            )
        elif delete_perm is None:
            findings.append("[UNKNOWN] s3:DeleteObject permission could not be determined")

        if put_perm is True:
            findings.append(
                "[RISK] Principal has s3:PutObject — "
                "can overwrite objects with encrypted versions"
            )
        elif put_perm is None:
            findings.append("[UNKNOWN] s3:PutObject permission could not be determined")

        observed: list[str] = []
        if delete_perm is True:
            observed.append("s3:DeleteObject")
        if put_perm is True:
            observed.append("s3:PutObject")

        detections = [
            "GuardDuty: Impact:S3/MaliciousIPCaller",
            "CloudTrail: high-volume DeleteObject or PutObject events",
            "S3 server access logs: mass delete patterns",
            "Security Hub: S3 bucket without versioning findings",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Scanned {scan_limit}/{len(buckets)} bucket(s): "
                f"{len(no_versioning)} no versioning, "
                f"{len(versioning_no_mfa)} versioning w/o MFA delete, "
                f"{len(protected)} protected."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=observed,
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,
            errors=errors,
            metadata={
                "total_buckets": len(buckets),
                "scanned_buckets": scan_limit,
                "no_versioning_count": len(no_versioning),
                "versioning_no_mfa_count": len(versioning_no_mfa),
                "protected_count": len(protected),
                "delete_object_permission": delete_perm,
                "put_object_permission": put_perm,
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "s3_ransomware_detection is dry-run only. "
            "Performing S3 ransomware operations is prohibited by the safety policy of this framework."
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


MODULE = S3RansomwareDetectionModule()
