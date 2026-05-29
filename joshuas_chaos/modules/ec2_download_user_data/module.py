"""EC2 Download User Data Module.

Enumerate EC2 instances and retrieve their user data, which often contains
bootstrap scripts with hardcoded credentials, API keys, or configuration secrets.
Execute targets AttackLab-tagged instances only.

Maps to Stratus Red Team aws.discovery.ec2-download-user-data.
"""

import base64
import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class EC2DownloadUserDataModule(ChaosModule):
    name = "ec2_download_user_data"
    description = (
        "Enumerate EC2 instances and retrieve their user data, which often contains "
        "bootstrap scripts with hardcoded credentials, API keys, or configuration secrets. "
        "Execute targets AttackLab-tagged instances only. "
        "Maps to Stratus Red Team aws.discovery.ec2-download-user-data."
    )
    category = "discovery"
    required_permissions = ["ec2:DescribeInstances", "ec2:DescribeInstanceAttribute"]
    cloudtrail_events = ["DescribeInstances", "DescribeInstanceAttribute"]
    mitre_attack = ["T1552.005", "T1078.004"]
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
            risk_summary="Check for EC2 instances accessible for user data retrieval.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate EC2 instances and assess user data access."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _list_all_instances(self, ec2) -> list[dict]:
        """Return all visible EC2 instances (no tag filter)."""
        instances: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        instances.append({
                            "instance_id": inst["InstanceId"],
                            "state": inst.get("State", {}).get("Name", "unknown"),
                            "tags": tags,
                            "platform": inst.get("Platform", "linux"),
                        })
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ec2:DescribeInstances failed: %s", code)
        return instances

    def _get_attacklab_instances(self, all_instances: list[dict], config: AppConfig) -> list[dict]:
        """Filter to AttackLab-tagged instances from an already-fetched list."""
        tag_key = config.resource_safety.required_tag_key
        tag_val = config.resource_safety.required_tag_value
        return [
            i for i in all_instances
            if i["tags"].get(tag_key) == tag_val
        ]

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate all EC2 instances and assess user data retrieval risk."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check DescribeInstanceAttribute permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2:DescribeInstanceAttribute"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        attr_perm: bool | None = perm_results.get("ec2:DescribeInstanceAttribute")

        # Enumerate all instances (no tag filter)
        all_instances = self._list_all_instances(ec2)
        api_calls.append("ec2:DescribeInstances")
        n_total = len(all_instances)

        # Filter AttackLab-tagged separately
        attacklab_instances = self._get_attacklab_instances(all_instances, config)
        n_attacklab = len(attacklab_instances)

        findings.append(f"Total EC2 instances visible: {n_total}")
        findings.append(f"AttackLab-tagged instances: {n_attacklab}")

        for inst in all_instances:
            findings.append(
                f"  Instance '{inst['instance_id']}' "
                f"(state={inst['state']}, platform={inst['platform']})"
            )

        if attr_perm is True:
            findings.append(
                f"[RISK] Principal can retrieve user data from {n_total} visible EC2 instance(s) "
                "— user data frequently contains bootstrap secrets, credentials, and configuration"
            )
        elif attr_perm is None:
            findings.append(
                "[UNKNOWN] ec2:DescribeInstanceAttribute permission could not be determined"
            )

        findings.append(
            f"[DRY-RUN] Would retrieve user data from {n_attacklab} AttackLab-tagged instance(s)"
        )
        findings.append(
            "Note: user data is base64-encoded and often contains cloud-init scripts, "
            "AWS credentials, database passwords"
        )

        detections = [
            "CloudTrail: DescribeInstanceAttribute with attribute=userData",
            "No GuardDuty detection by default — this is a blind spot",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {n_total} total instance(s), {n_attacklab} AttackLab-tagged. "
                f"DescribeInstanceAttribute permission: "
                f"{'confirmed' if attr_perm is True else 'unknown' if attr_perm is None else 'denied'}."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_instances),
            errors=errors,
            metadata={
                "total_instance_count": n_total,
                "attacklab_instance_ids": [i["instance_id"] for i in attacklab_instances],
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Retrieve and mask user data from AttackLab-tagged EC2 instances."""
        from joshuas_chaos.core.masking import mask_string

        identity = context.get_caller_identity()
        safety = SafetyChecker(config, identity)
        safety.assert_account_allowed()
        safety.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Enumerate all instances then filter to AttackLab
        all_instances = self._list_all_instances(ec2)
        api_calls.append("ec2:DescribeInstances")
        attacklab_instances = self._get_attacklab_instances(all_instances, config)

        if not attacklab_instances:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab-tagged EC2 instances found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-tagged EC2 instances found."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        user_data_results: list[dict] = []

        for inst in attacklab_instances:
            instance_id = inst["instance_id"]
            try:
                resp = ec2.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute="userData",
                )
                api_calls.append(f"ec2:DescribeInstanceAttribute ({instance_id})")

                raw_b64 = resp.get("UserData", {}).get("Value", "")
                if not raw_b64:
                    findings.append(
                        f"[EXECUTE] Instance '{instance_id}': user data is empty or not set."
                    )
                    user_data_results.append({
                        "instance_id": instance_id,
                        "user_data_bytes": 0,
                        "sensitive_patterns_detected": False,
                        "masked_content_preview": "",
                    })
                    continue

                # Decode base64 user data
                raw_bytes = base64.b64decode(raw_b64)
                raw_text = raw_bytes.decode("utf-8", errors="replace")
                byte_length = len(raw_bytes)

                # ALWAYS mask before storing — never record raw user data
                masked_text = mask_string(raw_text)
                sensitive_detected = masked_text != raw_text
                preview = masked_text[:500]

                findings.append(
                    f"[EXECUTE] Instance '{instance_id}': retrieved user data "
                    f"({byte_length} bytes, sensitive_patterns_detected={sensitive_detected}). "
                    f"Preview (masked, first 500 chars): {preview!r}"
                )
                user_data_results.append({
                    "instance_id": instance_id,
                    "user_data_bytes": byte_length,
                    "sensitive_patterns_detected": sensitive_detected,
                    "masked_content_preview": preview,
                })

            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "AccessDenied":
                    errors.append(
                        f"ec2:DescribeInstanceAttribute denied for '{instance_id}': AccessDenied"
                    )
                else:
                    errors.append(
                        f"ec2:DescribeInstanceAttribute failed for '{instance_id}': {code}"
                    )

        detections = [
            "CloudTrail: DescribeInstanceAttribute with attribute=userData",
            "No GuardDuty detection by default — this is a blind spot",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Retrieved user data from {len(user_data_results)} AttackLab instance(s). "
                "All content masked before storage."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ec2:DescribeInstanceAttribute"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={"user_data_results": user_data_results},
        )

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


MODULE = EC2DownloadUserDataModule()
