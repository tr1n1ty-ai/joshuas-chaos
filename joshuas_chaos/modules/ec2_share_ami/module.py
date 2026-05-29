"""EC2 Share AMI Module.

Simulate AMI exfiltration by making AttackLab-tagged private AMIs public.
Maps to Stratus Red Team aws.exfiltration.ec2-share-ami.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class EC2ShareAMIModule(ChaosModule):
    name = "ec2_share_ami"
    description = (
        "Simulate AMI exfiltration by making AttackLab-tagged private AMIs public "
        "or sharing with an external account. Dry-run only — execute sets launchPermission "
        "to public on AttackLab AMIs only."
        "Maps to Stratus Red Team aws.exfiltration.ec2-share-ami."
    )
    category = "exfiltration"
    required_permissions = [
        "ec2:DescribeImages",
        "ec2:ModifyImageAttribute",
    ]
    cloudtrail_events = [
        "DescribeImages",
        "ModifyImageAttribute",
    ]
    mitre_attack = ["T1537"]
    destructive = False
    reversible = True

    def _get_attacklab_amis(self, ec2) -> tuple[list[dict], list[dict]]:
        """Return (all_amis, attacklab_amis) owned by self."""
        all_amis: list[dict] = []
        attacklab_amis: list[dict] = []
        try:
            response = ec2.describe_images(Owners=["self"])
            for image in response.get("Images", []):
                image_id = image["ImageId"]
                image_name = image.get("Name", image_id)
                tags = {t["Key"]: t["Value"] for t in image.get("Tags", [])}
                all_amis.append({"image_id": image_id, "name": image_name, "tags": tags})
                if tags.get("AttackLab", "").lower() == "true":
                    attacklab_amis.append(
                        {"image_id": image_id, "name": image_name, "tags": tags}
                    )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ec2:DescribeImages failed: %s", code)
        return all_amis, attacklab_amis

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check AMI launch permission modification capabilities.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess AMI sharing exfiltration risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check permissions and enumerate AttackLab-tagged AMIs."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ec2:ModifyImageAttribute"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        simulation_available = any(v is not None for v in perm_results.values())
        if not simulation_available:
            findings.append(
                "[UNKNOWN] iam:SimulatePrincipalPolicy unavailable — "
                "permission state cannot be determined. Treat as potential risk."
            )

        if perm_results.get("ec2:ModifyImageAttribute") is True:
            findings.append("[RISK] Principal has ec2:ModifyImageAttribute permission.")

        all_amis, attacklab_amis = self._get_attacklab_amis(ec2)
        api_calls.append("ec2:DescribeImages")

        n_total = len(all_amis)
        n_attacklab = len(attacklab_amis)
        findings.append(f"Total visible AMIs (owned by self): {n_total}")
        findings.append(f"AttackLab-tagged AMIs: {n_attacklab}")
        findings.append(
            f"[DRY-RUN] Would call ec2:ModifyImageAttribute to make "
            f"{n_attacklab} AttackLab AMIs public"
        )

        detections = [
            "CloudTrail: ec2:ModifyImageAttribute with launchPermission Group=all",
            "AWS Config: ec2-ami-public rule",
            "GuardDuty: Policy:IAMUser/S3BlockPublicAccessDisabled (analogous)",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {n_total} total AMI(s), {n_attacklab} AttackLab-tagged. No changes made."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a is True],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_amis),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Make AttackLab-tagged AMIs public via launchPermission."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_amis, attacklab_amis = self._get_attacklab_amis(ec2)
        api_calls.append("ec2:DescribeImages")

        modified: list[str] = []
        for ami in attacklab_amis:
            image_id = ami["image_id"]
            image_name = ami["name"]
            tags = ami["tags"]

            try:
                checker.assert_resource_safe(image_name, tags)
            except SafetyError as exc:
                errors.append(f"Resource safety check failed for '{image_name}': {exc}")
                continue

            try:
                ec2.modify_image_attribute(
                    ImageId=image_id,
                    Attribute="launchPermission",
                    LaunchPermission={"Add": [{"Group": "all"}]},
                )
                api_calls.append(f"ec2:ModifyImageAttribute ({image_id})")
                findings.append(
                    f"[EXECUTE] Made AMI '{image_id}' ({image_name}) public "
                    "via launchPermission Group=all."
                )
                modified.append(image_id)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"ec2:ModifyImageAttribute failed for '{image_id}': {code}")

        detections = [
            "CloudTrail: ec2:ModifyImageAttribute with launchPermission Group=all",
            "AWS Config: ec2-ami-public rule",
            "GuardDuty: Policy:IAMUser/S3BlockPublicAccessDisabled (analogous)",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Made {len(modified)} AttackLab AMI(s) public.",
            required_permissions=self.required_permissions,
            observed_permissions=["ec2:ModifyImageAttribute"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
            metadata={"modified_ami_ids": modified},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Remove public launchPermission from AttackLab AMIs. Idempotent."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        all_amis, attacklab_amis = self._get_attacklab_amis(ec2)
        api_calls.append("ec2:DescribeImages")

        for ami in attacklab_amis:
            image_id = ami["image_id"]
            image_name = ami["name"]

            try:
                ec2.modify_image_attribute(
                    ImageId=image_id,
                    Attribute="launchPermission",
                    LaunchPermission={"Remove": [{"Group": "all"}]},
                )
                api_calls.append(f"ec2:ModifyImageAttribute ({image_id})")
                findings.append(
                    f"[CLEANUP] Removed public launchPermission from AMI "
                    f"'{image_id}' ({image_name})."
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"):
                    findings.append(
                        f"AMI '{image_id}' not found — already removed or deleted (idempotent)."
                    )
                else:
                    errors.append(
                        f"ec2:ModifyImageAttribute cleanup failed for '{image_id}': {code}"
                    )

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Removed public launchPermission from AttackLab AMIs.",
            required_permissions=["ec2:DescribeImages", "ec2:ModifyImageAttribute"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = EC2ShareAMIModule()
