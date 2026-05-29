"""EC2 Steal Instance Credentials Module.

Simulate EC2 instance credential theft by using SSM to run a benign command on an
AttackLab-tagged instance that queries the IMDS endpoint for the IAM role name ONLY.

SAFETY NOTE: The benign variant queries only:
  /latest/meta-data/iam/security-credentials/
which returns the IAM role name attached to the instance. A real attacker would follow
up with /latest/meta-data/iam/security-credentials/{role_name} to get actual temporary
credential values (AccessKeyId, SecretAccessKey, Token). This module explicitly does NOT
perform that second step — only the role name is retrieved and recorded.

Maps to Stratus Red Team aws.credential-access.ec2-steal-instance-credentials.
"""

import logging
import time

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_SSM_DOCUMENT = "AWS-RunShellScript"
# Query role name ONLY — never the credential values endpoint
_IMDS_ROLE_NAME_CMD = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"


class EC2StealInstanceCredentialsModule(ChaosModule):
    name = "ec2_steal_instance_credentials"
    description = (
        "Simulate EC2 instance credential theft by using SSM to run a benign command on an "
        "AttackLab-tagged instance that queries the IMDS endpoint for the IAM role name only "
        "(never the actual credential values). "
        "Maps to Stratus Red Team aws.credential-access.ec2-steal-instance-credentials."
    )
    category = "credential-access"
    required_permissions = [
        "ec2:DescribeInstances",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:DescribeInstanceInformation",
    ]
    cloudtrail_events = ["DescribeInstances", "SendCommand", "GetCommandInvocation"]
    mitre_attack = ["T1552.005"]
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
            risk_summary="Check for SSM-managed AttackLab instances accessible for IMDS credential theft simulation.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to enumerate AttackLab instances and assess SSM-based IMDS access."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def _get_attacklab_instances(self, ec2, config: AppConfig) -> list[dict]:
        """Return EC2 instances tagged AttackLab=true with their state and tags."""
        tag_key = config.resource_safety.required_tag_key
        tag_val = config.resource_safety.required_tag_value
        instances: list[dict] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": f"tag:{tag_key}", "Values": [tag_val]}]
            ):
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        instances.append({
                            "instance_id": inst["InstanceId"],
                            "state": inst.get("State", {}).get("Name", "unknown"),
                            "tags": tags,
                        })
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ec2:DescribeInstances failed: %s", code)
        return instances

    def _get_ssm_managed_instance_ids(self, ssm) -> set[str]:
        """Return set of instance IDs registered with SSM."""
        managed: set[str] = []
        try:
            paginator = ssm.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                for info in page.get("InstanceInformationList", []):
                    iid = info.get("InstanceId", "")
                    if iid:
                        managed.append(iid)
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.warning("ssm:DescribeInstanceInformation failed: %s", code)
        return set(managed)

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate AttackLab instances and assess SSM-based IMDS role-name access."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        ec2 = context.get_client("ec2")
        ssm = context.get_client("ssm")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Check SendCommand permission
        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["ssm:SendCommand"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")
        send_cmd_perm: bool | None = perm_results.get("ssm:SendCommand")

        if send_cmd_perm is True:
            findings.append("[RISK] Principal has ssm:SendCommand permission.")
        elif send_cmd_perm is None:
            findings.append("[UNKNOWN] ssm:SendCommand permission could not be determined.")

        # Enumerate AttackLab-tagged instances
        attacklab_instances = self._get_attacklab_instances(ec2, config)
        api_calls.append("ec2:DescribeInstances")
        findings.append(f"AttackLab-tagged EC2 instances found: {len(attacklab_instances)}")
        for inst in attacklab_instances:
            findings.append(f"  Instance '{inst['instance_id']}' (state={inst['state']})")

        # Find SSM-managed instances
        ssm_managed_ids = self._get_ssm_managed_instance_ids(ssm)
        api_calls.append("ssm:DescribeInstanceInformation")

        # Cross-reference
        ssm_eligible = [
            i for i in attacklab_instances if i["instance_id"] in ssm_managed_ids
        ]
        findings.append(
            f"AttackLab instances with SSM agent registered: {len(ssm_eligible)}"
        )
        for inst in ssm_eligible:
            findings.append(f"  SSM-managed: '{inst['instance_id']}' (state={inst['state']})")

        n_eligible = len(ssm_eligible)
        findings.append(
            f"[DRY-RUN] Would send benign IMDS role-name query to {n_eligible} "
            f"AttackLab SSM-managed instance(s)"
        )
        findings.append(
            "Attack path: SSM SendCommand → "
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
            "→ get role name → curl credentials endpoint → exfiltrate temporary credentials"
        )
        findings.append(
            "[NOTE] This module only queries the role name endpoint. "
            "The credentials endpoint is NEVER queried."
        )

        detections = [
            "GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "CloudTrail: ssm:SendCommand followed by sts:GetCallerIdentity from unexpected IP",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Found {len(attacklab_instances)} AttackLab instance(s), "
                f"{n_eligible} SSM-managed and eligible for IMDS role-name query."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(ssm_eligible),
            errors=errors,
            metadata={
                "attacklab_instance_ids": [i["instance_id"] for i in attacklab_instances],
                "ssm_eligible_ids": [i["instance_id"] for i in ssm_eligible],
            },
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Send benign IMDS role-name query via SSM to AttackLab-tagged instances.

        SAFETY: Only queries /latest/meta-data/iam/security-credentials/ which returns
        the IAM role name. NEVER queries the role-specific credential endpoint.
        """
        identity = context.get_caller_identity()
        safety = SafetyChecker(config, identity)
        safety.assert_account_allowed()
        safety.assert_region_allowed(context.region)

        ec2 = context.get_client("ec2")
        ssm = context.get_client("ssm")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Find running AttackLab instances that are SSM-managed
        attacklab_instances = self._get_attacklab_instances(ec2, config)
        api_calls.append("ec2:DescribeInstances")
        ssm_managed_ids = self._get_ssm_managed_instance_ids(ssm)
        api_calls.append("ssm:DescribeInstanceInformation")

        eligible = [
            i for i in attacklab_instances
            if i["state"] == "running" and i["instance_id"] in ssm_managed_ids
        ]

        if not eligible:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No running AttackLab SSM-managed instances found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No running AttackLab SSM-managed instances found."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        role_names_found: list[str] = []

        for inst in eligible:
            instance_id = inst["instance_id"]
            cmd_id: str | None = None

            try:
                resp = ssm.send_command(
                    InstanceIds=[instance_id],
                    DocumentName=_SSM_DOCUMENT,
                    Parameters={"commands": [_IMDS_ROLE_NAME_CMD]},
                    Comment="AttackLab ec2_steal_instance_credentials — IMDS role-name only",
                    TimeoutSeconds=30,
                )
                cmd_id = resp["Command"]["CommandId"]
                api_calls.append(f"ssm:SendCommand ({instance_id})")
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"ssm:SendCommand failed for '{instance_id}': {code}")
                continue

            # Poll for result — max 6 attempts, 5s between each
            role_name = "[UNKNOWN]"
            for attempt in range(6):
                time.sleep(5)
                try:
                    inv_resp = ssm.get_command_invocation(
                        CommandId=cmd_id,
                        InstanceId=instance_id,
                    )
                    api_calls.append(f"ssm:GetCommandInvocation ({instance_id})")
                    status = inv_resp.get("Status", "")
                    if status in ("Success", "Failed", "TimedOut", "Cancelled"):
                        if status == "Success":
                            # Strip whitespace; this is ONLY the role name string
                            role_name = (inv_resp.get("StandardOutputContent", "") or "").strip()
                            if not role_name:
                                role_name = "[EMPTY — no IAM role attached]"
                        else:
                            role_name = f"[COMMAND STATUS: {status}]"
                        break
                    logger.debug(
                        "Attempt %d/%d: command %s on %s status=%s",
                        attempt + 1, 6, cmd_id, instance_id, status,
                    )
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "Unknown")
                    errors.append(
                        f"ssm:GetCommandInvocation failed for '{instance_id}': {code}"
                    )
                    break

            role_names_found.append(role_name)
            findings.append(
                f"[EXECUTE] IMDS role name query returned '{role_name}' on instance "
                f"'{instance_id}'. Credential endpoint NOT queried."
            )

        detections = [
            "GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "CloudTrail: ssm:SendCommand followed by sts:GetCallerIdentity from unexpected IP",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"Queried IMDS role name on {len(eligible)} instance(s). "
                "Credential endpoint was NOT queried."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=["ssm:SendCommand", "ssm:GetCommandInvocation"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={
                "queried_instance_ids": [i["instance_id"] for i in eligible],
                "role_names": role_names_found,
            },
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — SSM commands complete on their own.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["SSM commands complete on their own — no state to clean up."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = EC2StealInstanceCredentialsModule()
