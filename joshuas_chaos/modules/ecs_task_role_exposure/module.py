"""ECS Task Role Exposure Module.

Dry-run ONLY.
List ECS task definitions using paginator.
Report task definitions that have taskRoleArn set.
Does NOT retrieve credentials.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class ECSTaskRoleExposureModule(ChaosModule):
    name = "ecs_task_role_exposure"
    description = (
        "List ECS task definitions with taskRoleArn set and assess exposure risk. "
        "Dry-run only — does NOT retrieve credentials."
    )
    category = "credential-access"
    required_permissions = [
        "ecs:ListTaskDefinitions",
        "ecs:DescribeTaskDefinition",
    ]
    cloudtrail_events = [
        "ListTaskDefinitions",
        "DescribeTaskDefinition",
    ]
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
            risk_summary="Read-only check of ECS task definitions.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to identify task definitions with taskRoleArn set."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=False,  # dry-run only
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """List ECS task definitions and report those with taskRoleArn."""
        identity = context.get_caller_identity()
        ecs = context.get_client("ecs")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        task_def_arns: list[str] = []
        try:
            paginator = ecs.get_paginator("list_task_definitions")
            for page in paginator.paginate(status="ACTIVE"):
                api_calls.append("ecs:ListTaskDefinitions")
                task_def_arns.extend(page.get("taskDefinitionArns", []))
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ecs:ListTaskDefinitions failed: {code}")

        findings.append(f"Total active ECS task definitions: {len(task_def_arns)}")

        with_role: list[dict] = []
        without_role: list[str] = []

        for arn in task_def_arns[:50]:  # limit to avoid excessive API calls
            try:
                resp = ecs.describe_task_definition(taskDefinition=arn)
                api_calls.append(f"ecs:DescribeTaskDefinition ({arn.split('/')[-1]})")
                td = resp.get("taskDefinition", {})
                task_role = td.get("taskRoleArn", "")
                execution_role = td.get("executionRoleArn", "")
                family = td.get("family", "")

                if task_role:
                    with_role.append({
                        "family": family,
                        "arn": arn,
                        "task_role_arn": task_role,
                        "execution_role_arn": execution_role,
                    })
                else:
                    without_role.append(family)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"ecs:DescribeTaskDefinition failed for {arn}: {code}")

        findings.append(f"Task definitions WITH taskRoleArn: {len(with_role)}")
        findings.append(f"Task definitions without taskRoleArn: {len(without_role)}")

        for td in with_role:
            findings.append(
                f"[FINDING] Task '{td['family']}' has taskRoleArn='{td['task_role_arn']}' — "
                "credentials accessible from within the container via ECS credential endpoint."
            )

        if not with_role:
            findings.append("No task definitions with taskRoleArn found.")

        detections = [
            "CloudTrail: ecs:ListTaskDefinitions + DescribeTaskDefinition enumeration",
            "GuardDuty: CredentialAccess:Container/MaliciousIPCaller",
            "Container-side: unusual metadata endpoint access patterns",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=(
                f"{len(with_role)} task definition(s) with taskRoleArn set (potential credential exposure)."
                if with_role
                else "No task definitions with taskRoleArn found."
            ),
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=False,  # dry-run only module
            errors=errors,
            metadata={"task_defs_with_role": [t["family"] for t in with_role]},
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        raise NotImplementedError(
            "ecs_task_role_exposure is a dry-run only module. "
            "It does not retrieve ECS task credentials."
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["No state created by this module."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = ECSTaskRoleExposureModule()
