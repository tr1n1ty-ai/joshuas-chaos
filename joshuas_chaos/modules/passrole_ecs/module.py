"""PassRole + ECS Abuse Module.

Detect iam:PassRole + ecs:RunTask risk.
Execute: Run an AttackLab ECS task with benign sts:GetCallerIdentity command.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_TASK_FAMILY = "AttackLabPassRoleECSTest"
_CLUSTER_PREFIX = "AttackLab"


class PassRoleECSModule(ChaosModule):
    name = "passrole_ecs"
    description = (
        "Detect iam:PassRole + ecs:RunTask risk and simulate by running a "
        "benign AttackLab ECS task (sts:GetCallerIdentity only)."
    )
    category = "privilege-escalation"
    required_permissions = [
        "iam:PassRole",
        "ecs:RunTask",
        "ecs:StopTask",
        "ecs:DescribeTasks",
        "ecs:ListClusters",
        "ecs:RegisterTaskDefinition",
        "ecs:DeregisterTaskDefinition",
    ]
    cloudtrail_events = [
        "RunTask",
        "StopTask",
        "RegisterTaskDefinition",
        "DeregisterTaskDefinition",
    ]
    mitre_attack = ["T1610"]
    destructive = False
    reversible = True

    _task_arn: str | None = None
    _task_def_arn: str | None = None

    def __init__(self) -> None:
        self._task_arn = None
        self._task_def_arn = None

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        ecs = context.get_client("ecs")
        findings: list[str] = []
        api_calls: list[str] = []

        try:
            clusters = ecs.list_clusters()
            api_calls.append("ecs:ListClusters")
            lab_clusters = [
                c for c in clusters.get("clusterArns", [])
                if _CLUSTER_PREFIX in c
            ]
            if lab_clusters:
                findings.append(f"AttackLab ECS clusters found: {lab_clusters}")
            else:
                findings.append(
                    "No AttackLab ECS clusters found. "
                    "Create an ECS cluster with 'AttackLab' in the name."
                )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            findings.append(f"ecs:ListClusters failed: {code}")

        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for AttackLab ECS clusters.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detect iam:PassRole + ecs:RunTask risk."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        findings: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["iam:PassRole", "ecs:RunTask"],
        )

        has_passrole = perm_results.get("iam:PassRole", False)
        has_run = perm_results.get("ecs:RunTask", False)

        if has_passrole and has_run:
            findings.append(
                "[HIGH RISK] Principal has iam:PassRole AND ecs:RunTask. "
                "Can run a task with any passed role."
            )
        elif has_passrole:
            findings.append("[MEDIUM] Principal has iam:PassRole but not ecs:RunTask.")
        elif has_run:
            findings.append("[LOW] Principal has ecs:RunTask but not iam:PassRole.")
        else:
            findings.append("No iam:PassRole or ecs:RunTask permissions detected.")

        findings.append(
            f"[DRY-RUN] Would register task family '{_TASK_FAMILY}' and run on an AttackLab cluster."
        )

        detections = [
            "CloudTrail: ecs:RunTask with taskRoleArn",
            "CloudTrail: iam:PassRole for ecs-tasks.amazonaws.com",
            "GuardDuty: PrivilegeEscalation:ECS/MaliciousContainerOnEC2",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed PassRole + ECS RunTask risk.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=["iam:SimulatePrincipalPolicy"],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Register and run a benign AttackLab ECS task."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe(_TASK_FAMILY, {})

        ecs = context.get_client("ecs")
        iam = context.get_client("iam")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        # Find AttackLab cluster
        try:
            clusters_resp = ecs.list_clusters()
            api_calls.append("ecs:ListClusters")
            lab_clusters = [
                c for c in clusters_resp.get("clusterArns", [])
                if _CLUSTER_PREFIX in c
            ]
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ecs:ListClusters failed: {code}")
            lab_clusters = []

        if not lab_clusters:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab ECS cluster found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab ECS cluster found. No action taken."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=errors,
            )

        cluster_arn = lab_clusters[0]

        # Find AttackLab task role
        role_arn: str | None = None
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    if role["RoleName"].startswith("AttackLab"):
                        role_arn = role["Arn"]
                        break
                if role_arn:
                    break
            api_calls.append("iam:ListRoles")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"iam:ListRoles failed: {code}")

        if not role_arn:
            errors.append("No AttackLab IAM role found for task role.")

        # Register benign task definition
        task_def_kwargs = {
            "family": _TASK_FAMILY,
            "containerDefinitions": [
                {
                    "name": "attacklab-test",
                    "image": "amazon/aws-cli:latest",
                    "command": ["sts", "get-caller-identity"],
                    "essential": True,
                    "memory": 128,
                }
            ],
            "tags": [{"key": "AttackLab", "value": "true"}],
        }
        if role_arn:
            task_def_kwargs["taskRoleArn"] = role_arn

        try:
            reg_resp = ecs.register_task_definition(**task_def_kwargs)
            self._task_def_arn = reg_resp["taskDefinition"]["taskDefinitionArn"]
            api_calls.append(f"ecs:RegisterTaskDefinition ({_TASK_FAMILY})")
            findings.append(f"[EXECUTE] Registered task definition '{self._task_def_arn}'.")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"ecs:RegisterTaskDefinition failed: {code}")

        if self._task_def_arn:
            try:
                run_resp = ecs.run_task(
                    cluster=cluster_arn,
                    taskDefinition=self._task_def_arn,
                    launchType="FARGATE",
                    networkConfiguration={
                        "awsvpcConfiguration": {
                            "subnets": [],  # Lab must provide subnets
                            "assignPublicIp": "DISABLED",
                        }
                    },
                )
                api_calls.append(f"ecs:RunTask ({_TASK_FAMILY})")
                tasks = run_resp.get("tasks", [])
                if tasks:
                    self._task_arn = tasks[0]["taskArn"]
                    findings.append(
                        f"[EXECUTE] Task launched: {self._task_arn}. "
                        "Command: aws sts get-caller-identity (benign)."
                    )
                failures = run_resp.get("failures", [])
                for f in failures:
                    errors.append(f"ECS task launch failure: {f.get('reason', 'unknown')}")
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"ecs:RunTask failed: {code}")

        detections = [
            "CloudTrail: ecs:RunTask with taskRoleArn",
            "CloudTrail: iam:PassRole for ecs-tasks.amazonaws.com",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Launched benign ECS task on AttackLab cluster.",
            required_permissions=self.required_permissions,
            observed_permissions=["iam:PassRole", "ecs:RunTask"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=True,
            safe_to_execute=True,
            errors=errors,
            metadata={
                "task_arn": self._task_arn,
                "task_def_arn": self._task_def_arn,
            },
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Stop ECS task and deregister task definition. Idempotent."""
        identity = context.get_caller_identity()
        ecs = context.get_client("ecs")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        if self._task_arn:
            try:
                ecs.stop_task(task=self._task_arn, reason="AttackLab cleanup")
                api_calls.append(f"ecs:StopTask ({self._task_arn})")
                findings.append(f"[CLEANUP] Stopped ECS task '{self._task_arn}'.")
                self._task_arn = None
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in ("InvalidParameterException", "ClusterNotFoundException"):
                    findings.append("Task already stopped or not found — idempotent.")
                else:
                    errors.append(f"ecs:StopTask failed: {code}")

        if self._task_def_arn:
            try:
                ecs.deregister_task_definition(taskDefinition=self._task_def_arn)
                api_calls.append(f"ecs:DeregisterTaskDefinition ({self._task_def_arn})")
                findings.append(f"[CLEANUP] Deregistered task definition '{self._task_def_arn}'.")
                self._task_def_arn = None
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code == "InvalidParameterException":
                    findings.append("Task definition already deregistered — idempotent.")
                else:
                    errors.append(f"ecs:DeregisterTaskDefinition failed: {code}")

        if not findings:
            findings.append("No ECS task state to clean up.")

        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="ECS task cleaned up.",
            required_permissions=["ecs:StopTask", "ecs:DeregisterTaskDefinition"],
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
        )


MODULE = PassRoleECSModule()
