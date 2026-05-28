"""CodeBuild Abuse Module.

Detect codebuild:StartBuild / codebuild:UpdateProject risk.
Execute: Only run AttackLab-tagged CodeBuild projects with benign buildspec.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_BENIGN_BUILDSPEC = """version: 0.2
phases:
  build:
    commands:
      - aws sts get-caller-identity
      - echo "AttackLab codebuild_abuse test complete"
"""


class CodeBuildAbuseModule(ChaosModule):
    name = "codebuild_abuse"
    description = (
        "Detect codebuild:StartBuild / codebuild:UpdateProject risk and simulate "
        "by running an AttackLab-tagged CodeBuild project with a benign buildspec."
    )
    category = "execution"
    required_permissions = [
        "codebuild:ListProjects",
        "codebuild:BatchGetProjects",
        "codebuild:StartBuild",
        "codebuild:UpdateProject",
    ]
    cloudtrail_events = [
        "ListProjects",
        "BatchGetProjects",
        "StartBuild",
        "UpdateProject",
    ]
    mitre_attack = ["T1610"]
    destructive = False
    reversible = True

    _started_builds: list[str]

    def __init__(self) -> None:
        self._started_builds = []

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for AttackLab CodeBuild projects.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess CodeBuild abuse risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detect codebuild:StartBuild / UpdateProject risk."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        cb = context.get_client("codebuild")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["codebuild:StartBuild", "codebuild:UpdateProject"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        if perm_results.get("codebuild:StartBuild"):
            findings.append("[RISK] Principal has codebuild:StartBuild permission.")
        if perm_results.get("codebuild:UpdateProject"):
            findings.append("[RISK] Principal has codebuild:UpdateProject permission.")

        # List AttackLab projects
        attacklab_projects: list[str] = []
        try:
            resp = cb.list_projects()
            api_calls.append("codebuild:ListProjects")
            all_projects = resp.get("projects", [])
            attacklab_projects = [
                p for p in all_projects
                if p.startswith(config.resource_safety.allowed_name_prefix)
            ]
            findings.append(
                f"Total CodeBuild projects: {len(all_projects)}, "
                f"AttackLab-prefixed: {len(attacklab_projects)}"
            )
            if attacklab_projects:
                findings.append(
                    f"[DRY-RUN] Would run projects with benign buildspec: {attacklab_projects}"
                )
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"codebuild:ListProjects failed: {code}")

        detections = [
            "CloudTrail: codebuild:StartBuild",
            "CloudTrail: codebuild:UpdateProject (buildspec override)",
            "CodeBuild build logs in CloudWatch",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed CodeBuild abuse risk.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_projects),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Run AttackLab-tagged CodeBuild projects with benign buildspec override."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        cb = context.get_client("codebuild")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            resp = cb.list_projects()
            api_calls.append("codebuild:ListProjects")
            all_projects = resp.get("projects", [])
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"codebuild:ListProjects failed: {code}")
            all_projects = []

        attacklab_projects = [
            p for p in all_projects
            if p.startswith(config.resource_safety.allowed_name_prefix)
        ]

        if not attacklab_projects:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab CodeBuild projects found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-prefixed CodeBuild projects found."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=errors,
            )

        for project_name in attacklab_projects:
            try:
                checker.assert_resource_safe(project_name, {})
                resp = cb.start_build(
                    projectName=project_name,
                    buildspecOverride=_BENIGN_BUILDSPEC,
                )
                build_id = resp["build"]["id"]
                api_calls.append(f"codebuild:StartBuild ({project_name})")
                self._started_builds.append(build_id)
                findings.append(
                    f"[EXECUTE] Started build '{build_id}' for project '{project_name}' "
                    "with benign buildspec override."
                )
            except Exception as exc:
                errors.append(f"Failed to start build for '{project_name}': {exc}")

        detections = [
            "CloudTrail: codebuild:StartBuild with buildspecOverride",
            "CodeBuild build logs in CloudWatch",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Started {len(self._started_builds)} CodeBuild build(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["codebuild:StartBuild"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,  # builds complete on their own
            safe_to_execute=True,
            errors=errors,
            metadata={"started_builds": self._started_builds},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        findings = [
            "CodeBuild builds complete automatically — no cleanup needed.",
            f"Started build IDs: {self._started_builds or 'none'}",
        ]
        self._started_builds = []
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No active cleanup required for CodeBuild.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
            errors=[],
        )


MODULE = CodeBuildAbuseModule()
