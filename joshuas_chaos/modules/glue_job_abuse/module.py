"""Glue Job Abuse Module.

Detect glue:CreateJob / glue:UpdateJob / glue:StartJobRun risk.
Execute: Only run AttackLab-tagged Glue jobs with benign behavior.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")

_JOB_NAME = "AttackLabGlueJobTest"


class GlueJobAbuseModule(ChaosModule):
    name = "glue_job_abuse"
    description = (
        "Detect glue:CreateJob / glue:UpdateJob / glue:StartJobRun risk and simulate "
        "by running AttackLab-tagged Glue jobs."
    )
    category = "execution"
    required_permissions = [
        "glue:GetJobs",
        "glue:CreateJob",
        "glue:UpdateJob",
        "glue:StartJobRun",
        "glue:GetJobRun",
        "glue:GetTags",
    ]
    cloudtrail_events = [
        "GetJobs",
        "CreateJob",
        "UpdateJob",
        "StartJobRun",
    ]
    mitre_attack = ["T1610"]
    destructive = False
    reversible = True

    _job_run_ids: list[str]

    def __init__(self) -> None:
        self._job_run_ids = []

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check for AttackLab Glue jobs.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess Glue job abuse risk."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Detect Glue job creation/update/run risk."""
        from joshuas_chaos.core.permissions import PermissionChecker

        identity = context.get_caller_identity()
        checker = PermissionChecker(context)
        glue = context.get_client("glue")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        perm_results = checker.simulate_permissions(
            principal_arn=identity.arn,
            actions=["glue:CreateJob", "glue:UpdateJob", "glue:StartJobRun"],
        )
        api_calls.append("iam:SimulatePrincipalPolicy")

        for perm, allowed in perm_results.items():
            if allowed:
                findings.append(f"[RISK] Principal has {perm}")

        attacklab_jobs: list[str] = []
        try:
            resp = glue.get_jobs()
            api_calls.append("glue:GetJobs")
            for job in resp.get("Jobs", []):
                name = job.get("Name", "")
                if name.startswith(config.resource_safety.allowed_name_prefix):
                    attacklab_jobs.append(name)
            findings.append(
                f"Total Glue jobs: {len(resp.get('Jobs', []))}, "
                f"AttackLab: {len(attacklab_jobs)}"
            )
            if attacklab_jobs:
                findings.append(f"[DRY-RUN] Would run jobs: {attacklab_jobs}")
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"glue:GetJobs failed: {code}")

        detections = [
            "CloudTrail: glue:StartJobRun",
            "CloudTrail: glue:UpdateJob (script override)",
            "Glue job CloudWatch logs",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Assessed Glue job abuse risk.",
            required_permissions=self.required_permissions,
            observed_permissions=[p for p, a in perm_results.items() if a],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(attacklab_jobs),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Run AttackLab-tagged Glue jobs."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        glue = context.get_client("glue")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        try:
            resp = glue.get_jobs()
            api_calls.append("glue:GetJobs")
            jobs = [
                j["Name"] for j in resp.get("Jobs", [])
                if j.get("Name", "").startswith(config.resource_safety.allowed_name_prefix)
            ]
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"glue:GetJobs failed: {code}")
            jobs = []

        if not jobs:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No AttackLab Glue jobs found.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=api_calls,
                cloudtrail_events=self.cloudtrail_events,
                findings=["No AttackLab-prefixed Glue jobs found."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=errors,
            )

        for job_name in jobs:
            try:
                checker.assert_resource_safe(job_name, {})
                resp = glue.start_job_run(JobName=job_name)
                run_id = resp["JobRunId"]
                self._job_run_ids.append(run_id)
                api_calls.append(f"glue:StartJobRun ({job_name})")
                findings.append(
                    f"[EXECUTE] Started Glue job '{job_name}' run ID: {run_id}"
                )
            except Exception as exc:
                errors.append(f"glue:StartJobRun failed for '{job_name}': {exc}")

        detections = [
            "CloudTrail: glue:StartJobRun",
            "Glue CloudWatch log group",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Started {len(self._job_run_ids)} Glue job run(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["glue:StartJobRun"],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={"job_run_ids": self._job_run_ids},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        findings = [
            "Glue job runs complete on their own — no cleanup needed.",
            f"Job run IDs: {self._job_run_ids or 'none'}",
        ]
        self._job_run_ids = []
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No active cleanup required for Glue.",
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


MODULE = GlueJobAbuseModule()
