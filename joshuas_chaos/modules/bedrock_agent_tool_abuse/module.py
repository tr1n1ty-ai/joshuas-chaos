"""Bedrock Agent Tool Abuse Module.

dry_run: Enumerate Bedrock agents, action groups, Lambda tools, roles.
execute: Only invoke explicitly configured benign AttackLab agent/action group from config.
"""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class BedrockAgentToolAbuseModule(ChaosModule):
    name = "bedrock_agent_tool_abuse"
    description = (
        "Enumerate Bedrock agents and action groups, then simulate abuse by invoking "
        "only explicitly configured AttackLab agents."
    )
    category = "execution"
    required_permissions = [
        "bedrock:ListAgents",
        "bedrock:GetAgent",
        "bedrock:ListAgentActionGroups",
        "bedrock:InvokeAgent",
    ]
    cloudtrail_events = [
        "ListAgents",
        "GetAgent",
        "ListAgentActionGroups",
        "InvokeAgent",
    ]
    mitre_attack = ["T1059"]
    destructive = False
    reversible = True

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        module_cfg = config.modules.get("bedrock_agent_tool_abuse", {})
        enabled = module_cfg.get("enabled", False)
        allowed_agents = module_cfg.get("allowed_agent_ids", []) or []

        findings = [
            f"Module enabled: {enabled}",
            f"Configured allowed_agent_ids: {allowed_agents or 'none'}",
        ]
        if not enabled:
            findings.append(
                "Module is disabled in config.yaml. "
                "Set modules.bedrock_agent_tool_abuse.enabled=true to use."
            )

        return ModuleResult(
            module=self.name,
            mode="check_prereqs",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="Check Bedrock agent configuration.",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=[],
            cleanup_required=False,
            safe_to_execute=enabled and bool(allowed_agents),
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Enumerate Bedrock agents, action groups, and Lambda tools."""
        identity = context.get_caller_identity()
        module_cfg = config.modules.get("bedrock_agent_tool_abuse", {})
        enabled = module_cfg.get("enabled", False)
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []

        if not enabled:
            findings.append(
                "Module disabled in config.yaml. "
                "Set modules.bedrock_agent_tool_abuse.enabled=true to enumerate."
            )
            return ModuleResult(
                module=self.name,
                mode="dry-run",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="Module disabled.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=[],
                cloudtrail_events=self.cloudtrail_events,
                findings=findings,
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
            )

        bedrock = context.get_client("bedrock-agent")
        agents: list[dict] = []

        try:
            paginator = bedrock.get_paginator("list_agents")
            for page in paginator.paginate():
                api_calls.append("bedrock:ListAgents")
                for agent in page.get("agentSummaries", []):
                    agent_id = agent.get("agentId", "")
                    agent_name = agent.get("agentName", "")
                    status = agent.get("agentStatus", "")
                    agents.append({
                        "agent_id": agent_id,
                        "agent_name": agent_name,
                        "status": status,
                    })
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            errors.append(f"bedrock:ListAgents failed: {code}")
        except Exception as exc:
            errors.append(f"bedrock:ListAgents error: {exc}")

        findings.append(f"Total Bedrock agents found: {len(agents)}")

        for agent in agents:
            agent_id = agent["agent_id"]
            agent_name = agent["agent_name"]
            try:
                resp = bedrock.list_agent_action_groups(
                    agentId=agent_id,
                    agentVersion="DRAFT",
                )
                api_calls.append(f"bedrock:ListAgentActionGroups ({agent_id})")
                action_groups = resp.get("actionGroupSummaries", [])
                findings.append(
                    f"Agent '{agent_name}' ({agent_id}): "
                    f"{len(action_groups)} action group(s): "
                    f"{[ag.get('actionGroupName', '') for ag in action_groups]}"
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"ListAgentActionGroups failed for '{agent_id}': {code}")

        allowed_agent_ids = module_cfg.get("allowed_agent_ids", []) or []
        if allowed_agent_ids:
            findings.append(
                f"[DRY-RUN] Would invoke configured agent(s): {allowed_agent_ids}"
            )
        else:
            findings.append(
                "No allowed_agent_ids configured. "
                "Set modules.bedrock_agent_tool_abuse.allowed_agent_ids to use execute mode."
            )

        detections = [
            "CloudTrail: bedrock:InvokeAgent",
            "Bedrock model invocation logs",
            "CloudWatch: Bedrock agent trace logs",
        ]

        return ModuleResult(
            module=self.name,
            mode="dry-run",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Found {len(agents)} Bedrock agent(s).",
            required_permissions=self.required_permissions,
            observed_permissions=[],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=bool(allowed_agent_ids),
            errors=errors,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Invoke only explicitly configured AttackLab agents."""
        identity = context.get_caller_identity()
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)

        module_cfg = config.modules.get("bedrock_agent_tool_abuse", {})
        enabled = module_cfg.get("enabled", False)
        allowed_agent_ids = module_cfg.get("allowed_agent_ids", []) or []
        if not enabled:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="Module disabled in config.yaml.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=[],
                cloudtrail_events=self.cloudtrail_events,
                findings=["Module is disabled. Set enabled=true in config.yaml."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        if not allowed_agent_ids:
            return ModuleResult(
                module=self.name,
                mode="execute",
                account_id=identity.account_id,
                principal_arn=identity.arn,
                region=context.region,
                risk_summary="No allowed_agent_ids configured.",
                required_permissions=self.required_permissions,
                observed_permissions=[],
                aws_api_calls=[],
                cloudtrail_events=self.cloudtrail_events,
                findings=["No allowed_agent_ids in config. Cannot execute without explicit configuration."],
                detections=[],
                cleanup_required=False,
                safe_to_execute=False,
                errors=[],
            )

        bedrock_rt = context.get_client("bedrock-agent-runtime")
        findings: list[str] = []
        errors: list[str] = []
        api_calls: list[str] = []
        invoked: list[str] = []

        for agent_id in allowed_agent_ids:
            # Validate agent name starts with AttackLab
            try:
                checker.assert_resource_safe(agent_id, {})
            except Exception:
                # agent_id might be a UUID — check name via get_agent
                errors.append(
                    f"Agent ID '{agent_id}' does not pass safety check. "
                    "Ensure the agent is named with 'AttackLab' prefix."
                )
                continue

            try:
                bedrock_rt.invoke_agent(
                    agentId=agent_id,
                    agentAliasId="TSTALIASID",  # Default test alias
                    sessionId="attacklab-test-session",
                    inputText="AttackLab test: what is your name?",
                )
                api_calls.append(f"bedrock:InvokeAgent ({agent_id})")
                invoked.append(agent_id)
                findings.append(
                    f"[EXECUTE] Invoked Bedrock agent '{agent_id}'. "
                    "Input: 'AttackLab test: what is your name?'"
                )
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(f"bedrock:InvokeAgent failed for '{agent_id}': {code}")
            except Exception as exc:
                errors.append(f"InvokeAgent error for '{agent_id}': {exc}")

        detections = [
            "CloudTrail: bedrock:InvokeAgent",
            "Bedrock model invocation logs",
        ]

        return ModuleResult(
            module=self.name,
            mode="execute",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary=f"Invoked {len(invoked)} Bedrock agent(s).",
            required_permissions=self.required_permissions,
            observed_permissions=["bedrock:InvokeAgent"] if invoked else [],
            aws_api_calls=api_calls,
            cloudtrail_events=self.cloudtrail_events,
            findings=findings,
            detections=detections,
            cleanup_required=False,
            safe_to_execute=True,
            errors=errors,
            metadata={"invoked_agents": invoked},
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name,
            mode="cleanup",
            account_id=identity.account_id,
            principal_arn=identity.arn,
            region=context.region,
            risk_summary="No cleanup required — agent invocations are stateless.",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=["Bedrock agent invocations are stateless. No cleanup needed."],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )


MODULE = BedrockAgentToolAbuseModule()
