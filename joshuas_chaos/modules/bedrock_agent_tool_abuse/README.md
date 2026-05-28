# bedrock_agent_tool_abuse

**Category:** execution  
**MITRE ATT&CK:** T1059

## Description

Enumerates Bedrock agents, action groups, Lambda tools, and roles. Execute
invokes only explicitly configured AttackLab agents from config.yaml.

## Configuration

```yaml
modules:
  bedrock_agent_tool_abuse:
    enabled: true
    allowed_agent_ids:
      - "ATTACKLABAGENTID"
    allowed_action_groups:
      - "AttackLabActionGroup"
```

## Safety

- Module disabled by default (`enabled: false`)
- Only invokes agents listed in `allowed_agent_ids`
- Input text is a benign "what is your name?" prompt only

## Detection

- CloudTrail: `bedrock:InvokeAgent`
- Bedrock model invocation logs
