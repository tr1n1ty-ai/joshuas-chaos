# ecs_task_role_exposure

**Category:** credential-access  
**MITRE ATT&CK:** T1552.005  
**Mode:** Dry-run ONLY

## Description

Lists ECS task definitions and reports those with `taskRoleArn` set,
which expose IAM credentials to containers via the ECS credential endpoint.

## Safety

- Read-only: `ecs:ListTaskDefinitions` + `ecs:DescribeTaskDefinition`
- Does NOT query the ECS credential endpoint or retrieve credentials
