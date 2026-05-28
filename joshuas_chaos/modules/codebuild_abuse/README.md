# codebuild_abuse

**Category:** execution  
**MITRE ATT&CK:** T1610

## Description

Detects `codebuild:StartBuild` / `codebuild:UpdateProject` risk and simulates
by running AttackLab-tagged projects with a benign buildspec override that only
runs `aws sts get-caller-identity`.

## Safety

- Only runs projects prefixed with `AttackLab`
- Buildspec override: `aws sts get-caller-identity` only
