# glue_job_abuse

**Category:** execution  
**MITRE ATT&CK:** T1610

## Description

Detects `glue:CreateJob` / `glue:UpdateJob` / `glue:StartJobRun` risk and
simulates by running AttackLab-prefixed Glue jobs.

## Safety

- Only runs jobs prefixed with `AttackLab`
- No script modification — runs existing job as-is
