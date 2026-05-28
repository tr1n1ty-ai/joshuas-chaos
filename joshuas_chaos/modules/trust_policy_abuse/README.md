# trust_policy_abuse

**Category:** privilege-escalation  
**MITRE ATT&CK:** T1098.003

## Description

Detects and simulates `iam:UpdateAssumeRolePolicy` abuse by modifying the
trust policy of `AttackLabTrustRole` with a benign test condition.

## Safety

- Only targets the role named exactly `AttackLabTrustRole`
- Backs up original trust policy before modification
- Cleanup restores the original policy

## Detection

- CloudTrail: `UpdateAssumeRolePolicy`
- IAM Access Analyzer: trust relationship change
