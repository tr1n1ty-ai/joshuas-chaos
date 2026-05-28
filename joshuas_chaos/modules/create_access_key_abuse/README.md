# create_access_key_abuse

**Category:** credential-access  
**MITRE ATT&CK:** T1098.001

## Description

Simulates `iam:CreateAccessKey` abuse by creating a test access key on
AttackLab-prefixed IAM users only. The SecretAccessKey is never stored,
logged, or displayed.

## Safety

- Only targets IAM users named `AttackLab*`
- SecretAccessKey is immediately discarded after creation
- AccessKeyId is tracked for cleanup

## Detection

- CloudTrail: `CreateAccessKey` event
- Security Hub: IAM.3
