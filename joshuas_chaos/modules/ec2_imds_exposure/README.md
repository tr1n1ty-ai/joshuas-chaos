# ec2_imds_exposure

**Category:** credential-access  
**MITRE ATT&CK:** T1552.005  
**Mode:** Dry-run ONLY

## Description

Enumerates EC2 instances and identifies those with IMDSv1 enabled
(`HttpTokens=optional`), which are vulnerable to SSRF-based credential theft.

## Safety

- Read-only: uses `ec2:DescribeInstances` only
- Does NOT query IMDS endpoints or retrieve any credentials

## Detection

- AWS Config: `ec2-imdsv2-check` rule
- Security Hub: EC2.8
