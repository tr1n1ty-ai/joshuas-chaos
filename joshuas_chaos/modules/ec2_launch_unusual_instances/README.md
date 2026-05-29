# ec2_launch_unusual_instances

## Description

Simulate launching unusual EC2 instance types (large GPU/compute instances) that attackers use for crypto-mining or ML workloads. Execute launches a single `t3.micro` (NOT GPU types — lab safety) tagged `AttackLab=true` in an AttackLab-tagged subnet.

## MITRE ATT&CK

- **T1578.002** — Modify Cloud Compute Infrastructure: Create Cloud Instance

## Stratus Red Team

`aws.execution.ec2-launch-unusual-instances`

Note: The real Stratus technique launches `p2.xlarge` (GPU). This framework uses `t3.micro` for lab cost/safety.

## CloudTrail Events

- `RunInstances`
- `DescribeInstances`
- `TerminateInstances`

## Required Permissions

- `ec2:RunInstances`
- `ec2:DescribeInstances`
- `ec2:DescribeSubnets`
- `ec2:TerminateInstances`

## Detection Notes

- **CloudTrail**: `RunInstances` with unusual instance types (p3, p4, g4, c5n, hpc6a)
- **GuardDuty**: `CryptoCurrency:EC2/BitcoinTool.B` or `Execution:EC2/SuspiciousCommand`
- **Cost Anomaly Detection**: sudden spike in EC2 spend

## Prerequisites

A subnet tagged `AttackLab=true` must exist in the target region for execute mode.

## Cleanup

Terminates all instances tagged `Name=AttackLabUnusualInstanceTest` that are not already terminated. Idempotent.
