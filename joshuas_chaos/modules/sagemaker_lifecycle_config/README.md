# sagemaker_lifecycle_config

## Description

Detect if principal can execute commands on SageMaker Notebook instances via lifecycle configuration updates. Execute creates or updates a lifecycle config named `AttackLabLifecycleTest` with a benign OnStart script and associates it with AttackLab-prefixed notebooks. Notebooks are NOT restarted.

## MITRE ATT&CK

- **T1059.006** — Command and Scripting Interpreter: Python
- **T1610** — Deploy Container

## Stratus Red Team

`aws.execution.sagemaker-update-lifecycle-config`

## CloudTrail Events

- `ListNotebookInstances`
- `ListNotebookInstanceLifecycleConfigs`
- `UpdateNotebookInstanceLifecycleConfig`

## Required Permissions

- `sagemaker:ListNotebookInstances`
- `sagemaker:ListNotebookInstanceLifecycleConfigs`
- `sagemaker:UpdateNotebookInstanceLifecycleConfig`
- `sagemaker:DescribeNotebookInstance`

## Detection Notes

- **CloudTrail**: `UpdateNotebookInstanceLifecycleConfig`
- **GuardDuty**: No specific finding for this technique — detection gap
- Lifecycle scripts execute as root when notebooks start or restart

## Prerequisites

At least one SageMaker Notebook Instance with a name starting with `AttackLab` must exist.

## Cleanup

Restores the original lifecycle config association on all modified notebooks. If the notebook originally had no lifecycle config, it is disassociated (manual deletion of the `AttackLabLifecycleTest` config resource may still be required). Idempotent.
