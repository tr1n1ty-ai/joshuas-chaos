"""IAM permission simulation for pre-flight checks."""

import logging

import botocore.exceptions

from joshuas_chaos.core.aws_context import AWSContext

logger = logging.getLogger("joshuas_chaos")


class PermissionChecker:
    """Uses iam:SimulatePrincipalPolicy to test permissions before acting.

    Falls back gracefully if the caller lacks permission to simulate.
    """

    def __init__(self, context: AWSContext) -> None:
        self._context = context

    def simulate_permissions(
        self,
        principal_arn: str,
        actions: list[str],
        resource: str = "*",
    ) -> dict[str, bool | None]:
        """Simulate the given IAM actions for a principal.

        Returns a dict mapping action -> result where:
          True  = simulation confirmed allowed
          False = simulation confirmed denied
          None  = simulation unavailable (AccessDenied on SimulatePrincipalPolicy
                  or other error) — callers must treat None as "unknown", not "safe"
        """
        if not actions:
            return {}

        results: dict[str, bool | None] = {}
        try:
            iam = self._context.get_client("iam")
            paginator = iam.get_paginator("simulate_principal_policy")
            pages = paginator.paginate(
                PolicySourceArn=principal_arn,
                ActionNames=actions,
                ResourceArns=[resource],
            )
            for page in pages:
                for eval_result in page.get("EvaluationResults", []):
                    action = eval_result["EvalActionName"]
                    decision = eval_result["EvalDecision"]
                    results[action] = decision == "allowed"

        except botocore.exceptions.ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                logger.warning(
                    "iam:SimulatePrincipalPolicy denied for %s — "
                    "permission state is unknown, not safe.",
                    principal_arn,
                )
            else:
                logger.error(
                    "Unexpected error simulating permissions for %s: %s",
                    principal_arn,
                    error_code,
                )
            return {action: None for action in actions}
        except Exception as exc:
            logger.error(
                "Failed to simulate permissions for %s: %s", principal_arn, exc
            )
            return {action: None for action in actions}

        # Fill in any actions not returned by the API as denied (simulation ran but omitted them)
        for action in actions:
            if action not in results:
                results[action] = False

        logger.info(
            "Permission simulation for %s: %s",
            principal_arn,
            {k: ("allowed" if v is True else "denied" if v is False else "unknown") for k, v in results.items()},
        )
        return results
