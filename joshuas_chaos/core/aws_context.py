"""AWS context: wraps boto3 session, identity checks, and client access."""

import logging

import boto3
import botocore.exceptions

from joshuas_chaos.core.models import CallerIdentity

logger = logging.getLogger("joshuas_chaos")


class AWSContextError(Exception):
    """Raised for unrecoverable AWS context failures."""


class AWSContext:
    """Thin wrapper around a boto3 Session.

    Never stores or logs credentials. All credential material is handled
    by boto3's credential chain (env vars, ~/.aws, instance profile, etc.).
    """

    def __init__(
        self,
        profile_name: str | None = None,
        region: str | None = None,
    ) -> None:
        self._session = boto3.Session(
            profile_name=profile_name,
            region_name=region,
        )
        self._region = region or self._session.region_name or "us-east-1"
        self._caller_identity: CallerIdentity | None = None

    @property
    def region(self) -> str:
        return self._region

    def get_caller_identity(self) -> CallerIdentity:
        """Call sts:GetCallerIdentity and cache the result.

        Raises AWSContextError on credential or API failure.
        """
        if self._caller_identity is not None:
            return self._caller_identity

        try:
            sts = self._session.client("sts", region_name=self._region)
            response = sts.get_caller_identity()
        except botocore.exceptions.NoCredentialsError as exc:
            raise AWSContextError(
                "No AWS credentials found. Configure via environment variables, "
                "~/.aws/credentials, or an instance profile."
            ) from exc
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            raise AWSContextError(
                f"Failed to call sts:GetCallerIdentity ({error_code}): {exc}"
            ) from exc

        self._caller_identity = CallerIdentity(
            account_id=response["Account"],
            user_id=response["UserId"],
            arn=response["Arn"],
        )
        logger.info(
            "Caller identity verified: account=%s principal=%s",
            self._caller_identity.account_id,
            self._caller_identity.arn,
        )
        return self._caller_identity

    def get_client(self, service: str) -> boto3.client:
        """Return a boto3 client for the given service in the configured region."""
        return self._session.client(service, region_name=self._region)

    def get_paginator(self, service: str, operation: str):
        """Return a paginator for the given service and operation."""
        client = self.get_client(service)
        return client.get_paginator(operation)
