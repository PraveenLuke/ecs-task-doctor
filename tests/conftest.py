"""Shared test helpers and constants."""
from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from ecs_doctor._aws import ServiceDataCache

REGION = "us-east-1"
CLUSTER = "test-cluster"
SERVICE = "test-service"
ACCOUNT = "123456789012"


def access_denied_error(operation: str, code: str = "AccessDeniedException") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "User is not authorized to perform this action"}},
        operation,
    )


def make_ecs_client(**method_returns) -> MagicMock:
    client = MagicMock()
    for method, value in method_returns.items():
        if isinstance(value, Exception):
            getattr(client, method).side_effect = value
        else:
            getattr(client, method).return_value = value
    return client


def make_logs_client(**method_returns) -> MagicMock:
    return make_ecs_client(**method_returns)


def make_elbv2_client(**method_returns) -> MagicMock:
    return make_ecs_client(**method_returns)


def make_service_cache(ecs_client: MagicMock) -> ServiceDataCache:
    """Wrap a mock ECS client in a ServiceDataCache for diagnoser tests."""
    return ServiceDataCache(ecs_client)
