
from botocore.exceptions import ClientError

from ecs_doctor.models import Finding, FindingType, Severity

_ACCESS_DENIED_CODES: frozenset[str] = frozenset({"AccessDenied", "AccessDeniedException"})


def is_access_denied(exc: ClientError) -> bool:
    return exc.response["Error"]["Code"] in _ACCESS_DENIED_CODES


def iam_finding(action: str, resource: str, source: str) -> Finding:
    return Finding(
        type=FindingType.IAM_DENIED,
        message=f"AccessDenied on {action}. Add {action} on {resource}",
        severity=Severity.CRITICAL,
        source=source,
    )


def service_resource_arn(region: str, account_id: str, cluster: str, service: str) -> str:
    return f"arn:aws:ecs:{region}:{account_id}:service/{cluster}/{service}"


def cluster_resource_arn(region: str, account_id: str, cluster: str) -> str:
    return f"arn:aws:ecs:{region}:{account_id}:cluster/{cluster}"


class _AccessDeniedCached(Exception):
    """Internal sentinel raised when a cached describe_services call was access-denied."""
    def __init__(self, action: str) -> None:
        self.action = action


class ServiceDataCache:
    """Per-request cache for ecs:DescribeServices.

    Eliminates duplicate API calls across diagnosers that all need the same
    service data. Instantiated once per diagnosis run in engine.py — never a
    global singleton, so test isolation is maintained.
    """

    def __init__(self, ecs_client) -> None:
        self._client = ecs_client
        self._cache: dict[tuple[str, str], dict] = {}

    def get_service(
        self,
        cluster: str,
        service: str,
        region: str,
        account_id: str,
    ) -> dict | None:
        """Return the first matching service dict, or None if not found.

        Raises ClientError for non-access-denied errors so callers can handle them.
        Raises _AccessDeniedCached (internal) if access was denied on the cached call.
        """
        key = (cluster, service)
        if key not in self._cache:
            try:
                resp = self._client.describe_services(cluster=cluster, services=[service])
                self._cache[key] = resp
            except ClientError as exc:
                if is_access_denied(exc):
                    self._cache[key] = {
                        "_access_denied": True,
                        "_action": "ecs:DescribeServices",
                        "_region": region,
                        "_account_id": account_id,
                    }
                else:
                    raise

        cached = self._cache[key]
        if "_access_denied" in cached:
            raise _AccessDeniedCached(cached["_action"])

        services = cached.get("services", [])
        return services[0] if services else None
