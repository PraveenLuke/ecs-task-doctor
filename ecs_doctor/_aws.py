
from botocore.exceptions import ClientError

from ecs_doctor.models import Finding, FindingType, Severity

# Single source of truth for access-denied error codes across ECS, ELBv2, etc.
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
