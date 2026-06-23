
import re

from botocore.exceptions import ClientError

from ecs_doctor._aws import iam_finding, is_access_denied, service_resource_arn
from ecs_doctor.models import Finding, FindingType, Severity

# Data-driven event rules — each rule matches one class of service event.
# Eliminates three structurally identical if-blocks (SonarQube S4144).
_EVENT_RULES: list[tuple[re.Pattern, FindingType, Severity, str]] = [
    (
        re.compile(r"unable to place a? ?task|Insufficient \w+", re.IGNORECASE),
        FindingType.PLACEMENT_FAILURE,
        Severity.HIGH,
        "Placement failure",
    ),
    (
        re.compile(
            r"failed container health checks?|"
            r"\(port \d+\) is unhealthy in \(target-group",
            re.IGNORECASE,
        ),
        FindingType.HEALTH_CHECK_FAIL,
        Severity.HIGH,
        "Health check failure",
    ),
    (
        re.compile(r"due to failed deployment checks|rolling back", re.IGNORECASE),
        FindingType.DEPLOYMENT_ROLLBACK,
        Severity.CRITICAL,
        "Deployment rollback triggered",
    ),
]

_STARTED_RE = re.compile(r"started \d+ task", re.IGNORECASE)
_STOPPED_RE = re.compile(r"stopped \d+ task", re.IGNORECASE)
_THRASH_THRESHOLD = 3


def diagnose_events(
    ecs_client,
    cluster: str,
    service: str,
    region: str,
    account_id: str,
    last_n: int = 20,
) -> list[Finding]:
    try:
        resp = ecs_client.describe_services(cluster=cluster, services=[service])
    except ClientError as exc:
        if is_access_denied(exc):
            return [iam_finding(
                "ecs:DescribeServices",
                service_resource_arn(region, account_id, cluster, service),
                "events",
            )]
        raise

    services = resp.get("services", [])
    if not services:
        return [Finding(
            type=FindingType.IAM_DENIED,
            message=f"Service '{service}' not found in cluster '{cluster}'.",
            severity=Severity.HIGH,
            source="events",
        )]

    events: list[dict] = services[0].get("events", [])
    findings: list[Finding] = []
    seen: set[FindingType] = set()

    for event in events:
        msg = event.get("message", "")
        raw = {"message": msg, "createdAt": str(event.get("createdAt", ""))}

        for pattern, ftype, severity, prefix in _EVENT_RULES:
            if ftype not in seen and pattern.search(msg):
                findings.append(Finding(
                    type=ftype,
                    message=f"{prefix}: {msg}",
                    severity=severity,
                    raw_data=raw,
                    source="events",
                ))
                seen.add(ftype)

    recent = events[:last_n]
    start_count = sum(1 for e in recent if _STARTED_RE.search(e.get("message", "")))
    stop_count = sum(1 for e in recent if _STOPPED_RE.search(e.get("message", "")))
    if start_count >= _THRASH_THRESHOLD and stop_count >= _THRASH_THRESHOLD:
        findings.append(Finding(
            type=FindingType.TASK_THRASHING,
            message=(
                f"Crash loop detected: {start_count} start(s) and "
                f"{stop_count} stop(s) in the last {last_n} events."
            ),
            severity=Severity.CRITICAL,
            raw_data={"start_count": start_count, "stop_count": stop_count},
            source="events",
        ))

    return findings
