
import re

from ecs_doctor._aws import ServiceDataCache, _AccessDeniedCached, iam_finding, service_resource_arn
from ecs_doctor.models import Finding, FindingType, Severity

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


def _check_deployment_deadlock(svc: dict) -> Finding | None:
    """Detect when minimumHealthyPercent + maximumPercent makes replacement impossible."""
    deploy = svc.get("deploymentConfiguration", {})
    min_pct = deploy.get("minimumHealthyPercent", 100)
    max_pct = deploy.get("maximumPercent", 200)
    desired = svc.get("desiredCount", 0)
    running = svc.get("runningCount", 0)
    pending = svc.get("pendingCount", 0)

    if desired > 0 and running == 0 and pending == 0 and min_pct == 100 and max_pct == 100:
        return Finding(
            type=FindingType.DEPLOYMENT_CONFIG_DEADLOCK,
            message=(
                f"Service has desiredCount={desired} but running=0 and pending=0. "
                f"minimumHealthyPercent={min_pct} and maximumPercent={max_pct} prevent "
                "ECS from launching a replacement task — the deployment is deadlocked."
            ),
            severity=Severity.CRITICAL,
            raw_data={
                "desiredCount": desired,
                "runningCount": running,
                "pendingCount": pending,
                "minimumHealthyPercent": min_pct,
                "maximumPercent": max_pct,
            },
            source="events",
        )
    return None


def diagnose_events(
    service_cache: ServiceDataCache,
    cluster: str,
    service: str,
    region: str,
    account_id: str,
    last_n: int = 20,
) -> list[Finding]:
    try:
        svc = service_cache.get_service(cluster, service, region, account_id)
    except _AccessDeniedCached:
        return [iam_finding(
            "ecs:DescribeServices",
            service_resource_arn(region, account_id, cluster, service),
            "events",
        )]

    if svc is None:
        return [Finding(
            type=FindingType.IAM_DENIED,
            message=f"Service '{service}' not found in cluster '{cluster}'.",
            severity=Severity.HIGH,
            source="events",
        )]

    findings: list[Finding] = []

    deadlock = _check_deployment_deadlock(svc)
    if deadlock:
        findings.append(deadlock)

    events: list[dict] = svc.get("events", [])
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
