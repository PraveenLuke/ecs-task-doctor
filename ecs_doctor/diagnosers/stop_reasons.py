
from collections import defaultdict
from typing import Any

from botocore.exceptions import ClientError

from ecs_doctor._aws import cluster_resource_arn, iam_finding, is_access_denied
from ecs_doctor.models import Finding, FindingType, Severity

_OOM_EXIT_CODES: frozenset[int] = frozenset({137, 139})
_SIGTERM_EXIT_CODE = 143
_STOPPED_STATUS = "STOPPED"
_ESSENTIAL_LOWER = "essential container"
_CANNOT_PULL_LOWER = "cannotpullcontainererror"


# ---------------------------------------------------------------------------
# Task-level classification (stopCode field — most reliable signal)
# ---------------------------------------------------------------------------

_TASK_STOP_CODE_MAP: dict[str, tuple[FindingType, str]] = {
    "ResourceInitializationError": (
        FindingType.SECRETS_INIT_FAILURE,
        "Task failed to initialize resources (secret/config unavailable). stoppedReason: {reason}",
    ),
    "CannotPullContainerImage": (
        FindingType.IMAGE_PULL_FAILURE,
        "Cannot pull container image. stoppedReason: {reason}",
    ),
    "SpotInterrupted": (
        FindingType.SPOT_INTERRUPTED,
        "Fargate Spot task was interrupted by AWS capacity reclamation. stoppedReason: {reason}",
    ),
    "TaskFailedToStart": (
        FindingType.TASK_FAILED_TO_START,
        "Task failed to start before startTimeout elapsed. stoppedReason: {reason}",
    ),
    "EssentialContainerExited": (
        FindingType.ESSENTIAL_EXITED,
        "Essential container exited (task-level stopCode). stoppedReason: {reason}",
    ),
}


def _classify_task(
    stop_code: str, stopped_reason: str, task_arn: str
) -> tuple[tuple, dict] | None:
    """Return (bucket_key, entry) for task-level stopCodes, or None."""
    if stop_code not in _TASK_STOP_CODE_MAP:
        return None
    ftype, msg_template = _TASK_STOP_CODE_MAP[stop_code]
    return (
        (ftype, "__task__", None),
        {
            "taskArn": task_arn,
            "stopCode": stop_code,
            "stoppedReason": stopped_reason,
            "severity": Severity.CRITICAL,
            "message": msg_template.format(reason=stopped_reason),
        },
    )


# ---------------------------------------------------------------------------
# Container-level classification (exit codes + reason text)
# ---------------------------------------------------------------------------

def _classify_container(
    name: str,
    exit_code: int | None,
    reason: str,
    stopped_reason: str,
    task_arn: str,
) -> tuple[tuple, dict] | None:
    """Return (bucket_key, entry) for a single container observation, or None.

    Evaluated top-to-bottom; first match wins. Extracted to reduce the
    cognitive complexity of the parent loop (SonarQube S3776).
    """
    lower_reason = reason.lower()
    lower_stopped = stopped_reason.lower()

    if _CANNOT_PULL_LOWER in lower_reason or _CANNOT_PULL_LOWER in lower_stopped:
        return (
            (FindingType.IMAGE_PULL_FAILURE, name, None),
            {
                "taskArn": task_arn,
                "containerName": name,
                "reason": reason,
                "stoppedReason": stopped_reason,
                "severity": Severity.CRITICAL,
                "message": f"Container '{name}' could not pull image. Reason: {reason or stopped_reason}",
            },
        )

    if exit_code in _OOM_EXIT_CODES:
        return (
            (FindingType.OOM_KILLED, name, exit_code),
            {
                "taskArn": task_arn,
                "containerName": name,
                "exitCode": exit_code,
                "stoppedReason": stopped_reason,
                "severity": Severity.CRITICAL,
                "message": f"Container '{name}' OOM-killed (exit {exit_code}). stoppedReason: {stopped_reason}",
            },
        )

    if exit_code == _SIGTERM_EXIT_CODE:
        return (
            (FindingType.GRACEFUL_SHUTDOWN_FAIL, name, exit_code),
            {
                "taskArn": task_arn,
                "containerName": name,
                "exitCode": exit_code,
                "stoppedReason": stopped_reason,
                "severity": Severity.MEDIUM,
                "message": (
                    f"Container '{name}' received SIGTERM but did not exit "
                    "gracefully (exit 143). Application may not handle SIGTERM."
                ),
            },
        )

    if exit_code == 0 and _ESSENTIAL_LOWER in lower_stopped:
        return (
            (FindingType.PREMATURE_EXIT, name, 0),
            {
                "taskArn": task_arn,
                "containerName": name,
                "exitCode": 0,
                "stoppedReason": stopped_reason,
                "severity": Severity.HIGH,
                "message": (
                    f"Container '{name}' exited cleanly (exit 0) but caused task to stop. "
                    "Check CMD/ENTRYPOINT — may be a one-shot script or misconfigured service."
                ),
            },
        )

    if exit_code is not None and exit_code != 0:
        return (
            (FindingType.NON_ZERO_EXIT, name, exit_code),
            {
                "taskArn": task_arn,
                "containerName": name,
                "exitCode": exit_code,
                "stoppedReason": stopped_reason,
                "severity": Severity.HIGH,
                "message": f"Container '{name}' exited with code {exit_code}. stoppedReason: {stopped_reason}",
            },
        )

    if _ESSENTIAL_LOWER in lower_stopped:
        return (
            (FindingType.ESSENTIAL_EXITED, name, None),
            {
                "taskArn": task_arn,
                "containerName": name,
                "exitCode": exit_code,
                "stoppedReason": stopped_reason,
                "severity": Severity.HIGH,
                "message": f"Essential container '{name}' exited, stopping the task. stoppedReason: {stopped_reason}",
            },
        )

    return None


# ---------------------------------------------------------------------------
# Collapse accumulated buckets into deduplicated Findings
# ---------------------------------------------------------------------------

def _buckets_to_findings(buckets: dict[tuple, list[dict]]) -> list[Finding]:
    findings: list[Finding] = []
    for (ftype, container_name, exit_code), entries in buckets.items():
        first = entries[0]
        msg = first["message"]
        if len(entries) > 1:
            msg = f"{msg} ({len(entries)} tasks affected)"
        raw: dict[str, Any] = {
            "affected_tasks": [e["taskArn"] for e in entries],
            "count": len(entries),
            "containerName": container_name,
            "exitCode": exit_code,
            "sample_stoppedReason": first.get("stoppedReason", ""),
        }
        if "stopCode" in first:
            raw["stopCode"] = first["stopCode"]
        findings.append(Finding(
            type=ftype,
            message=msg,
            severity=first["severity"],
            raw_data=raw,
            source="stop_reasons",
        ))
    return findings


# ---------------------------------------------------------------------------
# Public diagnoser
# ---------------------------------------------------------------------------

def diagnose_stop_reasons(
    ecs_client,
    cluster: str,
    service: str,
    region: str,
    account_id: str,
    max_tasks: int = 10,
) -> tuple[list[Finding], list[str]]:
    cluster_arn = cluster_resource_arn(region, account_id, cluster)

    try:
        list_resp = ecs_client.list_tasks(
            cluster=cluster,
            serviceName=service,
            desiredStatus=_STOPPED_STATUS,
            maxResults=max_tasks,
        )
    except ClientError as exc:
        if is_access_denied(exc):
            return [iam_finding("ecs:ListTasks", cluster_arn, "stop_reasons")], []
        raise

    task_arns: list[str] = list_resp.get("taskArns", [])
    if not task_arns:
        return [], []

    try:
        desc_resp = ecs_client.describe_tasks(cluster=cluster, tasks=task_arns)
    except ClientError as exc:
        if is_access_denied(exc):
            return [iam_finding("ecs:DescribeTasks", cluster_arn, "stop_reasons")], task_arns
        raise

    buckets: dict[tuple, list[dict]] = defaultdict(list)

    for task in desc_resp.get("tasks", []):
        task_arn = task.get("taskArn", "unknown")
        stop_code = task.get("stopCode", "")
        stopped_reason = task.get("stoppedReason", "")

        task_result = _classify_task(stop_code, stopped_reason, task_arn)
        if task_result:
            key, entry = task_result
            buckets[key].append(entry)
            continue

        for container in task.get("containers", []):
            result = _classify_container(
                name=container.get("name", "unknown"),
                exit_code=container.get("exitCode"),
                reason=container.get("reason", ""),
                stopped_reason=stopped_reason,
                task_arn=task_arn,
            )
            if result:
                key, entry = result
                buckets[key].append(entry)

    return _buckets_to_findings(buckets), task_arns
