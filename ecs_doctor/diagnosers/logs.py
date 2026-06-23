
import re
from typing import Any

from botocore.exceptions import ClientError

from ecs_doctor._aws import iam_finding, is_access_denied, service_resource_arn
from ecs_doctor.models import Finding, FindingType, Severity

_AWSLOGS_DRIVER = "awslogs"

# (regex pattern, human label, severity)
CRASH_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"Traceback \(most recent call last\)", "Python traceback", Severity.HIGH),
    (r"Exception in thread", "Java exception", Severity.HIGH),
    (r"panic:", "Go panic", Severity.HIGH),
    (r"UnhandledPromiseRejection", "Node.js unhandled rejection", Severity.HIGH),
    (r"Error: ", "Node.js/generic error", Severity.MEDIUM),
    (r"permission denied", "Permission denied", Severity.MEDIUM),
    (r"connection refused", "Connection refused", Severity.MEDIUM),
    (r"FATAL:", "DB fatal error", Severity.HIGH),
    (r"deadlock detected", "DB deadlock", Severity.HIGH),
    (r"out of memory", "OOM in logs", Severity.CRITICAL),
    (r"cannot allocate memory", "Memory alloc failure", Severity.HIGH),
    (r"dial tcp.*i/o timeout", "Network timeout", Severity.MEDIUM),
    (r"no such host", "DNS resolution failed", Severity.MEDIUM),
    (r"certificate.*expired|SSL.*error", "TLS/SSL error", Severity.MEDIUM),
    (r"exec format error", "Wrong CPU architecture in image", Severity.CRITICAL),
    (r"no such file or directory", "Missing file or binary", Severity.HIGH),
    (r"secret.*not found|SecretNotFound", "Missing secret", Severity.HIGH),
]

_COMPILED: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(pat, re.IGNORECASE), label, sev)
    for pat, label, sev in CRASH_PATTERNS
]


def _extract_context(lines: list[str], match_idx: int, context: int = 2) -> str:
    start = max(0, match_idx - context)
    end = min(len(lines), match_idx + context + 1)
    return "\n".join(lines[start:end])


def _awslogs_configs(container_defs: list[dict], region: str) -> dict[str, dict[str, str]]:
    """Extract per-container awslogs configuration from task definition containers."""
    configs: dict[str, dict[str, str]] = {}
    for c in container_defs:
        lc = c.get("logConfiguration", {})
        if lc.get("logDriver") == _AWSLOGS_DRIVER:
            opts = lc.get("options", {})
            configs[c["name"]] = {
                "log_group": opts.get("awslogs-group", ""),
                "stream_prefix": opts.get("awslogs-stream-prefix", ""),
                "log_region": opts.get("awslogs-region", region),
            }
    return configs


def _scan_log_stream(
    logs_client,
    log_group: str,
    stream_name: str,
    log_region: str,
    account_id: str,
    container_name: str,
    task_id: str,
) -> list[Finding]:
    """Fetch one log stream and return crash-signature findings. Returns None on AccessDenied."""
    try:
        log_resp = logs_client.get_log_events(
            logGroupName=log_group,
            logStreamName=stream_name,
            startFromHead=True,
            limit=200,
        )
    except ClientError as exc:
        if is_access_denied(exc):
            return [iam_finding(
                "logs:GetLogEvents",
                f"arn:aws:logs:{log_region}:{account_id}:log-group:{log_group}:*",
                "logs",
            )]
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise

    events: list[dict[str, Any]] = log_resp.get("events", [])
    if not events:
        return []

    log_lines = [e["message"] for e in events]
    log_text = "\n".join(log_lines)
    findings: list[Finding] = []
    seen_labels: set[str] = set()

    for pattern, label, severity in _COMPILED:
        if label in seen_labels:
            continue
        match = pattern.search(log_text)
        if match:
            match_line_idx = log_text[: match.start()].count("\n")
            findings.append(Finding(
                type=FindingType.LOG_CRASH_SIGNATURE,
                message=f"[{container_name}] {label} detected in logs (task {task_id})",
                severity=severity,
                raw_data={
                    "label": label,
                    "context": _extract_context(log_lines, match_line_idx),
                    "log_stream": stream_name,
                    "log_group": log_group,
                    "task_id": task_id,
                    "container": container_name,
                },
                source="logs",
            ))
            seen_labels.add(label)

    return findings


def diagnose_logs(
    ecs_client,
    logs_client,
    cluster: str,
    service: str,
    task_arns: list[str],
    region: str,
    account_id: str,
) -> list[Finding]:
    if not task_arns:
        return []

    try:
        svc_resp = ecs_client.describe_services(cluster=cluster, services=[service])
    except ClientError as exc:
        if is_access_denied(exc):
            return [iam_finding(
                "ecs:DescribeServices",
                service_resource_arn(region, account_id, cluster, service),
                "logs",
            )]
        raise

    svcs = svc_resp.get("services", [])
    if not svcs:
        return []

    task_def_arn = svcs[0].get("taskDefinition")
    if not task_def_arn:
        return []

    try:
        td_resp = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
    except ClientError as exc:
        if is_access_denied(exc):
            return [iam_finding("ecs:DescribeTaskDefinition", task_def_arn, "logs")]
        raise

    container_defs = td_resp.get("taskDefinition", {}).get("containerDefinitions", [])
    log_configs = _awslogs_configs(container_defs, region)
    if not log_configs:
        return []

    findings: list[Finding] = []
    for task_arn in task_arns:
        task_id = task_arn.split("/")[-1]
        for container_name, cfg in log_configs.items():
            stream_name = f"{cfg['stream_prefix']}/{container_name}/{task_id}"
            stream_findings = _scan_log_stream(
                logs_client,
                log_group=cfg["log_group"],
                stream_name=stream_name,
                log_region=cfg["log_region"],
                account_id=account_id,
                container_name=container_name,
                task_id=task_id,
            )
            findings.extend(stream_findings)
            # AccessDenied on a stream means all streams in this task will also fail
            if any(f.type == FindingType.IAM_DENIED for f in stream_findings):
                break

    return findings
