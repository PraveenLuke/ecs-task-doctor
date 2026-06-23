
"""Live log streaming from running ECS tasks."""
from __future__ import annotations

import time
from collections.abc import Generator

from botocore.exceptions import ClientError

_POLL_INTERVAL_SECONDS = 2.0
_RUNNING_STATUS = "RUNNING"
_MAX_LOG_LINES_PER_POLL = 100


def _get_running_task_arns(ecs_client, cluster: str, service: str, max_tasks: int) -> list[str]:
    try:
        resp = ecs_client.list_tasks(
            cluster=cluster,
            serviceName=service,
            desiredStatus=_RUNNING_STATUS,
            maxResults=max_tasks,
        )
        return resp.get("taskArns", [])
    except ClientError:
        return []


def _awslogs_streams(ecs_client, task_def_arn: str, task_arns: list[str], region: str) -> list[dict]:
    """Resolve log stream descriptors for each running task/container."""
    try:
        td_resp = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
    except ClientError:
        return []

    container_defs = td_resp.get("taskDefinition", {}).get("containerDefinitions", [])
    streams: list[dict] = []
    for task_arn in task_arns:
        task_id = task_arn.split("/")[-1]
        for cdef in container_defs:
            lc = cdef.get("logConfiguration", {})
            if lc.get("logDriver") != "awslogs":
                continue
            opts = lc.get("options", {})
            streams.append({
                "log_group": opts.get("awslogs-group", ""),
                "stream_name": f"{opts.get('awslogs-stream-prefix', '')}/{cdef['name']}/{task_id}",
                "container": cdef["name"],
                "task_id": task_id,
                "log_region": opts.get("awslogs-region", region),
            })
    return streams


def _poll_stream(
    logs_client,
    log_group: str,
    stream_name: str,
    next_token: str | None,
) -> tuple[list[dict], str | None]:
    """Fetch the next batch of events from one log stream."""
    kwargs: dict = {
        "logGroupName": log_group,
        "logStreamName": stream_name,
        "startFromHead": next_token is None,
        "limit": _MAX_LOG_LINES_PER_POLL,
    }
    if next_token:
        kwargs["nextToken"] = next_token

    try:
        resp = logs_client.get_log_events(**kwargs)
    except ClientError:
        return [], next_token

    events = [
        {"message": e["message"], "timestamp": e.get("timestamp", 0)}
        for e in resp.get("events", [])
    ]
    new_token = resp.get("nextForwardToken")
    return events, new_token


def iter_log_events(
    ecs_client,
    logs_client,
    cluster: str,
    service: str,
    region: str,
    max_tasks: int = 5,
) -> Generator[dict, None, None]:
    """Yield log event dicts indefinitely from running task log streams.

    Each dict: {"container": str, "task_id": str, "message": str, "timestamp": int}
    Per-stream forward tokens prevent re-delivery of already-seen events.
    The caller stops the generator by catching GeneratorExit (Ctrl+C in CLI,
    client disconnect in SSE).
    """
    task_arns = _get_running_task_arns(ecs_client, cluster, service, max_tasks)
    if not task_arns:
        return

    try:
        svc_resp = ecs_client.describe_services(cluster=cluster, services=[service])
        svcs = svc_resp.get("services", [])
        task_def_arn = svcs[0].get("taskDefinition", "") if svcs else ""
    except ClientError:
        return

    streams = _awslogs_streams(ecs_client, task_def_arn, task_arns, region)
    if not streams:
        return

    tokens: dict[str, str | None] = {s["stream_name"]: None for s in streams}

    while True:
        for stream in streams:
            sname = stream["stream_name"]
            events, new_token = _poll_stream(
                logs_client,
                log_group=stream["log_group"],
                stream_name=sname,
                next_token=tokens[sname],
            )
            tokens[sname] = new_token
            for event in events:
                yield {
                    "container": stream["container"],
                    "task_id": stream["task_id"],
                    "message": event["message"],
                    "timestamp": event["timestamp"],
                }
        time.sleep(_POLL_INTERVAL_SECONDS)
