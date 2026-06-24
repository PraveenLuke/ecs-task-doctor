
import asyncio
import json

import boto3
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router = APIRouter()


def _get_task_def_arn(ecs_client, cluster: str, service: str) -> str:
    resp = ecs_client.describe_services(cluster=cluster, services=[service])
    svcs = resp.get("services", [])
    return svcs[0].get("taskDefinition", "") if svcs else ""


async def _resolve_streams(ecs_client, cluster: str, service: str, region: str) -> tuple:
    """Return (streams, tokens) or (None, info_message) if streaming is not possible.

    Calls list_tasks directly (not through the helper that swallows ClientError) so
    credential and permission failures propagate up to the SSE error handler.
    """
    from ecs_doctor.streaming import _awslogs_streams

    def _list_running_tasks():
        return ecs_client.list_tasks(
            cluster=cluster, serviceName=service, desiredStatus="RUNNING", maxResults=5
        ).get("taskArns", [])

    task_arns = await asyncio.to_thread(_list_running_tasks)
    if not task_arns:
        return None, "No running tasks found in this service"

    task_def_arn = await asyncio.to_thread(_get_task_def_arn, ecs_client, cluster, service)
    streams = await asyncio.to_thread(_awslogs_streams, ecs_client, task_def_arn, task_arns, region)
    if not streams:
        return None, "No awslogs log streams configured for this service"

    tokens: dict[str, str | None] = {s["stream_name"]: None for s in streams}
    return streams, tokens


async def _poll_once(logs_client, streams: list, tokens: dict) -> list[str]:
    """Poll every stream once and return SSE data lines."""
    from ecs_doctor.streaming import _poll_stream

    lines: list[str] = []
    for stream in streams:
        sname = stream["stream_name"]
        events, new_token = await asyncio.to_thread(
            _poll_stream, logs_client, stream["log_group"], sname, tokens[sname]
        )
        tokens[sname] = new_token
        for event in events:
            payload = json.dumps({
                "container": stream["container"],
                "task_id": stream["task_id"],
                "message": event["message"],
                "timestamp": event["timestamp"],
            })
            lines.append(f"data: {payload}\n\n")
    return lines


@router.get("/api/stream-logs")
async def stream_logs(
    cluster: str,
    service: str,
    region: str = "us-east-1",
    profile: str | None = None,
) -> StreamingResponse:
    """SSE endpoint — streams live ECS task logs as JSON events."""

    async def event_generator():
        session = boto3.Session(region_name=region, profile_name=profile or None)
        ecs_client = session.client("ecs", region_name=region)
        logs_client = session.client("logs", region_name=region)

        yield ": connected\n\n"  # SSE comment — keeps the connection open while AWS calls run

        try:
            streams, tokens = await _resolve_streams(ecs_client, cluster, service, region)
            if streams is None:
                yield f"data: {json.dumps({'info': tokens})}\n\n"
                return

            while True:
                for line in await _poll_once(logs_client, streams, tokens):
                    yield line
                await asyncio.sleep(2.0)

        except GeneratorExit:
            pass
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
