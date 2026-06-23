
import asyncio
import json

import boto3
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router = APIRouter()


@router.get("/api/stream-logs")
async def stream_logs(
    cluster: str,
    service: str,
    region: str = "us-east-1",
    profile: str | None = None,
) -> StreamingResponse:
    """SSE endpoint — streams live ECS task logs as JSON events."""

    async def event_generator():
        from ecs_doctor.streaming import iter_log_events
        session = boto3.Session(region_name=region, profile_name=profile)
        ecs_client = session.client("ecs", region_name=region)
        logs_client = session.client("logs", region_name=region)
        try:
            for event in iter_log_events(ecs_client, logs_client, cluster, service, region):
                payload = json.dumps(event)
                yield f"data: {payload}\n\n"
                await asyncio.sleep(0)
        except Exception as exc:  # NOSONAR python:S2221 broad catch intentional — converts all errors to SSE error events
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
