
import json
from typing import Annotated, Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ecs_doctor.engine import DiagnosisRequest, run_diagnosis, to_json_safe

router = APIRouter()

_RESPONSES_401_500: dict[int | str, dict[str, Any]] = {
    401: {"description": "No AWS credentials found"},
    500: {"description": "Diagnosis failed — check cluster/service names and IAM permissions"},
}


def _build_clients(region: str, profile: str | None) -> tuple:
    session = boto3.Session(region_name=region, profile_name=profile or None)
    ecs = session.client("ecs", region_name=region)
    logs = session.client("logs", region_name=region)
    elb = session.client("elbv2", region_name=region)
    cw = session.client("cloudwatch", region_name=region)
    try:
        account_id = session.client("sts", region_name=region).get_caller_identity()["Account"]
    except (ClientError, NoCredentialsError):
        account_id = "unknown"
    return ecs, logs, elb, cw, account_id


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    from ecs_doctor.web.app import templates
    try:
        profiles = sorted(boto3.Session().available_profiles)
    except Exception:
        profiles = []
    return templates.TemplateResponse(request, "index.html", {"profiles": profiles})



@router.get("/api/clusters-options", response_class=HTMLResponse)
async def clusters_options(region: str = "us-east-1", profile: str | None = None):
    from ecs_doctor.wizard import _list_clusters
    try:
        session = boto3.Session(region_name=region, profile_name=profile or None)
        clusters = _list_clusters(session.client("ecs", region_name=region))
    except Exception:
        clusters = []
    if not clusters:
        return HTMLResponse('<option value="" disabled>No clusters found</option>')
    return HTMLResponse("\n".join(f'<option value="{c}">{c}</option>' for c in clusters))


@router.get("/api/services-options", response_class=HTMLResponse)
async def services_options(cluster: str = "", region: str = "us-east-1", profile: str | None = None):
    if not cluster:
        return HTMLResponse('<option value="" disabled>Select a cluster first</option>')
    from ecs_doctor.wizard import _list_services
    try:
        session = boto3.Session(region_name=region, profile_name=profile or None)
        services = _list_services(session.client("ecs", region_name=region), cluster)
    except Exception:
        services = []
    if not services:
        return HTMLResponse('<option value="" disabled>No services found</option>')
    return HTMLResponse("\n".join(f'<option value="{s}">{s}</option>' for s in services))


@router.post("/diagnose", response_class=HTMLResponse, responses=_RESPONSES_401_500)
async def diagnose_html(
    request: Request,
    cluster: Annotated[str, Form()],
    service: Annotated[str, Form()],
    region: Annotated[str, Form()] = "us-east-1",
    profile: Annotated[str, Form()] = "",
):
    from ecs_doctor.web.app import templates

    if not cluster or not service:
        return HTMLResponse(
            '<div class="card error-card">'
            '<h3>Missing required fields</h3>'
            '<p>Please select a cluster and service before running diagnosis.</p>'
            '</div>'
        )

    try:
        ecs, logs, elb, cw, account_id = _build_clients(region, profile or None)
        req = DiagnosisRequest(cluster=cluster, service=service, region=region, account_id=account_id)
        result = run_diagnosis(ecs_client=ecs, logs_client=logs, elb_client=elb, cw_client=cw, request=req)
    except NoCredentialsError:
        return HTMLResponse(
            '<div class="card error-card">'
            '<h3>No AWS credentials found</h3>'
            '<p>Select a named profile from the dropdown, or configure credentials via '
            'environment variables (<code>AWS_ACCESS_KEY_ID</code> / <code>AWS_SECRET_ACCESS_KEY</code>) '
            'or an IAM instance/task role.</p>'
            '</div>'
        )
    except Exception as exc:
        return HTMLResponse(
            f'<div class="card error-card"><h3>Diagnosis failed</h3>'
            f'<p><code>{exc}</code></p>'
            f'<p class="dim">Check that the cluster and service names are correct and '
            f'that your credentials have the necessary ECS permissions.</p>'
            f'</div>'
        )

    return templates.TemplateResponse(request, "report.html", {"result": result})


@router.get("/api/diagnose", responses=_RESPONSES_401_500)
async def diagnose_json(
    cluster: str,
    service: str,
    region: str = "us-east-1",
    profile: str | None = None,
) -> JSONResponse:
    try:
        ecs, logs, elb, cw, account_id = _build_clients(region, profile)
        req = DiagnosisRequest(cluster=cluster, service=service, region=region, account_id=account_id)
        result = run_diagnosis(ecs_client=ecs, logs_client=logs, elb_client=elb, cw_client=cw, request=req)
    except NoCredentialsError as exc:
        raise HTTPException(status_code=401, detail="No AWS credentials found.") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return JSONResponse(content=json.loads(json.dumps(to_json_safe(result), default=str)))
