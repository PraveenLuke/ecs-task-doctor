
import dataclasses
import json

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ecs_doctor.engine import DiagnosisRequest, run_diagnosis

router = APIRouter()


def _to_json_safe(obj: object) -> object:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_json_safe(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_json_safe(i) for i in obj]
    return obj


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
    return templates.TemplateResponse("index.html", {"request": request})


@router.post("/diagnose", response_class=HTMLResponse)
async def diagnose_html(
    request: Request,
    cluster: str = Form(...),
    service: str = Form(...),
    region: str = Form("us-east-1"),
    profile: str = Form(""),
):
    from ecs_doctor.web.app import templates
    try:
        ecs, logs, elb, cw, account_id = _build_clients(region, profile or None)
        req = DiagnosisRequest(cluster=cluster, service=service, region=region, account_id=account_id)
        result = run_diagnosis(ecs_client=ecs, logs_client=logs, elb_client=elb, cw_client=cw, request=req)
    except NoCredentialsError:
        raise HTTPException(status_code=401, detail="No AWS credentials found.")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return templates.TemplateResponse("report.html", {"request": request, "result": result})


@router.get("/api/diagnose")
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
    except NoCredentialsError:
        raise HTTPException(status_code=401, detail="No AWS credentials found.")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return JSONResponse(content=json.loads(json.dumps(_to_json_safe(result), default=str)))
