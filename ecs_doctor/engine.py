
import dataclasses
import time
from dataclasses import dataclass, field

from ecs_doctor._aws import ServiceDataCache
from ecs_doctor.aggregator import aggregate
from ecs_doctor.diagnosers.alb_health import diagnose_alb_health
from ecs_doctor.diagnosers.events import diagnose_events
from ecs_doctor.diagnosers.logs import diagnose_logs
from ecs_doctor.diagnosers.stop_reasons import diagnose_stop_reasons
from ecs_doctor.models import Finding, MetricSnapshot, RootCause, ServiceConfig, TaskConfig


@dataclass
class DiagnosisRequest:
    cluster: str
    service: str
    region: str
    account_id: str


@dataclass
class DiagnosisResult:
    request: DiagnosisRequest
    root_cause: RootCause
    all_findings: list[Finding]
    service_config: ServiceConfig | None = None
    task_config: TaskConfig | None = None
    metrics: MetricSnapshot | None = None
    duration_ms: int = 0


def to_json_safe(obj: object) -> object:
    """Recursively convert dataclasses and lists to JSON-serialisable dicts."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_json_safe(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [to_json_safe(i) for i in obj]
    return obj


def run_diagnosis(
    ecs_client,
    logs_client,
    elb_client,
    cw_client,
    request: DiagnosisRequest,
    include_metrics: bool = True,
    include_config: bool = True,
) -> DiagnosisResult:
    """Orchestrate all diagnosers and return a single DiagnosisResult.

    Called by both cli.py and web routes — zero logic is duplicated between surfaces.
    """
    start_ms = time.monotonic()

    cache = ServiceDataCache(ecs_client)
    kwargs = {
        "cluster": request.cluster,
        "service": request.service,
        "region": request.region,
        "account_id": request.account_id,
    }

    events_findings = diagnose_events(service_cache=cache, **kwargs)
    stop_findings, task_arns = diagnose_stop_reasons(ecs_client=ecs_client, **kwargs)
    log_findings = diagnose_logs(
        service_cache=cache,
        ecs_client=ecs_client,
        logs_client=logs_client,
        task_arns=task_arns,
        **kwargs,
    )
    alb_findings = diagnose_alb_health(service_cache=cache, elbv2_client=elb_client, **kwargs)

    all_findings: list[Finding] = (
        events_findings + stop_findings + log_findings + alb_findings
    )

    service_config: ServiceConfig | None = None
    task_config: TaskConfig | None = None
    if include_config:
        from ecs_doctor.diagnosers.config import diagnose_config
        config_findings, service_config, task_config = diagnose_config(
            service_cache=cache, ecs_client=ecs_client, **kwargs
        )
        all_findings.extend(config_findings)

    metrics: MetricSnapshot | None = None
    if include_metrics and cw_client is not None:
        from ecs_doctor.diagnosers.metrics import diagnose_metrics
        metric_findings, metrics = diagnose_metrics(cw_client=cw_client, **kwargs)
        all_findings.extend(metric_findings)

    root_cause = aggregate(all_findings)
    duration_ms = int((time.monotonic() - start_ms) * 1000)

    return DiagnosisResult(
        request=request,
        root_cause=root_cause,
        all_findings=all_findings,
        service_config=service_config,
        task_config=task_config,
        metrics=metrics,
        duration_ms=duration_ms,
    )
