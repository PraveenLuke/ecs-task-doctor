
import json
import sys

import boto3
import click
from botocore.exceptions import ClientError, NoCredentialsError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ecs_doctor.engine import DiagnosisRequest, DiagnosisResult, run_diagnosis, to_json_safe as _to_json_safe
from ecs_doctor.models import Finding, MetricSnapshot, RootCause, ServiceConfig, TaskConfig

console = Console(stderr=False)

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "bold red",
    "high": "orange1",
    "medium": "yellow",
    "low": "green",
}


def _confidence_color(confidence: float) -> str:
    if confidence >= 0.7:
        return "red"
    if confidence >= 0.4:
        return "yellow"
    return "green"


# ---------------------------------------------------------------------------
# Rich rendering helpers
# ---------------------------------------------------------------------------

def _render_root_cause(root_cause: RootCause) -> None:
    color = _confidence_color(root_cause.confidence)
    pct = f"{root_cause.confidence * 100:.0f}%"

    body = Text()
    body.append(root_cause.cause + "\n\n", style="bold")
    body.append("Confidence: ", style="dim")
    body.append(f"{pct}\n\n", style=f"bold {color}")
    body.append("Suggested fix:\n", style="italic dim")
    body.append(root_cause.suggested_fix)

    console.print(Panel(
        body,
        title=f"[bold {color}]Root Cause[/bold {color}]",
        border_style=color,
        padding=(1, 2),
    ))


def _render_evidence_table(root_cause: RootCause, all_findings: list[Finding]) -> None:
    if not root_cause.evidence:
        return

    table = Table(
        title="[bold]Supporting Evidence[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        expand=False,
    )
    table.add_column("Source", style="dim", no_wrap=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Message")

    for f in root_cause.evidence:
        sev_color = _SEVERITY_COLORS.get(f.severity.value, "white")
        table.add_row(
            f.source,
            f.type.value,
            f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
            f.message,
        )
    console.print(table)

    extra = len(all_findings) - len(root_cause.evidence)
    if extra > 0:
        console.print(
            f"\n[dim]({extra} additional finding(s) not shown — run with --json to see all.)[/dim]"
        )


def _render_metrics(metrics: MetricSnapshot) -> None:
    table = Table(
        title="[bold]CloudWatch Metrics (last 3h)[/bold]",
        box=box.SIMPLE,
        show_lines=False,
        expand=False,
    )
    table.add_column("Metric", style="cyan")
    table.add_column("Average", justify="right")
    table.add_column("Maximum", justify="right")

    def _fmt(val: float | None) -> str:
        return f"{val:.1f}%" if val is not None else "no data"

    table.add_row("CPU Utilization", _fmt(metrics.cpu_avg_percent), _fmt(metrics.cpu_max_percent))
    table.add_row("Memory Utilization", _fmt(metrics.memory_avg_percent), _fmt(metrics.memory_max_percent))
    console.print(table)


def _render_service_config(sc: ServiceConfig) -> None:
    dc = sc.deployment_config
    body = Text()
    body.append("Desired / Running / Pending: ", style="dim")
    body.append(f"{sc.desired_count} / {sc.running_count} / {sc.pending_count}\n")
    body.append("Launch type: ", style="dim")
    body.append(f"{sc.launch_type or 'capacity provider'}")
    if sc.platform_version:
        body.append(f"  Platform: {sc.platform_version}")
    body.append("\nDeployment: ", style="dim")
    body.append(
        f"min {dc.minimum_healthy_percent}% / max {dc.maximum_percent}%  "
        f"Circuit breaker: {'on' if dc.circuit_breaker_enabled else 'off'}"
    )
    if sc.health_check_grace_period_seconds is not None:
        body.append(f"\nHealth check grace period: {sc.health_check_grace_period_seconds}s", style="dim")
    console.print(Panel(body, title="[bold]Service Configuration[/bold]", border_style="dim", padding=(0, 2)))


def _render_task_config(tc: TaskConfig) -> None:
    table = Table(
        title="[bold]Task Definition[/bold]",
        box=box.SIMPLE,
        show_lines=False,
        expand=False,
    )
    table.add_column("Container", style="cyan")
    table.add_column("Image")
    table.add_column("CPU", justify="right")
    table.add_column("Memory", justify="right")
    table.add_column("Log Group", style="dim")

    for c in tc.containers:
        mem_str = str(c.memory or c.memory_reservation or "-")
        table.add_row(
            c.name,
            c.image.split("/")[-1],
            str(c.cpu),
            mem_str,
            c.log_group or "-",
        )

    task_info = f"[dim]Task CPU:[/dim] {tc.cpu}  [dim]Memory:[/dim] {tc.memory}  [dim]Network:[/dim] {tc.network_mode}"
    console.print(task_info)
    console.print(table)


def _render_report(result: DiagnosisResult) -> None:
    cluster = result.request.cluster
    service = result.request.service

    console.print()
    console.rule(f"[bold cyan]ECS Doctor — {cluster} / {service}[/bold cyan]")
    console.print()

    _render_root_cause(result.root_cause)
    _render_evidence_table(result.root_cause, result.all_findings)

    if result.metrics:
        _render_metrics(result.metrics)

    if result.service_config:
        _render_service_config(result.service_config)

    if result.task_config:
        _render_task_config(result.task_config)

    console.print(f"\n[dim]Diagnosis completed in {result.duration_ms}ms.[/dim]\n")


# ---------------------------------------------------------------------------
# AWS session setup
# ---------------------------------------------------------------------------

def _build_clients(region: str | None, profile: str | None, output_json: bool) -> tuple:
    session = boto3.Session(region_name=region, profile_name=profile)
    effective_region = session.region_name or "us-east-1"

    try:
        sts = session.client("sts", region_name=effective_region)
        account_id: str = sts.get_caller_identity()["Account"]
    except (ClientError, NoCredentialsError):
        account_id = "unknown"
        if not output_json:
            console.print(
                "[yellow]Warning: could not resolve AWS account ID "
                "(STS:GetCallerIdentity failed). "
                "IAM error messages may be incomplete.[/yellow]"
            )

    ecs_client = session.client("ecs", region_name=effective_region)
    logs_client = session.client("logs", region_name=effective_region)
    elb_client = session.client("elbv2", region_name=effective_region)
    cw_client = session.client("cloudwatch", region_name=effective_region)
    ec2_client = session.client("ec2", region_name=effective_region)

    return ecs_client, logs_client, elb_client, cw_client, ec2_client, effective_region, account_id


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="ecs-doctor")
def cli() -> None:
    """ECS Doctor — diagnose why your ECS service is failing."""


@cli.command()
@click.option("--cluster", required=True, help="ECS cluster name or ARN.")
@click.option("--service", required=True, help="ECS service name.")
@click.option("--region", default=None, help="AWS region (overrides profile/env default).")
@click.option("--profile", default=None, help="AWS named profile from ~/.aws/credentials.")
@click.option(
    "--json", "output_json", is_flag=True, default=False,
    help="Emit machine-readable JSON instead of the rich terminal report.",
)
@click.option(
    "--stream-logs", "stream_logs", is_flag=True, default=False,
    help="Stream live logs from running tasks instead of running diagnosis. Ctrl+C to stop.",
)
@click.option(
    "--no-metrics", "skip_metrics", is_flag=True, default=False,
    help="Skip CloudWatch metrics (faster, no cloudwatch:GetMetricData permission needed).",
)
@click.option(
    "--no-config", "skip_config", is_flag=True, default=False,
    help="Skip task definition config display.",
)
def diagnose(
    cluster: str,
    service: str,
    region: str | None,
    profile: str | None,
    output_json: bool,
    stream_logs: bool,
    skip_metrics: bool,
    skip_config: bool,
) -> None:
    """Run all diagnostic checks on an ECS service and report the most likely root cause."""
    if stream_logs and output_json:
        raise click.UsageError("--stream-logs and --json cannot be used together.")

    try:
        ecs_client, logs_client, elb_client, cw_client, _ec2_client, effective_region, account_id = (
            _build_clients(region, profile, output_json)
        )
    except NoCredentialsError:
        _no_creds_error(output_json)

    if stream_logs:
        _run_stream(ecs_client, logs_client, cluster, service, effective_region)
        return

    if not output_json:
        console.print(
            f"[dim]Running diagnostics on [bold]{cluster}[/bold] / "
            f"[bold]{service}[/bold] in [bold]{effective_region}[/bold]…[/dim]"
        )

    try:
        request = DiagnosisRequest(
            cluster=cluster,
            service=service,
            region=effective_region,
            account_id=account_id,
        )
        result = run_diagnosis(
            ecs_client=ecs_client,
            logs_client=logs_client,
            elb_client=elb_client,
            cw_client=cw_client,
            request=request,
            include_metrics=not skip_metrics,
            include_config=not skip_config,
        )
    except NoCredentialsError:
        _no_creds_error(output_json)

    if output_json:
        click.echo(json.dumps(_to_json_safe(result), indent=2, default=str))
        return

    _render_report(result)


@cli.command()
def browse() -> None:
    """Interactively browse clusters and services, then run diagnosis."""
    from ecs_doctor.wizard import run_wizard
    try:
        params = run_wizard()
    except ImportError as exc:
        raise click.ClickException(str(exc)) from exc

    session = params["session"]
    effective_region = params["region"]
    output_json = params["output_json"]

    try:
        sts = session.client("sts", region_name=effective_region)
        account_id: str = sts.get_caller_identity()["Account"]
    except (ClientError, NoCredentialsError):
        account_id = "unknown"

    ecs_client = session.client("ecs", region_name=effective_region)
    logs_client = session.client("logs", region_name=effective_region)
    elb_client = session.client("elbv2", region_name=effective_region)
    cw_client = session.client("cloudwatch", region_name=effective_region)

    request = DiagnosisRequest(
        cluster=params["cluster"],
        service=params["service"],
        region=effective_region,
        account_id=account_id,
    )

    if not output_json:
        console.print(
            f"[dim]Running diagnostics on [bold]{request.cluster}[/bold] / "
            f"[bold]{request.service}[/bold]…[/dim]"
        )

    result = run_diagnosis(
        ecs_client=ecs_client,
        logs_client=logs_client,
        elb_client=elb_client,
        cw_client=cw_client,
        request=request,
    )

    if output_json:
        click.echo(json.dumps(_to_json_safe(result), indent=2, default=str))
    else:
        _render_report(result)


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host.")
@click.option("--port", default=8080, show_default=True, help="Bind port.")
@click.option("--reload", is_flag=True, default=False, help="Auto-reload on code changes (dev only).")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the ECS Doctor web server."""
    try:
        import uvicorn
        from ecs_doctor.web.app import create_app
    except ImportError as exc:
        raise click.ClickException(
            "Web server requires optional dependencies. "
            "Install with: pip install 'ecs-doctor[web]'"
        ) from exc

    console.print(f"[bold cyan]ECS Doctor[/bold cyan] web server starting on http://{host}:{port}")
    uvicorn.run(create_app(), host=host, port=port, reload=reload)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_stream(ecs_client, logs_client, cluster: str, service: str, region: str) -> None:
    from ecs_doctor.streaming import iter_log_events
    console.print("[dim]Streaming live logs — Ctrl+C to stop…[/dim]\n")
    try:
        for event in iter_log_events(ecs_client, logs_client, cluster, service, region):
            console.print(f"[dim]{event['container']}[/dim]  {event['message']}")
    except KeyboardInterrupt:
        console.print("\n[dim]Log streaming stopped.[/dim]")


def _no_creds_error(output_json: bool) -> None:
    msg = (
        "No AWS credentials found. Configure credentials via:\n"
        "  - Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)\n"
        "  - AWS profile (~/.aws/credentials)\n"
        "  - IAM instance role / ECS task role"
    )
    if output_json:
        click.echo(json.dumps({"error": msg}))
    else:
        console.print(f"[bold red]Error:[/bold red] {msg}")
    sys.exit(1)
