
import dataclasses
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

from ecs_doctor.aggregator import aggregate
from ecs_doctor.diagnosers.alb_health import diagnose_alb_health
from ecs_doctor.diagnosers.events import diagnose_events
from ecs_doctor.diagnosers.logs import diagnose_logs
from ecs_doctor.diagnosers.stop_reasons import diagnose_stop_reasons
from ecs_doctor.models import Finding, RootCause, Severity

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


def _render_report(
    cluster: str,
    service: str,
    root_cause: RootCause,
    all_findings: list[Finding],
) -> None:
    console.print()
    console.rule(f"[bold cyan]ECS Task Doctor — {cluster} / {service}[/bold cyan]")
    console.print()

    color = _confidence_color(root_cause.confidence)
    pct = f"{root_cause.confidence * 100:.0f}%"

    body = Text()
    body.append(root_cause.cause + "\n\n", style="bold")
    body.append("Confidence: ", style="dim")
    body.append(f"{pct}\n\n", style=f"bold {color}")
    body.append("Suggested fix:\n", style="italic dim")
    body.append(root_cause.suggested_fix)

    console.print(
        Panel(
            body,
            title=f"[bold {color}]Root Cause[/bold {color}]",
            border_style=color,
            padding=(1, 2),
        )
    )

    if root_cause.evidence:
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
            f"\n[dim]({extra} additional finding(s) not shown above — "
            f"run with --json to see all.)[/dim]"
        )

    console.print()


def _to_json_safe(obj: object) -> object:
    """Recursively convert dataclass / enum objects to JSON-safe primitives."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_json_safe(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_json_safe(i) for i in obj]
    return obj


@click.group()
@click.version_option(package_name="ecs-doctor")
def cli() -> None:
    """ECS Task Doctor — diagnose why your ECS service is failing."""


@cli.command()
@click.option("--cluster", required=True, help="ECS cluster name or ARN.")
@click.option("--service", required=True, help="ECS service name.")
@click.option(
    "--region",
    default=None,
    show_default=True,
    help="AWS region (overrides profile/env default).",
)
@click.option(
    "--profile",
    default=None,
    help="AWS named profile from ~/.aws/credentials.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Emit machine-readable JSON instead of the rich terminal report.",
)
def diagnose(
    cluster: str,
    service: str,
    region: str | None,
    profile: str | None,
    output_json: bool,
) -> None:
    """Run all diagnostic checks on an ECS service and report the most likely root cause."""
    try:
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

        kwargs = dict(
            cluster=cluster,
            service=service,
            region=effective_region,
            account_id=account_id,
        )

        if not output_json:
            console.print(
                f"[dim]Running diagnostics on [bold]{cluster}[/bold] / "
                f"[bold]{service}[/bold] in [bold]{effective_region}[/bold]…[/dim]"
            )

        events_findings = diagnose_events(ecs_client, **kwargs)
        stop_findings, task_arns = diagnose_stop_reasons(ecs_client, **kwargs)
        log_findings = diagnose_logs(
            ecs_client, logs_client, task_arns=task_arns, **kwargs
        )
        alb_findings = diagnose_alb_health(ecs_client, elb_client, **kwargs)

        all_findings = events_findings + stop_findings + log_findings + alb_findings
        root_cause = aggregate(all_findings)

    except NoCredentialsError:
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

    if output_json:
        output = {
            "cluster": cluster,
            "service": service,
            "region": effective_region,
            "root_cause": _to_json_safe(root_cause),
            "all_findings": [_to_json_safe(f) for f in all_findings],
        }
        click.echo(json.dumps(output, indent=2, default=str))
        return

    _render_report(cluster, service, root_cause, all_findings)
