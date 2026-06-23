
"""Interactive wizard for browsing AWS accounts and selecting ECS targets."""
from __future__ import annotations

import boto3

_AWS_REGIONS: list[str] = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
    "ap-south-1", "ca-central-1", "sa-east-1", "me-south-1", "af-south-1",
]

_AUTH_CHOICES: list[str] = [
    "AWS Profile (~/.aws/credentials)",
    "Access Keys (enter inline)",
    "Default Credential Chain (env vars / instance role / ECS task role)",
]


def _ask(prompt_fn, *args, **kwargs):
    """Wrap questionary calls to raise ClickException on Ctrl+C / None answer."""
    import click
    result = prompt_fn(*args, **kwargs).ask()
    if result is None:
        raise click.Abort()
    return result


def _build_session_from_profile(region: str):
    import questionary
    profiles = boto3.Session().available_profiles or ["default"]
    profile = _ask(questionary.select, "Select AWS profile:", choices=profiles)
    return boto3.Session(profile_name=profile, region_name=region)


def _build_session_from_keys(region: str):
    import questionary
    key_id = _ask(questionary.text, "AWS Access Key ID:")
    secret = _ask(questionary.password, "AWS Secret Access Key:")
    token = _ask(questionary.text, "Session Token (leave blank if not using temporary credentials):")
    return boto3.Session(
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        aws_session_token=token or None,
        region_name=region,
    )


def _build_session(auth_choice: str, region: str):
    if "Profile" in auth_choice:
        return _build_session_from_profile(region)
    if "Access Keys" in auth_choice:
        return _build_session_from_keys(region)
    return boto3.Session(region_name=region)


def _list_clusters(ecs_client) -> list[str]:
    arns: list[str] = []
    paginator = ecs_client.get_paginator("list_clusters")
    for page in paginator.paginate():
        arns.extend(page.get("clusterArns", []))
    if not arns:
        return []
    resp = ecs_client.describe_clusters(clusters=arns)
    return [c["clusterName"] for c in resp.get("clusters", []) if c.get("status") == "ACTIVE"]


def _list_services(ecs_client, cluster: str) -> list[str]:
    arns: list[str] = []
    paginator = ecs_client.get_paginator("list_services")
    for page in paginator.paginate(cluster=cluster):
        arns.extend(page.get("serviceArns", []))
    return [a.split("/")[-1] for a in arns]


def run_wizard() -> dict:
    """Run the interactive wizard and return kwargs compatible with engine.run_diagnosis().

    Returns a dict with keys: session, cluster, service, region, output_json.
    Requires `questionary` to be installed (pip install ecs-doctor[interactive]).
    """
    try:
        import questionary
    except ImportError as exc:
        raise ImportError(
            "Interactive mode requires questionary. "
            "Install it with: pip install 'ecs-doctor[interactive]'"
        ) from exc

    import click

    auth = _ask(questionary.select, "Authentication method:", choices=_AUTH_CHOICES)
    region = _ask(questionary.select, "AWS Region:", choices=_AWS_REGIONS)
    session = _build_session(auth, region)
    ecs_client = session.client("ecs", region_name=region)

    click.echo(f"[dim]Fetching clusters in {region}…[/dim]")
    clusters = _list_clusters(ecs_client)
    if not clusters:
        raise click.ClickException(f"No active ECS clusters found in {region}.")
    cluster = _ask(questionary.select, "Select ECS cluster:", choices=clusters)

    click.echo(f"[dim]Fetching services in {cluster}…[/dim]")
    services = _list_services(ecs_client, cluster)
    if not services:
        raise click.ClickException(f"No services found in cluster '{cluster}'.")
    service = _ask(questionary.select, "Select ECS service:", choices=services)

    output_choice = _ask(
        questionary.select,
        "Output format:",
        choices=["Rich terminal report", "JSON"],
    )

    return {
        "session": session,
        "cluster": cluster,
        "service": service,
        "region": region,
        "output_json": output_choice == "JSON",
    }
