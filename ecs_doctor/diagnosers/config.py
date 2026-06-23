
from botocore.exceptions import ClientError

from ecs_doctor._aws import ServiceDataCache, _AccessDeniedCached, iam_finding, is_access_denied, service_resource_arn
from ecs_doctor.models import (
    ContainerConfig,
    DeploymentConfig,
    Finding,
    FindingType,
    HealthCheckConfig,
    ServiceConfig,
    Severity,
    TaskConfig,
)

_ENV_MASK_VALUE = "***MASKED***"
_SENSITIVE_KEY_PATTERNS: frozenset[str] = frozenset({
    "password", "secret", "token", "key", "credential", "api_key", "auth",
    "passwd", "pwd", "private", "cert", "certificate",
})

# Fargate valid CPU → allowed memory values (MiB)
_FARGATE_VALID_CPU_MEMORY: dict[int, list[int]] = {
    256:   [512, 1024, 2048],
    512:   list(range(1024, 4097, 1024)),
    1024:  list(range(2048, 8193, 1024)),
    2048:  list(range(4096, 16385, 1024)),
    4096:  list(range(8192, 30721, 1024)),
    8192:  list(range(16384, 61441, 4096)),
    16384: list(range(32768, 122881, 8192)),
}


def _mask_env_value(key: str, value: str) -> str:
    lower = key.lower()
    if any(pattern in lower for pattern in _SENSITIVE_KEY_PATTERNS):
        return _ENV_MASK_VALUE
    return value


def _extract_health_check(hc: dict | None) -> HealthCheckConfig | None:
    if not hc:
        return None
    return HealthCheckConfig(
        command=hc.get("command", []),
        interval_seconds=hc.get("interval", 30),
        timeout_seconds=hc.get("timeout", 5),
        retries=hc.get("retries", 3),
        start_period_seconds=hc.get("startPeriod", 0),
    )


def _extract_container_config(cdef: dict) -> ContainerConfig:
    lc = cdef.get("logConfiguration", {})
    opts = lc.get("options", {})
    env = {
        e["name"]: _mask_env_value(e["name"], e.get("value", ""))
        for e in cdef.get("environment", [])
    }
    return ContainerConfig(
        name=cdef.get("name", ""),
        image=cdef.get("image", ""),
        cpu=cdef.get("cpu", 0),
        memory=cdef.get("memory"),
        memory_reservation=cdef.get("memoryReservation"),
        essential=cdef.get("essential", True),
        environment=env,
        health_check=_extract_health_check(cdef.get("healthCheck")),
        log_driver=lc.get("logDriver", ""),
        log_group=opts.get("awslogs-group"),
    )


def _extract_deployment_config(svc: dict) -> DeploymentConfig:
    dc = svc.get("deploymentConfiguration", {})
    cb = dc.get("deploymentCircuitBreaker", {})
    return DeploymentConfig(
        minimum_healthy_percent=dc.get("minimumHealthyPercent", 100),
        maximum_percent=dc.get("maximumPercent", 200),
        circuit_breaker_enabled=cb.get("enable", False),
        rollback_on_failure=cb.get("rollback", False),
    )


def _extract_service_config(svc: dict) -> ServiceConfig:
    return ServiceConfig(
        service_arn=svc.get("serviceArn", ""),
        service_name=svc.get("serviceName", ""),
        cluster_arn=svc.get("clusterArn", ""),
        desired_count=svc.get("desiredCount", 0),
        running_count=svc.get("runningCount", 0),
        pending_count=svc.get("pendingCount", 0),
        launch_type=svc.get("launchType", ""),
        platform_version=svc.get("platformVersion"),
        deployment_config=_extract_deployment_config(svc),
        capacity_provider_strategy=svc.get("capacityProviderStrategy", []),
        health_check_grace_period_seconds=svc.get("healthCheckGracePeriodSeconds"),
    )


def _extract_task_config(td: dict) -> TaskConfig:
    containers = [_extract_container_config(c) for c in td.get("containerDefinitions", [])]
    return TaskConfig(
        task_definition_arn=td.get("taskDefinitionArn", ""),
        family=td.get("family", ""),
        revision=td.get("revision", 0),
        cpu=td.get("cpu", ""),
        memory=td.get("memory", ""),
        network_mode=td.get("networkMode", ""),
        launch_type=td.get("requiresCompatibilities", [""])[0] if td.get("requiresCompatibilities") else "",
        execution_role_arn=td.get("executionRoleArn"),
        task_role_arn=td.get("taskRoleArn"),
        containers=containers,
    )


def _validate_fargate_cpu_memory(td: dict) -> Finding | None:
    """Return a finding if the Fargate CPU/memory combination is invalid."""
    requires = td.get("requiresCompatibilities", [])
    if "FARGATE" not in requires:
        return None

    try:
        cpu = int(td.get("cpu", 0))
        memory = int(td.get("memory", 0))
    except (ValueError, TypeError):
        return None

    valid_memory = _FARGATE_VALID_CPU_MEMORY.get(cpu)
    if valid_memory is None or memory not in valid_memory:
        return Finding(
            type=FindingType.INVALID_TASK_CONFIG,
            message=(
                f"Invalid Fargate CPU/memory combination: {cpu} CPU units / {memory} MiB. "
                f"Valid memory values for {cpu} CPU: {valid_memory or 'CPU value not recognised'}."
            ),
            severity=Severity.CRITICAL,
            raw_data={"cpu": cpu, "memory": memory, "valid_memory": valid_memory},
            source="config",
        )
    return None


def diagnose_config(
    service_cache: ServiceDataCache,
    ecs_client,
    cluster: str,
    service: str,
    region: str,
    account_id: str,
) -> tuple[list[Finding], ServiceConfig | None, TaskConfig | None]:
    try:
        svc = service_cache.get_service(cluster, service, region, account_id)
    except _AccessDeniedCached:
        return (
            [iam_finding(
                "ecs:DescribeServices",
                service_resource_arn(region, account_id, cluster, service),
                "config",
            )],
            None,
            None,
        )

    if not svc:
        return [], None, None

    service_config = _extract_service_config(svc)

    task_def_arn = svc.get("taskDefinition")
    if not task_def_arn:
        return [], service_config, None

    try:
        td_resp = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
    except ClientError as exc:
        if is_access_denied(exc):
            return [iam_finding("ecs:DescribeTaskDefinition", task_def_arn, "config")], service_config, None
        raise

    td = td_resp.get("taskDefinition", {})
    task_config = _extract_task_config(td)

    findings: list[Finding] = []
    fargate_finding = _validate_fargate_cpu_memory(td)
    if fargate_finding:
        findings.append(fargate_finding)

    return findings, service_config, task_config
