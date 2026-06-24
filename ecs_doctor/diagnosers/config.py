
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

_SOURCE = "config"

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


def _validate_execution_role(td: dict) -> Finding | None:
    """Return a finding if executionRoleArn is absent from the task definition."""
    if not td.get("executionRoleArn"):
        return Finding(
            type=FindingType.MISSING_EXECUTION_ROLE,
            message=(
                "Task definition has no executionRoleArn. "
                "ECS cannot pull images from ECR, read Secrets Manager secrets, "
                "or write CloudWatch logs without an execution role."
            ),
            severity=Severity.CRITICAL,
            raw_data={"taskDefinitionArn": td.get("taskDefinitionArn", "")},
            source="config",
        )
    return None


def _validate_health_check_grace(td: dict, svc: dict) -> Finding | None:
    """Return a finding when containers define a health check but the service has no grace period."""
    container_has_healthcheck = any(
        c.get("healthCheck") for c in td.get("containerDefinitions", [])
    )
    grace = svc.get("healthCheckGracePeriodSeconds")
    if container_has_healthcheck and not grace:
        return Finding(
            type=FindingType.MISSING_HEALTH_CHECK_GRACE_PERIOD,
            message=(
                "Containers define a healthCheck but the service has no healthCheckGracePeriodSeconds. "
                "ECS may terminate tasks that are still starting up before they can pass the health check."
            ),
            severity=Severity.MEDIUM,
            raw_data={"healthCheckGracePeriodSeconds": grace},
            source="config",
        )
    return None


def _validate_port_mappings(td: dict, svc: dict) -> Finding | None:
    """Return a finding when load balancer expects a port not exposed by any container."""
    load_balancers = svc.get("loadBalancers", [])
    if not load_balancers:
        return None

    lb_ports = {lb.get("containerPort") for lb in load_balancers} - {None}
    exposed_ports = {
        pm.get("containerPort")
        for c in td.get("containerDefinitions", [])
        for pm in c.get("portMappings", [])
    } - {None}
    missing = lb_ports - exposed_ports
    if missing:
        return Finding(
            type=FindingType.MISSING_PORT_MAPPING,
            message=(
                f"Load balancer expects container port(s) {sorted(missing)} "
                "but no container in the task definition exposes them in portMappings."
            ),
            severity=Severity.HIGH,
            raw_data={"missing_ports": sorted(missing), "exposed_ports": sorted(exposed_ports)},
            source="config",
        )
    return None


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


def _validate_circuit_breaker(svc: dict) -> Finding | None:
    """Return a finding when the deployment circuit breaker is disabled."""
    dc = svc.get("deploymentConfiguration", {})
    cb = dc.get("deploymentCircuitBreaker", {})
    if not cb.get("enable", False):
        return Finding(
            type=FindingType.CIRCUIT_BREAKER_DISABLED,
            message=(
                "Deployment circuit breaker is disabled. "
                "Failed deployments will not auto-rollback, leaving the service stuck in a bad state."
            ),
            severity=Severity.LOW,
            raw_data={"deploymentCircuitBreaker": cb},
            source=_SOURCE,
        )
    return None


def _validate_log_config(td: dict) -> Finding | None:
    """Return a finding when any container has no logConfiguration."""
    containers_without_logs = [
        c.get("name", "unknown")
        for c in td.get("containerDefinitions", [])
        if not c.get("logConfiguration")
    ]
    if containers_without_logs:
        return Finding(
            type=FindingType.MISSING_LOG_CONFIG,
            message=(
                f"Container(s) {containers_without_logs} have no logConfiguration. "
                "stdout/stderr output will be lost — crash diagnostics become impossible."
            ),
            severity=Severity.HIGH,
            raw_data={"containers": containers_without_logs},
            source=_SOURCE,
        )
    return None


def _validate_memory_limits(td: dict) -> Finding | None:
    """Return a finding for EC2 containers with no memory or memoryReservation set."""
    requires = td.get("requiresCompatibilities", [])
    if "FARGATE" in requires:
        return None

    unlimited = [
        c.get("name", "unknown")
        for c in td.get("containerDefinitions", [])
        if c.get("memory") is None and c.get("memoryReservation") is None
    ]
    if unlimited:
        return Finding(
            type=FindingType.INVALID_TASK_CONFIG,
            message=(
                f"Container(s) {unlimited} on EC2 launch type have neither memory nor "
                "memoryReservation set. An unbounded container can consume all host memory "
                "and OOM-kill every task on the instance."
            ),
            severity=Severity.MEDIUM,
            raw_data={"containers": unlimited},
            source=_SOURCE,
        )
    return None


def _validate_depends_on_health(td: dict) -> Finding | None:
    """Detect dependsOn condition=HEALTHY where the referenced container has no healthCheck."""
    containers = td.get("containerDefinitions", [])
    containers_with_hc = {c.get("name", "") for c in containers if c.get("healthCheck")}

    for container in containers:
        for dep in container.get("dependsOn", []):
            if dep.get("condition") == "HEALTHY":
                ref = dep.get("containerName", "")
                if ref and ref not in containers_with_hc:
                    return Finding(
                        type=FindingType.INVALID_TASK_CONFIG,
                        message=(
                            f"Container '{container.get('name')}' has dependsOn condition=HEALTHY "
                            f"for '{ref}', but '{ref}' has no healthCheck configured. "
                            "The condition can never be satisfied — the task will never reach RUNNING."
                        ),
                        severity=Severity.HIGH,
                        raw_data={"container": container.get("name"), "depends_on_target": ref},
                        source=_SOURCE,
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
    for validator_result in (
        _validate_fargate_cpu_memory(td),
        _validate_execution_role(td),
        _validate_health_check_grace(td, svc),
        _validate_port_mappings(td, svc),
        _validate_circuit_breaker(svc),
        _validate_log_config(td),
        _validate_memory_limits(td),
        _validate_depends_on_health(td),
    ):
        if validator_result:
            findings.append(validator_result)

    return findings, service_config, task_config
