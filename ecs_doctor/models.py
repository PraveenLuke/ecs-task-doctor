
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(str, Enum):
    # events.py
    PLACEMENT_FAILURE = "placement_failure"
    HEALTH_CHECK_FAIL = "health_check_failure"
    TASK_THRASHING = "task_thrashing"
    DEPLOYMENT_ROLLBACK = "deployment_rollback"
    DEPLOYMENT_CONFIG_DEADLOCK = "deployment_config_deadlock"
    DEPLOYMENT_STALL = "deployment_stall"
    # stop_reasons.py
    OOM_KILLED = "oom_killed"
    NON_ZERO_EXIT = "non_zero_exit"
    IMAGE_PULL_FAILURE = "image_pull_failure"
    SECRETS_INIT_FAILURE = "secrets_init_failure"
    ESSENTIAL_EXITED = "essential_container_exited"
    PREMATURE_EXIT = "premature_exit"
    GRACEFUL_SHUTDOWN_FAIL = "graceful_shutdown_failure"
    SPOT_INTERRUPTED = "spot_interrupted"
    TASK_FAILED_TO_START = "task_failed_to_start"
    CONTAINER_START_FAILURE = "container_start_failure"
    SCHEDULER_REPLACED = "scheduler_replaced"
    USER_INITIATED_STOP = "user_initiated_stop"
    # logs.py
    LOG_CRASH_SIGNATURE = "log_crash_signature"
    DISK_ERROR = "disk_error"
    EFS_MOUNT_FAILURE = "efs_mount_failure"
    PORT_CONFLICT = "port_conflict"
    FIRELENS_LOG_DRIVER = "firelens_log_driver"
    # alb_health.py
    ALB_UNHEALTHY = "alb_unhealthy_target"
    NO_ALB_TARGETS = "no_alb_targets"
    # metrics.py
    HIGH_CPU_UTILIZATION = "high_cpu_utilization"
    HIGH_MEMORY_UTILIZATION = "high_memory_utilization"
    # config.py
    INVALID_TASK_CONFIG = "invalid_task_config"
    MISSING_EXECUTION_ROLE = "missing_execution_role"
    MISSING_HEALTH_CHECK_GRACE_PERIOD = "missing_health_check_grace_period"
    MISSING_PORT_MAPPING = "missing_port_mapping"
    # network.py
    NETWORK_CONNECTIVITY = "network_connectivity"
    NETWORK_ACL_DENY = "network_acl_deny"
    SG_INGRESS_BLOCKED = "sg_ingress_blocked"
    # stop_reasons.py
    DEPENDENCY_FAILED = "dependency_failed"
    # config.py
    CIRCUIT_BREAKER_DISABLED = "circuit_breaker_disabled"
    MISSING_LOG_CONFIG = "missing_log_config"
    # shared
    IAM_DENIED = "iam_access_denied"


@dataclass
class Finding:
    type: FindingType
    message: str
    severity: Severity
    raw_data: dict[str, Any] = field(default_factory=dict)
    source: str = ""


@dataclass
class RootCause:
    cause: str
    confidence: float
    evidence: list[Finding]
    suggested_fix: str


# ---------------------------------------------------------------------------
# Metrics models
# ---------------------------------------------------------------------------

@dataclass
class MetricPoint:
    timestamp: str
    average: float
    maximum: float
    unit: str


@dataclass
class MetricSnapshot:
    cluster: str
    service: str
    period_seconds: int
    lookback_hours: int
    cpu_avg_percent: float | None
    cpu_max_percent: float | None
    memory_avg_percent: float | None
    memory_max_percent: float | None
    cpu_datapoints: list[MetricPoint] = field(default_factory=list)
    memory_datapoints: list[MetricPoint] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Configuration models
# ---------------------------------------------------------------------------

@dataclass
class HealthCheckConfig:
    command: list[str]
    interval_seconds: int
    timeout_seconds: int
    retries: int
    start_period_seconds: int


@dataclass
class ContainerConfig:
    name: str
    image: str
    cpu: int
    memory: int | None
    memory_reservation: int | None
    essential: bool
    environment: dict[str, str]
    health_check: HealthCheckConfig | None
    log_driver: str
    log_group: str | None


@dataclass
class DeploymentConfig:
    minimum_healthy_percent: int
    maximum_percent: int
    circuit_breaker_enabled: bool
    rollback_on_failure: bool


@dataclass
class TaskConfig:
    task_definition_arn: str
    family: str
    revision: int
    cpu: str
    memory: str
    network_mode: str
    launch_type: str
    execution_role_arn: str | None
    task_role_arn: str | None
    containers: list[ContainerConfig]


@dataclass
class ServiceConfig:
    service_arn: str
    service_name: str
    cluster_arn: str
    desired_count: int
    running_count: int
    pending_count: int
    launch_type: str
    platform_version: str | None
    deployment_config: DeploymentConfig
    capacity_provider_strategy: list[dict]
    health_check_grace_period_seconds: int | None
