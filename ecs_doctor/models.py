
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
    # stop_reasons.py
    OOM_KILLED = "oom_killed"
    NON_ZERO_EXIT = "non_zero_exit"
    IMAGE_PULL_FAILURE = "image_pull_failure"
    SECRETS_INIT_FAILURE = "secrets_init_failure"
    ESSENTIAL_EXITED = "essential_container_exited"
    PREMATURE_EXIT = "premature_exit"
    GRACEFUL_SHUTDOWN_FAIL = "graceful_shutdown_failure"
    # logs.py
    LOG_CRASH_SIGNATURE = "log_crash_signature"
    # alb_health.py
    ALB_UNHEALTHY = "alb_unhealthy_target"
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
