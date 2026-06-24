from __future__ import annotations

import pytest

from ecs_doctor.diagnosers.stop_reasons import diagnose_stop_reasons
from ecs_doctor.models import FindingType, Severity
from tests.conftest import (
    ACCOUNT,
    CLUSTER,
    REGION,
    SERVICE,
    access_denied_error,
    make_ecs_client,
)

_TASK_ARN = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/{CLUSTER}/abc123"


def _make_client(task_arns: list[str], tasks: list[dict]) -> object:
    return make_ecs_client(
        list_tasks={"taskArns": task_arns},
        describe_tasks={"tasks": tasks},
    )


def _task(
    stop_code: str = "",
    stopped_reason: str = "",
    containers: list[dict] | None = None,
    task_arn: str = _TASK_ARN,
) -> dict:
    return {
        "taskArn": task_arn,
        "stopCode": stop_code,
        "stoppedReason": stopped_reason,
        "containers": containers or [],
    }


def _container(name: str = "app", exit_code: int | None = None, reason: str = "") -> dict:
    c: dict = {"name": name, "reason": reason}
    if exit_code is not None:
        c["exitCode"] = exit_code
    return c


# ---------------------------------------------------------------------------
# OOM (exit 137 / 139)
# ---------------------------------------------------------------------------

def test_oom_exit_137():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(stopped_reason="Essential container in task exited", containers=[_container(exit_code=137)])],
    )
    findings, arns = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.OOM_KILLED for f in findings)
    oom = next(f for f in findings if f.type == FindingType.OOM_KILLED)
    assert oom.severity == Severity.CRITICAL


def test_oom_exit_139_segfault():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(exit_code=139)])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.OOM_KILLED for f in findings)


# ---------------------------------------------------------------------------
# Image pull failure via stopCode
# ---------------------------------------------------------------------------

def test_image_pull_via_stop_code():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(stop_code="CannotPullContainerImage", stopped_reason="pull rate limit exceeded")],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.IMAGE_PULL_FAILURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.IMAGE_PULL_FAILURE)
    assert f.severity == Severity.CRITICAL
    assert "rate limit" in f.message


def test_image_pull_via_container_reason():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(reason="CannotPullContainerError: pull access denied")])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.IMAGE_PULL_FAILURE for f in findings)


# ---------------------------------------------------------------------------
# Secrets / ResourceInitializationError
# ---------------------------------------------------------------------------

def test_secrets_init_failure():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(
            stop_code="ResourceInitializationError",
            stopped_reason="unable to retrieve secret arn:aws:secretsmanager:...",
        )],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.SECRETS_INIT_FAILURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.SECRETS_INIT_FAILURE)
    assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Non-zero exit
# ---------------------------------------------------------------------------

def test_non_zero_exit_code_1():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(stopped_reason="Essential container in task exited", containers=[_container(exit_code=1)])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.NON_ZERO_EXIT for f in findings)
    f = next(x for x in findings if x.type == FindingType.NON_ZERO_EXIT)
    assert f.severity == Severity.HIGH


def test_non_zero_exit_code_255():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(exit_code=255)])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.NON_ZERO_EXIT for f in findings)


# ---------------------------------------------------------------------------
# Premature exit (exit 0)
# ---------------------------------------------------------------------------

def test_premature_exit_code_0():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(
            stopped_reason="Essential container in task exited",
            containers=[_container(exit_code=0)],
        )],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.PREMATURE_EXIT for f in findings)


# ---------------------------------------------------------------------------
# Graceful shutdown failure (exit 143)
# ---------------------------------------------------------------------------

def test_graceful_shutdown_failure():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(exit_code=143)])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.GRACEFUL_SHUTDOWN_FAIL for f in findings)
    f = next(x for x in findings if x.type == FindingType.GRACEFUL_SHUTDOWN_FAIL)
    assert f.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Essential container exited (text fallback, no exit code)
# ---------------------------------------------------------------------------

def test_essential_exited_no_exit_code():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(
            stopped_reason="Essential container in task exited",
            containers=[_container(exit_code=None)],
        )],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.ESSENTIAL_EXITED for f in findings)


# ---------------------------------------------------------------------------
# No stopped tasks
# ---------------------------------------------------------------------------

def test_no_stopped_tasks_returns_empty():
    ecs = make_ecs_client(list_tasks={"taskArns": []})
    findings, arns = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert findings == []
    assert arns == []


# ---------------------------------------------------------------------------
# Deduplication — multiple tasks with same failure
# ---------------------------------------------------------------------------

def test_deduplication_across_tasks():
    tasks = [
        _task(
            task_arn=f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/{CLUSTER}/task{i}",
            containers=[_container(exit_code=137)],
        )
        for i in range(3)
    ]
    ecs = _make_client(
        [t["taskArn"] for t in tasks],
        tasks,
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    oom_findings = [f for f in findings if f.type == FindingType.OOM_KILLED]
    assert len(oom_findings) == 1
    assert oom_findings[0].raw_data["count"] == 3


# ---------------------------------------------------------------------------
# AccessDenied
# ---------------------------------------------------------------------------

def test_access_denied_on_list_tasks():
    ecs = make_ecs_client(
        list_tasks=access_denied_error("ListTasks")
    )
    findings, arns = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert len(findings) == 1
    assert findings[0].type == FindingType.IAM_DENIED
    assert "ecs:ListTasks" in findings[0].message
    assert arns == []


def test_access_denied_on_describe_tasks():
    ecs = make_ecs_client(
        list_tasks={"taskArns": [_TASK_ARN]},
        describe_tasks=access_denied_error("DescribeTasks"),
    )
    findings, arns = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.IAM_DENIED for f in findings)
    assert "ecs:DescribeTasks" in findings[0].message
    # task_arns still returned so logs can try
    assert arns == [_TASK_ARN]


# ---------------------------------------------------------------------------
# task_arns passthrough
# ---------------------------------------------------------------------------

def test_task_arns_returned():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(exit_code=1)])],
    )
    _, arns = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert arns == [_TASK_ARN]


# ---------------------------------------------------------------------------
# Exit 126 / 127 — container start failure
# ---------------------------------------------------------------------------

def test_exit_126_not_executable():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(exit_code=126)])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.CONTAINER_START_FAILURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.CONTAINER_START_FAILURE)
    assert f.severity == Severity.HIGH
    assert "not executable" in f.message or "126" in f.message


def test_exit_127_command_not_found():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(exit_code=127)])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.CONTAINER_START_FAILURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.CONTAINER_START_FAILURE)
    assert f.severity == Severity.HIGH
    assert "not found" in f.message or "127" in f.message


# ---------------------------------------------------------------------------
# CannotStartContainerError in container reason
# ---------------------------------------------------------------------------

def test_cannot_start_container_error():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(reason="CannotStartContainerError: failed to start container")])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.CONTAINER_START_FAILURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.CONTAINER_START_FAILURE)
    assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# ServiceSchedulerInitiated / UserInitiated stopCodes
# ---------------------------------------------------------------------------

def test_scheduler_replaced_stop_code():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(stop_code="ServiceSchedulerInitiated", stopped_reason="Scaling activity initiated by deployment")],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.SCHEDULER_REPLACED for f in findings)


def test_user_initiated_stop_code():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(stop_code="UserInitiated", stopped_reason="Task stopped by user")],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.USER_INITIATED_STOP for f in findings)


# ---------------------------------------------------------------------------
# Exit 132 — SIGILL (wrong CPU architecture)
# ---------------------------------------------------------------------------

def test_exit_132_sigill():
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[_container(exit_code=132)])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.CONTAINER_START_FAILURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.CONTAINER_START_FAILURE)
    assert f.severity == Severity.HIGH
    assert "132" in f.message or "SIGILL" in f.message or "architecture" in f.message.lower()


# ---------------------------------------------------------------------------
# dependsOn — container with no exit code, no reason, not essential
# ---------------------------------------------------------------------------

def test_dependency_failed_no_exit_not_essential():
    container = {"name": "sidecar", "reason": "", "essential": False}
    ecs = _make_client(
        [_TASK_ARN],
        [_task(containers=[container])],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.DEPENDENCY_FAILED for f in findings)
    f = next(x for x in findings if x.type == FindingType.DEPENDENCY_FAILED)
    assert f.severity == Severity.LOW


def test_essential_container_no_exit_not_dependency_failed():
    container = {"name": "app", "reason": "", "essential": True}
    ecs = _make_client(
        [_TASK_ARN],
        [_task(
            stopped_reason="Essential container in task exited",
            containers=[container],
        )],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert not any(f.type == FindingType.DEPENDENCY_FAILED for f in findings)


# ---------------------------------------------------------------------------
# dependsOn — essential container stopped with "dependent container" reason
# ---------------------------------------------------------------------------

def test_dependency_failed_essential_with_reason():
    container = {
        "name": "app",
        "reason": "Dependent container failed health check conditions",
        "essential": True,
    }
    ecs = _make_client(
        [_TASK_ARN],
        [_task(
            stopped_reason="Dependent container failed health check conditions",
            containers=[container],
        )],
    )
    findings, _ = diagnose_stop_reasons(ecs, CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.DEPENDENCY_FAILED for f in findings)
    f = next(x for x in findings if x.type == FindingType.DEPENDENCY_FAILED)
    assert f.severity == Severity.MEDIUM
    assert "dependsOn" in f.message or "HEALTHY" in f.message
