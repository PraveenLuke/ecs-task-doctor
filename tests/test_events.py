from __future__ import annotations

from ecs_doctor.diagnosers.events import diagnose_events
from ecs_doctor.models import FindingType, Severity
from tests.conftest import (
    ACCOUNT,
    CLUSTER,
    REGION,
    SERVICE,
    access_denied_error,
    make_ecs_client,
    make_service_cache,
)


def _svc_resp(events: list[dict]) -> dict:
    return {"services": [{"events": events}]}


def _event(msg: str) -> dict:
    return {"message": msg, "createdAt": "2026-01-01T00:00:00Z"}


# ---------------------------------------------------------------------------
# Placement failures
# ---------------------------------------------------------------------------

def test_placement_failure_unable_to_place():
    ecs = make_ecs_client(
        describe_services=_svc_resp([_event("was unable to place a task because no container instance met all of its requirements")])
    )
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    types = [f.type for f in findings]
    assert FindingType.PLACEMENT_FAILURE in types


def test_placement_failure_insufficient_cpu():
    ecs = make_ecs_client(
        describe_services=_svc_resp([_event("Insufficient CPU available")])
    )
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.PLACEMENT_FAILURE for f in findings)


# ---------------------------------------------------------------------------
# Health check failures
# ---------------------------------------------------------------------------

def test_health_check_failure_container():
    ecs = make_ecs_client(
        describe_services=_svc_resp([_event("failed container health checks")])
    )
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.HEALTH_CHECK_FAIL for f in findings)


def test_health_check_failure_alb_event():
    ecs = make_ecs_client(
        describe_services=_svc_resp(
            [_event("(service my-svc) (port 8080) is unhealthy in (target-group arn:aws:...)")]
        )
    )
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.HEALTH_CHECK_FAIL for f in findings)


# ---------------------------------------------------------------------------
# Deployment rollback
# ---------------------------------------------------------------------------

def test_deployment_rollback():
    ecs = make_ecs_client(
        describe_services=_svc_resp([_event("rolling back to deployment")])
    )
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.DEPLOYMENT_ROLLBACK for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_deployment_rollback_circuit_breaker():
    ecs = make_ecs_client(
        describe_services=_svc_resp([_event("service deployment paused due to failed deployment checks")])
    )
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.DEPLOYMENT_ROLLBACK for f in findings)


# ---------------------------------------------------------------------------
# Thrashing
# ---------------------------------------------------------------------------

def test_task_thrashing_detected():
    events = (
        [_event("started 1 task") for _ in range(4)]
        + [_event("stopped 1 task") for _ in range(4)]
    )
    ecs = make_ecs_client(describe_services=_svc_resp(events))
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT, last_n=20)
    assert any(f.type == FindingType.TASK_THRASHING for f in findings)
    thrash = next(f for f in findings if f.type == FindingType.TASK_THRASHING)
    assert thrash.severity == Severity.CRITICAL


def test_task_thrashing_below_threshold():
    events = (
        [_event("started 1 task") for _ in range(2)]
        + [_event("stopped 1 task") for _ in range(2)]
    )
    ecs = make_ecs_client(describe_services=_svc_resp(events))
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT, last_n=20)
    assert not any(f.type == FindingType.TASK_THRASHING for f in findings)


# ---------------------------------------------------------------------------
# No events / empty
# ---------------------------------------------------------------------------

def test_no_events_returns_empty():
    ecs = make_ecs_client(describe_services=_svc_resp([]))
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert findings == []


# ---------------------------------------------------------------------------
# AccessDenied
# ---------------------------------------------------------------------------

def test_access_denied_returns_iam_finding():
    ecs = make_ecs_client(
        describe_services=access_denied_error("DescribeServices", "AccessDeniedException")
    )
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert len(findings) == 1
    assert findings[0].type == FindingType.IAM_DENIED
    assert "ecs:DescribeServices" in findings[0].message
    assert findings[0].severity == Severity.CRITICAL


def test_access_denied_uses_correct_arn():
    ecs = make_ecs_client(
        describe_services=access_denied_error("DescribeServices", "AccessDenied")
    )
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert CLUSTER in findings[0].message
    assert SERVICE in findings[0].message


# ---------------------------------------------------------------------------
# Deduplication — same pattern should not produce two findings of same type
# ---------------------------------------------------------------------------

def test_no_duplicate_placement_findings():
    events = [
        _event("unable to place a task (constraint)"),
        _event("unable to place a task (different reason)"),
    ]
    ecs = make_ecs_client(describe_services=_svc_resp(events))
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    placement = [f for f in findings if f.type == FindingType.PLACEMENT_FAILURE]
    assert len(placement) == 1


# ---------------------------------------------------------------------------
# Deployment deadlock detection
# ---------------------------------------------------------------------------

def test_deployment_deadlock_detected():
    svc_data = {
        "events": [],
        "desiredCount": 2,
        "runningCount": 0,
        "pendingCount": 0,
        "deploymentConfiguration": {
            "minimumHealthyPercent": 100,
            "maximumPercent": 100,
        },
    }
    ecs = make_ecs_client(describe_services={"services": [svc_data]})
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert any(f.type == FindingType.DEPLOYMENT_CONFIG_DEADLOCK for f in findings)
    deadlock = next(f for f in findings if f.type == FindingType.DEPLOYMENT_CONFIG_DEADLOCK)
    assert deadlock.severity == Severity.CRITICAL


def test_no_deadlock_when_running_tasks_present():
    svc_data = {
        "events": [],
        "desiredCount": 2,
        "runningCount": 1,
        "pendingCount": 0,
        "deploymentConfiguration": {
            "minimumHealthyPercent": 100,
            "maximumPercent": 100,
        },
    }
    ecs = make_ecs_client(describe_services={"services": [svc_data]})
    findings = diagnose_events(make_service_cache(ecs), CLUSTER, SERVICE, REGION, ACCOUNT)
    assert not any(f.type == FindingType.DEPLOYMENT_CONFIG_DEADLOCK for f in findings)
