from __future__ import annotations

from botocore.exceptions import ClientError

from ecs_doctor.diagnosers.logs import diagnose_logs
from ecs_doctor.models import FindingType, Severity
from tests.conftest import (
    ACCOUNT,
    CLUSTER,
    REGION,
    SERVICE,
    access_denied_error,
    make_ecs_client,
    make_logs_client,
)

_TASK_ARN = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/{CLUSTER}/abc123taskid"
_TASK_ID = "abc123taskid"
_LOG_GROUP = "/ecs/my-service"
_STREAM_PREFIX = "ecs"
_CONTAINER = "app"
_STREAM_NAME = f"{_STREAM_PREFIX}/{_CONTAINER}/{_TASK_ID}"
_TASK_DEF_ARN = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/my-td:1"


def _svc_resp(task_def_arn: str = _TASK_DEF_ARN) -> dict:
    return {
        "services": [
            {
                "taskDefinition": task_def_arn,
                "loadBalancers": [],
            }
        ]
    }


def _td_resp(log_driver: str = "awslogs", container_name: str = _CONTAINER) -> dict:
    log_config: dict = {}
    if log_driver == "awslogs":
        log_config = {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": _LOG_GROUP,
                "awslogs-stream-prefix": _STREAM_PREFIX,
                "awslogs-region": REGION,
            },
        }
    elif log_driver == "splunk":
        log_config = {"logDriver": "splunk", "options": {}}

    return {
        "taskDefinition": {
            "containerDefinitions": [
                {"name": container_name, "logConfiguration": log_config}
            ]
        }
    }


def _log_events(lines: list[str]) -> dict:
    return {"events": [{"message": line} for line in lines]}


def _make_ecs(log_driver: str = "awslogs") -> object:
    return make_ecs_client(
        describe_services=_svc_resp(),
        describe_task_definition=_td_resp(log_driver=log_driver),
    )


# ---------------------------------------------------------------------------
# Python traceback
# ---------------------------------------------------------------------------

def test_python_traceback_detected():
    ecs = _make_ecs()
    logs = make_logs_client(
        get_log_events=_log_events([
            "Starting app...",
            "Traceback (most recent call last):",
            '  File "app.py", line 10, in <module>',
            "AttributeError: 'NoneType' object has no attribute 'connect'",
        ])
    )
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    assert any(f.type == FindingType.LOG_CRASH_SIGNATURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.LOG_CRASH_SIGNATURE)
    assert f.severity == Severity.HIGH
    assert "Python traceback" in f.message


# ---------------------------------------------------------------------------
# Go panic
# ---------------------------------------------------------------------------

def test_go_panic_detected():
    ecs = _make_ecs()
    logs = make_logs_client(
        get_log_events=_log_events(["panic: runtime error: index out of range"])
    )
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    assert any("Go panic" in f.message for f in findings)


# ---------------------------------------------------------------------------
# Connection refused
# ---------------------------------------------------------------------------

def test_connection_refused_detected():
    ecs = _make_ecs()
    logs = make_logs_client(
        get_log_events=_log_events(["dial tcp 10.0.0.5:5432: connect: connection refused"])
    )
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    assert any(f.type == FindingType.LOG_CRASH_SIGNATURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.LOG_CRASH_SIGNATURE)
    assert f.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# DNS failure
# ---------------------------------------------------------------------------

def test_dns_resolution_failure_detected():
    ecs = _make_ecs()
    logs = make_logs_client(
        get_log_events=_log_events(["dial tcp: lookup mydb.internal: no such host"])
    )
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    assert any("DNS" in f.message for f in findings)


# ---------------------------------------------------------------------------
# exec format error (wrong arch)
# ---------------------------------------------------------------------------

def test_exec_format_error_detected():
    ecs = _make_ecs()
    logs = make_logs_client(
        get_log_events=_log_events([
            "standard_init_linux.go:228: exec user process caused: exec format error"
        ])
    )
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    assert any(f.type == FindingType.LOG_CRASH_SIGNATURE for f in findings)
    f = next(x for x in findings if x.type == FindingType.LOG_CRASH_SIGNATURE)
    assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# OOM in logs
# ---------------------------------------------------------------------------

def test_oom_signature_in_logs():
    ecs = _make_ecs()
    logs = make_logs_client(
        get_log_events=_log_events(["FATAL: out of memory (cannot allocate 1073741824 bytes)"])
    )
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    oom = [f for f in findings if "OOM" in f.message or "memory" in f.message.lower()]
    assert oom


# ---------------------------------------------------------------------------
# Missing log stream (graceful skip)
# ---------------------------------------------------------------------------

def test_missing_log_stream_is_skipped():
    ecs = _make_ecs()
    logs_client = make_logs_client()
    logs_client.get_log_events.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "The specified log stream does not exist"}},
        "GetLogEvents",
    )
    findings = diagnose_logs(ecs, logs_client, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    # Should return empty, not raise
    assert findings == []


# ---------------------------------------------------------------------------
# No awslogs driver — skip gracefully
# ---------------------------------------------------------------------------

def test_no_awslogs_driver_returns_empty():
    ecs = make_ecs_client(
        describe_services=_svc_resp(),
        describe_task_definition=_td_resp(log_driver="splunk"),
    )
    logs = make_logs_client(get_log_events=_log_events(["some log line"]))
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    assert findings == []


# ---------------------------------------------------------------------------
# Empty task_arns list — return immediately
# ---------------------------------------------------------------------------

def test_empty_task_arns_returns_empty():
    ecs = _make_ecs()
    logs = make_logs_client(get_log_events=_log_events(["error"]))
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [], REGION, ACCOUNT)
    assert findings == []


# ---------------------------------------------------------------------------
# AccessDenied on get_log_events
# ---------------------------------------------------------------------------

def test_access_denied_on_get_log_events():
    ecs = _make_ecs()
    logs_client = make_logs_client()
    logs_client.get_log_events.side_effect = access_denied_error("GetLogEvents", "AccessDeniedException")
    findings = diagnose_logs(ecs, logs_client, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    assert any(f.type == FindingType.IAM_DENIED for f in findings)
    f = next(x for x in findings if x.type == FindingType.IAM_DENIED)
    assert "logs:GetLogEvents" in f.message


# ---------------------------------------------------------------------------
# Log context snippet included in raw_data
# ---------------------------------------------------------------------------

def test_log_context_included_in_raw_data():
    ecs = _make_ecs()
    logs = make_logs_client(
        get_log_events=_log_events([
            "line 1",
            "Traceback (most recent call last):",
            "  File app.py line 5",
            "ValueError: boom",
        ])
    )
    findings = diagnose_logs(ecs, logs, CLUSTER, SERVICE, [_TASK_ARN], REGION, ACCOUNT)
    f = next(x for x in findings if x.type == FindingType.LOG_CRASH_SIGNATURE)
    assert "context" in f.raw_data
    assert "Traceback" in f.raw_data["context"]
