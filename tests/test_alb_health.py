from __future__ import annotations

from ecs_doctor.diagnosers.alb_health import diagnose_alb_health
from ecs_doctor.models import FindingType, Severity
from tests.conftest import (
    ACCOUNT,
    CLUSTER,
    REGION,
    SERVICE,
    access_denied_error,
    make_ecs_client,
    make_elbv2_client,
    make_service_cache,
)

_TG_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/my-tg/abc123"


def _svc_resp(load_balancers: list[dict]) -> dict:
    return {"services": [{"loadBalancers": load_balancers}]}


def _lb(tg_arn: str | None = _TG_ARN) -> dict:
    lb: dict = {"containerName": "app", "containerPort": 8080}
    if tg_arn is not None:
        lb["targetGroupArn"] = tg_arn
    return lb


def _target_health(state: str, reason: str = "", description: str = "") -> dict:
    return {
        "TargetHealthDescriptions": [
            {
                "Target": {"Id": "10.0.0.5", "Port": 8080},
                "TargetHealth": {
                    "State": state,
                    "Reason": reason,
                    "Description": description,
                },
            }
        ]
    }


def _call(ecs, elb):
    """Convenience wrapper for the new diagnose_alb_health(service_cache, elbv2_client, ...) signature."""
    return diagnose_alb_health(make_service_cache(ecs), elb, CLUSTER, SERVICE, REGION, ACCOUNT)


# ---------------------------------------------------------------------------
# No load balancers
# ---------------------------------------------------------------------------

def test_no_load_balancers_returns_empty():
    ecs = make_ecs_client(describe_services=_svc_resp([]))
    elb = make_elbv2_client()
    findings = _call(ecs, elb)
    assert findings == []
    elb.describe_target_health.assert_not_called()


# ---------------------------------------------------------------------------
# All targets healthy
# ---------------------------------------------------------------------------

def test_all_healthy_returns_empty():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb()]))
    elb = make_elbv2_client(describe_target_health=_target_health("healthy"))
    findings = _call(ecs, elb)
    assert findings == []


# ---------------------------------------------------------------------------
# Unhealthy — timeout
# ---------------------------------------------------------------------------

def test_unhealthy_timeout():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb()]))
    elb = make_elbv2_client(
        describe_target_health=_target_health(
            "unhealthy",
            reason="Target.Timeout",
            description="Request timed out",
        )
    )
    findings = _call(ecs, elb)
    assert len(findings) == 1
    assert findings[0].type == FindingType.ALB_UNHEALTHY
    assert findings[0].severity == Severity.CRITICAL
    assert "timed out" in findings[0].message


# ---------------------------------------------------------------------------
# Unhealthy — connection error
# ---------------------------------------------------------------------------

def test_unhealthy_connection_error():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb()]))
    elb = make_elbv2_client(
        describe_target_health=_target_health("unhealthy", reason="Target.ConnectionError")
    )
    findings = _call(ecs, elb)
    assert any(f.type == FindingType.ALB_UNHEALTHY for f in findings)
    f = next(x for x in findings if x.type == FindingType.ALB_UNHEALTHY)
    assert "refused" in f.message.lower() or "connection" in f.message.lower()


# ---------------------------------------------------------------------------
# Unhealthy — failed health checks (non-2xx)
# ---------------------------------------------------------------------------

def test_unhealthy_failed_health_checks():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb()]))
    elb = make_elbv2_client(
        describe_target_health=_target_health("unhealthy", reason="Target.FailedHealthChecks")
    )
    findings = _call(ecs, elb)
    assert any(f.type == FindingType.ALB_UNHEALTHY for f in findings)
    f = next(x for x in findings if x.type == FindingType.ALB_UNHEALTHY)
    assert "2xx" in f.message or "non-2xx" in f.message


# ---------------------------------------------------------------------------
# Initial state (advisory, not critical)
# ---------------------------------------------------------------------------

def test_initial_state_emits_advisory():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb()]))
    elb = make_elbv2_client(describe_target_health=_target_health("initial"))
    findings = _call(ecs, elb)
    assert any(f.severity == Severity.LOW for f in findings)
    assert any("initial" in f.message.lower() for f in findings)


# ---------------------------------------------------------------------------
# No targetGroupArn (CLB / missing config) — skip gracefully
# ---------------------------------------------------------------------------

def test_no_target_group_arn_skipped():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb(tg_arn=None)]))
    elb = make_elbv2_client()
    findings = _call(ecs, elb)
    assert findings == []
    elb.describe_target_health.assert_not_called()


# ---------------------------------------------------------------------------
# Unknown unhealthy reason
# ---------------------------------------------------------------------------

def test_unknown_unhealthy_reason():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb()]))
    elb = make_elbv2_client(
        describe_target_health=_target_health(
            "unhealthy",
            reason="Target.SomeNewReason",
            description="Something went wrong",
        )
    )
    findings = _call(ecs, elb)
    assert any(f.type == FindingType.ALB_UNHEALTHY for f in findings)


# ---------------------------------------------------------------------------
# AccessDenied on describe_target_health
# ---------------------------------------------------------------------------

def test_access_denied_on_describe_target_health():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb()]))
    elb = make_elbv2_client(
        describe_target_health=access_denied_error("DescribeTargetHealth", "AccessDenied")
    )
    findings = _call(ecs, elb)
    assert any(f.type == FindingType.IAM_DENIED for f in findings)
    f = next(x for x in findings if x.type == FindingType.IAM_DENIED)
    assert "elasticloadbalancing:DescribeTargetHealth" in f.message
    assert _TG_ARN in f.message


# ---------------------------------------------------------------------------
# AccessDenied on describe_services
# ---------------------------------------------------------------------------

def test_access_denied_on_describe_services():
    ecs = make_ecs_client(
        describe_services=access_denied_error("DescribeServices", "AccessDeniedException")
    )
    elb = make_elbv2_client()
    findings = _call(ecs, elb)
    assert any(f.type == FindingType.IAM_DENIED for f in findings)


# ---------------------------------------------------------------------------
# raw_data contains tg_arn for downstream use
# ---------------------------------------------------------------------------

def test_raw_data_contains_tg_arn():
    ecs = make_ecs_client(describe_services=_svc_resp([_lb()]))
    elb = make_elbv2_client(
        describe_target_health=_target_health("unhealthy", reason="Target.Timeout")
    )
    findings = _call(ecs, elb)
    f = next(x for x in findings if x.type == FindingType.ALB_UNHEALTHY)
    assert f.raw_data["tg_arn"] == _TG_ARN
