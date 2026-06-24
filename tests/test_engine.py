"""Tests for ecs_doctor.engine."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tests.conftest import ACCOUNT, CLUSTER, REGION, SERVICE

from ecs_doctor.engine import DiagnosisRequest, DiagnosisResult, run_diagnosis, to_json_safe
from ecs_doctor.models import (
    ContainerConfig,
    DeploymentConfig,
    Finding,
    FindingType,
    MetricSnapshot,
    RootCause,
    ServiceConfig,
    Severity,
    TaskConfig,
)

_PATCH_EVENTS = "ecs_doctor.engine.diagnose_events"
_PATCH_STOP = "ecs_doctor.engine.diagnose_stop_reasons"
_PATCH_LOGS = "ecs_doctor.engine.diagnose_logs"
_PATCH_ALB = "ecs_doctor.engine.diagnose_alb_health"
_PATCH_AGG = "ecs_doctor.engine.aggregate"
_PATCH_NETWORK = "ecs_doctor.diagnosers.network.diagnose_network"


def _req():
    return DiagnosisRequest(cluster=CLUSTER, service=SERVICE, region=REGION, account_id=ACCOUNT)


def _root_cause():
    return RootCause(cause="OOM", confidence=0.9, evidence=[], suggested_fix="Add more memory")


def _finding(ftype=FindingType.OOM_KILLED):
    return Finding(type=ftype, message="test", severity=Severity.CRITICAL, source="test")


def _run(
    request=None,
    include_metrics=False,
    include_config=False,
    events=None,
    stop_findings=None,
    logs=None,
    alb=None,
    extra_patches=None,
):
    patches = {
        _PATCH_EVENTS: events or [],
        _PATCH_STOP: (stop_findings or [], []),
        _PATCH_LOGS: logs or [],
        _PATCH_ALB: alb or [],
        _PATCH_AGG: _root_cause(),
    }
    ctx = [
        patch(_PATCH_EVENTS, return_value=patches[_PATCH_EVENTS]),
        patch(_PATCH_STOP, return_value=patches[_PATCH_STOP]),
        patch(_PATCH_LOGS, return_value=patches[_PATCH_LOGS]),
        patch(_PATCH_ALB, return_value=patches[_PATCH_ALB]),
        patch(_PATCH_AGG, return_value=patches[_PATCH_AGG]),
    ]
    if extra_patches:
        ctx.extend(extra_patches)

    with (
        patch(_PATCH_EVENTS, return_value=events or []),
        patch(_PATCH_STOP, return_value=(stop_findings or [], [])),
        patch(_PATCH_LOGS, return_value=logs or []),
        patch(_PATCH_ALB, return_value=alb or []),
        patch(_PATCH_AGG, return_value=_root_cause()),
        patch(_PATCH_NETWORK, return_value=[]),
    ):
        return run_diagnosis(
            ecs_client=MagicMock(),
            logs_client=MagicMock(),
            elb_client=MagicMock(),
            cw_client=MagicMock(),
            ec2_client=MagicMock(),
            request=request or _req(),
            include_metrics=include_metrics,
            include_config=include_config,
        )


# ---------------------------------------------------------------------------
# to_json_safe
# ---------------------------------------------------------------------------


class TestToJsonSafe:
    def test_dataclass_becomes_dict(self):
        f = _finding()
        result = to_json_safe(f)
        assert isinstance(result, dict)
        assert result["message"] == "test"
        assert result["source"] == "test"

    def test_list_of_dataclasses_becomes_list_of_dicts(self):
        findings = [_finding(), _finding(FindingType.ALB_UNHEALTHY)]
        result = to_json_safe(findings)
        assert isinstance(result, list)
        assert len(result) == 2
        assert all(isinstance(r, dict) for r in result)

    def test_string_passthrough(self):
        assert to_json_safe("hello") == "hello"

    def test_int_passthrough(self):
        assert to_json_safe(42) == 42

    def test_none_passthrough(self):
        assert to_json_safe(None) is None

    def test_nested_dataclass(self):
        rc = RootCause(cause="OOM", confidence=0.9, evidence=[_finding()], suggested_fix="Fix it")
        result = to_json_safe(rc)
        assert isinstance(result, dict)
        assert isinstance(result["evidence"], list)
        assert isinstance(result["evidence"][0], dict)


# ---------------------------------------------------------------------------
# run_diagnosis
# ---------------------------------------------------------------------------


class TestRunDiagnosis:
    def test_returns_diagnosis_result(self):
        result = _run()
        assert isinstance(result, DiagnosisResult)

    def test_request_preserved(self):
        req = _req()
        result = _run(request=req)
        assert result.request.cluster == CLUSTER
        assert result.request.service == SERVICE

    def test_root_cause_set(self):
        result = _run()
        assert result.root_cause.cause == "OOM"

    def test_duration_ms_is_non_negative(self):
        result = _run()
        assert result.duration_ms >= 0

    def test_all_findings_combined(self):
        e = [_finding(FindingType.PLACEMENT_FAILURE)]
        s = [_finding(FindingType.OOM_KILLED)]
        l = [_finding(FindingType.LOG_CRASH_SIGNATURE)]
        a = [_finding(FindingType.ALB_UNHEALTHY)]
        result = _run(events=e, stop_findings=s, logs=l, alb=a)
        assert len(result.all_findings) == 4

    def test_include_metrics_false_returns_none(self):
        result = _run(include_metrics=False)
        assert result.metrics is None

    def test_include_config_false_returns_none(self):
        result = _run(include_config=False)
        assert result.service_config is None
        assert result.task_config is None

    def test_include_metrics_true_populates_metrics(self):
        mock_snapshot = MetricSnapshot(
            cluster=CLUSTER, service=SERVICE,
            period_seconds=300, lookback_hours=3,
            cpu_avg_percent=50.0, cpu_max_percent=60.0,
            memory_avg_percent=40.0, memory_max_percent=50.0,
        )
        with (
            patch(_PATCH_EVENTS, return_value=[]),
            patch(_PATCH_STOP, return_value=([], [])),
            patch(_PATCH_LOGS, return_value=[]),
            patch(_PATCH_ALB, return_value=[]),
            patch(_PATCH_AGG, return_value=_root_cause()),
            patch(
                "ecs_doctor.diagnosers.metrics.diagnose_metrics",
                return_value=([], mock_snapshot),
            ),
        ):
            result = run_diagnosis(
                ecs_client=MagicMock(), logs_client=MagicMock(),
                elb_client=MagicMock(), cw_client=MagicMock(),
                ec2_client=MagicMock(),
                request=_req(), include_metrics=True, include_config=False,
            )
        assert result.metrics is not None
        assert result.metrics.cpu_avg_percent == 50.0

    def test_include_config_true_populates_configs(self):
        mock_dc = DeploymentConfig(100, 200, False, False)
        mock_svc_cfg = ServiceConfig(
            service_arn="arn:...", service_name=SERVICE, cluster_arn="arn:...",
            desired_count=2, running_count=1, pending_count=0,
            launch_type="FARGATE", platform_version="LATEST",
            deployment_config=mock_dc, capacity_provider_strategy=[],
            health_check_grace_period_seconds=None,
        )
        mock_container = ContainerConfig(
            name="app", image="myimage:latest", cpu=256, memory=512,
            memory_reservation=None, essential=True, environment={},
            health_check=None, log_driver="awslogs", log_group="/ecs/svc",
        )
        mock_task_cfg = TaskConfig(
            task_definition_arn="arn:...", family="my-td", revision=1,
            cpu="256", memory="512", network_mode="awsvpc", launch_type="FARGATE",
            execution_role_arn=None, task_role_arn=None,
            containers=[mock_container],
        )
        with (
            patch(_PATCH_EVENTS, return_value=[]),
            patch(_PATCH_STOP, return_value=([], [])),
            patch(_PATCH_LOGS, return_value=[]),
            patch(_PATCH_ALB, return_value=[]),
            patch(_PATCH_AGG, return_value=_root_cause()),
            patch(
                "ecs_doctor.diagnosers.config.diagnose_config",
                return_value=([], mock_svc_cfg, mock_task_cfg),
            ),
        ):
            result = run_diagnosis(
                ecs_client=MagicMock(), logs_client=MagicMock(),
                elb_client=MagicMock(), cw_client=MagicMock(),
                ec2_client=MagicMock(),
                request=_req(), include_metrics=False, include_config=True,
            )
        assert result.service_config is not None
        assert result.service_config.service_name == SERVICE
        assert result.task_config is not None
        assert result.task_config.family == "my-td"

    def test_config_findings_added_to_all_findings(self):
        config_finding = _finding(FindingType.INVALID_TASK_CONFIG)
        mock_dc = DeploymentConfig(100, 200, False, False)
        mock_svc_cfg = ServiceConfig(
            service_arn="arn:...", service_name=SERVICE, cluster_arn="arn:...",
            desired_count=1, running_count=0, pending_count=0,
            launch_type="FARGATE", platform_version=None,
            deployment_config=mock_dc, capacity_provider_strategy=[],
            health_check_grace_period_seconds=None,
        )
        with (
            patch(_PATCH_EVENTS, return_value=[]),
            patch(_PATCH_STOP, return_value=([], [])),
            patch(_PATCH_LOGS, return_value=[]),
            patch(_PATCH_ALB, return_value=[]),
            patch(_PATCH_AGG, return_value=_root_cause()),
            patch(
                "ecs_doctor.diagnosers.config.diagnose_config",
                return_value=([config_finding], mock_svc_cfg, None),
            ),
        ):
            result = run_diagnosis(
                ecs_client=MagicMock(), logs_client=MagicMock(),
                elb_client=MagicMock(), cw_client=MagicMock(),
                ec2_client=MagicMock(),
                request=_req(), include_metrics=False, include_config=True,
            )
        assert FindingType.INVALID_TASK_CONFIG in {f.type for f in result.all_findings}

    def test_network_findings_included_in_all_findings(self):
        net_finding = _finding(FindingType.NETWORK_CONNECTIVITY)
        with (
            patch(_PATCH_EVENTS, return_value=[]),
            patch(_PATCH_STOP, return_value=([], [])),
            patch(_PATCH_LOGS, return_value=[]),
            patch(_PATCH_ALB, return_value=[]),
            patch(_PATCH_AGG, return_value=_root_cause()),
            patch(
                "ecs_doctor.diagnosers.network.diagnose_network",
                return_value=[net_finding],
            ),
        ):
            result = run_diagnosis(
                ecs_client=MagicMock(), logs_client=MagicMock(),
                elb_client=MagicMock(), cw_client=MagicMock(),
                ec2_client=MagicMock(),
                request=_req(), include_metrics=False, include_config=False,
            )
        assert FindingType.NETWORK_CONNECTIVITY in {f.type for f in result.all_findings}

    def test_parallel_execution_all_diagnosers_called(self):
        """Verify all six diagnosers are invoked when ec2_client is provided."""
        with (
            patch(_PATCH_EVENTS, return_value=[]) as mock_events,
            patch(_PATCH_STOP, return_value=([], [])) as mock_stop,
            patch(_PATCH_LOGS, return_value=[]) as mock_logs,
            patch(_PATCH_ALB, return_value=[]) as mock_alb,
            patch(_PATCH_AGG, return_value=_root_cause()),
            patch("ecs_doctor.diagnosers.network.diagnose_network", return_value=[]) as mock_net,
        ):
            run_diagnosis(
                ecs_client=MagicMock(), logs_client=MagicMock(),
                elb_client=MagicMock(), cw_client=MagicMock(),
                ec2_client=MagicMock(),
                request=_req(), include_metrics=False, include_config=False,
            )
        mock_events.assert_called_once()
        mock_stop.assert_called_once()
        mock_logs.assert_called_once()
        mock_alb.assert_called_once()
        mock_net.assert_called_once()

    def test_diagnoser_exception_isolated(self):
        """A future that raises should produce one IAM_DENIED LOW instead of crashing."""
        from concurrent.futures import Future

        def _raise():
            raise RuntimeError("simulated AWS error")

        with (
            patch(_PATCH_EVENTS, side_effect=RuntimeError("events fail")),
            patch(_PATCH_STOP, return_value=([], [])),
            patch(_PATCH_LOGS, return_value=[]),
            patch(_PATCH_ALB, return_value=[_finding(FindingType.ALB_UNHEALTHY)]),
            patch(_PATCH_AGG, return_value=_root_cause()),
            patch(_PATCH_NETWORK, return_value=[]),
        ):
            result = run_diagnosis(
                ecs_client=MagicMock(), logs_client=MagicMock(),
                elb_client=MagicMock(), cw_client=MagicMock(),
                ec2_client=MagicMock(),
                request=_req(), include_metrics=False, include_config=False,
            )
        types = {f.type for f in result.all_findings}
        assert FindingType.IAM_DENIED in types
        assert FindingType.ALB_UNHEALTHY in types
        error_findings = [f for f in result.all_findings if f.type == FindingType.IAM_DENIED]
        assert all(f.severity == Severity.LOW for f in error_findings)
