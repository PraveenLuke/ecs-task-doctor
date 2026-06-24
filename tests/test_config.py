"""Tests for ecs_doctor.diagnosers.config."""
from __future__ import annotations

from tests.conftest import (
    ACCOUNT,
    CLUSTER,
    REGION,
    SERVICE,
    access_denied_error,
    make_ecs_client,
    make_service_cache,
)

from ecs_doctor.diagnosers.config import (
    _extract_health_check,
    _mask_env_value,
    _validate_circuit_breaker,
    _validate_execution_role,
    _validate_fargate_cpu_memory,
    _validate_health_check_grace,
    _validate_log_config,
    _validate_memory_limits,
    _validate_port_mappings,
    diagnose_config,
)
from ecs_doctor.models import FindingType, Severity

_TASK_DEF_ARN = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/my-td:1"


def _svc(task_def_arn=_TASK_DEF_ARN):
    return {
        "services": [
            {
                "serviceArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/{CLUSTER}/{SERVICE}",
                "serviceName": SERVICE,
                "clusterArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/{CLUSTER}",
                "taskDefinition": task_def_arn,
                "loadBalancers": [],
                "desiredCount": 2,
                "runningCount": 1,
                "pendingCount": 0,
                "launchType": "FARGATE",
                "deploymentConfiguration": {
                    "minimumHealthyPercent": 100,
                    "maximumPercent": 200,
                    "deploymentCircuitBreaker": {"enable": True, "rollback": True},
                },
            }
        ]
    }


def _td(cpu="256", memory="512", requires=None):
    return {
        "taskDefinition": {
            "taskDefinitionArn": _TASK_DEF_ARN,
            "family": "my-td",
            "revision": 1,
            "cpu": cpu,
            "memory": memory,
            "networkMode": "awsvpc",
            "executionRoleArn": f"arn:aws:iam::{ACCOUNT}:role/ecsTaskExecutionRole",
            "requiresCompatibilities": requires or ["FARGATE"],
            "containerDefinitions": [
                {
                    "name": "app",
                    "image": "my-image:latest",
                    "cpu": 256,
                    "memory": 512,
                    "essential": True,
                    "environment": [
                        {"name": "DEBUG", "value": "true"},
                        {"name": "DB_PASSWORD", "value": "secret123"},
                        {"name": "API_KEY", "value": "abcdef"},
                    ],
                    "logConfiguration": {
                        "logDriver": "awslogs",
                        "options": {"awslogs-group": "/ecs/my-service"},
                    },
                }
            ],
        }
    }


# ---------------------------------------------------------------------------
# _mask_env_value
# ---------------------------------------------------------------------------


class TestMaskEnvValue:
    def test_password_key_masked(self):
        assert _mask_env_value("DB_PASSWORD", "hunter2") == "***MASKED***"

    def test_api_key_masked(self):
        assert _mask_env_value("API_KEY", "abcdef") == "***MASKED***"

    def test_secret_key_masked(self):
        assert _mask_env_value("SECRET_TOKEN", "xyz") == "***MASKED***"

    def test_token_key_masked(self):
        assert _mask_env_value("AUTH_TOKEN", "tok") == "***MASKED***"

    def test_safe_key_passthrough(self):
        assert _mask_env_value("DEBUG", "true") == "true"
        assert _mask_env_value("PORT", "8080") == "8080"
        assert _mask_env_value("LOG_LEVEL", "info") == "info"


# ---------------------------------------------------------------------------
# _extract_health_check
# ---------------------------------------------------------------------------


class TestExtractHealthCheck:
    def test_none_returns_none(self):
        assert _extract_health_check(None) is None

    def test_empty_dict_returns_none(self):
        assert _extract_health_check({}) is None

    def test_valid_health_check_extracted(self):
        hc = {
            "command": ["CMD", "curl", "/health"],
            "interval": 30,
            "timeout": 5,
            "retries": 3,
            "startPeriod": 10,
        }
        result = _extract_health_check(hc)
        assert result is not None
        assert result.command == ["CMD", "curl", "/health"]
        assert result.interval_seconds == 30
        assert result.timeout_seconds == 5
        assert result.retries == 3
        assert result.start_period_seconds == 10

    def test_defaults_applied_when_fields_missing(self):
        result = _extract_health_check({"command": ["CMD-SHELL", "true"]})
        assert result is not None
        assert result.interval_seconds == 30
        assert result.timeout_seconds == 5
        assert result.retries == 3
        assert result.start_period_seconds == 0


# ---------------------------------------------------------------------------
# _validate_fargate_cpu_memory
# ---------------------------------------------------------------------------


class TestValidateFargateCpuMemory:
    def test_valid_256_512_returns_none(self):
        td = {"requiresCompatibilities": ["FARGATE"], "cpu": "256", "memory": "512"}
        assert _validate_fargate_cpu_memory(td) is None

    def test_valid_1024_2048_returns_none(self):
        td = {"requiresCompatibilities": ["FARGATE"], "cpu": "1024", "memory": "2048"}
        assert _validate_fargate_cpu_memory(td) is None

    def test_invalid_memory_returns_critical_finding(self):
        td = {"requiresCompatibilities": ["FARGATE"], "cpu": "256", "memory": "999"}
        finding = _validate_fargate_cpu_memory(td)
        assert finding is not None
        assert finding.type == FindingType.INVALID_TASK_CONFIG
        assert finding.severity == Severity.CRITICAL

    def test_invalid_cpu_returns_finding(self):
        td = {"requiresCompatibilities": ["FARGATE"], "cpu": "999", "memory": "512"}
        finding = _validate_fargate_cpu_memory(td)
        assert finding is not None
        assert finding.type == FindingType.INVALID_TASK_CONFIG

    def test_non_fargate_skips_validation(self):
        td = {"requiresCompatibilities": ["EC2"], "cpu": "256", "memory": "999"}
        assert _validate_fargate_cpu_memory(td) is None

    def test_non_numeric_cpu_returns_none(self):
        td = {"requiresCompatibilities": ["FARGATE"], "cpu": "notanumber", "memory": "512"}
        assert _validate_fargate_cpu_memory(td) is None


# ---------------------------------------------------------------------------
# diagnose_config
# ---------------------------------------------------------------------------


class TestDiagnoseConfig:
    def _call(self, ecs):
        return diagnose_config(make_service_cache(ecs), ecs, CLUSTER, SERVICE, REGION, ACCOUNT)

    def test_success_returns_configs(self):
        ecs = make_ecs_client(describe_services=_svc(), describe_task_definition=_td())
        findings, svc_cfg, task_cfg = self._call(ecs)
        assert findings == []
        assert svc_cfg is not None
        assert svc_cfg.service_name == SERVICE
        assert svc_cfg.desired_count == 2
        assert task_cfg is not None
        assert task_cfg.family == "my-td"
        assert len(task_cfg.containers) == 1

    def test_env_vars_masked(self):
        ecs = make_ecs_client(describe_services=_svc(), describe_task_definition=_td())
        _, _, task_cfg = self._call(ecs)
        env = task_cfg.containers[0].environment
        assert env["DEBUG"] == "true"
        assert env["DB_PASSWORD"] == "***MASKED***"
        assert env["API_KEY"] == "***MASKED***"

    def test_log_group_extracted(self):
        ecs = make_ecs_client(describe_services=_svc(), describe_task_definition=_td())
        _, _, task_cfg = self._call(ecs)
        assert task_cfg.containers[0].log_group == "/ecs/my-service"

    def test_access_denied_describe_services(self):
        ecs = make_ecs_client(
            describe_services=access_denied_error("DescribeServices")
        )
        findings, svc_cfg, task_cfg = self._call(ecs)
        assert any(f.type == FindingType.IAM_DENIED for f in findings)
        assert svc_cfg is None
        assert task_cfg is None

    def test_access_denied_describe_task_definition(self):
        ecs = make_ecs_client(
            describe_services=_svc(),
            describe_task_definition=access_denied_error("DescribeTaskDefinition"),
        )
        findings, svc_cfg, task_cfg = self._call(ecs)
        assert any(f.type == FindingType.IAM_DENIED for f in findings)
        assert svc_cfg is not None
        assert task_cfg is None

    def test_invalid_fargate_combo_produces_finding(self):
        ecs = make_ecs_client(
            describe_services=_svc(), describe_task_definition=_td(cpu="256", memory="999")
        )
        findings, _, _ = self._call(ecs)
        assert any(f.type == FindingType.INVALID_TASK_CONFIG for f in findings)

    def test_no_service_found_returns_empty(self):
        ecs = make_ecs_client(describe_services={"services": []})
        findings, svc_cfg, task_cfg = self._call(ecs)
        assert findings == []
        assert svc_cfg is None
        assert task_cfg is None

    def test_missing_execution_role_produces_finding(self):
        ecs = make_ecs_client(describe_services=_svc(), describe_task_definition=_td())
        # Override task definition to have no executionRoleArn
        td_no_role = _td()
        td_no_role["taskDefinition"].pop("executionRoleArn", None)
        ecs2 = make_ecs_client(describe_services=_svc(), describe_task_definition=td_no_role)
        findings, _, _ = self._call(ecs2)
        assert any(f.type == FindingType.MISSING_EXECUTION_ROLE for f in findings)
        f = next(x for x in findings if x.type == FindingType.MISSING_EXECUTION_ROLE)
        assert f.severity == Severity.CRITICAL

    def test_service_without_task_def_arn(self):
        svc_no_td = {"services": [{"serviceName": SERVICE, "loadBalancers": [],
                                    "desiredCount": 1, "runningCount": 0, "pendingCount": 0,
                                    "serviceArn": "arn:...", "clusterArn": "arn:..."}]}
        ecs = make_ecs_client(describe_services=svc_no_td)
        findings, svc_cfg, task_cfg = self._call(ecs)
        assert findings == []
        assert svc_cfg is not None
        assert task_cfg is None


# ---------------------------------------------------------------------------
# _validate_execution_role
# ---------------------------------------------------------------------------


class TestValidateExecutionRole:
    def test_no_execution_role_returns_finding(self):
        td = {"taskDefinitionArn": "arn:..."}
        finding = _validate_execution_role(td)
        assert finding is not None
        assert finding.type == FindingType.MISSING_EXECUTION_ROLE
        assert finding.severity == Severity.CRITICAL

    def test_execution_role_present_returns_none(self):
        td = {"executionRoleArn": "arn:aws:iam::123:role/ecsTaskExecution"}
        assert _validate_execution_role(td) is None


# ---------------------------------------------------------------------------
# _validate_health_check_grace
# ---------------------------------------------------------------------------


class TestValidateHealthCheckGrace:
    def test_healthcheck_without_grace_period_returns_finding(self):
        td = {"containerDefinitions": [{"healthCheck": {"command": ["CMD", "true"]}}]}
        svc = {}
        finding = _validate_health_check_grace(td, svc)
        assert finding is not None
        assert finding.type == FindingType.MISSING_HEALTH_CHECK_GRACE_PERIOD
        assert finding.severity == Severity.MEDIUM

    def test_healthcheck_with_grace_period_returns_none(self):
        td = {"containerDefinitions": [{"healthCheck": {"command": ["CMD", "true"]}}]}
        svc = {"healthCheckGracePeriodSeconds": 30}
        assert _validate_health_check_grace(td, svc) is None

    def test_no_healthcheck_returns_none(self):
        td = {"containerDefinitions": [{"name": "app"}]}
        svc = {}
        assert _validate_health_check_grace(td, svc) is None


# ---------------------------------------------------------------------------
# _validate_port_mappings
# ---------------------------------------------------------------------------


class TestValidatePortMappings:
    def test_missing_port_returns_finding(self):
        td = {"containerDefinitions": [{"portMappings": [{"containerPort": 8080}]}]}
        svc = {"loadBalancers": [{"containerPort": 9000}]}
        finding = _validate_port_mappings(td, svc)
        assert finding is not None
        assert finding.type == FindingType.MISSING_PORT_MAPPING
        assert finding.severity == Severity.HIGH
        assert 9000 in finding.raw_data["missing_ports"]

    def test_matching_port_returns_none(self):
        td = {"containerDefinitions": [{"portMappings": [{"containerPort": 8080}]}]}
        svc = {"loadBalancers": [{"containerPort": 8080}]}
        assert _validate_port_mappings(td, svc) is None

    def test_no_load_balancers_returns_none(self):
        td = {"containerDefinitions": [{"portMappings": [{"containerPort": 8080}]}]}
        svc = {"loadBalancers": []}
        assert _validate_port_mappings(td, svc) is None


# ---------------------------------------------------------------------------
# _validate_circuit_breaker
# ---------------------------------------------------------------------------


class TestValidateCircuitBreaker:
    def test_circuit_breaker_disabled_returns_finding(self):
        svc = {"deploymentConfiguration": {"deploymentCircuitBreaker": {"enable": False}}}
        finding = _validate_circuit_breaker(svc)
        assert finding is not None
        assert finding.type == FindingType.CIRCUIT_BREAKER_DISABLED
        assert finding.severity == Severity.LOW

    def test_circuit_breaker_absent_returns_finding(self):
        svc = {"deploymentConfiguration": {}}
        finding = _validate_circuit_breaker(svc)
        assert finding is not None
        assert finding.type == FindingType.CIRCUIT_BREAKER_DISABLED

    def test_circuit_breaker_enabled_returns_none(self):
        svc = {"deploymentConfiguration": {"deploymentCircuitBreaker": {"enable": True, "rollback": True}}}
        assert _validate_circuit_breaker(svc) is None


# ---------------------------------------------------------------------------
# _validate_log_config
# ---------------------------------------------------------------------------


class TestValidateLogConfig:
    def test_container_without_log_config_returns_finding(self):
        td = {"containerDefinitions": [{"name": "app"}]}
        finding = _validate_log_config(td)
        assert finding is not None
        assert finding.type == FindingType.MISSING_LOG_CONFIG
        assert finding.severity == Severity.HIGH
        assert "app" in str(finding.raw_data["containers"])

    def test_container_with_log_config_returns_none(self):
        td = {"containerDefinitions": [{"name": "app", "logConfiguration": {"logDriver": "awslogs"}}]}
        assert _validate_log_config(td) is None

    def test_mixed_containers_returns_finding_for_unconfigured(self):
        td = {
            "containerDefinitions": [
                {"name": "app", "logConfiguration": {"logDriver": "awslogs"}},
                {"name": "sidecar"},
            ]
        }
        finding = _validate_log_config(td)
        assert finding is not None
        assert "sidecar" in str(finding.raw_data["containers"])


# ---------------------------------------------------------------------------
# _validate_memory_limits
# ---------------------------------------------------------------------------


class TestValidateMemoryLimits:
    def test_ec2_container_without_memory_returns_finding(self):
        td = {
            "requiresCompatibilities": ["EC2"],
            "containerDefinitions": [{"name": "app"}],
        }
        finding = _validate_memory_limits(td)
        assert finding is not None
        assert finding.type == FindingType.INVALID_TASK_CONFIG
        assert finding.severity == Severity.MEDIUM

    def test_ec2_container_with_memory_returns_none(self):
        td = {
            "requiresCompatibilities": ["EC2"],
            "containerDefinitions": [{"name": "app", "memory": 512}],
        }
        assert _validate_memory_limits(td) is None

    def test_fargate_skips_check_regardless_of_memory(self):
        td = {
            "requiresCompatibilities": ["FARGATE"],
            "containerDefinitions": [{"name": "app"}],
        }
        assert _validate_memory_limits(td) is None


# ---------------------------------------------------------------------------
# _validate_depends_on_health
# ---------------------------------------------------------------------------

from ecs_doctor.diagnosers.config import _validate_depends_on_health


class TestValidateDependsOnHealth:
    def test_healthy_dep_without_healthcheck_returns_finding(self):
        td = {
            "containerDefinitions": [
                {"name": "sidecar"},
                {
                    "name": "app",
                    "dependsOn": [{"containerName": "sidecar", "condition": "HEALTHY"}],
                },
            ]
        }
        finding = _validate_depends_on_health(td)
        assert finding is not None
        assert finding.type == FindingType.INVALID_TASK_CONFIG
        assert finding.severity == Severity.HIGH
        assert "sidecar" in finding.message

    def test_healthy_dep_with_healthcheck_returns_none(self):
        td = {
            "containerDefinitions": [
                {"name": "sidecar", "healthCheck": {"command": ["CMD", "true"]}},
                {
                    "name": "app",
                    "dependsOn": [{"containerName": "sidecar", "condition": "HEALTHY"}],
                },
            ]
        }
        assert _validate_depends_on_health(td) is None

    def test_non_healthy_dep_without_healthcheck_returns_none(self):
        td = {
            "containerDefinitions": [
                {"name": "sidecar"},
                {
                    "name": "app",
                    "dependsOn": [{"containerName": "sidecar", "condition": "START"}],
                },
            ]
        }
        assert _validate_depends_on_health(td) is None
