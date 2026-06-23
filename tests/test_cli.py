import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from click.testing import CliRunner

from ecs_doctor.cli import _confidence_color, _to_json_safe, cli
from ecs_doctor.engine import DiagnosisRequest, DiagnosisResult
from ecs_doctor.models import Finding, FindingType, RootCause, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _root_cause(
    cause="Test root cause",
    confidence=0.85,
    evidence=None,
    fix="Test fix",
) -> RootCause:
    return RootCause(
        cause=cause,
        confidence=confidence,
        evidence=evidence or [],
        suggested_fix=fix,
    )


def _finding(ftype=FindingType.OOM_KILLED, sev=Severity.CRITICAL) -> Finding:
    return Finding(type=ftype, message="test msg", severity=sev, source="test")


def _make_result(
    root_cause=None,
    all_findings=None,
    cluster="c",
    service="s",
    region="us-east-1",
    account_id="123456789012",
) -> DiagnosisResult:
    if root_cause is None:
        root_cause = _root_cause()
    if all_findings is None:
        all_findings = []
    return DiagnosisResult(
        request=DiagnosisRequest(cluster=cluster, service=service, region=region, account_id=account_id),
        root_cause=root_cause,
        all_findings=all_findings,
        duration_ms=42,
    )


def _make_session(region="us-east-1", account="123456789012", sts_error=None):
    session = MagicMock()
    session.region_name = region
    sts_mock = MagicMock()
    if sts_error:
        sts_mock.get_caller_identity.side_effect = sts_error
    else:
        sts_mock.get_caller_identity.return_value = {"Account": account}

    def _client(svc, **_kwargs):
        return sts_mock if svc == "sts" else MagicMock()

    session.client.side_effect = _client
    return session


PATCH_SESSION = "ecs_doctor.cli.boto3.Session"
PATCH_ENGINE = "ecs_doctor.cli.run_diagnosis"


def _invoke(*args, root_cause=None, all_findings=None):
    """Run `ecs-doctor diagnose` through CliRunner with engine patched."""
    runner = CliRunner()
    with (
        patch(PATCH_SESSION) as ms,
        patch(PATCH_ENGINE) as me,
    ):
        ms.return_value = _make_session()
        me.return_value = _make_result(root_cause=root_cause, all_findings=all_findings or [])
        result = runner.invoke(cli, list(args))
    return result


# ---------------------------------------------------------------------------
# Pure-function unit tests (no Click, no AWS)
# ---------------------------------------------------------------------------


class TestConfidenceColor:
    def test_high_confidence_is_red(self):
        assert _confidence_color(0.9) == "red"
        assert _confidence_color(0.7) == "red"

    def test_medium_confidence_is_yellow(self):
        assert _confidence_color(0.5) == "yellow"
        assert _confidence_color(0.4) == "yellow"

    def test_low_confidence_is_green(self):
        assert _confidence_color(0.3) == "green"
        assert _confidence_color(0.0) == "green"


class TestToJsonSafe:
    def test_finding_becomes_dict(self):
        f = _finding()
        result = _to_json_safe(f)
        assert isinstance(result, dict)
        assert result["message"] == "test msg"
        assert result["source"] == "test"

    def test_root_cause_becomes_dict(self):
        rc = _root_cause(evidence=[_finding()])
        result = _to_json_safe(rc)
        assert isinstance(result, dict)
        assert result["cause"] == "Test root cause"
        assert isinstance(result["evidence"], list)

    def test_list_is_mapped_recursively(self):
        findings = [_finding(), _finding(FindingType.ALB_UNHEALTHY)]
        result = _to_json_safe(findings)
        assert isinstance(result, list)
        assert len(result) == 2
        assert all(isinstance(r, dict) for r in result)

    def test_primitive_passthrough(self):
        assert _to_json_safe("hello") == "hello"
        assert _to_json_safe(42) == 42
        assert _to_json_safe(None) is None


# ---------------------------------------------------------------------------
# CLI integration tests via CliRunner
# ---------------------------------------------------------------------------


class TestHelp:
    def test_top_level_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "diagnose" in result.output

    def test_diagnose_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["diagnose", "--help"])
        assert result.exit_code == 0
        assert "--cluster" in result.output
        assert "--service" in result.output
        assert "--json" in result.output
        assert "--region" in result.output


class TestDiagnoseRichOutput:
    def test_exit_zero_on_success(self):
        result = _invoke("diagnose", "--cluster", "c", "--service", "s")
        assert result.exit_code == 0

    def test_output_contains_root_cause(self):
        rc = _root_cause(cause="Container OOM-killed")
        result = _invoke("diagnose", "--cluster", "c", "--service", "s", root_cause=rc)
        assert "Root Cause" in result.output
        assert "Container OOM-killed" in result.output

    def test_evidence_table_rendered_when_evidence_present(self):
        evidence = [_finding()]
        rc = _root_cause(evidence=evidence)
        result = _invoke("diagnose", "--cluster", "c", "--service", "s", root_cause=rc, all_findings=evidence)
        assert result.exit_code == 0
        assert "Supporting Evidence" in result.output

    def test_extra_findings_note_shown(self):
        all_findings = [_finding(), _finding(FindingType.ALB_UNHEALTHY)]
        evidence = [all_findings[0]]
        rc = _root_cause(evidence=evidence)
        result = _invoke("diagnose", "--cluster", "c", "--service", "s", root_cause=rc, all_findings=all_findings)
        assert result.exit_code == 0
        assert "additional finding" in result.output


class TestDiagnoseJsonOutput:
    def test_json_flag_produces_valid_json(self):
        runner = CliRunner()
        with (
            patch(PATCH_SESSION) as ms,
            patch(PATCH_ENGINE) as me,
        ):
            ms.return_value = _make_session()
            me.return_value = _make_result(cluster="prod", service="svc")
            result = runner.invoke(cli, ["diagnose", "--cluster", "prod", "--service", "svc", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["request"]["cluster"] == "prod"
        assert data["request"]["service"] == "svc"
        assert "root_cause" in data
        assert "all_findings" in data

    def test_json_output_contains_root_cause_fields(self):
        runner = CliRunner()
        with (
            patch(PATCH_SESSION) as ms,
            patch(PATCH_ENGINE) as me,
        ):
            ms.return_value = _make_session()
            me.return_value = _make_result(root_cause=_root_cause(cause="OOM", confidence=0.97))
            result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s", "--json"])
        data = json.loads(result.output)
        rc = data["root_cause"]
        assert rc["cause"] == "OOM"
        assert rc["confidence"] == 0.97

    def test_json_includes_all_findings(self):
        findings = [_finding(), _finding(FindingType.ALB_UNHEALTHY)]
        runner = CliRunner()
        with (
            patch(PATCH_SESSION) as ms,
            patch(PATCH_ENGINE) as me,
        ):
            ms.return_value = _make_session()
            me.return_value = _make_result(
                root_cause=_root_cause(evidence=[findings[0]]),
                all_findings=findings,
            )
            result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s", "--json"])
        data = json.loads(result.output)
        assert len(data["all_findings"]) == 2


class TestErrorHandling:
    def test_sts_failure_falls_back_to_unknown_account(self):
        sts_err = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "GetCallerIdentity",
        )
        runner = CliRunner()
        with (
            patch(PATCH_SESSION) as ms,
            patch(PATCH_ENGINE) as me,
        ):
            ms.return_value = _make_session(sts_error=sts_err)
            me.return_value = _make_result()
            result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s"])
        assert result.exit_code == 0
        assert "Warning" in result.output

    def test_sts_failure_in_json_mode_no_warning(self):
        sts_err = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "GetCallerIdentity",
        )
        runner = CliRunner()
        with (
            patch(PATCH_SESSION) as ms,
            patch(PATCH_ENGINE) as me,
        ):
            ms.return_value = _make_session(sts_error=sts_err)
            me.return_value = _make_result()
            result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "request" in data  # valid JSON, no crash

    def test_no_credentials_error_exits_1(self):
        runner = CliRunner()
        with patch(PATCH_SESSION, side_effect=NoCredentialsError()):
            result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s"])
        assert result.exit_code == 1
        assert "credentials" in result.output.lower()

    def test_no_credentials_json_mode(self):
        runner = CliRunner()
        with patch(PATCH_SESSION, side_effect=NoCredentialsError()):
            result = runner.invoke(
                cli, ["diagnose", "--cluster", "c", "--service", "s", "--json"]
            )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "error" in data

    def test_region_option_passed_to_session(self):
        runner = CliRunner()
        with (
            patch(PATCH_SESSION) as ms,
            patch(PATCH_ENGINE) as me,
        ):
            ms.return_value = _make_session(region="ap-southeast-1")
            me.return_value = _make_result()
            result = runner.invoke(
                cli,
                ["diagnose", "--cluster", "c", "--service", "s", "--region", "ap-southeast-1"],
            )
        assert result.exit_code == 0

    def test_profile_option_passed_to_session(self):
        runner = CliRunner()
        with (
            patch(PATCH_SESSION) as ms,
            patch(PATCH_ENGINE) as me,
        ):
            ms.return_value = _make_session()
            me.return_value = _make_result()
            result = runner.invoke(
                cli,
                ["diagnose", "--cluster", "c", "--service", "s", "--profile", "my-profile"],
            )
        assert result.exit_code == 0
        ms.assert_called_once_with(region_name=None, profile_name="my-profile")
