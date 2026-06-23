import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from click.testing import CliRunner

from ecs_doctor.cli import _confidence_color, _to_json_safe, cli
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

PATCH_SESSION = "ecs_doctor.cli.boto3.Session"
PATCH_EVENTS = "ecs_doctor.cli.diagnose_events"
PATCH_STOP = "ecs_doctor.cli.diagnose_stop_reasons"
PATCH_LOGS = "ecs_doctor.cli.diagnose_logs"
PATCH_ALB = "ecs_doctor.cli.diagnose_alb_health"
PATCH_AGG = "ecs_doctor.cli.aggregate"


def _invoke(*args, **patches):
    """Run `ecs-doctor diagnose` through CliRunner, applying caller-supplied patches."""
    runner = CliRunner(mix_stderr=False)
    with (
        patch(PATCH_SESSION, **patches.get("session_patch", {})) as ms,
        patch(PATCH_EVENTS, return_value=[]) as _me,
        patch(PATCH_STOP, return_value=([], [])) as _mst,
        patch(PATCH_LOGS, return_value=[]) as _ml,
        patch(PATCH_ALB, return_value=[]) as _ma,
        patch(PATCH_AGG) as ma,
    ):
        ms.return_value = _make_session()
        ma.return_value = _root_cause()
        result = runner.invoke(cli, list(args))
    return result


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
    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_exit_zero_on_success(self, mock_agg, *mocks):
        mock_agg.return_value = _root_cause()
        mocks[-1].return_value = _make_session()  # Session mock is last positional
        runner = CliRunner()
        result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s"])
        assert result.exit_code == 0

    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_output_contains_root_cause(self, mock_agg, *mocks):
        mock_agg.return_value = _root_cause(cause="Container OOM-killed")
        mocks[-1].return_value = _make_session()
        runner = CliRunner()
        result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s"])
        assert "Root Cause" in result.output
        assert "Container OOM-killed" in result.output

    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_evidence_table_rendered_when_evidence_present(self, mock_agg, *mocks):
        evidence = [_finding()]
        mock_agg.return_value = _root_cause(evidence=evidence)
        mocks[-1].return_value = _make_session()
        runner = CliRunner()
        result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s"])
        assert result.exit_code == 0
        assert "Supporting Evidence" in result.output

    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_extra_findings_note_shown(self, mock_agg, *mocks):
        # evidence has 1 finding; all_findings has 2 → "1 additional finding" note
        all_findings = [_finding(), _finding(FindingType.ALB_UNHEALTHY)]
        evidence = [all_findings[0]]
        mock_agg.return_value = _root_cause(evidence=evidence)
        mocks[-1].return_value = _make_session()

        # Override events to return 2 findings total
        with (
            patch(PATCH_SESSION, return_value=_make_session()),
            patch(PATCH_EVENTS, return_value=all_findings),
            patch(PATCH_STOP, return_value=([], [])),
            patch(PATCH_LOGS, return_value=[]),
            patch(PATCH_ALB, return_value=[]),
            patch(PATCH_AGG, return_value=_root_cause(evidence=evidence)),
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["diagnose", "--cluster", "c", "--service", "s"]
            )
        assert result.exit_code == 0
        assert "additional finding" in result.output


class TestDiagnoseJsonOutput:
    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_json_flag_produces_valid_json(self, mock_agg, *mocks):
        mock_agg.return_value = _root_cause()
        mocks[-1].return_value = _make_session()
        runner = CliRunner()
        result = runner.invoke(
            cli, ["diagnose", "--cluster", "prod", "--service", "svc", "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["cluster"] == "prod"
        assert data["service"] == "svc"
        assert "root_cause" in data
        assert "all_findings" in data

    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_json_output_contains_root_cause_fields(self, mock_agg, *mocks):
        mock_agg.return_value = _root_cause(cause="OOM", confidence=0.97)
        mocks[-1].return_value = _make_session()
        runner = CliRunner()
        result = runner.invoke(
            cli, ["diagnose", "--cluster", "c", "--service", "s", "--json"]
        )
        data = json.loads(result.output)
        rc = data["root_cause"]
        assert rc["cause"] == "OOM"
        assert rc["confidence"] == 0.97

    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_json_includes_all_findings(self, mock_agg, *mocks):
        findings = [_finding(), _finding(FindingType.ALB_UNHEALTHY)]
        mock_agg.return_value = _root_cause(evidence=[findings[0]])
        mocks[-1].return_value = _make_session()

        with (
            patch(PATCH_SESSION, return_value=_make_session()),
            patch(PATCH_EVENTS, return_value=findings),
            patch(PATCH_STOP, return_value=([], [])),
            patch(PATCH_LOGS, return_value=[]),
            patch(PATCH_ALB, return_value=[]),
            patch(PATCH_AGG, return_value=_root_cause(evidence=[findings[0]])),
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["diagnose", "--cluster", "c", "--service", "s", "--json"]
            )
        data = json.loads(result.output)
        assert len(data["all_findings"]) == 2


class TestErrorHandling:
    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_sts_failure_falls_back_to_unknown_account(self, mock_agg, *mocks):
        mock_agg.return_value = _root_cause()
        sts_err = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "GetCallerIdentity",
        )
        mocks[-1].return_value = _make_session(sts_error=sts_err)
        runner = CliRunner()
        result = runner.invoke(cli, ["diagnose", "--cluster", "c", "--service", "s"])
        assert result.exit_code == 0
        assert "Warning" in result.output

    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_sts_failure_in_json_mode_no_warning(self, mock_agg, *mocks):
        mock_agg.return_value = _root_cause()
        sts_err = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "GetCallerIdentity",
        )
        mocks[-1].return_value = _make_session(sts_error=sts_err)
        runner = CliRunner()
        result = runner.invoke(
            cli, ["diagnose", "--cluster", "c", "--service", "s", "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "cluster" in data  # valid JSON, no crash

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

    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_region_option_passed_to_session(self, mock_agg, *mocks):
        mock_agg.return_value = _root_cause()
        session_mock = _make_session(region="ap-southeast-1")
        mocks[-1].return_value = session_mock
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["diagnose", "--cluster", "c", "--service", "s", "--region", "ap-southeast-1"],
        )
        assert result.exit_code == 0

    @patch(PATCH_SESSION)
    @patch(PATCH_EVENTS, return_value=[])
    @patch(PATCH_STOP, return_value=([], []))
    @patch(PATCH_LOGS, return_value=[])
    @patch(PATCH_ALB, return_value=[])
    @patch(PATCH_AGG)
    def test_profile_option_passed_to_session(self, mock_agg, *mocks):
        mock_agg.return_value = _root_cause()
        mock_session = mocks[-1]  # Session is outermost decorator → last positional arg
        mock_session.return_value = _make_session()
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["diagnose", "--cluster", "c", "--service", "s", "--profile", "my-profile"],
        )
        assert result.exit_code == 0
        mock_session.assert_called_once_with(region_name=None, profile_name="my-profile")
