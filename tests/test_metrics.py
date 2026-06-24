"""Tests for ecs_doctor.diagnosers.metrics."""
from __future__ import annotations

from datetime import datetime, timezone

from tests.conftest import ACCOUNT, CLUSTER, REGION, SERVICE, access_denied_error, make_ecs_client

from ecs_doctor.diagnosers.metrics import (
    _anomaly_findings,
    _build_metric_queries,
    _safe_avg,
    diagnose_metrics,
)
from ecs_doctor.models import FindingType, MetricSnapshot, Severity


def _make_cw(**method_returns):
    return make_ecs_client(**method_returns)


def _metric_resp(cpu_avg=None, cpu_max=None, mem_avg=None, mem_max=None):
    now = datetime.now(timezone.utc)
    results = []
    for qid, vals in [
        ("cpu_avg", [cpu_avg] if cpu_avg is not None else []),
        ("cpu_max", [cpu_max] if cpu_max is not None else []),
        ("mem_avg", [mem_avg] if mem_avg is not None else []),
        ("mem_max", [mem_max] if mem_max is not None else []),
    ]:
        results.append({
            "Id": qid,
            "Values": vals,
            "Timestamps": [now] if vals else [],
            "StatusCode": "Complete",
        })
    return {"MetricDataResults": results}


def _make_snapshot(cpu_avg=None, mem_avg=None):
    return MetricSnapshot(
        cluster=CLUSTER,
        service=SERVICE,
        period_seconds=300,
        lookback_hours=3,
        cpu_avg_percent=cpu_avg,
        cpu_max_percent=None,
        memory_avg_percent=mem_avg,
        memory_max_percent=None,
    )


# ---------------------------------------------------------------------------
# _build_metric_queries
# ---------------------------------------------------------------------------


class TestBuildMetricQueries:
    def test_returns_four_queries(self):
        queries = _build_metric_queries(CLUSTER, SERVICE, 300)
        assert len(queries) == 4

    def test_query_ids(self):
        queries = _build_metric_queries(CLUSTER, SERVICE, 300)
        ids = {q["Id"] for q in queries}
        assert ids == {"cpu_avg", "cpu_max", "mem_avg", "mem_max"}

    def test_namespace_is_aws_ecs(self):
        queries = _build_metric_queries(CLUSTER, SERVICE, 300)
        for q in queries:
            assert q["MetricStat"]["Metric"]["Namespace"] == "AWS/ECS"

    def test_period_propagated(self):
        queries = _build_metric_queries(CLUSTER, SERVICE, 600)
        for q in queries:
            assert q["MetricStat"]["Period"] == 600

    def test_dimensions_include_cluster_and_service(self):
        queries = _build_metric_queries(CLUSTER, SERVICE, 300)
        for q in queries:
            dims = q["MetricStat"]["Metric"]["Dimensions"]
            names = {d["Name"]: d["Value"] for d in dims}
            assert names["ClusterName"] == CLUSTER
            assert names["ServiceName"] == SERVICE


# ---------------------------------------------------------------------------
# _safe_avg
# ---------------------------------------------------------------------------


class TestSafeAvg:
    def test_empty_list_returns_none(self):
        assert _safe_avg([]) is None

    def test_single_value(self):
        assert _safe_avg([42.0]) == 42.0

    def test_multiple_values(self):
        assert _safe_avg([10.0, 20.0, 30.0]) == 20.0


# ---------------------------------------------------------------------------
# _anomaly_findings
# ---------------------------------------------------------------------------


class TestAnomalyFindings:
    def test_low_values_no_findings(self):
        snap = _make_snapshot(cpu_avg=50.0, mem_avg=60.0)
        assert _anomaly_findings(snap, CLUSTER, SERVICE) == []

    def test_high_cpu_produces_finding(self):
        snap = _make_snapshot(cpu_avg=90.0, mem_avg=50.0)
        findings = _anomaly_findings(snap, CLUSTER, SERVICE)
        assert len(findings) == 1
        assert findings[0].type == FindingType.HIGH_CPU_UTILIZATION

    def test_high_memory_produces_finding(self):
        snap = _make_snapshot(cpu_avg=50.0, mem_avg=90.0)
        findings = _anomaly_findings(snap, CLUSTER, SERVICE)
        assert len(findings) == 1
        assert findings[0].type == FindingType.HIGH_MEMORY_UTILIZATION

    def test_both_high_produces_two_findings(self):
        snap = _make_snapshot(cpu_avg=90.0, mem_avg=90.0)
        findings = _anomaly_findings(snap, CLUSTER, SERVICE)
        types = {f.type for f in findings}
        assert FindingType.HIGH_CPU_UTILIZATION in types
        assert FindingType.HIGH_MEMORY_UTILIZATION in types

    def test_exactly_at_threshold_no_finding(self):
        snap = _make_snapshot(cpu_avg=85.0, mem_avg=85.0)
        assert _anomaly_findings(snap, CLUSTER, SERVICE) == []

    def test_none_values_no_findings(self):
        snap = _make_snapshot(cpu_avg=None, mem_avg=None)
        assert _anomaly_findings(snap, CLUSTER, SERVICE) == []


# ---------------------------------------------------------------------------
# diagnose_metrics
# ---------------------------------------------------------------------------


class TestDiagnoseMetrics:
    def _call(self, cw):
        return diagnose_metrics(cw, CLUSTER, SERVICE, REGION, ACCOUNT)

    def test_success_low_values_no_findings(self):
        cw = _make_cw(get_metric_data=_metric_resp(cpu_avg=30.0, cpu_max=40.0, mem_avg=50.0, mem_max=55.0))
        findings, snapshot = self._call(cw)
        assert findings == []
        assert snapshot is not None
        assert snapshot.cpu_avg_percent == 30.0
        assert snapshot.memory_avg_percent == 50.0

    def test_success_high_cpu_produces_finding(self):
        cw = _make_cw(get_metric_data=_metric_resp(cpu_avg=90.0, cpu_max=95.0, mem_avg=40.0, mem_max=45.0))
        findings, snapshot = self._call(cw)
        assert any(f.type == FindingType.HIGH_CPU_UTILIZATION for f in findings)
        assert snapshot is not None

    def test_success_high_memory_produces_finding(self):
        cw = _make_cw(get_metric_data=_metric_resp(cpu_avg=30.0, cpu_max=35.0, mem_avg=90.0, mem_max=92.0))
        findings, snapshot = self._call(cw)
        assert any(f.type == FindingType.HIGH_MEMORY_UTILIZATION for f in findings)

    def test_access_denied_returns_iam_finding_and_none_snapshot(self):
        cw = _make_cw(get_metric_data=access_denied_error("GetMetricData"))
        findings, snapshot = self._call(cw)
        assert any(f.type == FindingType.IAM_DENIED for f in findings)
        assert snapshot is None

    def test_empty_data_snapshot_has_none_fields(self):
        cw = _make_cw(get_metric_data=_metric_resp())
        findings, snapshot = self._call(cw)
        assert findings == []
        assert snapshot is not None
        assert snapshot.cpu_avg_percent is None
        assert snapshot.memory_avg_percent is None

    def test_max_values_populated(self):
        cw = _make_cw(get_metric_data=_metric_resp(cpu_avg=30.0, cpu_max=40.0, mem_avg=50.0, mem_max=60.0))
        _, snapshot = self._call(cw)
        assert snapshot.cpu_max_percent == 40.0
        assert snapshot.memory_max_percent == 60.0

    def test_datapoints_populated(self):
        cw = _make_cw(get_metric_data=_metric_resp(cpu_avg=30.0, mem_avg=50.0))
        _, snapshot = self._call(cw)
        assert len(snapshot.cpu_datapoints) == 1
        assert len(snapshot.memory_datapoints) == 1


# ---------------------------------------------------------------------------
# Memory max spike check
# ---------------------------------------------------------------------------

def test_memory_max_spike_produces_high_finding():
    snapshot = MetricSnapshot(
        cluster=CLUSTER,
        service=SERVICE,
        period_seconds=300,
        lookback_hours=3,
        cpu_avg_percent=20.0,
        cpu_max_percent=25.0,
        memory_avg_percent=70.0,   # avg below CRITICAL threshold
        memory_max_percent=96.0,   # max above spike threshold (95%)
    )
    findings = _anomaly_findings(snapshot, CLUSTER, SERVICE)
    assert any(f.type == FindingType.HIGH_MEMORY_UTILIZATION for f in findings)
    f = next(x for x in findings if x.type == FindingType.HIGH_MEMORY_UTILIZATION)
    assert f.severity == Severity.HIGH
    assert "96" in f.message or "spike" in f.message.lower()


def test_no_spike_when_avg_already_critical():
    snapshot = MetricSnapshot(
        cluster=CLUSTER,
        service=SERVICE,
        period_seconds=300,
        lookback_hours=3,
        cpu_avg_percent=20.0,
        cpu_max_percent=25.0,
        memory_avg_percent=90.0,   # avg already over CRITICAL threshold
        memory_max_percent=97.0,   # also above spike threshold
    )
    findings = _anomaly_findings(snapshot, CLUSTER, SERVICE)
    mem_findings = [f for f in findings if f.type == FindingType.HIGH_MEMORY_UTILIZATION]
    assert len(mem_findings) == 1         # only one finding, not two
    assert mem_findings[0].severity == Severity.CRITICAL


def test_max_below_spike_threshold_no_extra_finding():
    snapshot = MetricSnapshot(
        cluster=CLUSTER,
        service=SERVICE,
        period_seconds=300,
        lookback_hours=3,
        cpu_avg_percent=None,
        cpu_max_percent=None,
        memory_avg_percent=60.0,   # below alert threshold
        memory_max_percent=80.0,   # below spike threshold
    )
    findings = _anomaly_findings(snapshot, CLUSTER, SERVICE)
    assert findings == []


# ---------------------------------------------------------------------------
# CPU max spike check (v0.4.2)
# ---------------------------------------------------------------------------

def test_cpu_max_spike_produces_high_finding():
    snapshot = MetricSnapshot(
        cluster=CLUSTER,
        service=SERVICE,
        period_seconds=300,
        lookback_hours=3,
        cpu_avg_percent=20.0,
        cpu_max_percent=96.0,   # above spike threshold (95%)
        memory_avg_percent=50.0,
        memory_max_percent=60.0,
    )
    findings = _anomaly_findings(snapshot, CLUSTER, SERVICE)
    assert any(f.type == FindingType.HIGH_CPU_UTILIZATION for f in findings)
    f = next(x for x in findings if x.type == FindingType.HIGH_CPU_UTILIZATION)
    assert f.severity == Severity.HIGH
    assert "96" in f.message or "spike" in f.message.lower()


def test_no_cpu_spike_when_avg_already_critical():
    snapshot = MetricSnapshot(
        cluster=CLUSTER,
        service=SERVICE,
        period_seconds=300,
        lookback_hours=3,
        cpu_avg_percent=90.0,   # avg already over threshold
        cpu_max_percent=97.0,   # also above spike threshold
        memory_avg_percent=50.0,
        memory_max_percent=60.0,
    )
    findings = _anomaly_findings(snapshot, CLUSTER, SERVICE)
    cpu_findings = [f for f in findings if f.type == FindingType.HIGH_CPU_UTILIZATION]
    assert len(cpu_findings) == 1   # only one finding, not two
    assert cpu_findings[0].severity == Severity.HIGH
