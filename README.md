# ECS Doctor 🩺

[![CI](https://github.com/PraveenLuke/ecs-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/PraveenLuke/ecs-doctor/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/ecs-doctor.svg)](https://pypi.org/project/ecs-doctor/)
[![PyPI downloads](https://img.shields.io/pypi/dm/ecs-doctor.svg)](https://pypi.org/project/ecs-doctor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)

**One command to diagnose why your ECS service is failing.**

ECS troubleshooting means jumping between the ECS console, CloudWatch Logs, ALB target groups, and task definitions — manually correlating signals across every incident. ECS Doctor pulls all of those signals together and gives you a single confidence-scored root-cause report with a suggested fix, in under a second.

```bash
pipx install ecs-doctor
ecs-doctor diagnose --cluster prod --service payments
```

```
╭─ Root Cause ──────────────────────────────────────────────────────────╮
│  Container is being OOM-killed (out of memory)          97% confidence │
│                                                                        │
│  Suggested fix: Increase the container memory reservation in the task  │
│  definition. Profile the application for memory leaks — common causes  │
│  include unbounded caches, unclosed DB connections, JVM heap settings. │
╰────────────────────────────────────────────────────────────────────────╯

  Source        Type            Severity   Message
  stop_reasons  oom_killed      CRITICAL   Container 'app' exit 137 (3 tasks)
  logs          log_crash_sig   CRITICAL   OOM detected in CloudWatch Logs
  events        task_thrashing  CRITICAL   4 starts / 4 stops in last 20 events

  Metric              Average    Maximum
  CPU Utilization      12.4%      18.1%
  Memory Utilization   94.2%      99.8%

Diagnosis completed in 843ms.
```

---

## What it checks

ECS Doctor runs **7 parallel diagnostic checks** across the AWS APIs that matter:

| Check | AWS APIs | What it catches |
|-------|----------|-----------------|
| **Service events** | `ecs:DescribeServices` | Placement failures, deployment rollbacks, crash loops, deployment config deadlock |
| **Stop reasons** | `ecs:ListTasks`, `ecs:DescribeTasks` | OOM (exit 137/139), image pull failure, missing secret, non-zero exit, SIGTERM not handled, Spot interruption |
| **CloudWatch Logs** | `logs:GetLogEvents` | Python / Java / Go / Node.js / Rust / .NET / PHP / Ruby crashes, DNS failures, TLS errors, wrong CPU architecture, EFS mount failures (25+ patterns) |
| **ALB health** | `elasticloadbalancing:DescribeTargetHealth` | Unhealthy targets — timeout, connection refused, non-2xx |
| **Metrics** | `cloudwatch:GetMetricData` | CPU or memory above 85% over the last 3 hours |
| **Task config** | `ecs:DescribeTaskDefinition` | Invalid Fargate CPU/memory combination |
| **Network** | `ec2:Describe*` | Security groups blocking egress, no NAT Gateway, ENI not attached |

All findings are scored, ranked by confidence, and collapsed into a single root cause.

---

## Installation

```bash
# Recommended — isolated install
pipx install ecs-doctor

# Terminal only
pip install ecs-doctor

# With web UI
pip install "ecs-doctor[web]"

# With interactive arrow-key browser
pip install "ecs-doctor[interactive]"

# Everything
pip install "ecs-doctor[web,interactive]"
```

---

## CLI Usage

```bash
# Diagnose a service
ecs-doctor diagnose --cluster my-cluster --service my-service

# Omit --service to pick interactively from the cluster
ecs-doctor diagnose --cluster my-cluster

# Use a named AWS profile
ecs-doctor diagnose --cluster my-cluster --service my-service --profile staging

# Specify region
ecs-doctor diagnose --cluster my-cluster --service my-service --region eu-west-1

# Machine-readable JSON (pipe to jq, Slack bots, incident tooling)
ecs-doctor diagnose --cluster my-cluster --service my-service --json

# Stream live logs from running tasks (Ctrl+C to stop)
ecs-doctor diagnose --cluster my-cluster --service my-service --stream-logs

# Skip CloudWatch metrics (faster, fewer IAM permissions needed)
ecs-doctor diagnose --cluster my-cluster --service my-service --no-metrics

# Interactive wizard — guides you through account → region → cluster → service
ecs-doctor browse
```

### Options reference

```
ecs-doctor diagnose [OPTIONS]

  --cluster TEXT      ECS cluster name or ARN  [required]
  --service TEXT      ECS service name (omit to pick interactively)
  --region TEXT       AWS region (overrides profile / env default)
  --profile TEXT      AWS named profile from ~/.aws/credentials
  --json              Machine-readable JSON output
  --stream-logs       Stream live logs from running tasks
  --no-metrics        Skip CloudWatch metrics
  --no-config         Skip task definition config panel
```

---

## Web UI

```bash
pip install "ecs-doctor[web]"
ecs-doctor serve          # opens at http://localhost:8080
```

The web interface provides the same diagnosis in a browser — useful for teams who prefer a point-and-click workflow or want to share results on screen.

**Key features:**

- **Profile → Cluster → Service dropdowns** auto-populated from your `~/.aws/credentials` — no typing required
- **Tabbed results** — Diagnosis, Metrics, Config, Live Logs in separate tabs so you never scroll through a wall of output
- **Metrics tab** — CPU and memory shown as color-coded progress bars (green / amber / red by threshold)
- **Live Logs tab** — streams CloudWatch log events directly in the browser via Server-Sent Events; Start / Stop with a status indicator

---

## Authentication

ECS Doctor follows the standard **boto3 credential chain** — the same one used by the AWS CLI:

| Method | How |
|--------|-----|
| Environment variables | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| Named profile | `--profile my-profile` or `AWS_PROFILE=my-profile` |
| ECS task role | Automatic when running inside Fargate / ECS |
| EC2 instance role | Automatic when running on EC2 |
| Web Identity / OIDC | Automatic via `AWS_WEB_IDENTITY_TOKEN_FILE` (GitHub Actions, EKS) |

If credentials cannot be resolved, the tool exits with a clear message listing all supported methods.

---

## IAM Permissions

Minimum policy for a full scan:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeServices", "ecs:DescribeTasks", "ecs:DescribeTaskDefinition",
        "ecs:DescribeClusters", "ecs:ListTasks", "ecs:ListClusters", "ecs:ListServices"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:GetLogEvents", "logs:FilterLogEvents", "logs:DescribeLogStreams"],
      "Resource": "arn:aws:logs:*:*:log-group:/ecs/*:*"
    },
    {
      "Effect": "Allow",
      "Action": ["cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["elasticloadbalancing:DescribeTargetHealth"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables", "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkInterfaces"
      ],
      "Resource": "*"
    },
    { "Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*" }
  ]
}
```

> **Tip:** If you only have ECS + Logs + ELB permissions, pass `--no-metrics`. ECS Doctor skips any check it lacks permissions for and tells you exactly which IAM action and resource ARN you'd need to add.

---

## JSON output

Pass `--json` to get a machine-readable report — useful for CI pipelines, Slack bots, PagerDuty runbooks, or any custom incident tooling:

```bash
ecs-doctor diagnose --cluster prod --service payments --json | jq .root_cause
```

```json
{
  "cause": "Container is being OOM-killed (out of memory)",
  "confidence": 0.97,
  "suggested_fix": "Increase the container memory reservation in the task definition...",
  "evidence": [...]
}
```

---

## Contributing

Contributions are welcome — bug reports, new diagnosers, additional log patterns, and documentation improvements.

```bash
git clone https://github.com/PraveenLuke/ecs-doctor
cd ecs-doctor
pip install -e ".[dev,web,interactive]"
pytest tests/ -v
```

To add a new diagnoser: create `ecs_doctor/diagnosers/my_check.py`, add `FindingType` entries to `models.py`, add a hypothesis to `aggregator.py`, wire it into `engine.py`, and add tests under `tests/`.

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built by [Praveen Rajkoilraj](https://github.com/PraveenLuke). If ECS Doctor saved you time during an incident, consider giving the repo a ⭐.*
