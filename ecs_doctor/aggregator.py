
import math
from collections import defaultdict

from ecs_doctor.models import Finding, FindingType, RootCause, Severity

_SEVERITY_MULTIPLIER: dict[Severity, float] = {
    Severity.LOW: 0.5,
    Severity.MEDIUM: 0.75,
    Severity.HIGH: 1.0,
    Severity.CRITICAL: 1.25,
}

# (label, base_weight, suggested_fix)
_HYPOTHESIS: dict[FindingType, tuple[str, float, str]] = {
    FindingType.OOM_KILLED: (
        "Container is being OOM-killed (out of memory)",
        0.95,
        "Increase the container's memory reservation in the task definition. "
        "Enable CloudWatch Container Insights to track memory utilization trends. "
        "Profile the application for memory leaks — common causes include "
        "unbounded caches, unclosed DB connections, and JVM heap misconfiguration.",
    ),
    FindingType.IMAGE_PULL_FAILURE: (
        "ECS cannot pull the container image",
        0.95,
        "Verify the image URI and tag exist in ECR/Docker Hub. "
        "Ensure the task execution role has ecr:GetAuthorizationToken and ecr:BatchGetImage. "
        "For Fargate, confirm the subnet has a NAT gateway or VPC endpoint for ECR. "
        "DockerHub rate limiting can also cause this — consider mirroring to ECR.",
    ),
    FindingType.SECRETS_INIT_FAILURE: (
        "Task cannot initialize — secret or config resource is missing or inaccessible",
        0.95,
        "Check the stoppedReason for the exact secret ARN or SSM parameter that failed. "
        "Verify the secret exists in Secrets Manager / SSM Parameter Store. "
        "Ensure the task execution role has secretsmanager:GetSecretValue or ssm:GetParameter. "
        "For S3 environment files, add s3:GetObject to the execution role.",
    ),
    FindingType.PLACEMENT_FAILURE: (
        "ECS cannot schedule tasks — insufficient cluster capacity",
        0.85,
        "Check cluster CPU and memory utilization. "
        "For EC2 launch type, scale up the Auto Scaling Group or reduce task resource requirements. "
        "For Fargate, verify the selected subnets have available IPs and Fargate capacity exists. "
        "Review placement constraints and strategies for conflicts.",
    ),
    FindingType.ALB_UNHEALTHY: (
        "ALB targets are unhealthy — incoming traffic cannot reach the application",
        0.85,
        "Check that security groups allow traffic from the ALB security group to the container port. "
        "Verify the health check path returns HTTP 2xx. "
        "Confirm the container is listening on the declared containerPort. "
        "Increase healthCheckGracePeriodSeconds if the app takes time to start up.",
    ),
    FindingType.NETWORK_CONNECTIVITY: (
        "Network connectivity issue — task cannot reach the internet or downstream services",
        0.85,
        "Check security group outbound rules allow traffic on required ports (443, 80). "
        "For tasks in private subnets, verify a NAT Gateway exists in the route table. "
        "Consider VPC endpoints for ECR, S3, and Secrets Manager to avoid NAT costs. "
        "Verify network ACLs allow return traffic (ephemeral ports 1024-65535).",
    ),
    FindingType.HEALTH_CHECK_FAIL: (
        "Container or ALB health checks are consistently failing",
        0.80,
        "Review the HEALTHCHECK definition in your Dockerfile or task definition. "
        "Increase startPeriod / healthCheckGracePeriodSeconds to allow application warm-up. "
        "Check that the health check path (e.g. /health) returns HTTP 200. "
        "Verify security groups allow the ALB to reach the container port.",
    ),
    FindingType.DEPLOYMENT_ROLLBACK: (
        "Deployment failed and was rolled back — circuit breaker triggered",
        0.80,
        "The new task definition caused the deployment to fail. "
        "Check the new task definition for regressions (image tag, env vars, resource limits). "
        "Review service events and logs from the new tasks that failed during deployment. "
        "Compare the failing task definition against the last known-good version.",
    ),
    FindingType.DEPLOYMENT_CONFIG_DEADLOCK: (
        "Deployment is deadlocked — minimumHealthyPercent/maximumPercent prevents task replacement",
        0.80,
        "Set maximumPercent to at least 200 so ECS can launch a new task before stopping the old one. "
        "If maximumPercent must stay at 100, set minimumHealthyPercent to 0 temporarily during deploy. "
        "After the deployment succeeds, restore the desired health percentages.",
    ),
    FindingType.EFS_MOUNT_FAILURE: (
        "EFS/NFS volume failed to mount — task cannot access persistent storage",
        0.85,
        "Verify the EFS mount target exists in the same AZ as the task's subnet. "
        "Ensure the EFS security group allows inbound NFS (port 2049) from the task security group. "
        "Check the task execution role has elasticfilesystem:ClientMount permission. "
        "Confirm the EFS file system is in the 'available' state.",
    ),
    FindingType.DISK_ERROR: (
        "Container filesystem error — disk full or read-only",
        0.80,
        "Check ephemeral storage allocation in the task definition (default 20GB for Fargate). "
        "Review application log rotation — unbounded logs are the most common cause of disk full. "
        "For EC2 launch type, check Docker data root disk usage on the host instance.",
    ),
    FindingType.TASK_FAILED_TO_START: (
        "Task failed to start — did not become healthy before startTimeout",
        0.90,
        "Check CloudWatch logs for startup errors in the container. "
        "Increase the startTimeout in the task definition health check if the app needs more warm-up time. "
        "Verify all required secrets and environment variables are available at startup.",
    ),
    FindingType.SPOT_INTERRUPTED: (
        "Fargate Spot task was interrupted by AWS capacity reclamation",
        0.70,
        "Fargate Spot interruptions are expected — design the workload to tolerate them. "
        "Add a SIGTERM handler to checkpoint state before the 2-minute warning expires. "
        "For services that cannot tolerate interruption, use ON_DEMAND capacity provider instead.",
    ),
    FindingType.PREMATURE_EXIT: (
        "Essential container exited with code 0 (clean exit) — causing the task to stop",
        0.75,
        "The container completed successfully but the ECS service expected it to run continuously. "
        "Check CMD/ENTRYPOINT — if this is a long-running service, ensure it does not exit on completion. "
        "If it is intentionally a one-shot job, consider ECS Scheduled Tasks or a Lambda instead.",
    ),
    FindingType.TASK_THRASHING: (
        "Service is crash-looping — tasks start and stop repeatedly",
        0.75,
        "This is a symptom, not the root cause. "
        "Check the stop_reasons and logs findings above for the underlying failure. "
        "Common causes: application startup crash, health check misconfiguration, OOM kill. "
        "Consider increasing minimumHealthyPercent to slow the thrash rate while diagnosing.",
    ),
    FindingType.NON_ZERO_EXIT: (
        "Application process is crashing with a non-zero exit code",
        0.70,
        "Review CloudWatch logs for stack traces or error messages at shutdown time. "
        "Check for missing environment variables, secrets, or configuration files. "
        "Run the container locally with the same env vars to reproduce the crash.",
    ),
    FindingType.ESSENTIAL_EXITED: (
        "An essential container exited, causing the whole task to stop",
        0.70,
        "Identify which container exited (check exitCode in stop_reasons). "
        "Review its CloudWatch logs for the root cause. "
        "If it is a sidecar not intended to stop the task, remove the 'essential' flag.",
    ),
    FindingType.GRACEFUL_SHUTDOWN_FAIL: (
        "Container is not handling SIGTERM — getting forcefully killed during shutdown",
        0.60,
        "Add a SIGTERM handler to your application to flush state and exit cleanly. "
        "Increase stopTimeout in the task definition if the graceful drain period needs more time. "
        "This often surfaces as slow deployments and connection errors during rollouts.",
    ),
    FindingType.LOG_CRASH_SIGNATURE: (
        "Application crash signature detected in CloudWatch logs",
        0.65,
        "Review the full log context above for the specific error. "
        "Use CloudWatch Logs Insights to query across multiple task log streams. "
        "Address the underlying application error — check stack traces, missing files, "
        "network timeouts, and TLS/SSL certificate issues.",
    ),
    FindingType.HIGH_CPU_UTILIZATION: (
        "Sustained high CPU utilization — tasks may be CPU-throttled",
        0.60,
        "Increase the task CPU allocation in the task definition. "
        "Profile the application for CPU-intensive hotspots (tight loops, regex, serialization). "
        "Consider horizontal scaling via Application Auto Scaling target tracking. "
        "Check for runaway goroutines, threads, or infinite loops.",
    ),
    FindingType.HIGH_MEMORY_UTILIZATION: (
        "Sustained high memory utilization — OOM kill risk is elevated",
        0.60,
        "Increase the container memory reservation in the task definition. "
        "Profile the application for memory leaks using heap dumps or memory profilers. "
        "Set JVM heap size (-Xmx) to 75% of the container memory limit for Java services. "
        "Enable CloudWatch Container Insights for trend-based alerting.",
    ),
    FindingType.INVALID_TASK_CONFIG: (
        "Task definition has an invalid Fargate CPU/memory combination",
        0.90,
        "Fargate requires specific CPU/memory pairings. Valid examples: "
        "256 CPU → 512–2048 MB, 512 CPU → 1–4 GB, 1024 CPU → 2–8 GB, "
        "2048 CPU → 4–16 GB, 4096 CPU → 8–30 GB. "
        "Update the task definition to use a valid combination.",
    ),
    FindingType.IAM_DENIED: (
        "Diagnosis incomplete — IAM permissions are blocking one or more checks",
        0.50,
        "Grant the IAM actions listed in the evidence to the role running this tool. "
        "Re-run ecs-doctor after updating permissions to get a full diagnosis.",
    ),
}


def aggregate(findings: list[Finding]) -> RootCause:
    if not findings:
        return RootCause(
            cause="No issues detected across all diagnostic checks",
            confidence=0.0,
            evidence=[],
            suggested_fix=(
                "The service appears to be healthy. "
                "Monitor CloudWatch metrics for CPU, memory, and request error rates. "
                "Check Application Auto Scaling if traffic spikes are expected."
            ),
        )

    scores: dict[str, float] = defaultdict(float)
    evidence_map: dict[str, list[Finding]] = defaultdict(list)
    fix_map: dict[str, str] = {}

    for finding in findings:
        if finding.type not in _HYPOTHESIS:
            continue
        label, base_weight, fix = _HYPOTHESIS[finding.type]
        score = base_weight * _SEVERITY_MULTIPLIER[finding.severity]
        scores[label] += score
        evidence_map[label].append(finding)
        fix_map[label] = fix

    if not scores:
        return RootCause(
            cause="Cannot determine root cause",
            confidence=0.0,
            evidence=findings,
            suggested_fix="Review the raw findings above for clues.",
        )

    best_label = max(scores, key=scores.__getitem__)
    raw_score = scores[best_label]
    # Asymptotic normalization: single CRITICAL finding ≈ 0.70, three ≈ 0.97
    confidence = round(1.0 - math.exp(-raw_score), 2)

    return RootCause(
        cause=best_label,
        confidence=confidence,
        evidence=evidence_map[best_label],
        suggested_fix=fix_map[best_label],
    )
