
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
    FindingType.DEPLOYMENT_STALL: (
        "Deployment is stalled — tasks are launching but failing health checks",
        0.75,
        "Check ALB health check path and grace period. Tasks are starting (pendingCount > 0) "
        "but not reaching healthy state. Review application startup logs and increase "
        "healthCheckGracePeriodSeconds.",
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
    FindingType.MISSING_EXECUTION_ROLE: (
        "Task definition is missing executionRoleArn — ECS cannot pull images or read secrets",
        0.90,
        "Add an executionRoleArn to the task definition. The execution role needs "
        "ecr:GetAuthorizationToken, ecr:BatchGetImage, logs:CreateLogStream, logs:PutLogEvents, "
        "and secretsmanager:GetSecretValue (if using Secrets Manager). "
        "Create or update the role in IAM and reference it in the task definition.",
    ),
    FindingType.CONTAINER_START_FAILURE: (
        "Container failed to start — bad entrypoint, missing binary, or runtime start error",
        0.85,
        "Exit 126 means the binary exists but is not executable (check file permissions in the image). "
        "Exit 127 means the binary was not found (check CMD/ENTRYPOINT spelling and PATH). "
        "CannotStartContainerError means the container runtime rejected the container at startup — "
        "check volume mounts, cgroup limits, and invalid environment variables.",
    ),
    FindingType.PORT_CONFLICT: (
        "Port already in use — container cannot bind to its declared port",
        0.90,
        "Another process is already listening on the port. Common causes: "
        "multiple containers in the task sharing a port without specifying different containerPort values, "
        "a sidecar not releasing the port on restart, or the previous task not fully stopped before replacement. "
        "Verify portMappings are unique across all containers in the task definition.",
    ),
    FindingType.NO_ALB_TARGETS: (
        "No targets registered in the ALB target group — traffic is not reaching the service",
        0.85,
        "ECS failed to register task IPs with the target group. Common causes: "
        "containerPort in the task definition does not match the load balancer configuration, "
        "the task never reached RUNNING state so ECS never attempted registration, "
        "or the target group and ECS service are in different VPCs. "
        "Check service events for 'registration' errors.",
    ),
    FindingType.MISSING_PORT_MAPPING: (
        "Load balancer expects a port that no container exposes",
        0.80,
        "Add the missing containerPort to the portMappings of the relevant container in the task definition. "
        "The port declared in the service's loadBalancers configuration must match a containerPort "
        "in the container definition. Update the task definition and redeploy.",
    ),
    FindingType.MISSING_HEALTH_CHECK_GRACE_PERIOD: (
        "Health checks may be killing tasks before the application finishes starting",
        0.60,
        "Set healthCheckGracePeriodSeconds on the ECS service to give the application time to warm up. "
        "A good starting value is the P95 startup time of the container plus 30 seconds. "
        "Without grace period, ECS may terminate tasks that are still initializing.",
    ),
    FindingType.NETWORK_ACL_DENY: (
        "Network ACL is blocking outbound traffic on required ports",
        0.85,
        "Review the NACL rules for the task's subnet. Ensure outbound ALLOW rules exist for "
        "ports 443 (HTTPS/ECR/Secrets Manager), 80 (HTTP), and ephemeral return ports 1024–65535. "
        "Unlike security groups, NACLs are stateless — both the outbound request and inbound response "
        "need explicit ALLOW rules.",
    ),
    FindingType.SCHEDULER_REPLACED: (
        "Task was replaced by the ECS scheduler (scale-in or deployment)",
        0.05,
        "This is expected behaviour during deployments or Auto Scaling scale-in events. "
        "If unexpected, check service events for deployment activity and Auto Scaling policies.",
    ),
    FindingType.USER_INITIATED_STOP: (
        "Task was manually stopped",
        0.05,
        "A user or automation called StopTask on this task. "
        "This is intentional — if tasks are being stopped unexpectedly, "
        "audit CloudTrail for ecs:StopTask events to identify the caller.",
    ),
    FindingType.FIRELENS_LOG_DRIVER: (
        "FireLens log driver in use — CloudWatch log scan skipped",
        0.05,
        "This service uses awsfirelens (Fluent Bit/Fluentd) for log routing. "
        "ecs-doctor cannot scan logs that are not sent to CloudWatch Logs directly. "
        "Check the FireLens destination (S3, Kinesis, third-party) for crash signatures manually.",
    ),
    FindingType.DEPENDENCY_FAILED: (
        "Container dependency condition never satisfied — dependent sidecar did not become HEALTHY",
        0.55,
        "Check the dependsOn configuration in the task definition. "
        "If a sidecar is declared with condition=HEALTHY, it must pass its own HEALTHCHECK. "
        "Verify the sidecar's health check command, interval, and startPeriod are correctly configured. "
        "Consider relaxing the condition to START if the sidecar does not expose a health check.",
    ),
    FindingType.CIRCUIT_BREAKER_DISABLED: (
        "Deployment circuit breaker is disabled — failed deployments will not auto-rollback",
        0.05,
        "Enable the ECS deployment circuit breaker on the service to automatically roll back "
        "failed deployments. Set deploymentCircuitBreaker.enable=true and rollback=true in the "
        "service's deploymentConfiguration.",
    ),
    FindingType.MISSING_LOG_CONFIG: (
        "Container has no log configuration — stdout/stderr are lost",
        0.20,
        "Add a logConfiguration block to the container definition. "
        "For CloudWatch Logs, use logDriver=awslogs and set awslogs-group, awslogs-region, "
        "and awslogs-stream-prefix. Ensure the task execution role has logs:CreateLogStream "
        "and logs:PutLogEvents permissions.",
    ),
    FindingType.SG_INGRESS_BLOCKED: (
        "Security group blocks inbound traffic on the container port — ALB cannot reach the task",
        0.90,
        "Add an inbound rule to the task security group allowing traffic on the container port "
        "from the ALB security group (preferred) or the VPC CIDR. "
        "Avoid opening 0.0.0.0/0 — scope the source to the ALB security group ID instead.",
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

    _FALLBACK_WEIGHT = 0.10

    for finding in findings:
        if finding.type not in _HYPOTHESIS:
            label = finding.type.value.replace("_", " ").title()
            base_weight = _FALLBACK_WEIGHT
            fix = "Review the raw finding for details."
        else:
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
