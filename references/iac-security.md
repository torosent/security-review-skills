# Infrastructure as Code (IaC) Security Checks

## Dockerfile

| Check | Grep Pattern | Severity |
|-------|-------------|----------|
| Running as root | `USER root\|^(?!.*USER)` (no USER directive) | High |
| Using `latest` tag | `FROM\s+\w+:latest\|FROM\s+\w+\s*$` (no tag) | Medium |
| Secrets in build args | `ARG.*password\|ARG.*secret\|ARG.*key\|ARG.*token` | Critical |
| `ADD` with remote URL | `ADD\s+https?://` | Medium |
| Privileged operations | `--privileged\|--cap-add\|SYS_ADMIN\|NET_ADMIN` | High |
| Missing healthcheck | No `HEALTHCHECK` directive | Low |
| Shell form CMD/RUN | `CMD\s+[^[]` (not exec form) | Low |

## Kubernetes

| Check | Grep Pattern | Severity |
|-------|-------------|----------|
| Privileged container | `privileged:\s*true` | Critical |
| Run as root | `runAsNonRoot:\s*false\|runAsUser:\s*0` | High |
| No resource limits | Missing `resources.limits` | Medium |
| Host network | `hostNetwork:\s*true` | High |
| Host PID/IPC | `hostPID:\s*true\|hostIPC:\s*true` | High |
| Wildcard RBAC | `resources:.*\["?\*"?\]\|verbs:.*\["?\*"?\]` | Critical |
| No seccomp profile | Missing `seccompProfile` | Medium |
| Default namespace | `namespace:\s*default` | Low |
| No readOnlyRootFS | `readOnlyRootFilesystem:\s*false` or missing | Medium |
| Secrets in env | `valueFrom:\s*\n.*secretKeyRef` vs inline `value:` | Medium |

## Terraform / Bicep

| Check | Grep Pattern | Severity |
|-------|-------------|----------|
| Public access | `public_access\s*=\s*true\|publicAccess.*Enabled\|publicNetworkAccess.*Enabled` | High |
| HTTP allowed | `https_only\s*=\s*false\|httpsOnly.*false` | High |
| No encryption | `encryption\s*=\s*false\|sseAlgorithm.*None` | High |
| Open security group | `0\.0\.0\.0/0\|::/0` in ingress rules | Critical |
| Hardcoded secrets | `password\s*=\s*"\|admin_password\s*=\s*"` in .tf/.bicep | Critical |
| No logging | Missing `logging\|diagnostic_setting\|audit` blocks | Medium |
| Outdated TLS | `tls_version.*1\.[01]\|minTlsVersion.*TLS1_0\|TLS1_1` | High |

## Helm Charts

| Check | Pattern | Severity |
|-------|---------|----------|
| Hardcoded secrets | `data:` in Secret without `{{ }}` templates | Critical |
| No NetworkPolicy | Missing NetworkPolicy template | Medium |
| Default ServiceAccount | Missing `serviceAccountName` | Low |
| No PodDisruptionBudget | Missing PDB template | Low |

## Scan Workflow

1. Use `glob` to find IaC files: `**/Dockerfile*`, `**/*.yaml`, `**/*.yml`, `**/*.tf`, `**/*.bicep`, `**/Chart.yaml`
2. Use `grep` with patterns above against matched files
3. Use `view` to verify findings in context (reduce false positives)
4. Report with file path, line number, and specific remediation
