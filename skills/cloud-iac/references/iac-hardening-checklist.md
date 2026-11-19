# IaC hardening checklist

Use it after the scanner. It covers the scanner rules (with the fix) and the things a static scan cannot see.

## Dockerfile

- [ ] Base image pinned to a version and, for production, a digest (IAC-001)
  `FROM python:3.12.3-slim@sha256:<digest>`. Renovate or Dependabot can keep digests fresh
- [ ] Final stage runs as a non-root user (IAC-002)
  ```dockerfile
  RUN groupadd -r -g 10001 app && useradd -r -u 10001 -g app app
  USER 10001
  ```
  Use a numeric UID so Kubernetes `runAsNonRoot` can verify it
- [ ] No `ADD <url>` (IAC-003). Download with `curl -fsSL`, check a pinned sha256, or use `ADD --checksum=sha256:...` (BuildKit)
- [ ] No secrets in `ENV` or `ARG` (IAC-004). Both end up in `docker history`. Use a build secret:
  ```dockerfile
  RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
  ```
  `docker build --secret id=npmrc,src=$HOME/.npmrc .`
- [ ] No `curl ... | sh` (IAC-005). Fetch, verify checksum or signature, then run
- [ ] Multi-stage build so compilers and package caches stay out of the runtime image
- [ ] `.dockerignore` excludes `.git`, `.env`, keys and local configs
- [ ] `HEALTHCHECK` defined (or a probe in Kubernetes)
- [ ] Image scanned for CVEs in CI (Trivy, Grype) and rebuilt on a schedule, not just on code change

## Terraform (AWS)

### S3

- [ ] No `acl = "public-read"` / `public-read-write` (IAC-101). Prefer `object_ownership = "BucketOwnerEnforced"` which disables ACLs entirely
- [ ] `aws_s3_bucket_public_access_block` with all four flags `true` (IAC-104), plus the account-level block (`aws_s3_account_public_access_block`)
- [ ] Bucket policies name principals; no `Principal: "*"` without a Condition (IAC-105)
- [ ] Encryption declared (IAC-102). New objects get SSE-S3 by default since January 2023; use `aws:kms` with your own key when you need key policies, audit of decrypts or cross-account control
- [ ] Versioning on for anything you cannot lose (IAC-103); add Object Lock for backups that must survive a compromised admin
- [ ] A policy statement that denies requests where `aws:SecureTransport` is `false`
- [ ] Access logging or CloudTrail data events for sensitive buckets

### Network

- [ ] No 0.0.0.0/0 or ::/0 ingress on 22, 3389, 23, 5900, 2375/2376 (IAC-110). Use SSM Session Manager or EC2 Instance Connect Endpoint
- [ ] No all-ports ingress from the internet (IAC-111)
- [ ] Databases and caches only reachable from app security groups (IAC-112)
- [ ] Default security group of each VPC has no rules
- [ ] VPC flow logs on

### IAM

- [ ] No `Action = "*"` (IAC-120), no `NotAction` with Allow (IAC-122), `Resource = "*"` only for actions that do not support resource scoping (IAC-121)
- [ ] Run `iam_policy_audit.py` on every rendered policy; escalation paths hide in combinations
- [ ] Roles for workloads (instance profiles, IRSA / EKS Pod Identity, Lambda execution roles), no long-lived IAM user keys
- [ ] No access keys in provider blocks or variables defaults (IAC-140). Use environment credentials, SSO or OIDC from CI

### RDS and data

- [ ] `publicly_accessible = false` (IAC-130)
- [ ] `storage_encrypted = true` (IAC-131); it cannot be turned on later without snapshot copy and restore
- [ ] `manage_master_user_password = true` (Secrets Manager) instead of a `password` literal (IAC-140)
- [ ] `deletion_protection = true` and backups retained for production
- [ ] Remote state bucket encrypted, versioned and private; state files contain secrets in plain text

### Logging and detection (not scanned)

- [ ] CloudTrail multi-region trail with log file validation, delivered to a separate account
- [ ] GuardDuty and Security Hub (or equivalent) enabled
- [ ] Budget alarms, since cryptomining is the most common result of leaked keys

## Kubernetes (Pod Security Standards, Restricted profile)

The Restricted profile is the target for app workloads. Turn it on per namespace:

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

Per workload:

- [ ] No `privileged: true` (IAC-201)
- [ ] No `hostNetwork`, `hostPID`, `hostIPC` (IAC-202, IAC-208)
- [ ] No `hostPath` volumes (IAC-203). Never mount `/`, `/etc`, the kubelet dir or a container runtime socket
- [ ] `runAsNonRoot: true` and a non-zero `runAsUser` (IAC-204)
- [ ] `allowPrivilegeEscalation: false` (IAC-206)
- [ ] `capabilities: {drop: ["ALL"]}`, add back only `NET_BIND_SERVICE` if needed (IAC-209)
- [ ] `seccompProfile: {type: RuntimeDefault}`
- [ ] `readOnlyRootFilesystem: true`, with `emptyDir` for scratch paths
- [ ] `resources.limits.memory` set, plus requests (IAC-205). A namespace `LimitRange` backs this up
- [ ] Images pinned by digest (IAC-207); admission policy that only allows your registry
- [ ] Secrets via `secretKeyRef` or an external secrets operator, never `value:` (IAC-210). Enable encryption at rest for Secrets in etcd
- [ ] `automountServiceAccountToken: false` unless the pod calls the API
- [ ] RBAC: no `cluster-admin` bindings for apps, no `*` verbs or resources, no `create pods` / `pods/exec` for CI identities you do not fully trust
- [ ] A default-deny `NetworkPolicy` per namespace, then allow what is needed

Secure container template:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 10001
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
resources:
  requests: {cpu: 100m, memory: 128Mi}
  limits: {memory: 256Mi}
```

## docker-compose

- [ ] No `privileged: true` (IAC-301), no `network_mode: host` / `pid: host` / `ipc: host` (IAC-302)
- [ ] No `/var/run/docker.sock` mount (IAC-303). Mounting it gives root on the host. If a tool needs it, use a filtering socket proxy, read-only
- [ ] Secrets through `${VAR}` from an untracked `.env` or compose `secrets:` (IAC-304); `.env` in `.gitignore`
- [ ] Publish ports on `127.0.0.1:` when only local access is needed; `"5432:5432"` binds every interface and Docker's iptables rules bypass ufw
- [ ] `user:`, `read_only: true`, `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`
- [ ] Images pinned (IAC-306)
