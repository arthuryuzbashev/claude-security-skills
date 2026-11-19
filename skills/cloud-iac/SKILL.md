---
name: cloud-iac
description: Cloud and infrastructure-as-code security review. Scans Dockerfiles, Terraform (AWS, plus key GCP and Azure resources), Kubernetes manifests (pods and RBAC) and docker-compose files for misconfigurations (public S3 or GCS buckets, 0.0.0.0/0 on SSH/RDP, wildcard IAM, public RDS, IMDSv1, open EKS endpoint, privileged pods, hostPath, root containers, missing seccomp, wildcard or escalating RBAC, unpinned images, secrets in ENV, TLS checks turned off in builds), and audits AWS IAM policy JSON for wildcard grants, NotAction, iam:PassRole on *, public principals and 28 privilege escalation paths. Use whenever someone shares or asks about a Dockerfile, .tf file, Helm/k8s YAML, Role or ClusterRole, compose file, IAM policy, bucket policy or trust policy, says "is my infra secure", "review my terraform", "least privilege", "harden this deployment", or before a cloud deploy or audit.
---

# Cloud IaC

Find the cloud and container misconfigurations that turn into breaches, point at the exact file and line, and hand back a fix that fits the code.

## When to use

- A PR or repo touches `Dockerfile`, `*.tf`, Kubernetes YAML, Helm output or `docker-compose.yml`
- "Is this IAM policy too broad?", "least privilege", bucket or trust policy questions
- Hardening a deployment before launch, or prepping for a cloud security audit
- Explaining a finding from another scanner (Checkov, tfsec, Trivy, kube-bench) in plain words

## Ground rules

- Static review only. The scripts read files; they never call AWS, kubectl or Docker. Do not run `terraform apply`, `kubectl apply` or any change against a live account as part of a review
- If the user wants live state checked, ask them to export it themselves (`terraform show -json`, `kubectl get -o yaml`, `aws iam get-policy-version`) and scan the saved file
- Secrets found in code are reported masked (first 4 chars). Tell the user to rotate any real credential that was committed; deleting it from the file does not remove it from git history or images
- Severity reflects the config alone. Say so when context changes it (a public bucket that hosts a static site is fine; a public bucket with backups is not)

## Workflow

1. Find the IaC: `iac_scan.py <repo>` walks the tree and picks file types by name and content
2. For Helm or Kustomize, render first (`helm template ... > out.yaml`, `kubectl kustomize > out.yaml`) and scan the output, since templates are not valid YAML
3. Run `iam_policy_audit.py` on every IAM, bucket or trust policy JSON, including ones rendered from Terraform (`terraform show -json` then extract the policy, or paste it)
4. Triage: critical and high first. IAC-212 and other low findings are hardening, batch them into one change. Check context that a scanner cannot see (is it really internet facing, is the account a sandbox)
5. For each issue: what it is, what an attacker does with it in one sentence, severity, and the exact code change
6. Point the user at `references/iac-hardening-checklist.md` for anything the scanner does not cover (logging, KMS, network policies, admission control)
7. Re-run the scripts after fixes and show the diff in findings

## Tools

### iac_scan.py

Static scan of Dockerfiles, Terraform, Kubernetes manifests and compose files. Reports `file:line`.

```bash
python3 scripts/iac_scan.py .                               # whole repo
python3 scripts/iac_scan.py infra/ k8s/deployment.yaml
python3 scripts/iac_scan.py . --json --fail-on medium        # CI gate
helm template ./chart | python3 scripts/iac_scan.py - --type kubernetes
```

Rules:

| Area | IDs |
|---|---|
| Dockerfile | IAC-001 unpinned base image, IAC-002 runs as root, IAC-003 ADD from URL, IAC-004 secret in ENV/ARG, IAC-005 curl piped to shell, IAC-006 TLS verification off (curl -k, wget --no-check-certificate, pip --trusted-host, sslVerify false, NODE_TLS_REJECT_UNAUTHORIZED=0) |
| Terraform S3 | IAC-101 public ACL, IAC-102 no explicit encryption, IAC-103 no versioning, IAC-104 public access block off, IAC-105 bucket policy Principal * |
| Terraform network | IAC-110 SSH/RDP/Telnet/VNC/Docker API open to 0.0.0.0/0, IAC-111 all ports open, IAC-112 database port open (AWS security groups, GCP firewalls, Azure NSG rules) |
| Terraform IAM | IAC-120 Action *, IAC-121 Resource *, IAC-122 NotAction |
| Terraform RDS / secrets | IAC-130 publicly_accessible, IAC-131 storage not encrypted, IAC-140 hard-coded password or key |
| Terraform compute | IAC-150 IMDSv1 allowed, IAC-151 EBS not encrypted (skipped when `aws_ebs_encryption_by_default` is present), IAC-152 EKS endpoint public to 0.0.0.0/0, IAC-153 Lambda function URL with auth NONE |
| Terraform logging / keys | IAC-160 KMS rotation off, IAC-161 CloudTrail without log validation, single region or disabled |
| Terraform GCP / Azure | IAC-170 IAM member allUsers or allAuthenticatedUsers, IAC-171 storage account with public blobs, TLS below 1.2 or HTTP allowed |
| Kubernetes pods | IAC-201 privileged, IAC-202 hostNetwork, IAC-203 hostPath, IAC-204 root user, IAC-205 no limits, IAC-206 privilege escalation, IAC-207 unpinned image, IAC-208 hostPID/hostIPC, IAC-209 dangerous capabilities, IAC-210 secret in env value, IAC-211 seccomp or AppArmor Unconfined, IAC-212 below the restricted profile (seccomp RuntimeDefault, drop ALL, read-only root), IAC-213 hostPort |
| Kubernetes RBAC | IAC-220 wildcard verbs or resources, IAC-221 escalate/bind/impersonate, pods/exec, nodes/proxy, token minting or Secret reads, IAC-222 binding to system:anonymous, system:unauthenticated or system:authenticated |
| Compose | IAC-301 privileged, IAC-302 host network/pid/ipc, IAC-303 Docker socket or / mounted, IAC-304 secret in environment, IAC-305 dangerous cap_add, IAC-306 unpinned image, IAC-307 database port published on all interfaces |

Limits: the YAML and HCL readers are line based. They handle normal manifests and modules but not every YAML feature (anchors are kept as text) or Terraform expressions (`for_each`, modules, variables are not evaluated). A missing finding is not proof of safety.

### iam_policy_audit.py

Analyzes AWS IAM policy JSON. Accepts a bare document, `get-policy-version` output, `get-bucket-policy` output, URL-encoded documents or a list.

```bash
python3 scripts/iam_policy_audit.py policy.json
aws iam get-policy-version --policy-arn "$ARN" --version-id v3 | python3 scripts/iam_policy_audit.py -
python3 scripts/iam_policy_audit.py user-policies/*.json --combine    # all policies of one identity
```

Rules: IAM-001 full admin, IAM-002 Action *, IAM-003 service wildcard (`iam:*` is high), IAM-004 Allow + NotAction, IAM-005 Allow + NotResource, IAM-006 iam:PassRole on *, IAM-010 privilege escalation path (CreatePolicyVersion, AttachUserPolicy, PutRolePolicy, PassRole + lambda:CreateFunction + InvokeFunction, PassRole + ec2:RunInstances and 23 more), IAM-020 sensitive action on * with no Condition, IAM-030/031 Principal *, IAM-040 old or missing Version.

`--combine` matters: escalation paths often need two actions granted by two different policies.
Unconditional Deny statements on `Resource: "*"` are subtracted. Permission boundaries, SCPs and session policies are not, so a reported path may still be blocked higher up.

Both tools: `--json` prints `{"scanned"|"sources", "count", "findings": [{id, severity, title, detail, fix, location}]}`. Exit `0` clean, `1` a finding at or above `--fail-on` (default `high`, `never` to disable), `2` bad input.

## Output

Lead with one line: how many files, how many critical/high, the single worst issue.
Then a table grouped by file:

| Severity | ID | Where | Issue | Fix |
|---|---|---|---|---|

Give the fix as a code snippet in the file's own language (HCL, YAML, Dockerfile). Close with what was not checked (live account state, modules not in the repo, Helm values not rendered, SCPs and boundaries).

## References

- `references/iac-hardening-checklist.md` per-platform hardening checklist (Docker, Terraform AWS, Kubernetes Pod Security Standards, compose) with the fix snippet for each scanner rule
- `references/iam-privesc-cheatsheet.md` IAM escalation paths, what each needs, how to block it, and the condition keys that make broad grants safe
