# AWS IAM privilege escalation cheat sheet

How a limited identity becomes admin, how to spot it in a policy, and how to block it.
Based on publicly documented research (Rhino Security Labs' IAM escalation methods and AWS documentation).
`iam_policy_audit.py` reports these as IAM-010.

## Direct IAM changes

| Path | Needs | What happens | Block it |
|---|---|---|---|
| CreatePolicyVersion | `iam:CreatePolicyVersion` | Creates a new version of a managed policy attached to the attacker, sets it as default (`--set-as-default` needs no extra permission) with `"Action": "*"` | Only an admin role gets this; scope Resource to policies the identity does not use |
| SetDefaultPolicyVersion | `iam:SetDefaultPolicyVersion` | Rolls a policy back to an older, broader version | Delete old versions; deny the action |
| AttachUserPolicy / AttachGroupPolicy / AttachRolePolicy | `iam:Attach*Policy` | Attaches `AdministratorAccess` to self, own group, or an assumable role | Permission boundary + condition `iam:PolicyARN` limited to an allow list |
| PutUserPolicy / PutGroupPolicy / PutRolePolicy | `iam:Put*Policy` | Writes an inline admin policy | Deny, or permission boundary |
| AddUserToGroup | `iam:AddUserToGroup` | Joins an admin group | Scope Resource to specific low-privilege groups |
| CreateAccessKey | `iam:CreateAccessKey` | Creates keys for a more privileged user | Scope Resource to `arn:aws:iam::*:user/${aws:username}` |
| CreateLoginProfile / UpdateLoginProfile | `iam:CreateLoginProfile`, `iam:UpdateLoginProfile` | Sets or resets another user's console password | Same self-only scoping |
| UpdateAssumeRolePolicy | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Rewrites a privileged role's trust policy to trust the attacker, then assumes it | Deny on privileged roles; SCP protecting admin roles |

## PassRole paths (run code as a stronger role)

`iam:PassRole` lets an identity hand a role to a service. Combined with a way to run code in that service, the code runs with the passed role's permissions.

| Path | Needs |
|---|---|
| EC2 | `iam:PassRole` + `ec2:RunInstances` (instance profile, read credentials from IMDS) |
| Lambda | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` (or `lambda:CreateEventSourceMapping`) |
| Glue | `iam:PassRole` + `glue:CreateDevEndpoint` |
| CloudFormation | `iam:PassRole` + `cloudformation:CreateStack` |
| Data Pipeline | `iam:PassRole` + `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` |

Same idea without PassRole, by hijacking something that already runs as a privileged role:

- `lambda:UpdateFunctionCode` on a function whose execution role is privileged
- `glue:UpdateDevEndpoint` to add an SSH key to an existing endpoint

Safe PassRole pattern:

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/app-worker",
  "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
}
```

## Red flags when reading a policy

- `"Action": "*"` or `"*:*"`: full access to that resource scope
- `"iam:*"`, `"sts:*"`, `"kms:*"`, `"organizations:*"`: service wildcards on control-plane services
- `Allow` + `NotAction`: allows everything except a list, including services launched later
- `Allow` + `NotResource`: applies to every resource except a list
- `"Principal": "*"` in resource or trust policies with no Condition
- `iam:PassRole` with `"Resource": "*"`
- Wildcards inside action names: `iam:Put*` covers `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`
- Version missing or `2008-10-17`: `${aws:username}` and other policy variables are not substituted

## Condition keys that make broad grants safer

| Key | Use |
|---|---|
| `aws:PrincipalOrgID` | Resource policies: only principals from your AWS Organization |
| `aws:SourceAccount`, `aws:SourceArn` | Service principals: stop the confused deputy problem |
| `aws:SourceVpce`, `aws:SourceVpc` | Only through your VPC endpoint |
| `aws:SecureTransport` | Deny plain HTTP |
| `aws:MultiFactorAuthPresent` | Require MFA for sensitive console/API actions |
| `aws:ResourceTag/<key>`, `aws:PrincipalTag/<key>` | Attribute-based access control |
| `aws:RequestedRegion` | Keep activity in approved regions |
| `iam:PassedToService` | Limit which service a role can be passed to |
| `iam:PermissionsBoundary` | Force a boundary on users/roles the identity creates |
| `kms:ViaService` | Allow a KMS key only when used through a given service |
| `s3:prefix` | Scope ListBucket to a prefix |

## Guardrails above the policy

- **Permission boundaries** cap what an identity's own policies can grant. Use them on any identity that can create users or roles
- **Service control policies (SCPs)** cap whole accounts. Common ones: deny leaving the organization, deny disabling CloudTrail/GuardDuty, deny changes to the security role, region restriction
- **IAM Access Analyzer** finds resources shared outside the account and can generate a least-privilege policy from CloudTrail activity
- `iam_policy_audit.py` does not evaluate boundaries, SCPs or session policies, so treat its escalation findings as "possible, check the guardrails"

## Least-privilege workflow

1. Start from what the workload calls (CloudTrail, Access Analyzer policy generation, or the SDK calls in code)
2. Write explicit actions and ARNs; use `Resource: "*"` only for actions that do not support resource scoping (many `Describe*`/`List*` calls)
3. Add conditions for anything that touches IAM, KMS, secrets or networking
4. Run `iam_policy_audit.py --combine` on all policies of the identity
5. Review unused permissions after 30-90 days (IAM last accessed data) and remove them
