#!/usr/bin/env python3
"""Audit AWS IAM policy JSON for over-broad grants and privilege escalation paths.

Reads policy documents from files or stdin. Accepts a bare policy document,
`aws iam get-policy-version` output, `aws s3api get-bucket-policy` output
({"Policy": "<json string>"}), a URL-encoded document, or a JSON list of them.
Never calls AWS.

Usage:
  iam_policy_audit.py policy.json
  aws iam get-policy-version --policy-arn ARN --version-id v3 | iam_policy_audit.py -
  iam_policy_audit.py user-policies/*.json --combine     # one identity, several policies
  iam_policy_audit.py policy.json --json --fail-on medium
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

SENSITIVE_SERVICES = {"iam", "sts", "kms", "organizations", "secretsmanager", "ssm", "lambda", "ec2"}

# Sensitive single actions that deserve a Condition when granted on Resource "*".
# iam:PassRole is left out here because IAM-006 covers it.
SENSITIVE_ACTIONS = [
    "sts:AssumeRole", "kms:Decrypt", "kms:CreateGrant", "secretsmanager:GetSecretValue",
    "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:SendCommand",
    "s3:DeleteBucket", "s3:PutBucketPolicy", "ec2:TerminateInstances", "iam:CreateAccessKey",
    "lambda:UpdateFunctionCode", "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
]

# Well-known IAM privilege escalation paths (public research, e.g. Rhino Security Labs).
# Every action in a path must be allowed for the path to count.
ESCALATION_PATHS: List[Tuple[str, List[str], str]] = [
    ("CreatePolicyVersion", ["iam:CreatePolicyVersion"], "create a new default version of a managed policy that grants admin"),
    ("SetDefaultPolicyVersion", ["iam:SetDefaultPolicyVersion"], "switch a policy back to an older, more permissive version"),
    ("CreateAccessKey", ["iam:CreateAccessKey"], "mint access keys for another, more privileged user"),
    ("CreateLoginProfile", ["iam:CreateLoginProfile"], "set a console password on a user that has none"),
    ("UpdateLoginProfile", ["iam:UpdateLoginProfile"], "reset another user's console password"),
    ("AttachUserPolicy", ["iam:AttachUserPolicy"], "attach AdministratorAccess to a user they control"),
    ("AttachGroupPolicy", ["iam:AttachGroupPolicy"], "attach an admin policy to their own group"),
    ("AttachRolePolicy", ["iam:AttachRolePolicy"], "attach an admin policy to a role they can assume"),
    ("PutUserPolicy", ["iam:PutUserPolicy"], "write an inline admin policy on a user"),
    ("PutGroupPolicy", ["iam:PutGroupPolicy"], "write an inline admin policy on their group"),
    ("PutRolePolicy", ["iam:PutRolePolicy"], "write an inline admin policy on a role they can assume"),
    ("AddUserToGroup", ["iam:AddUserToGroup"], "add themselves to an admin group"),
    ("UpdateAssumeRolePolicy", ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"], "rewrite a privileged role's trust policy, then assume it"),
    ("PassRole + EC2", ["iam:PassRole", "ec2:RunInstances"], "launch an instance with a privileged instance profile and read its credentials"),
    ("PassRole + Lambda invoke", ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "create a function running as a privileged role and invoke it"),
    ("PassRole + Lambda event source", ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"], "create a privileged function triggered by an event source"),
    ("UpdateFunctionCode", ["lambda:UpdateFunctionCode"], "replace the code of a function that already runs as a privileged role"),
    ("PassRole + Glue", ["iam:PassRole", "glue:CreateDevEndpoint"], "create a Glue dev endpoint with a privileged role and log in to it"),
    ("UpdateDevEndpoint", ["glue:UpdateDevEndpoint"], "add an SSH key to an existing privileged Glue dev endpoint"),
    ("PassRole + CloudFormation", ["iam:PassRole", "cloudformation:CreateStack"], "create a stack that runs as a privileged role and creates anything"),
    ("PassRole + Data Pipeline", ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"], "run commands through a pipeline with a privileged role"),
]


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: str = "") -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def extract_documents(data: Any) -> List[Dict[str, Any]]:
    """Find policy documents in the common AWS CLI output shapes."""
    if isinstance(data, str):
        text = urllib.parse.unquote(data) if data.lstrip().startswith("%7B") else data
        try:
            return extract_documents(json.loads(text))
        except ValueError:
            return []
    if isinstance(data, list):
        out = []
        for item in data:
            out += extract_documents(item)
        return out
    if not isinstance(data, dict):
        return []
    if "Statement" in data:
        return [data]
    for key in ("PolicyVersion", "Document", "PolicyDocument", "Policy", "AssumeRolePolicyDocument"):
        if key in data:
            return extract_documents(data[key])
    return []


def normalize(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for i, st in enumerate(_as_list(doc.get("Statement"))):
        if not isinstance(st, dict):
            continue
        out.append({
            "index": i,
            "sid": str(st.get("Sid", "")),
            "effect": str(st.get("Effect", "")).lower(),
            "actions": [str(a).lower() for a in _as_list(st.get("Action"))],
            "not_actions": [str(a).lower() for a in _as_list(st.get("NotAction"))],
            "has_not_action": "NotAction" in st,
            "resources": [str(r) for r in _as_list(st.get("Resource"))],
            "has_not_resource": "NotResource" in st,
            "principal": st.get("Principal"),
            "has_principal": "Principal" in st or "NotPrincipal" in st,
            "condition": st.get("Condition") or {},
        })
    return out


def _matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def statement_allows(st: Dict[str, Any], action: str) -> bool:
    if st["has_not_action"]:
        return not any(_matches(p, action) for p in st["not_actions"])
    return any(_matches(p, action) for p in st["actions"])


def _wild_res(st: Dict[str, Any]) -> bool:
    return "*" in st["resources"] or st["has_not_resource"]


def _loc(source: str, st: Dict[str, Any]) -> str:
    return f"{source}#Statement[{st['index']}]" + (f" ({st['sid']})" if st["sid"] else "")


def _public_principal(p: Any) -> bool:
    if p == "*":
        return True
    if isinstance(p, dict):
        return any(v == "*" or (isinstance(v, list) and "*" in v) for v in p.values())
    return False


def audit_statements(stmts: List[Dict[str, Any]], source: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for st in stmts:
        if st["effect"] != "allow":
            continue
        loc = _loc(source, st)
        cond = bool(st["condition"])
        if st["has_principal"] and _public_principal(st["principal"]):
            writes = st["has_not_action"] or any(
                a in ("*", "*:*") or not a.partition(":")[2].startswith(("get", "list", "describe")) for a in st["actions"])
            out.append(finding("IAM-030" if not cond else "IAM-031",
                               ("critical" if writes else "high") if not cond else "medium",
                               "Principal \"*\" with no Condition" if not cond else "Principal \"*\" limited by a Condition",
                               "Any AWS account or anonymous caller matches this statement" +
                               (", and it allows more than reads." if writes else " (read actions only; fine for a deliberate public website, nothing else).") if not cond else
                               f"Anyone matches unless the Condition holds: {json.dumps(st['condition'])[:160]}",
                               "Name exact principals, or require aws:PrincipalOrgID / aws:SourceAccount / aws:SourceVpce.", loc))
        acts = st["actions"]
        if st["has_not_action"]:
            sev = "high" if _wild_res(st) else "medium"
            out.append(finding("IAM-004", sev, "Allow with NotAction",
                               f"Grants every action except {', '.join(st['not_actions'][:5])}, including any service AWS adds later.",
                               "Replace NotAction with an explicit Action list. Use NotAction only inside Deny statements.", loc))
        elif "*" in acts or "*:*" in acts:
            if _wild_res(st):
                out.append(finding("IAM-001", "critical" if not cond else "high", "Full admin: Action \"*\" on Resource \"*\"",
                                   "This statement allows every API call on every resource" + (" (a Condition narrows it)." if cond else "."),
                                   "Replace with the specific actions and ARNs the identity needs. Generate a starting point from CloudTrail with IAM Access Analyzer policy generation.", loc))
            else:
                out.append(finding("IAM-002", "high", "Wildcard Action \"*\"",
                                   f"Every action is allowed on {', '.join(st['resources'][:3])}.",
                                   "List the specific actions needed on these resources.", loc))
        else:
            for a in acts:
                svc, _, name = a.partition(":")
                if name == "*":
                    sev = "high" if svc in SENSITIVE_SERVICES else "medium"
                    out.append(finding("IAM-003", sev, f"Service-wide wildcard {a}",
                                       f"Allows every {svc} action" + (", which includes privilege-changing calls." if sev == "high" else ", including destructive ones."),
                                       f"List the {svc} actions needed (for example read-only Get*/List*/Describe* if that is all it does).", loc))
        if st["has_not_resource"]:
            out.append(finding("IAM-005", "medium", "Allow with NotResource",
                               "Applies to every resource except the listed ones, including resources created later.",
                               "List the resources explicitly.", loc))
        if not ("*" in acts or st["has_not_action"]) and any(_matches(p, "iam:PassRole") for p in acts) and _wild_res(st):
            passed_to = "iam:PassedToService" in json.dumps(st["condition"])
            out.append(finding("IAM-006", "medium" if passed_to else "high", "iam:PassRole on any role",
                               "The identity can hand any role in the account to a service it controls" +
                               (" (limited by iam:PassedToService)." if passed_to else ", which is how most escalation paths start."),
                               "Scope Resource to the specific role ARNs and add a Condition on iam:PassedToService.", loc))
        if _wild_res(st) and not cond and not ("*" in acts or "*:*" in acts or st["has_not_action"]):
            hits = sorted({a for a in SENSITIVE_ACTIONS if statement_allows(st, a)})
            if hits:
                out.append(finding("IAM-020", "medium", "Sensitive actions on Resource \"*\" without a Condition",
                                   f"{', '.join(hits[:6])}{' ...' if len(hits) > 6 else ''} can be used on every matching resource in the account.",
                                   "Scope Resource to ARNs, or add conditions (aws:ResourceTag, kms:ViaService, aws:SourceVpce, iam:PassedToService).", loc))
    return out


def escalation_paths(stmts: List[Dict[str, Any]], source: str) -> List[Dict[str, str]]:
    """Report well-known escalation paths allowed by these statements (taken together)."""
    allows = [s for s in stmts if s["effect"] == "allow" and not s["has_principal"]]
    denies = [s for s in stmts if s["effect"] == "deny" and "*" in s["resources"] and not s["condition"]]
    if any(("*" in s["actions"] or "*:*" in s["actions"]) and _wild_res(s) for s in allows):
        return []  # already full admin, IAM-001 covers it

    def granting(action: str) -> List[Dict[str, Any]]:
        if any(statement_allows(d, action) for d in denies):
            return []
        return [s for s in allows if statement_allows(s, action)]

    out = []
    for name, actions, how in ESCALATION_PATHS:
        grants = [granting(a) for a in actions]
        if not all(grants):
            continue
        used = [s for g in grants for s in g]
        all_wild = all(any(_wild_res(s) for s in g) for g in grants)
        conditioned = all(all(s["condition"] for s in g) for g in grants)
        sev = "medium" if conditioned else ("critical" if all_wild else "high")
        where = ", ".join(sorted({f"Statement[{s['index']}]" for s in used}))
        out.append(finding("IAM-010", sev, f"Privilege escalation path: {name}",
                           f"Allowed: {', '.join(actions)}. An attacker with this identity could {how}." +
                           ("" if all_wild else " Resources are scoped, so check what those ARNs cover.") +
                           (" Every grant has a Condition, check whether it really blocks this." if conditioned else ""),
                           "Remove the action(s), or scope them to specific ARNs and add conditions. Keep IAM write actions for a small admin role behind MFA.",
                           f"{source} ({where})"))
    return out


def audit_document(doc: Dict[str, Any], source: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    version = doc.get("Version")
    if version != "2012-10-17":
        out.append(finding("IAM-040", "low", f"Policy Version is {version or 'missing'}",
                           "Without Version 2012-10-17, policy variables such as ${aws:username} are treated as literal text.",
                           "Set \"Version\": \"2012-10-17\".", source))
    stmts = normalize(doc)
    out += audit_statements(stmts, source)
    out += escalation_paths(stmts, source)
    return out


def audit_sources(sources: List[Tuple[str, Any]], combine: bool = False) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    combined: List[Dict[str, Any]] = []
    for name, data in sources:
        docs = extract_documents(data)
        if not docs:
            raise ValueError(f"{name}: no IAM policy document found (expected a JSON object with Statement)")
        for n, doc in enumerate(docs):
            label = name if len(docs) == 1 else f"{name}[{n}]"
            if combine:
                out += [f for f in audit_document(doc, label) if f["id"] != "IAM-010"]
                stmts = normalize(doc)
                for s in stmts:
                    s["index"] = f"{label}:{s['index']}"
                combined += stmts
            else:
                out += audit_document(doc, label)
    if combine:
        out += escalation_paths(combined, "combined")
    out.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return out


def render_text(findings: List[Dict[str, str]], names: List[str]) -> str:
    lines = [f"IAM policy audit: {', '.join(names)}", f"{len(findings)} finding(s)", ""]
    if not findings:
        lines.append("No issues found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           at {f.get('location', '?')}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Audit AWS IAM policy JSON (offline, read-only).")
    ap.add_argument("files", nargs="+", help="policy JSON files; '-' reads stdin")
    ap.add_argument("--combine", action="store_true",
                    help="treat all inputs as the policies of one identity when looking for escalation paths")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    sources: List[Tuple[str, Any]] = []
    try:
        for f in args.files:
            text = sys.stdin.read() if f == "-" else open(f, encoding="utf-8").read()
            sources.append(("<stdin>" if f == "-" else f, json.loads(text)))
        findings = audit_sources(sources, args.combine)
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    names = [n for n, _ in sources]
    if args.json:
        print(json.dumps({"sources": names, "count": len(findings), "findings": findings}, indent=2))
    else:
        print(render_text(findings, names))
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
