#!/usr/bin/env python3
"""Audit GitHub Actions workflows for supply-chain and injection risks.

Checks unpinned actions, pull_request_target with PR checkout, script
injection through untrusted ${{ }} contexts, token permissions,
self-hosted runners on PR triggers and leaked secrets. Offline only.

Usage:
  ci_audit.py .                              # finds .github/workflows/*.yml
  ci_audit.py .github/workflows/release.yml
  ci_audit.py . --json --fail-on medium
  cat workflow.yml | ci_audit.py -
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Contexts an outside contributor controls (issue/PR/comment text, branch names, commit metadata).
UNTRUSTED_CONTEXT = re.compile(
    r"github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|review\.body|review_comment\.body"
    r"|discussion\.(title|body)|pages\.[^}]*\.page_name|commits\.[^}]*\.(message|author\.(email|name))"
    r"|head_commit\.(message|author\.(email|name)|committer\.(email|name))"
    r"|pull_request\.head\.(ref|label|repo\.default_branch)|workflow_run\.(head_branch|head_commit\.message|display_title))"
    r"|github\.head_ref"
    r"|inputs\.[A-Za-z0-9_-]+")
EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
PR_TRIGGERS = {"pull_request", "pull_request_target", "issue_comment", "pull_request_review",
               "pull_request_review_comment", "discussion_comment", "issues"}
TRUSTED_OWNERS = {"actions", "github"}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: str = "") -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


# --------------------------------------------------------------------------- tiny YAML reader
# Good enough for workflow files: block mappings and sequences,
# quoted and plain scalars, simple flow [..] / {..}, block scalars, comments,
# several documents. Every node remembers its line number.

class YMap(dict):
    def __init__(self, line: int = 0):
        super().__init__()
        self.line = line
        self.key_lines: Dict[str, int] = {}


class YSeq(list):
    def __init__(self, line: int = 0):
        super().__init__()
        self.line = line


class YStr(str):
    def __new__(cls, value: str, line: int = 0, block: bool = False):
        obj = str.__new__(cls, value)
        obj.line = line
        obj.block = block  # True for | and > scalars; their text starts on line + 1
        return obj


def _strip_comment(text: str) -> str:
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"" and (i == 0 or text[i - 1] in " \t:[{,-"):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == "'":
        return v[1:-1].replace("''", "'")
    if len(v) >= 2 and v[0] == v[-1] == '"':
        try:
            return json.loads(v)
        except ValueError:
            return v[1:-1]
    return v


def _split_key(text: str) -> Optional[Tuple[str, str]]:
    if not text or text[0] in "[{":
        return None
    start = 0
    if text[0] in "'\"":
        end = text.find(text[0], 1)
        if end < 0:
            return None
        start = end + 1
    for i in range(start, len(text)):
        if text[i] == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return _unquote(text[:i]), text[i + 1:].strip()
    return None


def _split_flow(s: str) -> List[str]:
    parts, depth, quote, cur = [], 0, None, ""
    for ch in s:
        if quote:
            quote = None if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
            continue
        cur += ch
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts]


def _scalar(val: str, line: int) -> Any:
    v = val.strip()
    while v[:1] in ("!", "&"):
        bits = v.split(None, 1)
        v = bits[1] if len(bits) > 1 else ""
    if v.startswith("[") and v.endswith("]"):
        seq = YSeq(line)
        seq.extend(_scalar(p, line) for p in _split_flow(v[1:-1]))
        return seq
    if v.startswith("{") and v.endswith("}"):
        m = YMap(line)
        for p in _split_flow(v[1:-1]):
            k, _, rest = p.partition(":")
            m[_unquote(k)] = _scalar(rest, line)
            m.key_lines[_unquote(k)] = line
        return m
    return YStr(_unquote(v), line)


class _Reader:
    def __init__(self, lines: List[List[Any]]):
        self.lines = lines  # [[lineno, raw], ...]
        self.pos = 0

    def info(self, i: int) -> Tuple[int, int, str]:
        lineno, raw = self.lines[i]
        body = raw.lstrip(" ")
        return lineno, len(raw) - len(body), _strip_comment(body)

    def skip(self) -> None:
        while self.pos < len(self.lines) and not self.info(self.pos)[2]:
            self.pos += 1

    @staticmethod
    def is_item(content: str) -> bool:
        return content == "-" or content.startswith("- ")

    def node(self, min_indent: int) -> Any:
        self.skip()
        if self.pos >= len(self.lines):
            return None
        lineno, indent, content = self.info(self.pos)
        if indent < min_indent:
            return None
        if self.is_item(content):
            return self.seq(indent)
        if _split_key(content) is None:
            self.pos += 1
            return self.value(content, lineno, indent)
        return self.mapping(indent)

    def mapping(self, indent: int) -> YMap:
        m = YMap(self.info(self.pos)[0])
        while True:
            self.skip()
            if self.pos >= len(self.lines):
                break
            lineno, ind, content = self.info(self.pos)
            if ind < indent or (ind == indent and self.is_item(content)):
                break
            kv = _split_key(content) if ind == indent else None
            self.pos += 1
            if kv is None:
                continue  # tolerate lines we do not understand
            key, val = kv
            m.key_lines[key] = lineno
            m[key] = self.value(val, lineno, indent)
        return m

    def seq(self, indent: int) -> YSeq:
        s = YSeq(self.info(self.pos)[0])
        while True:
            self.skip()
            if self.pos >= len(self.lines):
                break
            lineno, ind, content = self.info(self.pos)
            if ind != indent or not self.is_item(content):
                break
            rest = content[1:].lstrip(" ")
            if not rest:
                self.pos += 1
                item = self.node(indent + 1)
                s.append(item if item is not None else YStr("", lineno))
                continue
            col = indent + len(content) - len(rest)
            raw_body = self.lines[self.pos][1].lstrip(" ")
            self.lines[self.pos][1] = " " * col + raw_body[len(content) - len(rest):]
            if self.is_item(rest):
                s.append(self.seq(col))
            elif _split_key(rest) is not None:
                s.append(self.mapping(col))
            else:
                self.pos += 1
                s.append(self.value(rest, lineno, indent))
        return s

    def value(self, val: str, lineno: int, indent: int) -> Any:
        if not val or re.fullmatch(r"([&!]\S+\s*)+", val):
            self.skip()
            if self.pos < len(self.lines):
                _, ind2, c2 = self.info(self.pos)
                if ind2 > indent:
                    got = self.node(ind2)
                    return got if got is not None else YStr("", lineno)
                if ind2 == indent and self.is_item(c2):
                    return self.seq(indent)
            return YStr("", lineno)
        if val[0] in "|>":
            return self.block(lineno, indent)
        if val[0] in "[{":
            while val.count("[") + val.count("{") > val.count("]") + val.count("}") and self.pos < len(self.lines):
                val += " " + self.info(self.pos)[2]
                self.pos += 1
        return _scalar(val, lineno)

    def block(self, lineno: int, indent: int) -> YStr:
        out, block_indent = [], None
        while self.pos < len(self.lines):
            raw = self.lines[self.pos][1]
            if raw.strip():
                ind = len(raw) - len(raw.lstrip(" "))
                if ind <= indent:
                    break
                block_indent = ind if block_indent is None else block_indent
                out.append(raw[min(block_indent, ind):])
            else:
                out.append("")
            self.pos += 1
        while out and not out[-1]:
            out.pop()
        return YStr("\n".join(out), lineno, block=True)


def _from_json(obj: Any) -> Any:
    if isinstance(obj, dict):
        m = YMap()
        for k, v in obj.items():
            m[str(k)] = _from_json(v)
        return m
    if isinstance(obj, list):
        s = YSeq()
        s.extend(_from_json(v) for v in obj)
        return s
    return YStr("" if obj is None else (str(obj).lower() if isinstance(obj, bool) else str(obj)))


def load_yaml_docs(text: str) -> List[Any]:
    """Parse YAML (or JSON) text into a list of documents."""
    if text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
            return [_from_json(d) for d in (data if isinstance(data, list) else [data])]
        except ValueError:
            pass
    docs, cur = [], []
    for n, raw in enumerate(text.replace("\t", "  ").splitlines(), 1):
        if re.match(r"^(---|\.\.\.)(\s|$)", raw):
            docs.append(cur)
            cur = []
            rest = raw[3:].strip()
            if rest and not rest.startswith("#") and not rest.startswith("!"):
                cur.append([n, rest])
            continue
        if raw.startswith("%"):
            continue
        cur.append([n, raw])
    docs.append(cur)
    out = []
    for lines in docs:
        node = _Reader(lines).node(0)
        if node is not None:
            out.append(node)
    return out


def ytrue(v: Any) -> bool:
    return isinstance(v, str) and v.strip().lower() in ("true", "yes", "on")


def line_of(m: Any, key: str) -> int:
    if isinstance(m, YMap) and key in m.key_lines:
        return m.key_lines[key]
    return getattr(m, "line", 0)


def triggers(doc: Dict[str, Any]) -> List[str]:
    on = doc.get("on", doc.get("true"))
    if isinstance(on, str):
        return [on.strip()]
    if isinstance(on, list):
        return [str(x) for x in on]
    if isinstance(on, dict):
        return list(on.keys())
    return []


def _steps(doc: Dict[str, Any]):
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if isinstance(step, dict):
                yield job_id, job, step


def check_uses(ref: str, line: int, path: str) -> Optional[Dict[str, str]]:
    ref = ref.strip()
    loc = f"{path}:{line}"
    if ref.startswith("./") or not ref:
        return None
    if ref.startswith("docker://"):
        if "@sha256:" not in ref:
            return finding("GHA-001", "medium", f"Docker action not pinned by digest: {ref}",
                           "A tag on a container image can be moved to a different image at any time.",
                           "Pin the image digest: docker://image@sha256:<digest>.", loc)
        return None
    name, _, version = ref.partition("@")
    if FULL_SHA.match(version):
        return None
    owner = name.split("/")[0].lower()
    if not version or version in ("main", "master", "HEAD", "latest", "dev", "develop", "trunk"):
        sev = "high"
        why = "a branch, so every push to it changes the code your workflow runs"
    elif owner in TRUSTED_OWNERS:
        sev = "low"
        why = "a tag; GitHub-owned, so lower risk, but tags can still be moved"
    else:
        sev = "medium"
        why = "a tag, and tags can be moved by whoever controls the repo (this is how the tj-actions/changed-files compromise spread in 2025)"
    return finding("GHA-001", sev, f"Action not pinned to a commit SHA: {ref}",
                   f"The ref '{version or '(none)'}' is {why}.",
                   f"Pin the full 40-char SHA and keep the tag as a comment: uses: {name}@<sha> # {version or 'vX.Y.Z'}. Dependabot can update pinned SHAs.", loc)


def _block_line(value: Any, match_start: int) -> int:
    """Line of a match inside a scalar. Block scalars start on the line after the key."""
    text = str(value)
    base = getattr(value, "line", 0)
    if getattr(value, "block", False):
        return base + 1 + text[:match_start].count("\n")
    return base


def audit_workflow(doc: Any, path: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not isinstance(doc, dict) or "jobs" not in doc:
        return out
    trig = set(triggers(doc))
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}

    # permissions
    top_perm = doc.get("permissions")
    if isinstance(top_perm, str) and top_perm.strip() == "write-all":
        out.append(finding("GHA-020", "high", "permissions: write-all",
                           "Every job's GITHUB_TOKEN can push code, create releases and change settings it can reach.",
                           "Set permissions: contents: read at the top and grant writes per job only where needed.",
                           f"{path}:{line_of(doc, 'permissions')}"))
    for job_id, job in jobs.items():
        if isinstance(job, dict) and isinstance(job.get("permissions"), str) and job["permissions"].strip() == "write-all":
            out.append(finding("GHA-020", "high", f"job {job_id}: permissions: write-all",
                               "The job token gets write access to everything.",
                               "List only the scopes the job needs (e.g. contents: read, pull-requests: write).",
                               f"{path}:{line_of(job, 'permissions')}"))
    if top_perm is None and any(isinstance(j, dict) and "permissions" not in j for j in jobs.values()):
        out.append(finding("GHA-021", "medium", "No permissions block",
                           "Without one, GITHUB_TOKEN gets the repository or organization default, which is read/write on older repos and orgs.",
                           "Add a top-level permissions: {contents: read} and widen per job.", f"{path}:1"))

    # pull_request_target / workflow_run with untrusted checkout
    privileged = trig & {"pull_request_target", "workflow_run"}
    for job_id, job, step in _steps(doc):
        uses = str(step.get("uses", ""))
        if privileged and uses.startswith("actions/checkout"):
            ref = str((step.get("with") or {}).get("ref", "")) if isinstance(step.get("with"), dict) else ""
            if re.search(r"pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/|workflow_run\.head_(sha|branch)", ref):
                out.append(finding("GHA-002", "critical", f"{', '.join(sorted(privileged))} checks out untrusted PR code",
                                   f"job {job_id} checks out ref '{ref}' in a workflow that has secrets and a write token. Any build, test or install step then runs the attacker's code with those privileges.",
                                   "Use the pull_request trigger for building PR code. If you need pull_request_target, never check out the head ref, or split into an unprivileged build and a privileged workflow_run that only reads artifacts.",
                                   f"{path}:{line_of(step, 'with')}"))
    if "pull_request_target" in trig and not any(f["id"] == "GHA-002" for f in out):
        out.append(finding("GHA-003", "low", "Uses pull_request_target",
                           "This trigger runs with secrets and a write token for PRs from forks. Safe only while it never runs PR code or PR text unsafely.",
                           "Prefer pull_request; if you keep it, review every step for use of PR-controlled data.",
                           f"{path}:{line_of(doc, 'on')}"))

    for job_id, job, step in _steps(doc):
        if "uses" in step:
            f = check_uses(str(step["uses"]), line_of(step, "uses"), path)
            if f:
                out.append(f)
        scripts: List[Tuple[str, Any]] = []
        if "run" in step:
            scripts.append(("run", step["run"]))
        if str(step.get("uses", "")).startswith("actions/github-script") and isinstance(step.get("with"), dict) and "script" in step["with"]:
            scripts.append(("script", step["with"]["script"]))
        for kind, body in scripts:
            text = str(body)
            for m in EXPR.finditer(text):
                expr = m.group(1).strip()
                if UNTRUSTED_CONTEXT.search(expr):
                    hot = bool(trig & PR_TRIGGERS) or not expr.startswith("inputs.")
                    lang = "shell script" if kind == "run" else "JavaScript"
                    use = '"$VALUE"' if kind == "run" else "process.env.VALUE"
                    out.append(finding("GHA-010", "high" if hot else "medium",
                                       f"Script injection: ${{{{ {expr} }}}} in {kind}",
                                       f"job {job_id}: the expression is pasted into the {lang} as text before it runs, so a crafted title, comment or branch name becomes code that runs with the job's token and secrets.",
                                       f"Pass it through env: instead: env: VALUE: ${{{{ {expr} }}}} then read {use} in the {lang}.",
                                       f"{path}:{_block_line(body, m.start())}"))
                if re.search(r"toJSON\(\s*secrets\s*\)", expr, re.I):
                    out.append(finding("GHA-030", "high", "All secrets dumped with toJSON(secrets)",
                                       "Serializing the whole secrets context exposes every secret to the step, and masking can fail on transformed values.",
                                       "Reference only the specific secret the step needs.", f"{path}:{_block_line(body, m.start())}"))
            for m in re.finditer(r"(?m)^[^\n#]*\b(echo|printf|print|cat)\b[^\n]*\$\{\{\s*secrets\.[A-Za-z0-9_]+", text):
                out.append(finding("GHA-030", "high", "Secret written to the log or a file",
                                   "A secret is echoed or printed. Log masking misses encoded or split values, and files can end up in artifacts.",
                                   "Pass secrets through env: to the tool that needs them; never print them.", f"{path}:{_block_line(body, m.start())}"))
            for m in re.finditer(r"(curl|wget)\b[^\n|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b", text):
                out.append(finding("GHA-040", "medium", "Remote script piped to a shell",
                                   "Whatever the URL serves at run time executes with the job's token and secrets.",
                                   "Download, verify a pinned checksum, then run; or use a pinned action.", f"{path}:{_block_line(body, m.start())}"))

    # self-hosted runners on PR-triggered workflows
    if trig & PR_TRIGGERS:
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            runs_on = job.get("runs-on")
            labels = [str(x) for x in runs_on] if isinstance(runs_on, list) else [str(runs_on or "")]
            if any("self-hosted" in l for l in labels):
                out.append(finding("GHA-031", "high", f"job {job_id}: self-hosted runner on a PR trigger",
                                   f"Triggers {', '.join(sorted(trig & PR_TRIGGERS))} can run code from outside contributors. On a public repo that code runs on your machine and can persist between jobs.",
                                   "Use GitHub-hosted runners for PR jobs, or ephemeral, isolated self-hosted runners with 'Require approval for all outside collaborators'.",
                                   f"{path}:{line_of(job, 'runs-on')}"))

    env_sources = [doc.get("env")] + [j.get("env") for j in jobs.values() if isinstance(j, dict)] + \
                  [s.get("env") for _, _, s in _steps(doc)]
    for env in env_sources:
        if isinstance(env, dict) and str(env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS", "")).lower() == "true":
            out.append(finding("GHA-041", "medium", "ACTIONS_ALLOW_UNSECURE_COMMANDS enabled",
                               "Re-enables the deprecated set-env/add-path log commands, which let anything printed to the log change the environment.",
                               "Remove it and write to $GITHUB_ENV / $GITHUB_PATH instead.",
                               f"{path}:{line_of(env, 'ACTIONS_ALLOW_UNSECURE_COMMANDS')}"))
    return out


def collect(paths: List[str]) -> List[str]:
    files = []
    for p in paths:
        if p == "-" or os.path.isfile(p):
            files.append(p)
            continue
        wf = os.path.join(p, ".github", "workflows")
        base = wf if os.path.isdir(wf) else p
        for name in sorted(os.listdir(base)):
            if name.endswith((".yml", ".yaml")):
                files.append(os.path.join(base, name))
    return files


def audit_paths(paths: List[str], stdin_text: str = "") -> Tuple[List[Dict[str, str]], List[str]]:
    findings: List[Dict[str, str]] = []
    scanned = []
    for path in collect(paths):
        if path == "-":
            text, label = stdin_text, "<stdin>"
        else:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text, label = fh.read(), path
        docs = load_yaml_docs(text)
        if any(isinstance(d, dict) and "jobs" in d for d in docs):
            scanned.append(label)
        for doc in docs:
            findings += audit_workflow(doc, label)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("location", "")))
    return findings, scanned


def render_text(findings: List[Dict[str, str]], scanned: List[str]) -> str:
    lines = [f"Workflow audit: {len(scanned)} workflow(s), {len(findings)} finding(s)", ""]
    if not scanned:
        lines.append("No GitHub Actions workflows found.")
    elif not findings:
        lines.append("No issues found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           at {f.get('location', '?')}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Audit GitHub Actions workflows (offline, read-only).")
    ap.add_argument("paths", nargs="+", help="repo dir, workflows dir or workflow files; '-' reads stdin")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    for p in args.paths:
        if p != "-" and not os.path.exists(p):
            print(f"error: no such file or directory: {p}", file=sys.stderr)
            return 2
    try:
        findings, scanned = audit_paths(args.paths, sys.stdin.read() if "-" in args.paths else "")
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if not scanned:
        print("error: no workflow (YAML with a jobs: key) found", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"scanned": scanned, "count": len(findings), "findings": findings}, indent=2))
    else:
        print(render_text(findings, scanned))
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
