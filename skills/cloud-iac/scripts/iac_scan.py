#!/usr/bin/env python3
"""Scan infrastructure-as-code for common security misconfigurations.

Covers Dockerfiles, Terraform (AWS provider), Kubernetes manifests and
docker-compose files. Works fully offline on files you already have.

Usage:
  iac_scan.py .                          # scan a repo
  iac_scan.py infra/ k8s/deploy.yaml     # several paths
  iac_scan.py main.tf --json --fail-on medium
  cat Dockerfile | iac_scan.py - --type dockerfile
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SKIP_DIRS = {".git", "node_modules", ".terraform", "vendor", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_BYTES = 2_000_000


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: str = "") -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


# --------------------------------------------------------------------------- secrets

SECRET_NAME = re.compile(
    r"(passw(or)?d|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth[_-]?key)",
    re.I)
NOT_SECRET_SUFFIX = re.compile(r"(_file|_path|_url|_uri|_endpoint|_host|_name|_user|_username|_id|_ttl|_length|_expiry)$", re.I)
TOKEN_PATTERNS = [
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


def mask(value: str) -> str:
    value = str(value)
    return value[:4] + "..." if len(value) > 4 else "***"


def is_reference(value: str) -> bool:
    """True for values that point at a secret instead of containing one."""
    v = value.strip().strip("'\"")
    if not v or v.lower() in ("true", "false", "null", "none", "yes", "no") or v.isdigit():
        return True
    return v.startswith("$") or "${" in v or v.startswith("<") or v.startswith("/run/secrets/")


def looks_like_secret(name: str, value: str) -> bool:
    if is_reference(value):
        return False
    if any(p.search(value) for p in TOKEN_PATTERNS):
        return True
    return bool(SECRET_NAME.search(name)) and not NOT_SECRET_SUFFIX.search(name)


# --------------------------------------------------------------------------- tiny YAML reader
# Good enough for manifests and compose files: block mappings and sequences,
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


# --------------------------------------------------------------------------- Dockerfile

def _docker_instructions(text: str) -> List[Tuple[int, str, str]]:
    out, buf, start = [], "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if buf and line.startswith("#"):
            continue
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        parts = buf.split(None, 1)
        out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buf = ""
    if buf:
        parts = buf.split(None, 1)
        out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return out


def _env_pairs(args: str) -> List[Tuple[str, str]]:
    """ENV/ARG accept `K=V K2=V2` or the legacy `K V`."""
    if "=" not in args.split(None, 1)[0]:
        bits = args.split(None, 1)
        return [(bits[0], bits[1] if len(bits) > 1 else "")]
    pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S*)", args)
    return [(k, v.strip("'\"")) for k, v in pairs]


TLS_OFF_PATTERNS = [
    ("curl -k", re.compile(r"\bcurl\b[^|;&]*\s(-[A-Za-z]*k[A-Za-z]*|--insecure)(\s|$)")),
    ("wget --no-check-certificate", re.compile(r"\bwget\b[^|;&]*--no-check-certificate")),
    ("pip --trusted-host", re.compile(r"\bpip3?\b[^|;&]*--trusted-host")),
    ("npm strict-ssl false", re.compile(r"\b(npm|yarn)\b[^|;&]*strict-ssl[\s=]+false", re.I)),
    ("git sslVerify false", re.compile(r"http\.sslverify[\s=]+(false|0)", re.I)),
    ("GIT_SSL_NO_VERIFY", re.compile(r"\bGIT_SSL_NO_VERIFY[\s=]+(1|true)", re.I)),
    ("NODE_TLS_REJECT_UNAUTHORIZED=0", re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED[\s=]+[\"']?0")),
]


def scan_dockerfile(text: str, path: str = "Dockerfile") -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    instructions = _docker_instructions(text)
    stage_names: set = set()
    last_from_line, user_in_stage = 0, None
    for line, inst, args in instructions:
        loc = f"{path}:{line}"
        if inst == "FROM":
            last_from_line, user_in_stage = line, None
            words = [w for w in args.split() if not w.startswith("--")]
            if not words:
                continue
            image = words[0]
            if len(words) >= 3 and words[1].lower() == "as":
                stage_names.add(words[2].lower())
            if image.lower() in stage_names or image == "scratch" or "@sha256:" in image or "$" in image:
                continue
            tag = image.rsplit("/", 1)[-1].partition(":")[2]
            if not tag or tag == "latest":
                out.append(finding("IAC-001", "medium", f"Base image {image} is not pinned",
                                   "No tag or :latest means every build can pull a different image, so builds are not reproducible and a poisoned upstream push lands silently.",
                                   f"Pin a version tag, ideally a digest: FROM {image.split(':')[0]}:<version>@sha256:<digest>", loc))
        elif inst == "USER":
            user_in_stage = (args.split() or [""])[0]
        elif inst == "ADD" and re.search(r"https?://", args):
            out.append(finding("IAC-003", "medium", "ADD downloads from a URL",
                               "ADD fetches remote files without any integrity check, and the result is hard to audit.",
                               "Use RUN curl -fsSLo file <url> && echo '<sha256>  file' | sha256sum -c -, or ADD --checksum=sha256:<hash>.", loc))
        elif inst in ("ENV", "ARG") and args.strip():
            for key, value in _env_pairs(args):
                if value and looks_like_secret(key, value):
                    out.append(finding("IAC-004", "high", f"Secret baked into the image ({inst} {key})",
                                       f"{key}={mask(value)} (masked). ENV and ARG values stay in the image history and are readable by anyone who can pull it.",
                                       "Pass secrets at runtime (orchestrator secrets) or use RUN --mount=type=secret during the build.", loc))
        elif inst == "RUN" and re.search(r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b", args):
            out.append(finding("IAC-005", "medium", "Remote script piped to a shell",
                               "curl | sh runs whatever the server returns at build time, with no integrity check.",
                               "Download, verify a pinned checksum or signature, then run.", loc))
        if inst in ("RUN", "ENV", "ARG"):
            hit = next((label for label, rx in TLS_OFF_PATTERNS if rx.search(args)), None)
            if hit:
                out.append(finding("IAC-006", "medium", f"TLS verification turned off in the build ({hit})",
                                   "Downloads in this step accept any certificate, so anyone on the network path can swap the package or script.",
                                   "Remove the flag and fix the trust store instead (COPY your CA into the image and run update-ca-certificates).", loc))
    if last_from_line:
        if user_in_stage is None or user_in_stage.split(":")[0] in ("root", "0"):
            what = "no USER instruction" if user_in_stage is None else f"USER {user_in_stage}"
            out.append(finding("IAC-002", "medium", "Container runs as root",
                               f"The final stage has {what}, so the process runs as UID 0 and a container escape starts with root.",
                               "Add a non-root user and switch to it: RUN useradd -r -u 10001 app && USER 10001",
                               f"{path}:{last_from_line}"))
    return out


# --------------------------------------------------------------------------- Terraform (HCL-lite)

class Block:
    def __init__(self, kind: str, labels: List[str], line: int):
        self.kind, self.labels, self.line = kind, labels, line
        self.attrs: Dict[str, Tuple[str, int]] = {}
        self.blocks: List["Block"] = []

    def attr(self, name: str) -> Optional[str]:
        return self.attrs[name][0] if name in self.attrs else None

    def sub(self, kind: str) -> List["Block"]:
        return [b for b in self.blocks if b.kind == kind]


def _strip_hcl_comment(line: str) -> str:
    quote = False
    for i, ch in enumerate(line):
        if ch == '"' and (i == 0 or line[i - 1] != "\\"):
            quote = not quote
        elif not quote and (ch == "#" or line[i:i + 2] == "//"):
            return line[:i]
    return line


def _depth(text: str) -> int:
    d, quote = 0, False
    for i, ch in enumerate(text):
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            quote = not quote
        elif not quote:
            d += ch in "{[(" and 1 or 0
            d -= ch in "}])" and 1 or 0
    return d


BLOCK_RE = re.compile(r'^\s*([A-Za-z_][\w-]*)((?:\s+"[^"]*"|\s+[A-Za-z_][\w-]*)*)\s*\{\s*$')
ATTR_RE = re.compile(r'^\s*"?([A-Za-z_][\w-]*)"?\s*=\s*(.*)$')


def parse_hcl(text: str) -> Block:
    raw_lines = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), text, flags=re.S).splitlines()
    lines = [_strip_hcl_comment(raw) for raw in raw_lines]
    root = Block("root", [], 0)
    stack = [root]
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        m = BLOCK_RE.match(line)
        if m and "=" not in line.split("{")[0]:
            labels = [l.strip('"') for l in re.findall(r'"[^"]*"|[A-Za-z_][\w-]*', m.group(2))]
            blk = Block(m.group(1), labels, i + 1)
            stack[-1].blocks.append(blk)
            stack.append(blk)
            i += 1
            continue
        if stripped == "}" and len(stack) > 1:
            stack.pop()
            i += 1
            continue
        a = ATTR_RE.match(line)
        if a:
            name, value, start = a.group(1), a.group(2).strip(), i + 1
            here = re.match(r"^<<-?\s*([A-Za-z_]\w*)\s*$", value)
            if here:
                tag, body = here.group(1), []
                i += 1
                while i < len(lines) and lines[i].strip() != tag:
                    body.append(raw_lines[i])
                    i += 1
                value = "\n".join(body)
            else:
                while _depth(value) > 0 and i + 1 < len(lines):
                    i += 1
                    value += "\n" + lines[i]
            stack[-1].attrs[name] = (value, start)
        i += 1
    return root


def _s(v: Optional[str]) -> str:
    return (v or "").strip().strip('"')


def _int(v: Optional[str]) -> Optional[int]:
    m = re.match(r"^\s*\"?(-?\d+)", v or "")
    return int(m.group(1)) if m else None


def _open_world(*values: Optional[str]) -> bool:
    return any(v and ('"0.0.0.0/0"' in v or '"::/0"' in v) for v in values)


ADMIN_PORTS = {22: "SSH", 3389: "RDP", 23: "Telnet", 5900: "VNC", 2375: "Docker API", 2376: "Docker API (TLS)"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB",
              6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB"}


def _ingress_findings(proto: str, from_p: Optional[int], to_p: Optional[int], loc: str, name: str) -> List[Dict[str, str]]:
    proto = _s(proto).lower()
    if proto in ("-1", "all") or (from_p is not None and to_p is not None and from_p <= 0 and to_p >= 65535):
        return [finding("IAC-111", "critical", f"{name}: every port open to the internet",
                        "Ingress from 0.0.0.0/0 (or ::/0) on all ports and protocols exposes every service on the attached hosts.",
                        "Allow only the ports the service needs, and only from known CIDRs or other security groups.", loc)]
    if from_p is None:
        return []
    to_p = from_p if to_p is None else to_p
    out = []
    admin = [f"{p} ({n})" for p, n in ADMIN_PORTS.items() if from_p <= p <= to_p]
    data = [f"{p} ({n})" for p, n in DATA_PORTS.items() if from_p <= p <= to_p]
    if admin:
        out.append(finding("IAC-110", "high", f"{name}: remote admin port open to the internet",
                           f"Port(s) {', '.join(admin)} reachable from 0.0.0.0/0. These are brute-forced constantly.",
                           "Restrict to a VPN or bastion CIDR, or use SSM Session Manager / EC2 Instance Connect instead of open SSH/RDP.", loc))
    if data:
        out.append(finding("IAC-112", "high", f"{name}: database port open to the internet",
                           f"Port(s) {', '.join(data)} reachable from 0.0.0.0/0.",
                           "Keep data stores in private subnets and allow only the app's security group.", loc))
    return out


def _policy_statements(text: str) -> List[Dict[str, Any]]:
    """Best effort: JSON heredoc/string, else a regex view over jsonencode()."""
    body = text.strip()
    if body.startswith('"') and body.endswith('"'):
        try:
            body = json.loads(body)
        except ValueError:
            pass
    try:
        doc = json.loads(body)
        stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
        stmts = [stmts] if isinstance(stmts, dict) else stmts
        out = []
        for st in stmts:
            if not isinstance(st, dict):
                continue
            acts = st.get("Action", st.get("NotAction", []))
            res = st.get("Resource", st.get("NotResource", []))
            out.append({"effect": str(st.get("Effect", "Allow")), "actions": acts if isinstance(acts, list) else [acts],
                        "not_action": "NotAction" in st, "resources": res if isinstance(res, list) else [res], "offset": 0})
        return out
    except (ValueError, AttributeError):
        pass
    effects = re.findall(r'(?i)"?effect"?\s*[:=]\s*"(\w+)"', text)
    if effects and all(e.lower() == "deny" for e in effects):
        return []
    acts, res, not_action, offset = [], [], False, 0
    for m in re.finditer(r'(?i)"?(not)?action"?\s*[:=]\s*(\[[^\]]*\]|"[^"]*")', text):
        acts += re.findall(r'"([^"]*)"', m.group(2))
        not_action = not_action or bool(m.group(1))
        offset = offset or m.start()
    for m in re.finditer(r'(?i)"?(not)?resource"?\s*[:=]\s*(\[[^\]]*\]|"[^"]*")', text):
        res += re.findall(r'"([^"]*)"', m.group(2))
    return [{"effect": "Allow", "actions": acts, "not_action": not_action, "resources": res, "offset": offset}] if acts else []


def _iam_findings(stmts: List[Dict[str, Any]], loc: str, name: str) -> List[Dict[str, str]]:
    out = []
    for st in stmts:
        if st["effect"].lower() != "allow":
            continue
        acts = [str(a) for a in st["actions"]]
        res = [str(r) for r in st["resources"]]
        if st["not_action"]:
            out.append(finding("IAC-122", "medium", f"{name}: Allow with NotAction",
                               "Allow + NotAction grants every action except the listed ones, including services added later.",
                               "List the allowed actions explicitly.", loc))
        elif "*" in acts or "*:*" in acts:
            full = "*" in res
            out.append(finding("IAC-120", "critical" if full else "high",
                               f"{name}: wildcard Action" + (" on Resource *" if full else ""),
                               "Action \"*\" allows every API call" + (" on every resource, which is full admin." if full else "."),
                               "Grant only the actions the workload calls. Run iam_policy_audit.py on the rendered policy for a full review.", loc))
        elif "*" in res:
            out.append(finding("IAC-121", "low", f"{name}: Resource \"*\"",
                               f"Actions {', '.join(acts[:5])} apply to every resource of that type in the account.",
                               "Scope Resource to ARNs where the service supports it.", loc))
    return out


SECRET_ATTRS = {"password", "master_password", "secret_key", "access_key", "token", "api_key", "client_secret",
                "private_key", "secret", "admin_password"}


def scan_terraform_files(files: List[Tuple[str, str]]) -> List[Dict[str, str]]:
    """files = [(path, text)]. Scanned together so split S3 resources are matched to their bucket."""
    parsed = [(path, parse_hcl(text)) for path, text in files]
    resources: List[Tuple[str, Block]] = []
    for path, root in parsed:
        for b in root.blocks:
            if b.kind in ("resource", "data") and len(b.labels) >= 2:
                resources.append((path, b))
            if b.kind == "provider":
                resources.append((path, b))

    def refs(rtype: str, bucket: str) -> List[Block]:
        return [b for _, b in resources if b.kind == "resource" and b.labels[0] == rtype
                and re.search(rf"aws_s3_bucket\.{re.escape(bucket)}\b", b.attr("bucket") or "")]

    ebs_default = any(b.kind == "resource" and b.labels[0] == "aws_ebs_encryption_by_default"
                      and _s(b.attr("enabled")).lower() != "false" for _, b in resources)
    out: List[Dict[str, str]] = []
    for path, b in resources:
        rtype = b.labels[0] if b.labels else b.kind
        rname = ".".join(b.labels[:2]) if b.kind != "provider" else f"provider.{b.labels[0] if b.labels else ''}"
        loc = f"{path}:{b.line}"

        def aloc(attr: str) -> str:
            return f"{path}:{b.attrs[attr][1]}" if attr in b.attrs else loc

        for attr, (value, line) in b.attrs.items():
            v = value.strip()
            if attr in SECRET_ATTRS and v.startswith('"') and not is_reference(v) and "${" not in v:
                out.append(finding("IAC-140", "high", f"{rname}: hard-coded {attr}",
                                   f"{attr} = \"{mask(v.strip(chr(34)))}\" is stored in the repo and in state in plain text.",
                                   "Use a variable marked sensitive, a secrets manager data source, or manage_master_user_password for RDS.",
                                   f"{path}:{line}"))
        if b.kind == "provider":
            continue

        if b.kind == "resource" and rtype in ("aws_s3_bucket", "aws_s3_bucket_acl"):
            acl = _s(b.attr("acl"))
            if acl in ("public-read", "public-read-write", "authenticated-read"):
                sev = "critical" if acl == "public-read-write" else "high"
                out.append(finding("IAC-101", sev, f"{rname}: public bucket ACL ({acl})",
                                   "Anyone on the internet (or any AWS account for authenticated-read) can list and read objects" +
                                   (", and write them." if acl == "public-read-write" else "."),
                                   "Remove the ACL, set object_ownership = \"BucketOwnerEnforced\" and keep the public access block on.", aloc("acl")))
        if b.kind == "resource" and rtype == "aws_s3_bucket":
            bucket = b.labels[1]
            enc = b.sub("server_side_encryption_configuration") or refs("aws_s3_bucket_server_side_encryption_configuration", bucket)
            if not enc:
                out.append(finding("IAC-102", "low", f"{rname}: no explicit encryption config",
                                   "AWS applies SSE-S3 to new objects by default since January 2023, but nothing here states the intent or uses a customer-managed KMS key.",
                                   "Add aws_s3_bucket_server_side_encryption_configuration (aws:kms with your key for sensitive data).", loc))
            versioned = any("true" in (v.attr("enabled") or "") for v in b.sub("versioning"))
            for v in refs("aws_s3_bucket_versioning", bucket):
                versioned = versioned or any(_s(c.attr("status")) == "Enabled" for c in v.sub("versioning_configuration"))
            if not versioned:
                out.append(finding("IAC-103", "low", f"{rname}: versioning not enabled",
                                   "Overwrites and deletes (accidental or ransomware) cannot be rolled back.",
                                   "Add aws_s3_bucket_versioning with status = \"Enabled\".", loc))
        if b.kind == "resource" and rtype == "aws_s3_bucket_public_access_block":
            off = [k for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
                   if _s(b.attr(k)).lower() == "false"]
            if off:
                out.append(finding("IAC-104", "medium", f"{rname}: public access block partly off",
                                   f"{', '.join(off)} set to false.",
                                   "Set all four settings to true unless the bucket is deliberately public (then document why).", loc))
        if b.kind == "resource" and rtype == "aws_s3_bucket_policy":
            pol = b.attr("policy") or ""
            if re.search(r'(?i)"?principal"?\s*[:=]\s*("\*"|\{\s*"?AWS"?\s*[:=]\s*"\*")', pol) and \
                    re.search(r'(?i)"?effect"?\s*[:=]\s*"allow"', pol):
                cond = re.search(r"(?i)condition", pol)
                out.append(finding("IAC-105", "medium" if cond else "high", f"{rname}: bucket policy allows Principal \"*\"",
                                   "The policy grants access to anyone" + (" (a Condition narrows it, check it)." if cond else " with no Condition."),
                                   "Name the exact principals, or add conditions such as aws:SourceVpce or aws:PrincipalOrgID.", aloc("policy")))

        if b.kind == "resource" and rtype == "aws_security_group":
            for ing in b.sub("ingress"):
                if _open_world(ing.attr("cidr_blocks"), ing.attr("ipv6_cidr_blocks")):
                    out += _ingress_findings(ing.attr("protocol") or "", _int(ing.attr("from_port")), _int(ing.attr("to_port")),
                                             f"{path}:{ing.line}", rname)
        if b.kind == "resource" and rtype == "aws_security_group_rule" and _s(b.attr("type")) == "ingress":
            if _open_world(b.attr("cidr_blocks"), b.attr("ipv6_cidr_blocks")):
                out += _ingress_findings(b.attr("protocol") or "", _int(b.attr("from_port")), _int(b.attr("to_port")), loc, rname)
        if b.kind == "resource" and rtype == "aws_vpc_security_group_ingress_rule":
            if _s(b.attr("cidr_ipv4")) == "0.0.0.0/0" or _s(b.attr("cidr_ipv6")) == "::/0":
                out += _ingress_findings(b.attr("ip_protocol") or "", _int(b.attr("from_port")), _int(b.attr("to_port")), loc, rname)

        if b.kind == "resource" and rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
            if "policy" in b.attrs:
                out += _iam_findings(_policy_statements(b.attrs["policy"][0]), aloc("policy"), rname)
        if b.kind == "data" and rtype == "aws_iam_policy_document":
            for st in b.sub("statement"):
                acts = re.findall(r'"([^"]*)"', st.attr("actions") or st.attr("not_actions") or "")
                res = re.findall(r'"([^"]*)"', st.attr("resources") or st.attr("not_resources") or "")
                stmt = {"effect": _s(st.attr("effect")) or "Allow", "actions": acts,
                        "not_action": "not_actions" in st.attrs, "resources": res}
                out += _iam_findings([stmt], f"{path}:{st.line}", rname)

        if b.kind == "resource" and rtype in ("aws_db_instance", "aws_rds_cluster_instance"):
            if _s(b.attr("publicly_accessible")).lower() == "true":
                out.append(finding("IAC-130", "high", f"{rname}: database is publicly accessible",
                                   "publicly_accessible = true gives the instance a public DNS name/IP, so only the security group stands between it and the internet.",
                                   "Set publicly_accessible = false and reach it from inside the VPC.", aloc("publicly_accessible")))
        if b.kind == "resource" and rtype == "aws_db_instance" and "replicate_source_db" not in b.attrs:
            if _s(b.attr("storage_encrypted")).lower() != "true":
                out.append(finding("IAC-131", "medium", f"{rname}: storage not encrypted",
                                   "storage_encrypted is not true. Encryption can only be turned on at creation (or via snapshot copy and restore).",
                                   "Set storage_encrypted = true (and kms_key_id for a customer-managed key).", loc))
        if b.kind == "resource":
            out += _tf_compute_findings(b, rtype, rname, loc, aloc, ebs_default)
            out += _tf_logging_findings(b, rtype, rname, loc, aloc)
            out += _tf_other_cloud_findings(b, rtype, rname, path, loc, aloc)
    return out


def _tf_compute_findings(b: Block, rtype: str, rname: str, loc: str, aloc, ebs_default: bool) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if rtype in ("aws_instance", "aws_launch_template", "aws_launch_configuration"):
        meta = b.sub("metadata_options")
        tokens = _s(meta[0].attr("http_tokens")).lower() if meta else ""
        endpoint = _s(meta[0].attr("http_endpoint")).lower() if meta else ""
        if tokens != "required" and endpoint != "disabled":
            out.append(finding("IAC-150", "medium", f"{rname}: IMDSv1 still allowed",
                               "Without http_tokens = \"required\" the instance metadata service answers plain GET requests, so one SSRF bug in the app can read the instance role's credentials.",
                               "Add metadata_options { http_tokens = \"required\"  http_put_response_hop_limit = 1 } (2 for containers on the host).",
                               f"{loc.rsplit(':', 1)[0]}:{meta[0].line}" if meta else loc))
    if not ebs_default:
        if rtype == "aws_ebs_volume" and _s(b.attr("encrypted")).lower() != "true":
            out.append(finding("IAC-151", "low", f"{rname}: EBS volume not encrypted",
                               "encrypted is not true and no aws_ebs_encryption_by_default resource was found in the scanned files.",
                               "Set encrypted = true (kms_key_id for your own key), or turn on aws_ebs_encryption_by_default for the account and region.", loc))
        if rtype in ("aws_instance", "aws_launch_template"):
            for dev in b.sub("root_block_device") + b.sub("ebs_block_device") + \
                    [e for bd in b.sub("block_device_mappings") for e in bd.sub("ebs")]:
                if _s(dev.attr("encrypted")).lower() != "true" and not dev.attr("snapshot_id"):
                    out.append(finding("IAC-151", "low", f"{rname}: {dev.kind} not encrypted",
                                       "encrypted is not true and no aws_ebs_encryption_by_default resource was found in the scanned files.",
                                       "Set encrypted = true on the block device, or turn on EBS encryption by default for the account.",
                                       f"{loc.rsplit(':', 1)[0]}:{dev.line}"))
    if rtype == "aws_eks_cluster":
        for vpc in b.sub("vpc_config"):
            public = _s(vpc.attr("endpoint_public_access")).lower() != "false"
            cidrs = vpc.attr("public_access_cidrs")
            if public and (cidrs is None or _open_world(cidrs) or '"0.0.0.0/0"' in cidrs):
                out.append(finding("IAC-152", "medium", f"{rname}: EKS API endpoint open to the internet",
                                   "endpoint_public_access defaults to true and public_access_cidrs to 0.0.0.0/0, so the Kubernetes API answers anyone; a leaked kubeconfig or an API bug is reachable from everywhere.",
                                   "Set endpoint_private_access = true and endpoint_public_access = false, or limit public_access_cidrs to your office or VPN ranges.",
                                   f"{loc.rsplit(':', 1)[0]}:{vpc.line}"))
    if rtype == "aws_lambda_function_url" and _s(b.attr("authorization_type")).upper() == "NONE":
        out.append(finding("IAC-153", "medium", f"{rname}: Lambda function URL without auth",
                           "authorization_type = \"NONE\" makes the function callable by anyone with the URL. Fine for a public webhook that checks its own signature, risky for anything else.",
                           "Use authorization_type = \"AWS_IAM\", or verify a signature or token inside the function and document why it is public.", aloc("authorization_type")))
    return out


def _tf_logging_findings(b: Block, rtype: str, rname: str, loc: str, aloc) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if rtype == "aws_kms_key":
        spec = _s(b.attr("customer_master_key_spec")) or "SYMMETRIC_DEFAULT"
        if spec == "SYMMETRIC_DEFAULT" and _s(b.attr("enable_key_rotation")).lower() != "true":
            out.append(finding("IAC-160", "low", f"{rname}: KMS key rotation off",
                               "enable_key_rotation defaults to false, so the key material never changes (CIS AWS Foundations asks for rotation on symmetric customer keys).",
                               "Set enable_key_rotation = true (rotation_period_in_days if you need a period other than 365).", loc))
    if rtype == "aws_cloudtrail":
        gaps = []
        if _s(b.attr("enable_log_file_validation")).lower() != "true":
            gaps.append("log file validation off")
        if _s(b.attr("is_multi_region_trail")).lower() != "true":
            gaps.append("single region")
        if _s(b.attr("enable_logging")).lower() == "false":
            gaps.append("logging disabled")
        if gaps:
            out.append(finding("IAC-161", "medium" if "logging disabled" in gaps else "low", f"{rname}: CloudTrail gaps ({', '.join(gaps)})",
                               "Without validation, edited or deleted log files go unnoticed; a single-region trail misses activity in other regions.",
                               "Set enable_log_file_validation = true and is_multi_region_trail = true, and send logs to a bucket in a separate account.", loc))
    return out


INTERNET_PREFIXES = {"*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "::/0"}


def _port_ranges(values: List[str]) -> List[Tuple[Optional[int], Optional[int]]]:
    out: List[Tuple[Optional[int], Optional[int]]] = []
    for v in values:
        v = v.strip()
        if v in ("*", ""):
            out.append((0, 65535))
            continue
        lo, _, hi = v.partition("-")
        if lo.isdigit():
            out.append((int(lo), int(hi) if hi.isdigit() else int(lo)))
    return out


def _tf_other_cloud_findings(b: Block, rtype: str, rname: str, path: str, loc: str, aloc) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if rtype.startswith("google_"):
        for attr in ("member", "members"):
            v = b.attr(attr) or ""
            who = [p for p in ("allUsers", "allAuthenticatedUsers") if f'"{p}"' in v]
            if who:
                out.append(finding("IAC-170", "high", f"{rname}: IAM grant to {', '.join(who)}",
                                   "allUsers is anyone on the internet; allAuthenticatedUsers is anyone with any Google account, which is no real restriction.",
                                   "Grant the role to specific users, groups or service accounts. For public static assets, put a load balancer or CDN in front instead.", aloc(attr)))
    if rtype == "google_compute_firewall" and _s(b.attr("direction")).upper() in ("", "INGRESS"):
        if _open_world(b.attr("source_ranges")):
            for allow in b.sub("allow"):
                proto = _s(allow.attr("protocol")).lower()
                ports = re.findall(r'"([^"]*)"', allow.attr("ports") or "")
                ranges = _port_ranges(ports) if ports else [(0, 65535)]
                for lo, hi in ranges:
                    out += _ingress_findings("-1" if proto == "all" else proto, lo, hi, f"{path}:{allow.line}", rname)
    rules: List[Block] = []
    if rtype == "azurerm_network_security_rule":
        rules = [b]
    elif rtype == "azurerm_network_security_group":
        rules = b.sub("security_rule")
    for r in rules:
        if _s(r.attr("direction")).lower() != "inbound" or _s(r.attr("access")).lower() != "allow":
            continue
        sources = [_s(r.attr("source_address_prefix")).lower()] + \
            [x.lower() for x in re.findall(r'"([^"]*)"', r.attr("source_address_prefixes") or "")]
        if not any(s in INTERNET_PREFIXES for s in sources):
            continue
        ports = [_s(r.attr("destination_port_range"))] if r.attr("destination_port_range") else []
        ports += re.findall(r'"([^"]*)"', r.attr("destination_port_ranges") or "")
        proto = _s(r.attr("protocol")).lower()
        for lo, hi in _port_ranges(ports):
            out += _ingress_findings("-1" if proto == "*" and (lo, hi) == (0, 65535) else proto, lo, hi,
                                     f"{path}:{r.line}", rname)
    if rtype == "azurerm_storage_account":
        gaps = []
        if _s(b.attr("allow_nested_items_to_be_public")).lower() == "true" or _s(b.attr("allow_blob_public_access")).lower() == "true":
            gaps.append("blob containers may be public")
        if _s(b.attr("min_tls_version")).upper() in ("TLS1_0", "TLS1_1"):
            gaps.append(f"min_tls_version {_s(b.attr('min_tls_version'))}")
        if _s(b.attr("https_traffic_only_enabled")).lower() == "false" or _s(b.attr("enable_https_traffic_only")).lower() == "false":
            gaps.append("plain HTTP allowed")
        if gaps:
            out.append(finding("IAC-171", "medium", f"{rname}: storage account weakened ({', '.join(gaps)})",
                               "Each of these widens who can read the data or how it travels.",
                               "Set allow_nested_items_to_be_public = false, min_tls_version = \"TLS1_2\" and keep HTTPS-only traffic on.", loc))
    return out


# --------------------------------------------------------------------------- Kubernetes

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "BPF"}


def _walk(node: Any):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def _image_unpinned(image: str) -> bool:
    if "@sha256:" in image or "$" in image or "{{" in image:
        return False
    tag = image.rsplit("/", 1)[-1].partition(":")[2]
    return not tag or tag == "latest"


def _profile_type(sc: Dict[str, Any], key: str) -> str:
    prof = sc.get(key) if isinstance(sc.get(key), dict) else {}
    return str(prof.get("type", "")).strip()


def _k8s_restricted_findings(c: Dict[str, Any], sc: Dict[str, Any], pod_sc: Dict[str, Any], cname: str, path: str) -> List[Dict[str, str]]:
    """Pod Security Standards: Unconfined profiles (baseline) and restricted-profile gaps."""
    out: List[Dict[str, str]] = []
    cline = f"{path}:{getattr(c, 'line', 0)}"
    seccomp = _profile_type(sc, "seccompProfile") or _profile_type(pod_sc, "seccompProfile")
    apparmor = _profile_type(sc, "appArmorProfile") or _profile_type(pod_sc, "appArmorProfile")
    unconfined = [n for n, v in (("seccompProfile", seccomp), ("appArmorProfile", apparmor)) if v == "Unconfined"]
    if unconfined:
        out.append(finding("IAC-211", "medium", f"{cname}: {' and '.join(unconfined)} set to Unconfined",
                           "Unconfined turns off the syscall or LSM filter the runtime applies by default, so kernel bugs are easier to reach from the container. The Pod Security baseline profile forbids it.",
                           "Use type: RuntimeDefault (or Localhost with a reviewed profile).", cline))
    if ytrue(sc.get("privileged")):
        return out
    gaps = []
    if seccomp not in ("RuntimeDefault", "Localhost") and not unconfined:
        gaps.append("seccompProfile RuntimeDefault")
    caps = sc.get("capabilities") if isinstance(sc.get("capabilities"), dict) else {}
    if "ALL" not in {str(x).upper() for x in (caps.get("drop") or [])}:
        gaps.append("capabilities.drop [ALL]")
    if not ytrue(sc.get("readOnlyRootFilesystem")):
        gaps.append("readOnlyRootFilesystem true")
    if gaps:
        out.append(finding("IAC-212", "low", f"{cname}: below the restricted profile (missing {', '.join(gaps)})",
                           "The Pod Security restricted profile is the target for app workloads. Each missing item removes a layer that makes a code execution bug harder to turn into node access or persistence.",
                           "Add to the container securityContext: seccompProfile {type: RuntimeDefault}, capabilities {drop: [ALL]}, readOnlyRootFilesystem: true (emptyDir for scratch paths).",
                           cline))
    for port in c.get("ports") or []:
        if isinstance(port, dict) and (_int(port.get("hostPort")) or 0) > 0:
            out.append(finding("IAC-213", "low", f"{cname}: hostPort {port.get('hostPort')}",
                               "hostPort binds the port on the node's own IP, bypassing Service and NetworkPolicy design and pinning the pod to nodes where the port is free.",
                               "Expose the port through a Service (ClusterIP, NodePort or LoadBalancer) instead.", f"{path}:{line_of(port, 'hostPort')}"))
    return out


RBAC_DANGEROUS = [
    ({"escalate", "bind", "impersonate"}, None, "can grant itself or act as any identity (escalate, bind, impersonate)"),
    ({"create", "*"}, {"pods/exec", "pods/attach"}, "can run commands inside other pods and take their service account"),
    ({"get", "create", "*"}, {"nodes/proxy"}, "can reach the kubelet API on every node"),
    ({"create", "*"}, {"serviceaccounts/token"}, "can mint tokens for other service accounts"),
    ({"get", "list", "watch", "*"}, {"secrets"}, "can read Secrets, which usually hold credentials and service account tokens"),
]
BROAD_GROUPS = {"system:anonymous": "critical", "system:unauthenticated": "critical", "system:authenticated": "high"}


def scan_rbac_doc(doc: Dict[str, Any], path: str, obj: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    kind = str(doc.get("kind", ""))
    if kind in ("Role", "ClusterRole"):
        for rule in doc.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            verbs = {str(v).lower() for v in (rule.get("verbs") or [])}
            res = {str(r).lower() for r in (rule.get("resources") or [])}
            where = f"{path}:{getattr(rule, 'line', 0)}"
            if "*" in verbs or "*" in res:
                full = "*" in verbs and "*" in res
                out.append(finding("IAC-220", "critical" if full and kind == "ClusterRole" else "high",
                                   f"{obj}: wildcard {'verbs and resources' if full else 'verbs' if '*' in verbs else 'resources'}",
                                   "A * in RBAC also matches subresources and any resource type added later, so the role grows silently." +
                                   (" verbs * on resources * is cluster-admin." if full and kind == "ClusterRole" else ""),
                                   "List the exact resources and verbs the workload calls (kubectl auth can-i --list helps).", where))
                continue
            for need_verbs, need_res, what in RBAC_DANGEROUS:
                if verbs & need_verbs and (need_res is None or res & need_res):
                    sev = "medium" if need_res == {"secrets"} and kind == "Role" else "high"
                    out.append(finding("IAC-221", sev, f"{obj}: privilege-escalating RBAC rule",
                                       f"verbs {sorted(verbs)} on {sorted(res) or ['*']}: the subject {what}.",
                                       "Drop the rule, or scope it with resourceNames and give it only to a break-glass admin role.", where))
                    break
    if kind in ("RoleBinding", "ClusterRoleBinding"):
        for subj in doc.get("subjects") or []:
            if not isinstance(subj, dict):
                continue
            name = str(subj.get("name", ""))
            if name in BROAD_GROUPS:
                role = (doc.get("roleRef") or {}).get("name", "?") if isinstance(doc.get("roleRef"), dict) else "?"
                out.append(finding("IAC-222", BROAD_GROUPS[name], f"{obj}: {role} bound to {name}",
                                   f"{name} covers " + ("every request without credentials." if name != "system:authenticated"
                                                        else "every identity that can log in, including every service account and, on GKE, anyone with a Google account."),
                                   "Bind the role to specific users, groups or service accounts.", f"{path}:{getattr(subj, 'line', 0)}"))
    return out


def scan_k8s_doc(doc: Any, path: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not isinstance(doc, dict):
        return out
    obj = f"{doc.get('kind', 'object')}/{(doc.get('metadata') or {}).get('name', '?') if isinstance(doc.get('metadata'), dict) else '?'}"
    out += scan_rbac_doc(doc, path, obj)
    for spec in _walk(doc):
        if not isinstance(spec.get("containers"), list):
            continue
        def loc(m: Any, key: str) -> str:
            return f"{path}:{line_of(m, key)}"
        for key, fid, sev, what in (("hostNetwork", "IAC-202", "high", "the node's network stack"),
                                    ("hostPID", "IAC-208", "high", "the node's process table"),
                                    ("hostIPC", "IAC-208", "high", "the node's IPC namespace")):
            if ytrue(spec.get(key)):
                out.append(finding(fid, sev, f"{obj}: {key}: true",
                                   f"The pod shares {what}, which breaks the isolation between the pod and the node.",
                                   f"Remove {key} unless this is a node agent that truly needs it (and then isolate it in its own namespace).", loc(spec, key)))
        for vol in spec.get("volumes") or []:
            if isinstance(vol, dict) and "hostPath" in vol:
                hp = vol.get("hostPath")
                hpath = hp.get("path", "") if isinstance(hp, dict) else ""
                sev = "critical" if hpath in ("/", "/etc", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/lib/kubelet") else "high"
                out.append(finding("IAC-203", sev, f"{obj}: hostPath volume {hpath or ''}".rstrip(),
                                   "Mounting a node path lets the pod read or change node files; sensitive paths are a direct route to node takeover.",
                                   "Use emptyDir, a PVC, a ConfigMap or a CSI driver instead of hostPath.", loc(vol, "hostPath")))
        pod_sc = spec.get("securityContext") if isinstance(spec.get("securityContext"), dict) else {}
        pod_non_root = ytrue(pod_sc.get("runAsNonRoot")) or (_int(pod_sc.get("runAsUser")) or 0) > 0
        containers = []
        for k in ("initContainers", "containers", "ephemeralContainers"):
            containers += [c for c in (spec.get(k) or []) if isinstance(c, dict)]
        for c in containers:
            cname = f"{obj} container {c.get('name', '?')}"
            sc = c.get("securityContext") if isinstance(c.get("securityContext"), dict) else {}
            if ytrue(sc.get("privileged")):
                out.append(finding("IAC-201", "critical", f"{cname}: privileged",
                                   "A privileged container has all capabilities and device access; escaping to the node is trivial.",
                                   "Remove privileged: true and add only the specific capability needed.", loc(sc, "privileged")))
            ape = sc.get("allowPrivilegeEscalation")
            if ytrue(ape):
                out.append(finding("IAC-206", "high", f"{cname}: allowPrivilegeEscalation: true",
                                   "setuid binaries inside the container can gain more privileges than the process started with.",
                                   "Set allowPrivilegeEscalation: false.", loc(sc, "allowPrivilegeEscalation")))
            elif ape is None and not ytrue(sc.get("privileged")):
                out.append(finding("IAC-206", "medium", f"{cname}: allowPrivilegeEscalation not set to false",
                                   "The default allows escalation through setuid binaries.",
                                   "Set securityContext.allowPrivilegeEscalation: false.", f"{path}:{getattr(c, 'line', 0)}"))
            uid = _int(sc.get("runAsUser")) if "runAsUser" in sc else _int(pod_sc.get("runAsUser"))
            if uid == 0:
                where = sc if "runAsUser" in sc else pod_sc
                out.append(finding("IAC-204", "high", f"{cname}: runs as root (runAsUser: 0)",
                                   "The process runs as UID 0 inside the container.",
                                   "Run as a non-root UID (e.g. runAsUser: 10001) with runAsNonRoot: true.", loc(where, "runAsUser")))
            elif not (ytrue(sc.get("runAsNonRoot")) or (uid or 0) > 0 or pod_non_root):
                out.append(finding("IAC-204", "medium", f"{cname}: may run as root",
                                   "Neither runAsNonRoot: true nor a non-zero runAsUser is set, so the image's default user (often root) is used.",
                                   "Set runAsNonRoot: true and runAsUser: <non-zero> in the pod or container securityContext.", f"{path}:{getattr(c, 'line', 0)}"))
            caps = sc.get("capabilities") if isinstance(sc.get("capabilities"), dict) else {}
            added = {str(x).upper() for x in (caps.get("add") or [])}
            bad = sorted(added & DANGEROUS_CAPS)
            if bad:
                out.append(finding("IAC-209", "high", f"{cname}: adds capabilities {', '.join(bad)}",
                                   "These capabilities give near-root power over the node or other workloads.",
                                   "Drop ALL and add back only narrow capabilities like NET_BIND_SERVICE.", loc(caps, "add")))
            res = c.get("resources") if isinstance(c.get("resources"), dict) else {}
            limits = res.get("limits") if isinstance(res.get("limits"), dict) else {}
            if "memory" not in limits or "cpu" not in limits:
                missing = [k for k in ("cpu", "memory") if k not in limits]
                out.append(finding("IAC-205", "low", f"{cname}: no {' / '.join(missing)} limit",
                                   "Without limits one pod can starve the node (noisy neighbour or a cheap DoS).",
                                   "Set resources.limits.memory (and cpu, or rely on requests plus a LimitRange).", f"{path}:{getattr(c, 'line', 0)}"))
            out += _k8s_restricted_findings(c, sc, pod_sc, cname, path)
            image = str(c.get("image", ""))
            if image and _image_unpinned(image):
                out.append(finding("IAC-207", "medium", f"{cname}: image {image} not pinned",
                                   "No tag or :latest means the running code can change on any restart.",
                                   "Pin a version tag, ideally a digest (image@sha256:...).", loc(c, "image")))
            for env in c.get("env") or []:
                if isinstance(env, dict) and "value" in env and looks_like_secret(str(env.get("name", "")), str(env.get("value"))):
                    out.append(finding("IAC-210", "high", f"{cname}: secret in plain env value ({env.get('name')})",
                                       f"{env.get('name')}={mask(env.get('value'))} (masked). Anyone who can read the manifest or the pod spec sees it.",
                                       "Use valueFrom.secretKeyRef (with encryption at rest for Secrets) or an external secrets operator.", loc(env, "value")))
    return out


# --------------------------------------------------------------------------- docker-compose

def scan_compose_doc(doc: Any, path: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return out
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        label = f"service {name}"
        loc = lambda key: f"{path}:{line_of(svc, key)}"
        if ytrue(svc.get("privileged")):
            out.append(finding("IAC-301", "critical", f"{label}: privileged: true",
                               "The container gets all capabilities and host devices.",
                               "Remove privileged and use cap_add for the one capability needed.", loc("privileged")))
        for key in ("network_mode", "pid", "ipc"):
            if str(svc.get(key, "")).strip() == "host":
                out.append(finding("IAC-302", "high", f"{label}: {key}: host",
                                   f"The container shares the host's {key.replace('_mode', '')} namespace.",
                                   f"Remove {key}: host and publish only the ports you need.", loc(key)))
        for vol in svc.get("volumes") or []:
            src = vol.get("source", "") if isinstance(vol, dict) else str(vol).split(":")[0]
            if "docker.sock" in str(src):
                out.append(finding("IAC-303", "critical", f"{label}: Docker socket mounted",
                                   "Access to /var/run/docker.sock is root on the host (start a privileged container, mount /).",
                                   "Do not mount the socket. If a tool needs it, put a filtering socket proxy in front, read-only.", loc("volumes")))
            elif str(src).strip() in ("/", "/etc", "/root"):
                out.append(finding("IAC-303", "high", f"{label}: host path {src} mounted",
                                   "The container can read (and maybe change) sensitive host files.",
                                   "Mount only the specific directory needed, read-only (:ro).", loc("volumes")))
        caps = {str(c).upper() for c in (svc.get("cap_add") or [])} & DANGEROUS_CAPS
        if caps:
            out.append(finding("IAC-305", "high", f"{label}: cap_add {', '.join(sorted(caps))}",
                               "Broad capabilities give near-root power over the host.",
                               "Drop them, or keep only narrow ones like NET_BIND_SERVICE.", loc("cap_add")))
        env = svc.get("environment")
        pairs: List[Tuple[str, str, int]] = []
        if isinstance(env, dict):
            pairs = [(k, str(v), env.key_lines.get(k, 0) if isinstance(env, YMap) else 0) for k, v in env.items()]
        elif isinstance(env, list):
            pairs = [(str(e).partition("=")[0], str(e).partition("=")[2], getattr(e, "line", 0)) for e in env]
        for k, v, ln in pairs:
            if v and looks_like_secret(k, v):
                out.append(finding("IAC-304", "high", f"{label}: secret in environment ({k})",
                                   f"{k}={mask(v)} is committed in the compose file.",
                                   "Use an untracked .env file with ${VAR} references, or compose secrets:.", f"{path}:{ln}"))
        for port in svc.get("ports") or []:
            spec = str(port.get("published", "")) + ":" + str(port.get("target", "")) if isinstance(port, dict) else str(port)
            if isinstance(port, dict) and port.get("host_ip"):
                spec = str(port.get("host_ip")) + ":" + spec
            parts = spec.split("/")[0].split(":")
            if len(parts) < 2:
                continue  # container-only port, not published
            host_ip = parts[0] if len(parts) >= 3 else ""
            target = _int(parts[-1])
            if host_ip in ("", "0.0.0.0", "::", "[::]") and target in DATA_PORTS:
                out.append(finding("IAC-307", "medium", f"{label}: {DATA_PORTS[target]} port published on all interfaces",
                                   f"\"{spec}\" binds every host interface, and Docker's iptables rules bypass host firewalls such as ufw, so the data store is reachable from the network.",
                                   f"Drop the ports entry (services reach it on the compose network) or bind it locally: \"127.0.0.1:{parts[-2]}:{parts[-1]}\".",
                                   f"{path}:{getattr(port, 'line', 0) or line_of(svc, 'ports')}"))
        image = str(svc.get("image", ""))
        if image and _image_unpinned(image):
            out.append(finding("IAC-306", "low", f"{label}: image {image} not pinned",
                               "No tag or :latest means each pull can bring different code.",
                               "Pin a version tag or digest.", loc("image")))
    return out


# --------------------------------------------------------------------------- discovery

def detect_type(path: str, text: str) -> Optional[str]:
    base = os.path.basename(path).lower()
    if base in ("dockerfile", "containerfile") or base.startswith("dockerfile.") or base.endswith(".dockerfile"):
        return "dockerfile"
    if base.endswith(".tf"):
        return "terraform"
    if base.endswith((".yml", ".yaml", ".json")):
        if re.match(r"^(docker-)?compose([.-].*)?\.ya?ml$", base):
            return "compose"
        if re.search(r"^\s*\"?apiVersion\"?\s*:", text, re.M) and re.search(r"^\s*\"?kind\"?\s*:", text, re.M):
            return "kubernetes"
        if re.search(r"^services\s*:", text, re.M):
            return "compose"
    return None


def collect(paths: List[str]) -> List[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                files += [os.path.join(root, n) for n in sorted(names)]
        else:
            files.append(p)
    return files


def scan_paths(paths: List[str], forced_type: Optional[str] = None, stdin_text: Optional[str] = None) -> Tuple[List[Dict[str, str]], List[str]]:
    findings: List[Dict[str, str]] = []
    scanned: List[str] = []
    tf_files: List[Tuple[str, str]] = []
    sources: List[Tuple[str, str]] = []
    for path in collect(paths):
        if path == "-":
            sources.append(("<stdin>", stdin_text or ""))
            continue
        if os.path.getsize(path) > MAX_BYTES:
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            sources.append((path, fh.read()))
    for path, text in sources:
        kind = forced_type or detect_type(path, text)
        if kind is None:
            continue
        scanned.append(path)
        if kind == "dockerfile":
            findings += scan_dockerfile(text, path)
        elif kind == "terraform":
            tf_files.append((path, text))
        else:
            for doc in load_yaml_docs(text):
                findings += scan_compose_doc(doc, path) if kind == "compose" else scan_k8s_doc(doc, path)
    if tf_files:
        findings += scan_terraform_files(tf_files)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("location", ""), f["id"]))
    return findings, scanned


def render_text(findings: List[Dict[str, str]], scanned: List[str]) -> str:
    counts = {s: sum(f["severity"] == s for f in findings) for s in reversed(SEVERITY_ORDER)}
    lines = [f"IaC scan: {len(scanned)} file(s), {len(findings)} finding(s) "
             f"({', '.join(f'{v} {k}' for k, v in counts.items() if v) or 'clean'})", ""]
    if not scanned:
        lines.append("No Dockerfile, Terraform, Kubernetes or compose files found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           at {f.get('location', '?')}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan Dockerfiles, Terraform, Kubernetes and compose files for misconfigurations.")
    ap.add_argument("paths", nargs="+", help="files or directories to scan; '-' reads stdin (needs --type)")
    ap.add_argument("--type", choices=["dockerfile", "terraform", "kubernetes", "compose"], help="force the file type")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    if "-" in args.paths and not args.type:
        print("error: reading stdin needs --type", file=sys.stderr)
        return 2
    for p in args.paths:
        if p != "-" and not os.path.exists(p):
            print(f"error: no such file or directory: {p}", file=sys.stderr)
            return 2
    try:
        stdin_text = sys.stdin.read() if "-" in args.paths else None
        findings, scanned = scan_paths(args.paths, args.type, stdin_text)
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
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
