#!/usr/bin/env python3
"""Audit AI coding agent configs: Claude Code settings and MCP server configs.

Reads .claude/settings.json, .claude/settings.local.json, .mcp.json,
.cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json or any JSON
file with a "permissions", "hooks", "mcpServers" or "servers" block.
Offline and read-only. Secrets in the output are masked.

Usage:
  agent_config_audit.py .                         # finds the config files in a project
  agent_config_audit.py .claude/settings.json .mcp.json --json
  agent_config_audit.py ~/Library/Application\\ Support/Claude/claude_desktop_config.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

DISCOVER = [".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".cursor/mcp.json",
            ".vscode/mcp.json", "claude_desktop_config.json", ".gemini/settings.json"]

# Commands that turn a Bash allow rule into "run anything" or "send anything anywhere".
BROAD_HIGH = {"curl", "wget", "nc", "ncat", "netcat", "sh", "bash", "zsh", "fish", "python", "python3", "node",
              "deno", "bun", "perl", "ruby", "php", "ssh", "scp", "rsync", "sudo", "su", "eval", "exec", "env",
              "xargs", "osascript", "powershell", "pwsh", "find", "awk", "chmod", "chown", "dd"}
BROAD_MEDIUM = {"npx", "bunx", "uvx", "pnpx", "rm", "docker", "kubectl", "terraform", "aws", "gcloud", "az",
                "gh", "git", "npm", "pnpm", "yarn", "pip", "pip3", "make", "open", "mv", "cp"}

SECRET_KEY = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|BEARER|COOKIE|SESSION)", re.I)
SECRET_VALUE = re.compile(r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
                          r"xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{16,}|"
                          r"npm_[A-Za-z0-9]{30,}|sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,})")
PLACEHOLDER = re.compile(r"^\s*$|^\$\{?[A-Za-z_][A-Za-z0-9_:-]*\}?$|^\$\{(?:env|input):[^}]+\}$|^<[^>]*>$|^(?:your|my|replace|change|insert|todo|xxx|example|placeholder)[\w-]*$|^\*+$|^x+$",
                         re.I)
NETWORK_HOOK = re.compile(r"\b(curl|wget|nc|ncat|Invoke-WebRequest|iwr)\b|https?://", re.I)
PIPE_SHELL = re.compile(r"\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(ba|z)?sh\s+<\(\s*(curl|wget)|\beval\s+\"?\$\((curl|wget)", re.I)
RUNNERS = {"npx": "npm", "bunx": "npm", "pnpx": "npm", "uvx": "pypi"}


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: str = "") -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def mask(value: str) -> str:
    """First 4 chars + '...'; an auth scheme like 'Bearer ' is kept and the credential after it masked."""
    m = re.match(r"^(Bearer|Basic|Token|token)\s+(.+)$", value)
    if m:
        return f"{m.group(1)} {mask(m.group(2))}"
    return value[:4] + "..." if len(value) > 4 else "..."


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside strings (VS Code style JSON)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            nl = text.count("\n", i, end if end >= 0 else n)
            out.append("\n" * nl)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


class Locator:
    """Approximate line numbers by searching the raw text for a quoted key or value."""

    def __init__(self, text: str):
        self.lines = text.split("\n")

    def line(self, *needles: str, after: int = 0) -> int:
        for needle in needles:
            if not needle:
                continue
            q = json.dumps(needle)[1:-1]
            for i in range(max(after - 1, 0), len(self.lines)):
                if f'"{q}"' in self.lines[i]:
                    return i + 1
        return after or 1


def is_secret(key: str, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    if SECRET_VALUE.search(v):
        return True
    if not SECRET_KEY.search(key) or PLACEHOLDER.match(v) or "${" in v:
        return False
    if re.match(r"^(?:Bearer|Basic|token)\s+(\$\{?[\w:]+\}?|<[^>]*>)$", v, re.I):
        return False
    return len(v) >= 12 and not v.lower().startswith(("http://", "https://", "/", "./", "~"))


def secret_in(value: str) -> Optional[str]:
    m = SECRET_VALUE.search(value)
    if m:
        return m.group(0)
    m = re.search(r"(?:--?(?:api[-_]?key|token|password|secret|auth)[= ]|[?&](?:api_?key|token|key|access_token|secret)=)([^\s&\"']{12,})",
                  value, re.I)
    if m and not PLACEHOLDER.match(m.group(1)) and "${" not in m.group(1):
        return m.group(1)
    return None


# --------------------------------------------------------------------------- Claude settings

def bash_rule_command(rule: str) -> Optional[str]:
    """'Bash(curl:*)' -> 'curl'; 'Bash' / 'Bash(*)' -> '*'; non-Bash rules -> None."""
    m = re.match(r"^\s*Bash\s*(?:\((.*)\))?\s*$", rule)
    if not m:
        return None
    inner = (m.group(1) or "").strip()
    if inner in ("", "*", ":*"):
        return "*"
    return inner


def audit_settings(data: Dict[str, Any], path: str, loc: Locator) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    allow = [str(r) for r in perms.get("allow") or [] if isinstance(r, str)]
    deny = [str(r) for r in perms.get("deny") or [] if isinstance(r, str)]

    if perms.get("defaultMode") == "bypassPermissions":
        out.append(finding("AGT-001", "critical", "defaultMode is bypassPermissions",
                           "Every tool call runs without asking, including shell commands, file writes and network calls. One prompt injection in a README, issue or web page is enough to run anything as you.",
                           'Use "default" or "acceptEdits", and allow specific commands instead. Keep bypass mode for throwaway containers or VMs with no secrets and no network you care about.',
                           f"{path}:{loc.line('defaultMode')}"))

    for rule in allow:
        cmd = bash_rule_command(rule)
        if cmd is None:
            if rule.strip() in ("WebFetch", "WebFetch(*)"):
                out.append(finding("AGT-002", "medium", f"Broad allow rule: {rule}",
                                   "The agent can fetch any URL without asking, which is both a way in for injected content and a way out for data.",
                                   'Allow per domain instead, e.g. "WebFetch(domain:docs.example.test)".',
                                   f"{path}:{loc.line(rule)}"))
            continue
        if cmd == "*":
            out.append(finding("AGT-002", "critical", f"All shell commands allowed: {rule}",
                               "Any command the model decides to run executes without a prompt.",
                               'Remove it and allow the few commands you need, e.g. "Bash(npm run test:*)", "Bash(git diff:*)".',
                               f"{path}:{loc.line(rule)}"))
            continue
        first = re.split(r"[\s:]", cmd, maxsplit=1)[0].lower()
        prefix = re.sub(r"(:\*|\s\*|\*)$", "", cmd).strip()
        wild = prefix.lower() == first and cmd.strip() != prefix  # "curl:*" or "curl *", not "npm run test:*"
        if first in BROAD_HIGH and wild:
            out.append(finding("AGT-002", "high", f"Broad shell allow rule: {rule}",
                               f"'{first}' with any arguments can run arbitrary code or send data anywhere, so this rule is close to allowing every command.",
                               f"Allow exact invocations (e.g. a specific script) or move '{rule}' to \"ask\".",
                               f"{path}:{loc.line(rule)}"))
        elif first in BROAD_MEDIUM and wild:
            out.append(finding("AGT-002", "medium", f"Wide shell allow rule: {rule}",
                               f"'{first}' with any arguments covers destructive or code-fetching subcommands (installs, deletes, deploys, pushes).",
                               f"Narrow it to the subcommands you use, e.g. \"Bash({first} <subcommand>:*)\".",
                               f"{path}:{loc.line(rule)}"))

    is_claude_settings = os.path.basename(path).startswith("settings") or "permissions" in data
    if is_claude_settings and not any(".env" in r for r in deny):
        out.append(finding("AGT-010", "medium", "No deny rule for .env files",
                           "Nothing stops the agent from reading local secrets, and anything it reads can end up in a prompt, a log or a tool call.",
                           'Add to permissions.deny: "Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)" (and any key or credential paths you keep in the repo).',
                           f"{path}:{loc.line('permissions') if perms else 1}"))

    for d in perms.get("additionalDirectories") or []:
        ds = str(d).strip().rstrip("/") or "/"
        if ds in ("/", "~", "$HOME", "${HOME}", "/Users", "/home", "/root") or re.match(r"^(/Users|/home)/[^/]+$", ds):
            out.append(finding("AGT-011", "high", f"additionalDirectories includes {d}",
                               "The agent gets file access to your whole home or the whole disk: SSH keys, cloud credentials, browser profiles.",
                               "List only the project folders the agent needs.", f"{path}:{loc.line(str(d))}"))

    if data.get("enableAllProjectMcpServers") is True:
        out.append(finding("AGT-012", "medium", "enableAllProjectMcpServers is on",
                           "Every MCP server listed in a repo's .mcp.json starts without a review, so cloning a hostile repo can launch its servers.",
                           "Turn it off and approve servers by name with enabledMcpjsonServers.",
                           f"{path}:{loc.line('enableAllProjectMcpServers')}"))

    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            for h in (group.get("hooks") if isinstance(group, dict) else None) or []:
                cmd = str(h.get("command", "")) if isinstance(h, dict) else ""
                if not cmd:
                    continue
                if PIPE_SHELL.search(cmd):
                    sev, why = "high", "downloads a script and runs it, so whoever controls that URL runs code on every matching event"
                elif NETWORK_HOOK.search(cmd):
                    sev, why = "medium", "makes a network call; hook input includes tool arguments and file paths, which can carry secrets out"
                else:
                    continue
                s = secret_in(cmd)
                shown = cmd.replace(s, mask(s)) if s else cmd
                out.append(finding("AGT-020", sev, f"{event} hook {why.split(',')[0]}",
                                   f"Hook command '{shown[:160]}' {why}. Hooks run automatically with your user's permissions.",
                                   "Run a local, reviewed script instead; if it must send data, send only fields you chose to a host you control.",
                                   f"{path}:{loc.line(cmd)}"))
                if s:
                    out.append(finding("AGT-030", "high", "Secret inline in a hook command",
                                       f"Value {mask(s)} is stored in plain text in the config.",
                                       "Read it from the environment or a keychain at run time and rotate the exposed value.",
                                       f"{path}:{loc.line(cmd)}"))

    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    for k, v in env.items():
        if is_secret(k, v):
            out.append(finding("AGT-030", "high", f"Secret inline in settings env: {k}",
                               f"Value {mask(str(v))} is stored in plain text; settings files get committed, synced and shared.",
                               "Move it to your shell environment, a keychain or a git-ignored file, and rotate the exposed value.",
                               f"{path}:{loc.line(k)}"))
    return out


# --------------------------------------------------------------------------- MCP servers

def runner_package(args: List[str]) -> Optional[str]:
    """First non-flag argument after npx/bunx/uvx (skipping values of -p/--package/--from)."""
    skip_next = False
    for a in args:
        if skip_next:
            return a
        if a in ("-p", "--package", "--from"):
            skip_next = True
            continue
        if a.startswith("--package=") or a.startswith("--from="):
            return a.split("=", 1)[1]
        if a.startswith("-"):
            continue
        return a
    return None


def pinned(pkg: str, eco: str) -> bool:
    if eco == "pypi":
        return bool(re.search(r"==\s*[\w.]+$", pkg)) or bool(re.search(r"@\s*\d[\w.]*$", pkg))
    name, _, version = pkg.rpartition("@") if pkg.count("@") > (1 if pkg.startswith("@") else 0) else (pkg, "", "")
    return bool(version) and bool(re.match(r"^\d", version))


def _host_is_local(host: str) -> bool:
    if host in ("localhost", "") or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def audit_mcp(servers: Dict[str, Any], path: str, loc: Locator) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        at = loc.line(name)
        where = f"{path}:{at}"
        command = str(cfg.get("command", ""))
        args = [str(a) for a in cfg.get("args") or [] if isinstance(a, (str, int, float))]
        if isinstance(cfg.get("command"), str) and " " in command and not args:
            parts = command.split()
            command, args = parts[0], parts[1:]
        base = os.path.basename(command).lower()
        if base.endswith(".cmd") or base.endswith(".exe"):
            base = base.rsplit(".", 1)[0]
        if base in ("cmd",) and args[:1] == ["/c"] and len(args) > 1:
            base, args = os.path.basename(args[1]).lower(), args[2:]

        runner, run_args = None, args
        if base in RUNNERS:
            runner = base
        elif base in ("pnpm", "yarn") and args[:1] == ["dlx"]:
            runner, run_args = base + " dlx", args[1:]
        if runner:
            eco = "pypi" if runner == "uvx" else "npm"
            pkg = runner_package(run_args)
            if pkg and not pkg.startswith((".", "/", "~", "file:", "git+", "http")) and not pinned(pkg, eco):
                auto = " with -y, so a new release installs and runs without any prompt" if any(a in ("-y", "--yes") for a in run_args) else ""
                pin = f"{pkg}==<version>" if eco == "pypi" else f"{pkg.rsplit('@', 1)[0] if pkg.count('@') > (1 if pkg.startswith('@') else 0) else pkg}@<version>"
                out.append(finding("AGT-040", "medium", f"MCP server '{name}' runs an unpinned package: {pkg}",
                                   f"{runner} fetches the latest '{pkg}' at start{auto}. A hijacked or typosquatted release runs with your user's access and the server's tokens.",
                                   f"Pin an exact version ({pin}) or install it once and point the config at the local binary.",
                                   where))

        if base == "docker" or base == "podman":
            joined = " ".join(args)
            bad = []
            if "--privileged" in args:
                bad.append("--privileged")
            if "docker.sock" in joined:
                bad.append("the Docker socket")
            if re.search(r"(?:-v|--volume)[ =]/:|(?:source|src)=/(?:,|$)", joined):
                bad.append("the host root mounted")
            if bad:
                out.append(finding("AGT-043", "high", f"MCP server '{name}' container escapes isolation",
                                   f"It runs with {', '.join(bad)}, which gives it control of the host.",
                                   "Drop --privileged, mount only the folders it needs (read-only where possible) and never the Docker socket.",
                                   where))

        url = str(cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl") or "")
        if url:
            u = urlparse(url)
            if u.scheme == "http" and not _host_is_local(u.hostname or ""):
                out.append(finding("AGT-041", "high", f"MCP server '{name}' uses plain http to {u.hostname}",
                                   "Requests, tool results and any auth header travel unencrypted and can be read or changed on the network.",
                                   "Use https, or a loopback address for local servers.", f"{path}:{loc.line(url, after=at)}"))
            s = secret_in(url)
            if s:
                out.append(finding("AGT-030", "high", f"MCP server '{name}': secret in the URL",
                                   f"Value {mask(s)} sits in the URL, which ends up in logs and process lists.",
                                   "Send it in a header read from the environment, and rotate it.", f"{path}:{loc.line(url, after=at)}"))

        for block in ("env", "headers"):
            values = cfg.get(block) if isinstance(cfg.get(block), dict) else {}
            for k, v in values.items():
                if is_secret(k, v):
                    out.append(finding("AGT-030", "high", f"MCP server '{name}': secret inline in {block}.{k}",
                                       f"Value {mask(str(v))} is stored in plain text. MCP configs like .mcp.json are meant to be committed.",
                                       ('Reference the environment instead ("${' + re.sub(r"\W", "_", str(k)).upper() + '}" in .mcp.json, an input in VS Code)'
                                        if block == "env" else
                                        'Reference the environment instead (e.g. "Bearer ${API_TOKEN}" in .mcp.json, an input in VS Code)') +
                                       " and rotate the exposed value.",
                                       f"{path}:{loc.line(k, after=at)}"))
        for a in args:
            s = secret_in(a)
            if s:
                out.append(finding("AGT-030", "high", f"MCP server '{name}': secret in command arguments",
                                   f"Value {mask(s)} is in args, so it is in the config file and visible in process lists.",
                                   "Pass it through env from your shell or a keychain, and rotate it.", f"{path}:{loc.line(a, after=at)}"))
    return out


# --------------------------------------------------------------------------- driver

def mcp_servers(data: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("mcpServers", "servers", "context_servers"):
        block = data.get(key)
        if isinstance(block, dict) and all(isinstance(v, dict) for v in block.values()):
            return block
    return {}


def audit_text(text: str, path: str) -> List[Dict[str, str]]:
    data = json.loads(strip_jsonc(text))
    if not isinstance(data, dict):
        raise ValueError("top level is not a JSON object")
    loc = Locator(text)
    out: List[Dict[str, str]] = []
    if any(k in data for k in ("permissions", "hooks", "enableAllProjectMcpServers", "env")) or \
            os.path.basename(path) in ("settings.json", "settings.local.json"):
        out += audit_settings(data, path, loc)
    out += audit_mcp(mcp_servers(data), path, loc)
    return out


def collect(paths: List[str]) -> List[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for rel in DISCOVER:
                full = os.path.join(p, rel)
                if os.path.isfile(full):
                    files.append(full)
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise FileNotFoundError(p)
    return files


def audit_paths(paths: List[str]) -> Tuple[List[Dict[str, str]], List[str]]:
    files = collect(paths)
    findings: List[Dict[str, str]] = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        try:
            findings += audit_text(text, path)
        except ValueError as err:  # json.JSONDecodeError is a ValueError
            raise ValueError(f"{path}: {err}") from None
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("location", "")))
    return findings, files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Audit Claude Code settings and MCP configs (offline, read-only).")
    ap.add_argument("paths", nargs="+", help="project dirs or config files (settings.json, .mcp.json, mcp.json ...)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    try:
        findings, files = audit_paths(args.paths)
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if not files:
        print("error: no agent config files found (looked for " + ", ".join(DISCOVER) + ")", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"files": files, "count": len(findings), "findings": findings}, indent=2))
    else:
        print(f"Agent config audit: {len(files)} file(s), {len(findings)} finding(s)\n")
        if not findings:
            print("No issues found.")
        for f in findings:
            print(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}\n           at {f.get('location', '?')}\n"
                  f"           {f['detail']}\n           fix: {f['fix']}")
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
