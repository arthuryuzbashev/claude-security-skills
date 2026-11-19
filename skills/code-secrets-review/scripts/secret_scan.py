#!/usr/bin/env python3
"""Find leaked secrets in a source tree: cloud and AI provider keys, tokens, private keys, passwords,
.env files and credential files (SSH keys, .netrc, Terraform state).

Walks a directory (skips .git, node_modules, virtualenvs, binaries and big files),
applies provider-specific patterns plus an entropy check on secret-looking
assignments, and prints every match masked to its first 4 characters.

Suppress a line with an inline `secskills:ignore` comment. Suppress paths or rules
with a `.secskills-ignore` file at the scan root:
  tests/fixtures/*          ignore every rule under that path
  SEC-008:docs/*            ignore one rule under that path

Usage:
  secret_scan.py .
  secret_scan.py src/ --json --fail-on medium
  secret_scan.py config/settings.py --entropy 4.0
  git diff --cached | secret_scan.py --stdin
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
             ".pytest_cache", "dist", "build", ".next", ".nuxt", "vendor", "bower_components", ".terraform", "target"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z",
            ".jar", ".war", ".class", ".so", ".dylib", ".dll", ".exe", ".bin", ".woff", ".woff2", ".ttf", ".otf",
            ".mp3", ".mp4", ".mov", ".lock", ".min.js", ".map", ".pyc", ".sqlite", ".db"}
IGNORE_FILE = ".secskills-ignore"
INLINE_IGNORE = "secskills:ignore"
PLACEHOLDER = re.compile(r"(?i)(example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|\*\*\*\*|<[^>]+>|"
                         r"\$\{|\{\{|%\(|process\.env|os\.environ|getenv|redacted|todo|fixme|test(ing)?_?(key|secret|token)?$|"
                         r"^(password|secret|token|none|null|true|false)$)")

# id, severity, title, regex, group holding the secret (0 = whole match), fix
RULES: List[Tuple[str, str, str, "re.Pattern[str]", int, str]] = [
    ("SEC-001", "high", "AWS access key id", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), 1,
     "Deactivate the key in IAM, check CloudTrail for its use, move to roles or a secrets manager."),
    ("SEC-002", "critical", "AWS secret access key",
     re.compile(r"(?i)aws.{0,20}?(?:secret|private)?.{0,10}?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1,
     "Rotate the key pair now, review CloudTrail, and load credentials from the environment or a role."),
    ("SEC-003", "critical", "GitHub token",
     re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"), 1,
     "Revoke it in GitHub settings (or the org's token list) and check the audit log."),
    ("SEC-004", "high", "Slack token", re.compile(r"\b(xox[baprse]-[A-Za-z0-9-]{10,}|xapp-\d-[A-Za-z0-9]+-\d+-[A-Za-z0-9]+)\b"), 1,
     "Revoke the token in the Slack app settings and reissue."),
    ("SEC-005", "medium", "Slack incoming webhook",
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"), 1,
     "Regenerate the webhook URL; anyone with it can post to the channel."),
    ("SEC-006", "critical", "Stripe live secret key", re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"), 1,
     "Roll the key in the Stripe dashboard and check recent API activity."),
    ("SEC-007", "low", "Stripe test secret key", re.compile(r"\b((?:sk|rk)_test_[0-9a-zA-Z]{24,})\b"), 1,
     "Test keys cannot move money but expose test data; roll it and keep it out of the repo."),
    ("SEC-008", "high", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 1,
     "Restrict or regenerate the key in Google Cloud console (API and referrer/IP restrictions)."),
    ("SEC-009", "critical", "Private key block",
     re.compile(r"(-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----)"), 1,
     "Treat the key as compromised: replace it everywhere it is trusted, then remove it from history."),
    ("SEC-010", "high", "Password in connection URL",
     re.compile(r"\b([a-z][a-z0-9+.-]{1,20}://[^\s:/@'\"]{1,64}:([^\s@/'\"]{3,128})@[^\s'\"]+)", re.I), 2,
     "Rotate the database/service password and read the URL from the environment."),
    ("SEC-011", "high", "SendGrid API key", re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"), 1,
     "Delete the key in SendGrid and create a new one with minimal scopes."),
    ("SEC-012", "high", "npm access token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), 1,
     "Revoke it with `npm token revoke` or on npmjs.com, and use CI secrets instead."),
    # Shapes below follow the gitleaks default config (github.com/gitleaks/gitleaks, config/gitleaks.toml).
    ("SEC-013", "critical", "Anthropic API key",
     re.compile(r"\b(sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA)(?![A-Za-z0-9_-])"), 1,
     "Delete the key in the Anthropic Console (API keys page), create a new one and check usage for the exposure window."),
    ("SEC-014", "critical", "OpenAI API key",
     re.compile(r"\b(sk-(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})"), 1,
     "Revoke the key on the OpenAI API keys page (project or admin keys), then review usage."),
    ("SEC-015", "high", "GitLab token",
     re.compile(r"\b(gl(?:pat|dt|rt|ptt|soat)-[A-Za-z0-9_.-]{20,})"), 1,
     "Revoke it under the user's or project's Access tokens page in GitLab and check the audit events."),
    ("SEC-016", "high", "Hugging Face token", re.compile(r"\b(hf_[A-Za-z]{34})\b"), 1,
     "Invalidate the token in Hugging Face settings (Access Tokens) and create a fine-grained one."),
    ("SEC-017", "high", "Shopify access token", re.compile(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"), 1,
     "Rotate the app's credentials in the Shopify admin or Partner dashboard."),
    ("SEC-018", "high", "DigitalOcean token", re.compile(r"\b(do[opr]_v1_[a-f0-9]{64})\b"), 1,
     "Delete the token under API, Tokens in the DigitalOcean control panel."),
    ("SEC-019", "high", "Databricks token", re.compile(r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b"), 1,
     "Revoke it in the workspace (User settings, Developer, Access tokens) or with the Token API."),
    ("SEC-040", "high", "PyPI upload token", re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})"), 1,
     "Remove the token in PyPI account settings, check recent releases, and switch to trusted publishing."),
    ("SEC-041", "high", "Azure AD client secret",
     re.compile(r"(?:^|['\"`\s>=:(,])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|['\"`\s<),])"), 1,
     "Delete the secret under the app registration's Certificates and secrets, then prefer certificates or workload identity."),
    ("SEC-042", "high", "HashiCorp Vault token",
     re.compile(r"\b(hvs\.[A-Za-z0-9_-]{90,120}|hvb\.[A-Za-z0-9_-]{138,300})(?![A-Za-z0-9_-])"), 1,
     "Revoke it with `vault token revoke` and review the audit device log."),
    ("SEC-043", "high", "Terraform Cloud token",
     re.compile(r"(?i)\b([a-z0-9]{14}\.atlasv1\.[a-z0-9_=-]{60,70})\b"), 1,
     "Delete the token in HCP Terraform (user, team or organization tokens page)."),
    ("SEC-044", "medium", "Telegram bot token", re.compile(r"(?<![\w:])(\d{5,16}:A[A-Za-z0-9_-]{34})(?![\w-])"), 1,
     "Revoke it with @BotFather (/revoke) and update the bot's config."),
    ("SEC-045", "critical", "age secret key",
     re.compile(r"\b(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b"), 1,
     "Re-encrypt everything for a new age identity; anything encrypted to the old key is readable."),
    ("SEC-046", "high", "Postman API key", re.compile(r"(?i)\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"), 1,
     "Delete the key in Postman settings (API keys)."),
    ("SEC-047", "medium", "Sentry auth token",
     re.compile(r"\b(sntrys_eyJpYXQiO[A-Za-z0-9+/=_-]{50,}|sntryu_[a-f0-9]{64})(?![A-Za-z0-9+/=_-])"), 1,
     "Revoke the token in Sentry (organization or user auth tokens)."),
    ("SEC-048", "high", "Grafana token",
     re.compile(r"\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/]{32,400}={0,2})(?![A-Za-z0-9+/=])"), 1,
     "Delete the service account token or Cloud access policy token in Grafana."),
    ("SEC-049", "medium", "Linear API key", re.compile(r"\b(lin_api_[A-Za-z0-9]{40})\b"), 1,
     "Revoke the key in Linear settings (Security and access, Personal API keys)."),
    ("SEC-050", "high", "Doppler token", re.compile(r"\b(dp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,44})\b"), 1,
     "Revoke the token in the Doppler dashboard and re-issue a scoped service token."),
    ("SEC-051", "medium", "JSON Web Token",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), 1,
     "Check what it grants (web-appsec jwt_inspect.py). Long-lived or service-role tokens must be revoked and the signing key rotated if needed."),
]

GENERIC = re.compile(
    r"(?i)([a-z0-9_.-]*(?:secret|token|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|"
    r"client[_-]?secret|private[_-]?key|credential)s?[a-z0-9_.-]*)['\"]?\s*(?::=|=>|[:=])\s*[rbfu]?(['\"`])([^'\"`\s]{8,200})\2")
# Unquoted NAME=value lines (.env, .ini, shell, properties). Not used on source code, where an unquoted
# right-hand side is a variable or a call.
GENERIC_KV = re.compile(
    r"(?i)^\s*(?:export\s+)?([a-z0-9_.-]*(?:secret|token|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|"
    r"auth[_-]?key|private[_-]?key|credential)s?[a-z0-9_.-]*)\s*[:=]\s*([^\s'\"`#()\[\]{},;]{8,200})\s*$")
CODE_EXT = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".php", ".go", ".java", ".kt", ".rb", ".cs",
            ".c", ".h", ".cpp", ".rs", ".swift", ".scala")
GENERIC_ID, GENERIC_SEV = "SEC-020", "medium"
ENV_ID = "SEC-030"
ENV_EXAMPLE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: Optional[str] = None) -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def mask(secret: str) -> str:
    """Show only the first 4 characters."""
    return secret[:4] + "..." if secret else "..."


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.search(value)) or len(set(value)) <= 3


def load_ignore(root: str) -> List[Tuple[Optional[str], str]]:
    """Parse .secskills-ignore into (rule or None, glob) pairs."""
    path = os.path.join(root, IGNORE_FILE) if os.path.isdir(root) else os.path.join(os.path.dirname(root) or ".", IGNORE_FILE)
    rules: List[Tuple[Optional[str], str]] = []
    if not os.path.isfile(path):
        return rules
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.split("#")[0].strip()
            if not line:
                continue
            m = re.match(r"^(SEC-\d{3}):(.+)$", line)
            rules.append((m.group(1), m.group(2).strip()) if m else (None, line))
    return rules


def ignored(rel: str, rule: Optional[str], ignores: List[Tuple[Optional[str], str]]) -> bool:
    for r, pattern in ignores:
        if r is not None and r != rule:
            continue
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.rstrip("/") + "/*") or \
                fnmatch.fnmatch(os.path.basename(rel), pattern):
            return True
    return False


def is_example_value(secret: str) -> bool:
    """AWS documents AKIAIOSFODNN7EXAMPLE and its secret; values ending in EXAMPLE are demo data."""
    return "EXAMPLE" in secret.upper()


def scan_text(text: str, rel: str, entropy: float = 3.5, ignores: Optional[List[Tuple[Optional[str], str]]] = None) -> List[Dict[str, str]]:
    ignores = ignores or []
    out: List[Dict[str, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        if INLINE_IGNORE in line or len(line) > 5000:
            continue
        loc = f"{rel}:{n}"
        hit_spans: List[Tuple[int, int]] = []
        for rid, sev, title, rx, grp, fix in RULES:
            for m in rx.finditer(line):
                secret = m.group(grp)
                if rid == "SEC-010" and (is_placeholder(secret) or secret.startswith("$")):
                    continue
                if ignored(rel, rid, ignores):
                    continue
                hit_spans.append(m.span())
                s = sev
                detail = f"{title} found: {mask(secret)}"
                if rid in ("SEC-001", "SEC-002") and is_example_value(secret):
                    s, detail = "info", detail + " (matches AWS's documented example key, likely not real)"
                out.append(finding(rid, s, title, detail, fix, loc))
        candidates = [(m.group(1), m.group(3), m.start(3)) for m in GENERIC.finditer(line)]
        if not candidates and not rel.lower().endswith(CODE_EXT):
            kv = GENERIC_KV.match(line)
            if kv:
                candidates.append((kv.group(1), kv.group(2), kv.start(2)))
        for name, value, start in candidates:
            if any(a <= start < b for a, b in hit_spans):
                continue
            if is_placeholder(value) or ignored(rel, GENERIC_ID, ignores):
                continue
            ent = shannon_entropy(value)
            if ent < entropy:
                continue
            out.append(finding(GENERIC_ID, GENERIC_SEV, f"Hard-coded secret in '{name}'",
                               f"High-entropy value ({ent:.1f} bits/char) assigned to a secret-looking name: {mask(value)}",
                               "Move it to environment variables or a secrets manager and rotate it if it was ever real.", loc))
    return out


def is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\0" in fh.read(8192)
    except OSError:
        return True


def iter_files(root: str, max_size: int) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            low = name.lower()
            if any(low.endswith(ext) for ext in SKIP_EXT) or name == IGNORE_FILE:
                continue
            try:
                if os.path.islink(path) or os.path.getsize(path) > max_size:
                    continue
            except OSError:
                continue
            if not is_binary(path):
                yield path


def env_file_finding(rel: str) -> Optional[Dict[str, str]]:
    base = os.path.basename(rel)
    if (base == ".env" or base.startswith(".env.") or base.endswith(".env")) and not ENV_EXAMPLE.search(base):
        return finding(ENV_ID, "medium", f"Environment file {base} in the tree",
                       ".env files usually hold real credentials and end up committed or shipped in images by accident.",
                       "Add .env* to .gitignore (keep a .env.example with fake values), rotate anything that was committed.", rel)
    return None


CRED_ID = "SEC-031"
CRED_FILES = {
    "id_rsa": "high", "id_dsa": "high", "id_ecdsa": "high", "id_ed25519": "high",
    ".netrc": "medium", "_netrc": "medium", ".git-credentials": "high", ".pypirc": "medium", ".pgpass": "medium",
    ".htpasswd": "medium", ".dockercfg": "medium", "credentials.json": "medium",
}
NPMRC_AUTH = re.compile(r"(?i)^\s*(?:\S*:)?_(?:authToken|auth|password)\s*=\s*(?!\$\{)\S{8,}")


def cred_file_finding(rel: str, text: str = "") -> Optional[Dict[str, str]]:
    """Files that hold credentials by design: SSH keys, netrc, git-credentials, Terraform state, .npmrc with auth."""
    base = os.path.basename(rel)
    low = base.lower()
    sev = CRED_FILES.get(low)
    why = "This file type stores credentials by design."
    if sev is None and (low.endswith(".tfstate") or low.endswith(".tfstate.backup")):
        sev, why = "high", "Terraform state stores resource attributes in plain text, including generated passwords and keys."
    if sev is None and low == "config.json" and "/.docker/" in "/" + rel:
        sev = "medium"
    if sev is None and low == ".npmrc" and any(NPMRC_AUTH.match(l) for l in text.splitlines()):
        sev, why = "high", ".npmrc holds a literal registry auth value instead of ${NPM_TOKEN}."
    if sev is None:
        return None
    return finding(CRED_ID, sev, f"Credential file {base} in the tree", why,
                   "Remove it from the repo and the image, add it to .gitignore, rotate whatever it holds. "
                   "Keep Terraform state in a remote backend with encryption.", rel)


def scan_path(root: str, entropy: float = 3.5, max_size: int = 1_000_000) -> Tuple[List[Dict[str, str]], int]:
    ignores = load_ignore(root)
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    findings: List[Dict[str, str]] = []
    count = 0
    for path in iter_files(root, max_size):
        rel = os.path.relpath(path, base).replace(os.sep, "/")
        if ignored(rel, None, [(r, p) for r, p in ignores if r is None]):
            continue
        count += 1
        env = env_file_finding(rel)
        if env and not ignored(rel, ENV_ID, ignores):
            findings.append(env)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        cred = cred_file_finding(rel, text)
        if cred and not ignored(rel, CRED_ID, ignores):
            findings.append(cred)
        findings += scan_text(text, rel, entropy, ignores)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("location", "")))
    return findings, count


def render_text(target: str, files: int, findings: List[Dict[str, str]]) -> str:
    lines = [f"Secret scan: {target}", f"{files} file(s) scanned, {len(findings)} finding(s)", ""]
    if not findings:
        lines.append("No secrets found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f.get('location', '')}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan files for leaked secrets (output is always masked).")
    ap.add_argument("path", nargs="?", help="directory or file to scan")
    ap.add_argument("--stdin", action="store_true", help="scan text from stdin (e.g. git diff output)")
    ap.add_argument("--entropy", type=float, default=3.5, help="minimum Shannon entropy for generic secrets (default 3.5)")
    ap.add_argument("--max-size", type=int, default=1_000_000, help="skip files larger than this many bytes")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    if args.stdin:
        findings = scan_text(sys.stdin.read(), "<stdin>", args.entropy)
        findings.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
        target, files = "<stdin>", 1
    elif args.path and os.path.exists(args.path):
        findings, files = scan_path(args.path, args.entropy, args.max_size)
        target = args.path
    else:
        print(f"error: {'path not found: ' + args.path if args.path else 'pass a path or --stdin'}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"target": target, "files_scanned": files, "findings": findings}, indent=2))
    else:
        print(render_text(target, files, findings))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
