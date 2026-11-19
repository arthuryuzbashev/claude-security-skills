#!/usr/bin/env python3
"""Grep-level static checks for risky code patterns in Python, JavaScript/TypeScript, PHP and Go.

Line-based rules, each with a CWE id and a concrete fix. Fast, offline, no
dependencies. It finds candidates for review, not proven bugs: a human (or the
reviewing agent) confirms whether untrusted input reaches each one.

Suppress a reviewed line with an inline `secskills:ignore` comment.

Usage:
  sast_lite.py .
  sast_lite.py src/ --lang py,js --json
  sast_lite.py app.py --fail-on medium
  sast_lite.py --list-rules
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", "dist", "build",
             ".next", ".nuxt", "vendor", "bower_components", "target", "coverage"}
LANG_EXT = {
    "py": (".py",),
    "js": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue"),
    "php": (".php", ".phtml"),
    "go": (".go",),
}
COMMENT_PREFIX = {"py": ("#",), "js": ("//", "/*", "*"), "php": ("//", "#", "/*", "*"), "go": ("//", "/*", "*")}
INLINE_IGNORE = "secskills:ignore"
SQL = r"(?:SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)"


def quoted(prefix: str, tail: str, quotes: str = "'\"") -> str:
    """Regex for a string literal (in any of `quotes`) that contains SQL, followed by `tail`.
    The body may hold the other quote characters, so f"... name = '{x}'" still matches."""
    return "(?:" + "|".join(prefix + re.escape(q) + "[^" + q + "]*" + SQL + "[^" + q + "]*" + tail.replace("Q", re.escape(q))
                            for q in quotes) + ")"


# lang, id, severity, cwe, title, pattern, fix, optional negative pattern (match = skip)
RULE_DEFS = [
    ("py", "PY-001", "high", "CWE-95", "eval/exec on dynamic input",
     r"(?<![\w.])(?:eval|exec)\s*\((?!\s*['\"][^'\"]*['\"]\s*\))",
     "Do not evaluate strings. Use ast.literal_eval for literals, json.loads for data, or a lookup table.", None),
    ("py", "PY-002", "high", "CWE-78", "Shell command execution",
     r"shell\s*=\s*True|\bos\.(?:system|popen)\s*\(",
     "Call subprocess.run([...]) with an argument list and shell=False; never build a command string from input.", None),
    ("py", "PY-003", "high", "CWE-502", "Unsafe deserialization (pickle/marshal)",
     r"\b(?:pickle|cPickle|dill|marshal)\.loads?\s*\(",
     "Never unpickle untrusted data. Use JSON, or sign and verify the payload (hmac) before loading.", None),
    ("py", "PY-004", "high", "CWE-502", "yaml.load without a safe loader",
     r"\byaml\.(?:load|load_all)\s*\(",
     "Use yaml.safe_load(), or pass Loader=yaml.SafeLoader.", r"Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader"),
    ("py", "PY-005", "high", "CWE-89", "SQL built with string formatting",
     r"(?i)" + quoted(r"\bf", r"\{") + "|" + quoted("", r"Q\s*(?:%|\+|\.format\s*\()"),
     "Use parameterized queries: cursor.execute(\"... WHERE id = %s\", (value,)) or the ORM's bind parameters.", None),
    ("py", "PY-006", "medium", "CWE-295", "TLS certificate verification disabled",
     r"verify\s*=\s*False|_create_unverified_context\s*\(|CERT_NONE",
     "Keep verification on; for a private CA pass verify='/path/to/ca.pem'.", None),
    ("py", "PY-007", "medium", "CWE-489", "Debug mode hard-coded on",
     r"(?:\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True)",
     "Read debug from the environment and default it to off; a debug console in production can run code.", None),
    ("py", "PY-008", "low", "CWE-328", "Weak hash (MD5/SHA-1)",
     r"\bhashlib\.(?:md5|sha1)\s*\(|hashlib\.new\s*\(\s*['\"](?:md5|sha1)['\"]",
     "Use SHA-256 or better for integrity, and bcrypt/scrypt/argon2 for passwords. Add usedforsecurity=False for non-security checksums.",
     r"usedforsecurity\s*=\s*False"),
    ("py", "PY-009", "medium", "CWE-377", "Insecure temporary file name",
     r"\btempfile\.mktemp\s*\(",
     "Use tempfile.mkstemp() or NamedTemporaryFile(), which create the file atomically.", None),
    ("py", "PY-010", "high", "CWE-347", "JWT signature check disabled or alg none allowed",
     r"['\"]verify_signature['\"]\s*:\s*False|algorithms\s*=\s*\[[^\]]*['\"]none['\"]",
     "Verify every token: jwt.decode(token, key, algorithms=['RS256'], audience=..., issuer=...).", None),
    ("py", "PY-011", "medium", "CWE-338", "Non-cryptographic random for a secret value",
     r"(?i)(?:token|secret|passw|otp|nonce|salt|session|api_?key|reset)\w*\s*=.*\brandom\.(?:random|randint|choice|choices|randrange|getrandbits|sample)\s*\(",
     "Use the secrets module (secrets.token_urlsafe(32), secrets.choice) for tokens, OTPs, salts and IDs.", None),

    ("js", "JS-001", "high", "CWE-95", "eval or Function constructor",
     r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*['\"`]",
     "Do not run strings as code. Use JSON.parse for data and pass functions, not strings, to timers.", None),
    ("js", "JS-002", "high", "CWE-78", "Shell command built from a string",
     r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)|spawn\w*\([^)]*shell\s*:\s*true",
     "Use execFile/spawn with an argument array and no shell; validate input against an allowlist.", None),
    ("js", "JS-003", "medium", "CWE-79", "HTML sink (innerHTML, document.write)",
     r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)|\.insertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(",
     "Use textContent or DOM APIs; if HTML is required, sanitize it with a vetted sanitizer such as DOMPurify.", None),
    ("js", "JS-004", "medium", "CWE-79", "Raw HTML rendering in a framework",
     r"dangerouslySetInnerHTML|\bv-html\s*=|\[innerHTML\]\s*=|bypassSecurityTrust\w*\(",
     "Render text normally; sanitize any HTML before it reaches this prop.", None),
    ("js", "JS-005", "high", "CWE-89", "SQL built with a template literal or concatenation",
     r"(?i)" + quoted("", r"\$\{", "`") + "|" + quoted("", r"Q\s*\+"),
     "Use placeholders (? or $1) and pass values separately, or the query builder's bindings.", None),
    ("js", "JS-006", "low", "CWE-328", "Weak hash (MD5/SHA-1)",
     r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
     "Use sha256 or better; for passwords use bcrypt, scrypt or argon2.", None),
    ("js", "JS-007", "medium", "CWE-295", "TLS certificate verification disabled",
     r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
     "Keep verification on; for a private CA pass it with the `ca` option.", None),
    ("js", "JS-008", "high", "CWE-347", "JWT checks disabled or alg none allowed",
     r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]|ignoreExpiration\s*:\s*true",
     "Pass algorithms: ['RS256'] (or the one you issue), keep expiry checks, and verify with jwt.verify, never jwt.decode.", None),
    ("js", "JS-009", "medium", "CWE-338", "Math.random for a secret value",
     r"(?i)(?:token|secret|passw|otp|nonce|salt|session|api_?key|reset)\w*\s*[:=][^=].*Math\.random\s*\(",
     "Use crypto.randomBytes(32).toString('hex'), crypto.randomUUID() or crypto.getRandomValues for anything secret.", None),

    ("php", "PHP-001", "high", "CWE-95", "eval or code-running callback",
     r"(?<![\w>$])(?:eval|assert|create_function)\s*\(",
     "Do not evaluate strings as PHP. Use a lookup table or a real parser.", None),
    ("php", "PHP-002", "high", "CWE-78", "Shell command execution",
     r"(?<![\w>$])(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(|`[^`]*\$",
     "Avoid the shell; if unavoidable, wrap each argument in escapeshellarg() and allowlist values.", None),
    ("php", "PHP-003", "high", "CWE-502", "unserialize on data",
     r"(?<![\w>$])unserialize\s*\(",
     "Use json_decode; if unserialize is needed, pass ['allowed_classes' => false] and only for trusted data.",
     r"allowed_classes['\"]\s*=>\s*false"),
    ("php", "PHP-004", "high", "CWE-89", "SQL built from request data or concatenation",
     r"(?i)(?:" + SQL + r"[^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|['\"]\s*\.\s*\$)|" + SQL + r"[^'\"]*\{?\$\w+)",
     "Use PDO or mysqli prepared statements with bound parameters.", None),
    ("php", "PHP-005", "medium", "CWE-79", "Request data echoed without escaping",
     r"(?:echo|print)\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)",
     "Escape output with htmlspecialchars($v, ENT_QUOTES, 'UTF-8') or use a templating engine that escapes by default.",
     r"htmlspecialchars|htmlentities"),
    ("php", "PHP-006", "low", "CWE-328", "Weak hash (MD5/SHA-1)",
     r"(?<![\w>$])(?:md5|sha1)\s*\(",
     "Use hash('sha256', ...) for integrity and password_hash() for passwords.", None),
    ("php", "PHP-007", "high", "CWE-98", "include/require with request data",
     r"\b(?:include|require)(?:_once)?\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)",
     "Map the input to a fixed allowlist of files; never pass it to include.", None),

    ("go", "GO-001", "high", "CWE-78", "Shell command via exec.Command",
     r"exec\.Command(?:Context)?\s*\([^)]*['\"](?:/bin/)?(?:ba)?sh['\"]\s*,\s*['\"]-c['\"]",
     "Call the program directly with separate arguments, not through sh -c.", None),
    ("go", "GO-002", "high", "CWE-89", "SQL built with Sprintf or concatenation",
     r"(?i)" + quoted(r"fmt\.Sprintf\s*\(\s*", "", "`\"") + "|" + quoted("", r"Q\s*\+", "`\""),
     "Use placeholders (? or $1) with db.Query/Exec arguments.", None),
    ("go", "GO-003", "medium", "CWE-295", "TLS certificate verification disabled",
     r"InsecureSkipVerify\s*:\s*true",
     "Remove InsecureSkipVerify; add a private CA to RootCAs instead.", None),
    ("go", "GO-004", "low", "CWE-328", "Weak hash (MD5/SHA-1)",
     r"\b(?:md5|sha1)\.(?:New|Sum)\s*\(",
     "Use crypto/sha256 for integrity and golang.org/x/crypto/bcrypt or argon2 for passwords.", None),
    ("go", "GO-005", "medium", "CWE-79", "Escaping bypassed with template.HTML",
     r"template\.(?:HTML|JS|URL)\s*\(",
     "Pass plain strings to html/template so it escapes them; only wrap constants you control.", None),
]

RULES = [
    {"lang": lang, "id": rid, "severity": sev, "cwe": cwe, "title": title, "rx": re.compile(rx),
     "fix": fix, "skip": re.compile(neg) if neg else None}
    for lang, rid, sev, cwe, title, rx, fix, neg in RULE_DEFS
]


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: Optional[str] = None) -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def lang_of(path: str) -> Optional[str]:
    low = path.lower()
    for lang, exts in LANG_EXT.items():
        if low.endswith(exts):
            return lang
    return None


def snippet(line: str, limit: int = 120) -> str:
    s = line.strip()
    return s if len(s) <= limit else s[:limit - 3] + "..."


def scan_text(text: str, lang: str, rel: str = "<input>", langs: Optional[Iterable[str]] = None) -> List[Dict[str, str]]:
    """Run every rule for `lang` over the text. Comment-only lines and secskills:ignore lines are skipped."""
    out: List[Dict[str, str]] = []
    rules = [r for r in RULES if r["lang"] == lang]
    prefixes = COMMENT_PREFIX[lang]
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(prefixes) or INLINE_IGNORE in line or len(line) > 2000:
            continue
        for r in rules:
            if not r["rx"].search(line):
                continue
            if r["skip"] is not None and r["skip"].search(line):
                continue
            f = finding(r["id"], r["severity"], r["title"], f"{r['cwe']}: {snippet(line)}", r["fix"], f"{rel}:{n}")
            f["cwe"] = r["cwe"]
            f["language"] = lang
            out.append(f)
    return out


def iter_files(root: str, langs: List[str], max_size: int) -> Iterable[Tuple[str, str]]:
    if os.path.isfile(root):
        lang = lang_of(root)
        if lang in langs:
            yield root, lang  # type: ignore[misc]
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            lang = lang_of(name)
            if lang not in langs or name.endswith((".min.js", ".d.ts")):
                continue
            try:
                if os.path.islink(path) or os.path.getsize(path) > max_size:
                    continue
            except OSError:
                continue
            yield path, lang  # type: ignore[misc]


def scan_path(root: str, langs: Optional[List[str]] = None, max_size: int = 1_000_000) -> Tuple[List[Dict[str, str]], int]:
    langs = langs or list(LANG_EXT)
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    findings: List[Dict[str, str]] = []
    count = 0
    for path, lang in iter_files(root, langs, max_size):
        count += 1
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        findings += scan_text(text, lang, os.path.relpath(path, base).replace(os.sep, "/"))
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("location", "")))
    return findings, count


def render_text(target: str, files: int, findings: List[Dict[str, str]]) -> str:
    lines = [f"SAST lite: {target}", f"{files} source file(s) scanned, {len(findings)} finding(s)", ""]
    if not findings:
        lines.append("No risky patterns found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f.get('location', '')}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Line-level static checks with CWE ids for Python, JS/TS, PHP and Go.")
    ap.add_argument("path", nargs="?", help="directory or file to scan")
    ap.add_argument("--lang", default=",".join(LANG_EXT), help="comma list of languages: py,js,php,go (js includes ts)")
    ap.add_argument("--max-size", type=int, default=1_000_000, help="skip files larger than this many bytes")
    ap.add_argument("--list-rules", action="store_true", help="print the rule table and exit")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    if args.list_rules:
        rows = [{k: r[k] for k in ("id", "lang", "severity", "cwe", "title", "fix")} for r in RULES]
        if args.json:
            print(json.dumps({"rules": rows}, indent=2))
        else:
            for r in rows:
                print(f"{r['id']:8} {r['severity']:7} {r['cwe']:8} {r['title']}")
        return 0
    langs = [x.strip() for x in args.lang.split(",") if x.strip()]
    bad = [x for x in langs if x not in LANG_EXT]
    if bad:
        print(f"error: unknown language(s): {', '.join(bad)} (use py, js, php, go)", file=sys.stderr)
        return 2
    if not args.path or not os.path.exists(args.path):
        print(f"error: {'path not found: ' + args.path if args.path else 'pass a path to scan'}", file=sys.stderr)
        return 2

    findings, files = scan_path(args.path, langs, args.max_size)
    if args.json:
        print(json.dumps({"target": args.path, "files_scanned": files, "findings": findings}, indent=2))
    else:
        print(render_text(args.path, files, findings))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
