#!/usr/bin/env python3
"""Grade the HTTP security headers and cookies of a web response.

Works on a live URL (one GET, no crawling) or on saved response headers,
so it can run in CI and offline.

Usage:
  header_audit.py https://example.com
  header_audit.py --file response_headers.txt
  curl -sI https://example.com | header_audit.py --file -
  header_audit.py https://example.com --json --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_PENALTY = {"critical": 30, "high": 20, "medium": 10, "low": 4, "info": 0}


def finding(fid: str, severity: str, title: str, detail: str, fix: str) -> Dict[str, str]:
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}


def parse_raw_headers(raw: str) -> Tuple[Dict[str, List[str]], Optional[int]]:
    """Parse `curl -I` style text. Keeps repeated headers (Set-Cookie). Uses the last response block."""
    blocks = re.split(r"\r?\n\r?\n", raw.strip())
    # curl -IL prints one block per redirect; the final response is what the browser renders
    block = blocks[-1] if blocks else ""
    headers: Dict[str, List[str]] = {}
    status = None
    for line in block.splitlines():
        line = line.rstrip("\r")
        if not line:
            continue
        m = re.match(r"^HTTP/\S+\s+(\d{3})", line)
        if m:
            status = int(m.group(1))
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return headers, status


def fetch_headers(url: str, timeout: float = 10.0, insecure: bool = False) -> Tuple[Dict[str, List[str]], int, str]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "claude-security-skills-header-audit/1.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except urllib.error.HTTPError as err:  # 4xx/5xx still carry headers worth grading
        resp = err
    headers: Dict[str, List[str]] = {}
    for name, value in resp.headers.items():
        headers.setdefault(name.lower(), []).append(value)
    return headers, resp.status if hasattr(resp, "status") else resp.code, resp.geturl()


def _first(headers: Dict[str, List[str]], name: str) -> Optional[str]:
    values = headers.get(name)
    return values[0] if values else None


def check_hsts(headers, is_https) -> List[Dict[str, str]]:
    value = _first(headers, "strict-transport-security")
    if not is_https:
        return []
    if value is None:
        return [finding("HDR-001", "high", "Strict-Transport-Security missing",
                        "Browsers can be downgraded to plain HTTP on the first visit or a hostile network.",
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    max_age = int(m.group(1)) if m else 0
    if max_age < 15552000:  # 180 days
        return [finding("HDR-002", "medium", "HSTS max-age is short",
                        f"max-age={max_age}s. Under 180 days leaves long gaps between visits unprotected.",
                        "Raise max-age to 31536000 (1 year) once HTTPS is stable everywhere.")]
    return []


def check_csp(headers) -> List[Dict[str, str]]:
    value = _first(headers, "content-security-policy")
    report_only = _first(headers, "content-security-policy-report-only")
    if value is None:
        if report_only:
            return [finding("HDR-010", "medium", "CSP is report-only",
                            "A report-only policy logs violations but blocks nothing.",
                            "Promote the policy to Content-Security-Policy once the reports are clean.")]
        return [finding("HDR-011", "high", "Content-Security-Policy missing",
                        "Nothing limits where scripts load from, so any injection runs freely.",
                        "Start with: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")]
    out = []
    directives = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = [b.lower() for b in bits[1:]]
    script_src = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script_src and not any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script_src):
        out.append(finding("HDR-012", "medium", "CSP allows inline scripts",
                           "'unsafe-inline' in script-src cancels most of the XSS protection CSP gives.",
                           "Move inline scripts to files or use nonces/hashes, then drop 'unsafe-inline'."))
    if "'unsafe-eval'" in script_src:
        out.append(finding("HDR-013", "low", "CSP allows eval",
                           "'unsafe-eval' lets strings run as code (eval, new Function).",
                           "Remove 'unsafe-eval' after replacing eval-style calls."))
    if any(s in ("*", "http:", "https:", "data:") for s in script_src):
        out.append(finding("HDR-014", "medium", "CSP script-src is a wildcard",
                           f"script-src contains {', '.join(s for s in script_src if s in ('*', 'http:', 'https:', 'data:'))}, which allows scripts from almost anywhere.",
                           "List the exact script origins, or use 'strict-dynamic' with nonces."))
    if "script-src" not in directives and "default-src" not in directives:
        out.append(finding("HDR-015", "medium", "CSP has no script-src or default-src",
                           "Without either directive scripts are unrestricted.",
                           "Add default-src 'self' as the fallback."))
    if "object-src" not in directives and "'none'" not in directives.get("default-src", []):
        out.append(finding("HDR-016", "low", "CSP does not restrict object-src",
                           "Plugins (<object>, <embed>) fall back to default-src or nothing.",
                           "Add object-src 'none'."))
    return out


def check_framing(headers) -> List[Dict[str, str]]:
    xfo = _first(headers, "x-frame-options")
    csp = (_first(headers, "content-security-policy") or "").lower()
    if "frame-ancestors" in csp:
        return []
    if xfo is None:
        return [finding("HDR-020", "medium", "No clickjacking protection",
                        "Neither X-Frame-Options nor CSP frame-ancestors is set, so any site can frame these pages.",
                        "Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).")]
    if xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return [finding("HDR-021", "medium", "X-Frame-Options value is not enforced",
                        f"'{xfo}' is ignored by modern browsers (ALLOW-FROM is obsolete).",
                        "Use CSP frame-ancestors with the exact origins allowed to frame you.")]
    return []


def check_simple(headers) -> List[Dict[str, str]]:
    out = []
    xcto = _first(headers, "x-content-type-options")
    if (xcto or "").strip().lower() != "nosniff":
        out.append(finding("HDR-030", "low", "X-Content-Type-Options not nosniff",
                           "Browsers may guess content types and run uploads as scripts.",
                           "X-Content-Type-Options: nosniff"))
    if _first(headers, "referrer-policy") is None:
        out.append(finding("HDR-031", "low", "Referrer-Policy missing",
                           "Full URLs (with tokens or IDs in the query) can leak to third parties.",
                           "Referrer-Policy: strict-origin-when-cross-origin"))
    if _first(headers, "permissions-policy") is None:
        out.append(finding("HDR-032", "info", "Permissions-Policy missing",
                           "Camera, microphone, geolocation and similar APIs are not explicitly turned off.",
                           "Permissions-Policy: camera=(), microphone=(), geolocation=()"))
    acao = _first(headers, "access-control-allow-origin")
    acac = (_first(headers, "access-control-allow-credentials") or "").lower() == "true"
    if acao == "*" and acac:
        out.append(finding("HDR-040", "high", "CORS wildcard with credentials",
                           "Allow-Origin * together with Allow-Credentials true is a broken config; some proxies rewrite it into a reflected origin.",
                           "Return a specific allow-listed origin and add Vary: Origin."))
    elif acao == "*":
        out.append(finding("HDR-041", "info", "CORS allows any origin",
                           "Fine for public, unauthenticated data. A problem if this endpoint serves user data.",
                           "Limit Access-Control-Allow-Origin to known origins for private endpoints."))
    leaks = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = _first(headers, name)
        if v and re.search(r"\d", v):
            leaks.append(f"{name}: {v}")
    if leaks:
        out.append(finding("HDR-050", "low", "Version numbers disclosed",
                           "; ".join(leaks) + ". Exact versions make it easy to match known CVEs.",
                           "Strip version numbers from Server / X-Powered-By at the proxy or framework."))
    return out


def parse_cookie(raw: str) -> Tuple[str, Dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        elif p:
            attrs[p.lower()] = ""
    return name, attrs


SESSIONISH = re.compile(r"(sess|sid|auth|token|jwt|login|remember|csrf|xsrf)", re.I)


def check_cookies(headers, is_https) -> List[Dict[str, str]]:
    out = []
    for raw in headers.get("set-cookie", []):
        name, attrs = parse_cookie(raw)
        sensitive = bool(SESSIONISH.search(name)) or name.startswith(("__Host-", "__Secure-"))
        sev = "medium" if sensitive else "low"
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs and not re.search(r"csrf|xsrf", name, re.I):
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        elif attrs["samesite"].lower() == "none" and "secure" not in attrs:
            out.append(finding("CK-002", "medium", f"Cookie {name}: SameSite=None without Secure",
                               "Browsers reject SameSite=None cookies that are not Secure.",
                               "Add Secure, or use SameSite=Lax."))
        if missing:
            out.append(finding("CK-001", sev, f"Cookie {name} missing {', '.join(missing)}",
                               ("Looks like a session or auth cookie. " if sensitive else "") +
                               "Missing flags expose it to network sniffing, script theft or cross-site requests.",
                               f"Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Lax; Path=/"))
    return out


def audit(headers: Dict[str, List[str]], is_https: bool = True) -> List[Dict[str, str]]:
    results = []
    results += check_hsts(headers, is_https)
    results += check_csp(headers)
    results += check_framing(headers)
    results += check_simple(headers)
    results += check_cookies(headers, is_https)
    results.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return results


def score(findings: List[Dict[str, str]]) -> Tuple[int, str]:
    points = max(0, 100 - sum(SEVERITY_PENALTY[f["severity"]] for f in findings))
    for limit, grade in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if points >= limit:
            return points, grade
    return points, "F"


def render_text(target: str, status, findings, points, grade) -> str:
    lines = [f"Header audit: {target}" + (f" (HTTP {status})" if status else ""),
             f"Score {points}/100, grade {grade}, {len(findings)} finding(s)", ""]
    if not findings:
        lines.append("No issues found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Grade HTTP security headers and cookies.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("url", nargs="?", help="URL to fetch with one GET request")
    src.add_argument("--file", help="saved response headers (curl -I output); '-' for stdin")
    ap.add_argument("--http", action="store_true", help="with --file: treat the response as plain HTTP (skip HSTS/Secure checks)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (self-signed test hosts)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    try:
        if args.file:
            raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8", errors="replace").read()
            headers, status = parse_raw_headers(raw)
            if not headers:
                print("error: no headers found in input", file=sys.stderr)
                return 2
            target, is_https = args.file, not args.http
        else:
            if not re.match(r"^https?://", args.url):
                args.url = "https://" + args.url
            headers, status, final_url = fetch_headers(args.url, args.timeout, args.insecure)
            target, is_https = final_url, final_url.startswith("https://")
    except (OSError, urllib.error.URLError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    findings = audit(headers, is_https)
    points, grade = score(findings)
    if args.json:
        print(json.dumps({"target": target, "status": status, "score": points, "grade": grade,
                          "findings": findings}, indent=2))
    else:
        print(render_text(target, status, findings, points, grade))

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
