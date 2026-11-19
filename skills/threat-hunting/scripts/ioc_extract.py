#!/usr/bin/env python3
"""Pull indicators of compromise (IOCs) out of reports, emails, logs or notes.

Finds IPv4/IPv6 addresses, domains, URLs, email addresses, MD5/SHA1/SHA256
hashes, CVE IDs, Windows/Unix file paths and registry keys. Defanged input
(hxxp, [.], (.), [at]) is refanged before matching. Private and reserved IPs
and well-known benign domains are dropped unless --keep-all is set.

Usage:
  ioc_extract.py report.txt
  ioc_extract.py --file - < email.eml
  ioc_extract.py report.txt --json
  ioc_extract.py report.txt --format csv --defang
  ioc_extract.py report.txt --types ipv4,domain,sha256 --format list
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys
from typing import Dict, List
from urllib.parse import parse_qsl, urlsplit

TYPES = ["ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256",
         "cve", "filepath", "registry"]

# Order matters: longer patterns first so "[.]" handling does not eat "[dot]".
REFANG_RULES = [
    (re.compile(r"\bhxxps\b", re.I), "https"),
    (re.compile(r"\bhxxp\b", re.I), "http"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[\s*:\s*//\s*\]"), "://"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\s?[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]\s?", re.I), "."),
    (re.compile(r"\s?[\[\(\{]\s*(?:@|at)\s*[\]\)\}]\s?", re.I), "@"),
    (re.compile(r"\\\."), "."),
]

# Domains that show up in almost every report and are not indicators by themselves.
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "live.com",
    "google.com", "googleapis.com", "gstatic.com", "apple.com", "mozilla.org",
    "w3.org", "xmlsoap.org", "schemas.openxmlformats.org", "openxmlformats.org",
    "mitre.org", "virustotal.com", "example.com", "example.org", "example.net",
    "localhost", "cisa.gov", "nist.gov", "first.org", "sigmahq.io",
}

# Things that look like domains but are file names.
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse",
    "wsf", "hta", "lnk", "scr", "msi", "jar", "py", "sh", "txt", "log", "csv",
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf",
    "png", "jpg", "jpeg", "gif", "bmp", "html", "htm", "php", "asp", "aspx",
    "jsp", "json", "xml", "yml", "yaml", "ini", "cfg", "conf", "tmp", "dat",
    "bin", "iso", "img", "vhd", "zip", "rar", "7z", "gz", "tar", "md", "db",
    "sqlite", "evtx", "dmp", "tmp", "lock", "pid", "key", "pem", "crt", "pcap", "eml", "msg", "one", "inf", "reg", "so", "elf",
}

SECRET_PARAM = re.compile(r"(token|key|secret|pass(word)?|pwd|sig(nature)?|session|auth|code)", re.I)

RE_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]*\d)")
RE_IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])")
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\)\}|`]+", re.I)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
RE_DOMAIN = re.compile(r"(?<![\w@.\\/%-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,22}[A-Za-z0-9](?![\w-]|\.[A-Za-z0-9])")
RE_MD5 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
RE_SHA1 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
RE_SHA256 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_WINPATH = re.compile(r"(?:\b[A-Za-z]:\\|%[A-Za-z_]+%\\|\\\\[A-Za-z0-9._$-]+\\)[^\s\"'<>|*?\r\n]*")
RE_UNIXPATH = re.compile(r"(?<![\w/.:~-])/(?:etc|tmp|var|usr|home|root|opt|bin|sbin|dev/shm|lib|lib64|proc|srv|mnt|Library|Users|Applications|private)/[^\s\"'<>|;,)]*")
RE_REGISTRY = re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)(?::)?(?:\\[^\s\"'<>|\\]+)+", re.I)

TRAILING = ".,;:!?'\")]}>"


def refang(text: str) -> str:
    """Undo common defanging so the patterns can match."""
    for pattern, repl in REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, kind: str) -> str:
    """Make an IOC safe to paste into tickets and chat (not clickable)."""
    if kind in ("url", "domain", "ipv4", "email"):
        value = re.sub(r"^http", "hxxp", value, flags=re.I)
        value = re.sub(r"^ftp", "fxp", value, flags=re.I)
        value = value.replace("://", "[://]", 1) if kind == "url" else value
        value = value.replace("@", "[@]")
        if kind == "url":
            parts = value.split("/", 3)
            if len(parts) >= 3:
                parts[2] = parts[2].replace(".", "[.]")
            value = "/".join(parts)
        else:
            value = value.replace(".", "[.]")
    return value


def mask_url(url: str) -> str:
    """Mask values of query parameters that look like secrets (first 4 chars kept)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    out = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if SECRET_PARAM.search(k) and len(v) > 4:
            v = v[:4] + "..."
        out.append(f"{k}={v}")
    return url.split("?", 1)[0] + "?" + "&".join(out) + (("#" + parts.fragment) if parts.fragment else "")


def ip_is_interesting(ip: str) -> bool:
    """Public addresses plus documentation ranges (so sample data works). Drops private, loopback and so on."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    if any(addr in n for n in doc_nets if n.version == addr.version):
        return True
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return addr.is_global and not addr.is_multicast


def domain_is_interesting(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return not any(d == b or d.endswith("." + b) for b in BENIGN_DOMAINS)


def _strip(value: str) -> str:
    while value and value[-1] in TRAILING:
        value = value[:-1]
    return value


def extract(text: str, keep_all: bool = False, types=None) -> Dict[str, List[str]]:
    """Return {type: sorted unique values}. Input may be defanged."""
    text = refang(text)
    wanted = set(types or TYPES)
    found: Dict[str, set] = {t: set() for t in TYPES}

    urls = {_strip(m.group(0)) for m in RE_URL.finditer(text)}
    found["url"] = {mask_url(u) for u in urls}
    emails = {m.group(0).lower() for m in RE_EMAIL.finditer(text)}
    found["email"] = emails

    for m in RE_IPV4.finditer(text):
        if keep_all or ip_is_interesting(m.group(0)):
            found["ipv4"].add(m.group(0))
    for m in RE_IPV6.finditer(text):
        cand = m.group(0)
        if cand.count(":") < 2:
            continue
        try:
            addr = ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        if keep_all or ip_is_interesting(str(addr)):
            found["ipv6"].add(str(addr))

    skip_spans = [m.span() for m in RE_EMAIL.finditer(text)]
    skip_spans += [m.span() for m in RE_WINPATH.finditer(text)]
    skip_spans += [m.span() for m in RE_UNIXPATH.finditer(text)]
    for m in RE_DOMAIN.finditer(text):
        if any(s <= m.start() < e for s, e in skip_spans):
            continue
        dom = m.group(0).lower().rstrip(".")
        tld = dom.rsplit(".", 1)[-1]
        if tld in FILE_EXTENSIONS or tld.isdigit():
            continue
        if keep_all or domain_is_interesting(dom):
            found["domain"].add(dom)
    # hosts of URLs count as domains too
    for u in urls:
        host = (urlsplit(u).hostname or "").lower()
        if host and not RE_IPV4.fullmatch(host) and ":" not in host and "." in host:
            if keep_all or domain_is_interesting(host):
                found["domain"].add(host)
    if not keep_all:
        found["url"] = {u for u in found["url"]
                        if domain_is_interesting((urlsplit(u).hostname or ""))}
        found["email"] = {e for e in found["email"] if domain_is_interesting(e.split("@", 1)[1])}

    found["sha256"] = {m.group(0).lower() for m in RE_SHA256.finditer(text)}
    found["sha1"] = {m.group(0).lower() for m in RE_SHA1.finditer(text)}
    found["md5"] = {m.group(0).lower() for m in RE_MD5.finditer(text)}
    found["cve"] = {m.group(0).upper() for m in RE_CVE.finditer(text)}
    found["registry"] = {_strip(m.group(0)) for m in RE_REGISTRY.finditer(text)}
    paths = {_strip(m.group(0)) for m in RE_WINPATH.finditer(text)}
    paths |= {_strip(m.group(0)) for m in RE_UNIXPATH.finditer(text)}
    found["filepath"] = {p for p in paths if len(p) > 3}

    return {t: sorted(found[t]) for t in TYPES if t in wanted}


def rows(result: Dict[str, List[str]], defanged: bool = False):
    for kind, values in result.items():
        for v in values:
            yield kind, (defang(v, kind) if defanged else v)


def render(result: Dict[str, List[str]], fmt: str, defanged: bool) -> str:
    if fmt == "json":
        return json.dumps({k: [defang(v, k) if defanged else v for v in vals] for k, vals in result.items()}, indent=2)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["type", "value"])
        for kind, v in rows(result, defanged):
            w.writerow([kind, v])
        return buf.getvalue().rstrip("\n")
    if fmt == "list":
        return "\n".join(v for _, v in rows(result, defanged))
    lines = []
    total = sum(len(v) for v in result.values())
    lines.append(f"{total} indicator(s)")
    for kind, values in result.items():
        if not values:
            continue
        lines.append("")
        lines.append(f"{kind} ({len(values)})")
        for v in values:
            lines.append("  " + (defang(v, kind) if defanged else v))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Extract IOCs (IPs, domains, URLs, emails, hashes, CVEs, paths, registry keys) from text.")
    ap.add_argument("path", nargs="?", help="text file to read")
    ap.add_argument("--file", help="text file to read; '-' for stdin")
    ap.add_argument("--format", choices=["text", "list", "csv", "json"], default="text")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    out = ap.add_mutually_exclusive_group()
    out.add_argument("--defang", action="store_true", help="defang output (hxxp, [.]) for tickets and chat")
    out.add_argument("--refang", action="store_true", help="plain, clickable output (the default)")
    ap.add_argument("--keep-all", action="store_true", help="keep private/reserved IPs and common benign domains")
    ap.add_argument("--types", help=f"comma list to keep, from: {','.join(TYPES)}")
    args = ap.parse_args(argv)

    src = args.file or args.path
    if not src:
        print("error: give a file path or --file - for stdin", file=sys.stderr)
        return 2
    types = None
    if args.types:
        types = [t.strip() for t in args.types.split(",") if t.strip()]
        bad = [t for t in types if t not in TYPES]
        if bad:
            print(f"error: unknown type(s): {', '.join(bad)}", file=sys.stderr)
            return 2
    try:
        text = sys.stdin.read() if src == "-" else open(src, encoding="utf-8", errors="replace").read()
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    result = extract(text, keep_all=args.keep_all, types=types)
    print(render(result, "json" if args.json else args.format, args.defang))
    return 0


if __name__ == "__main__":
    sys.exit(main())
