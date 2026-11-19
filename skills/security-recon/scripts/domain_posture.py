#!/usr/bin/env python3
"""Check a domain's public security posture records: security.txt, CAA and DNSSEC.

security.txt (RFC 9116) tells researchers where to report bugs. CAA (RFC 8659) limits
which certificate authorities may issue for the domain. A DS record in the parent zone
means DNSSEC is switched on. Works on saved files (offline) or live for a domain you
name: dig CAA/DS lookups and one HTTPS GET for /.well-known/security.txt, all read-only
with a timeout.

Usage:
  domain_posture.py example.com                                 # live, needs dig for CAA/DS
  domain_posture.py example.com --no-fetch                      # DNS only, no HTTPS request
  domain_posture.py --security-txt security.txt --today 2026-11-19
  domain_posture.py --records dns.txt --security-txt security.txt --json --fail-on medium
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
KNOWN_CAA_TAGS = ("issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone")
STX_FIELDS = ("acknowledgments", "canonical", "contact", "encryption", "expires", "hiring",
              "policy", "preferred-languages", "csaf")


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: Optional[str] = None) -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


# ---------------------------------------------------------------- security.txt

def strip_pgp(text: str) -> Tuple[str, bool]:
    """Return the body of a cleartext-signed file and whether it was signed."""
    if "-----BEGIN PGP SIGNED MESSAGE-----" not in text:
        return text, False
    body = text.split("-----BEGIN PGP SIGNED MESSAGE-----", 1)[1]
    body = body.split("-----BEGIN PGP SIGNATURE-----", 1)[0]
    lines = body.splitlines()
    while lines and (lines[0].strip() == "" or lines[0].lower().startswith("hash:")):
        lines.pop(0)
    return "\n".join(l[2:] if l.startswith("- ") else l for l in lines), True


def parse_security_txt(text: str) -> Dict[str, object]:
    body, signed = strip_pgp(text)
    fields: Dict[str, List[str]] = {}
    unknown = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$", line)
        if not m:
            continue
        name = m.group(1).lower()
        fields.setdefault(name, []).append(m.group(2).strip())
        if name not in STX_FIELDS:
            unknown.append(m.group(1))
    return {"fields": fields, "signed": signed, "unknown_fields": unknown}


def parse_expires(value: str) -> Optional[dt.date]:
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[Tt ]\d{2}:\d{2}:\d{2}", value.strip())
    if not m:
        return None
    try:
        return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def check_security_txt(text: Optional[str], today: dt.date, legacy_only: bool = False) -> List[Dict[str, str]]:
    loc = "security.txt"
    if text is None:
        return [finding("STX-001", "low", "No security.txt",
                        "Researchers who find a problem have no published way to reach you, so reports go to "
                        "support queues, social media or nowhere.",
                        "Publish /.well-known/security.txt with Contact and Expires (RFC 9116). "
                        "securitytxt.org generates one.", loc)]
    parsed = parse_security_txt(text)
    fields: Dict[str, List[str]] = parsed["fields"]  # type: ignore[assignment]
    out = []
    if legacy_only:
        out.append(finding("STX-008", "low", "security.txt only at the legacy /security.txt path",
                           "RFC 9116 says the file MUST be at /.well-known/security.txt; the root path is only "
                           "allowed as a redirect.",
                           "Serve the file at /.well-known/security.txt and redirect /security.txt to it.", loc))
    contacts = fields.get("contact", [])
    if not contacts:
        out.append(finding("STX-002", "medium", "security.txt has no Contact field",
                           "Contact is required. Without it the file gives no way to report a problem.",
                           "Add Contact: mailto:security@<domain> (or an https:// form).", loc))
    for c in contacts:
        low = c.lower()
        if low.startswith("http://"):
            out.append(finding("STX-006", "low", "security.txt Contact uses http://",
                               f"Contact: {c}. RFC 9116 requires web URIs to use https://.",
                               "Change the Contact URI to https://.", loc))
        elif not low.startswith(("mailto:", "tel:", "https://")):
            out.append(finding("STX-006", "low", "security.txt Contact is not a URI",
                               f"Contact: {c}. The value must be a URI such as mailto:, tel: or https://.",
                               "Write it as mailto:security@<domain> or https://<domain>/report.", loc))
    expires = fields.get("expires", [])
    if not expires:
        out.append(finding("STX-003", "medium", "security.txt has no Expires field",
                           "Expires is required so readers can tell a maintained file from a stale one.",
                           "Add Expires: <date less than a year ahead>, e.g. Expires: 2027-06-30T23:00:00.000Z.", loc))
    elif len(expires) > 1 or parse_expires(expires[0]) is None:
        out.append(finding("STX-007", "medium", "security.txt Expires is repeated or not a valid date",
                           f"Expires: {' | '.join(expires)}. It must appear once, as an RFC 3339 date-time.",
                           "Keep a single Expires line like 2027-06-30T23:00:00.000Z.", loc))
    else:
        when = parse_expires(expires[0])
        if when is not None and when < today:
            out.append(finding("STX-004", "medium", f"security.txt expired on {when.isoformat()}",
                               "Readers should treat an expired file as stale, so the contact data may be ignored.",
                               "Check the contacts are still right and set a new Expires date.", loc))
        elif when is not None and (when - today).days > 366:
            out.append(finding("STX-005", "low", f"security.txt Expires is far ahead ({when.isoformat()})",
                               "RFC 9116 recommends an Expires value less than a year ahead so the file gets reviewed.",
                               "Set Expires to less than a year from now and add the renewal to a calendar.", loc))
    for url in fields.get("canonical", []) + fields.get("policy", []) + fields.get("encryption", []):
        if url.lower().startswith("http://"):
            out.append(finding("STX-006", "low", "security.txt links over http://",
                               f"{url}. RFC 9116 requires web URIs in the file to use https://.",
                               "Change the link to https://.", loc))
    return out


# ---------------------------------------------------------------- CAA and DNSSEC

def parse_records(raw: str) -> Dict[str, List[Tuple[str, str]]]:
    """Parse dig/zone lines into {"CAA": [(name, rdata)], "DS": [(name, rdata)]}."""
    out: Dict[str, List[Tuple[str, str]]] = {"CAA": [], "DS": []}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        m = re.match(r"^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?(CAA|DS)\s+(.*)$", line, re.I)
        if m:
            out[m.group(2).upper()].append((m.group(1).rstrip(".").lower(), m.group(3).strip()))
    return out


def parse_caa(rdata: str) -> Optional[Tuple[int, str, str]]:
    m = re.match(r'^(\d+)\s+([A-Za-z0-9]+)\s+"?(.*?)"?$', rdata.strip())
    if not m:
        return None
    return int(m.group(1)), m.group(2).lower(), m.group(3)


def check_caa(rdatas: List[str], target: str) -> List[Dict[str, str]]:
    loc = f"CAA {target}"
    if not rdatas:
        return [finding("CAA-001", "low", "No CAA record",
                        "Any public certificate authority may issue certificates for this domain, which widens the "
                        "options for a mis-issued certificate.",
                        'Publish CAA for the CAs you use, e.g. 0 issue "letsencrypt.org" and 0 iodef '
                        '"mailto:security@<domain>".', loc)]
    out = []
    parsed = [p for p in (parse_caa(r) for r in rdatas) if p]
    for flags, tag, value in parsed:
        if flags & 128 and tag not in KNOWN_CAA_TAGS:
            out.append(finding("CAA-002", "medium", f"CAA critical flag on unknown tag '{tag}'",
                               "RFC 8659 says a CA must refuse to issue when it meets a critical tag it does not "
                               "understand, so renewals can fail.",
                               "Remove the critical flag (use 0) or fix the tag name.", loc))
    tags = {t for _, t, _ in parsed}
    if ("issue" in tags or "issuewild" in tags) and "iodef" not in tags:
        out.append(finding("CAA-003", "info", "CAA has no iodef contact",
                           "CAs that refuse a request have no address to report the attempt to.",
                           'Add 0 iodef "mailto:security@<domain>".', loc))
    return out


def closest_caa(pairs: List[Tuple[str, str]], domain: str) -> List[str]:
    """Records from the closest name that has any. CAA applies that way (RFC 8659 section 3); DS
    only exists at a zone cut, so a host inside a signed zone uses the zone's DS."""
    labels = domain.split(".")
    for i in range(len(labels)):
        name = ".".join(labels[i:])
        found = [r for n, r in pairs if n == name]
        if found:
            return found
    return []


def check_dnssec(ds_rdatas: List[str], target: str) -> List[Dict[str, str]]:
    if ds_rdatas:
        return []
    return [finding("DNS-001", "low", "DNSSEC is not enabled (no DS record)",
                    "Without DNSSEC, resolvers cannot detect forged answers for this zone (cache poisoning, "
                    "spoofed MX or CAA answers).",
                    "Turn on DNSSEC signing at the DNS provider and publish the DS record at the registrar.",
                    f"DS {target}")]


# ---------------------------------------------------------------- live collection

def dig(rtype: str, name: str, timeout: float) -> List[str]:
    tool = shutil.which("dig")
    if not tool:
        raise RuntimeError("dig not found; install bind tools or pass saved answers with --records")
    try:
        proc = subprocess.run([tool, "+short", f"+time={max(1, int(timeout))}", "+tries=2", rtype, name],
                              capture_output=True, text=True, timeout=timeout * 3)
    except subprocess.TimeoutExpired:
        return []
    return [l.strip() for l in proc.stdout.splitlines() if l.strip() and not l.startswith(";")]


def live_caa(domain: str, timeout: float) -> List[str]:
    """CAA applies from the closest name that has records, walking up toward the parent."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        found = [r for r in dig("CAA", name, timeout) if parse_caa(r)]
        if found:
            return found
    return []


def live_ds(domain: str, timeout: float) -> List[str]:
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        found = dig("DS", ".".join(labels[i:]), timeout)
        if found:
            return found
    return []


def fetch_security_txt(domain: str, timeout: float) -> Tuple[Optional[str], bool]:
    """Return (text, legacy_only). Pages that look like HTML count as missing."""
    for path, legacy in (("/.well-known/security.txt", False), ("/security.txt", True)):
        req = urllib.request.Request(f"https://{domain}{path}", headers={"User-Agent": "domain-posture-check/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read(32768).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError):
            continue
        if "<html" in text[:2000].lower() or not re.search(r"(?im)^\s*(contact|expires)\s*:", text):
            continue
        return text, legacy
    return None, False


# ---------------------------------------------------------------- main

def render_text(target: str, report: Dict[str, object]) -> str:
    findings: List[Dict[str, str]] = report["findings"]  # type: ignore[assignment]
    lines = [f"Domain posture: {target}", f"Checked: {', '.join(report['checks'])}, {len(findings)} finding(s)", ""]  # type: ignore[arg-type]
    if not findings:
        lines.append("No issues found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check security.txt, CAA and DNSSEC for a domain.")
    ap.add_argument("domain", nargs="?", help="domain to check live (dig CAA/DS, HTTPS GET for security.txt)")
    ap.add_argument("--security-txt", help="saved security.txt file ('-' for stdin)")
    ap.add_argument("--records", help="saved dig/zone answers with CAA and DS lines")
    ap.add_argument("--no-fetch", action="store_true", help="live mode: skip the HTTPS request for security.txt")
    ap.add_argument("--today", help="date for the Expires check, YYYY-MM-DD (default: today)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    if not (args.domain or args.security_txt or args.records):
        ap.print_usage(sys.stderr)
        print("error: pass a domain, --security-txt or --records", file=sys.stderr)
        return 2
    try:
        today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    except ValueError:
        print("error: --today must be YYYY-MM-DD", file=sys.stderr)
        return 2

    domain = args.domain.strip().rstrip(".").lower() if args.domain else None
    target = domain or args.records or args.security_txt
    offline = bool(args.security_txt or args.records)
    findings: List[Dict[str, str]] = []
    checks: List[str] = []
    stx: Optional[Dict[str, object]] = None
    caa: List[str] = []
    dnssec: Optional[bool] = None
    try:
        if args.security_txt:
            text = sys.stdin.read() if args.security_txt == "-" else open(args.security_txt, encoding="utf-8", errors="replace").read()
            findings += check_security_txt(text, today)
            stx = parse_security_txt(text)
            checks.append("security.txt")
        elif domain and not offline and not args.no_fetch:
            text, legacy = fetch_security_txt(domain, args.timeout)
            findings += check_security_txt(text, today, legacy)
            stx = parse_security_txt(text) if text else None
            checks.append("security.txt")
        if args.records:
            raw = sys.stdin.read() if args.records == "-" else open(args.records, encoding="utf-8", errors="replace").read()
            recs = parse_records(raw)
            name = domain or (recs["CAA"] + recs["DS"] + [("(records)", "")])[0][0]
            caa = closest_caa(recs["CAA"], domain) if domain else [r for _, r in recs["CAA"]]
            ds = closest_caa(recs["DS"], domain) if domain else [r for _, r in recs["DS"]]
            findings += check_caa(caa, name) + check_dnssec(ds, name)
            dnssec = bool(ds)
            checks += ["caa", "dnssec"]
        elif domain and not offline:
            caa = live_caa(domain, args.timeout)
            ds = live_ds(domain, args.timeout)
            findings += check_caa(caa, domain) + check_dnssec(ds, domain)
            dnssec = bool(ds)
            checks += ["caa", "dnssec"]
    except (OSError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    findings.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    report = {"target": target, "checks": checks, "security_txt": stx, "caa": caa, "dnssec": dnssec,
              "findings": findings}
    print(json.dumps(report, indent=2) if args.json else render_text(str(target), report))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
