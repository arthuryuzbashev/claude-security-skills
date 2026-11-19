#!/usr/bin/env python3
"""Grade a domain's email authentication records: SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI.

Works on record text you pass in, on a saved file of TXT records (dig or zone
style), or live with `dig` when you pass a domain. Read-only DNS lookups only.

Usage:
  email_auth_audit.py example.com                      # live, needs dig
  email_auth_audit.py example.com --selector google --selector s1
  email_auth_audit.py --file records.txt --domain example.test
  email_auth_audit.py --spf "v=spf1 include:_spf.example.test -all" --dmarc "v=DMARC1; p=none"
  email_auth_audit.py --file records.txt --json --fail-on medium
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_PENALTY = {"critical": 30, "high": 20, "medium": 10, "low": 4, "info": 0}
COMMON_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail"]
SPF_LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists")
SPF_MECHANISMS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")

Resolver = Callable[[str], List[str]]


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: Optional[str] = None) -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


# ---------------------------------------------------------------- input parsing

def join_txt_strings(text: str) -> str:
    """Join DNS character-strings: '"v=spf1 a" " -all"' -> 'v=spf1 a -all'. Unquoted text is returned as is."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    if not parts:
        return text.strip()
    return "".join(p.replace('\\"', '"') for p in parts)


def classify(text: str) -> Optional[str]:
    t = text.strip().lower()
    if re.match(r"^v=spf1(\s|$)", t):
        return "spf"
    if t.startswith("v=dmarc1"):
        return "dmarc"
    if t.startswith("v=dkim1") or re.match(r"^(k|p|h|t|s|n)=", t) and "p=" in t:
        return "dkim"
    if t.startswith("v=stsv1"):
        return "mta_sts"
    if t.startswith("v=tlsrptv1"):
        return "tls_rpt"
    if re.match(r"^v\s*=\s*bimi1\s*(;|$)", t):
        return "bimi"
    return None


def parse_record_lines(raw: str) -> List[Tuple[Optional[str], str]]:
    """Parse dig answer lines, zone lines or bare record text into (name, text) pairs."""
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        name = None
        m = re.match(r"^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?TXT\s+(.*)$", line, re.I)
        if m:
            name, line = m.group(1).rstrip(".").lower(), m.group(2)
        out.append((name, join_txt_strings(line)))
    return out


def dig_txt(name: str, timeout: float = 5.0) -> List[str]:
    """Live TXT lookup through dig. Raises RuntimeError when dig is missing."""
    dig = shutil.which("dig")
    if not dig:
        raise RuntimeError("dig not found; install bind tools or pass records with --file/--spf/--dmarc")
    try:
        proc = subprocess.run([dig, "+short", f"+time={max(1, int(timeout))}", "+tries=2", "TXT", name],
                              capture_output=True, text=True, timeout=timeout * 3)
    except subprocess.TimeoutExpired:
        return []
    return [join_txt_strings(line) for line in proc.stdout.splitlines() if line.strip()]


def file_resolver(pairs: List[Tuple[Optional[str], str]]) -> Resolver:
    table: Dict[str, List[str]] = {}
    for name, text in pairs:
        if name:
            table.setdefault(name, []).append(text)
    return lambda n: table.get(n.rstrip(".").lower(), [])


# ---------------------------------------------------------------- SPF

def spf_terms(record: str) -> List[str]:
    return record.split()[1:]


def _term_parts(term: str) -> Tuple[str, str, str]:
    """Split an SPF term into (qualifier, name, value). Modifiers come back with qualifier '='."""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9_.-]*)=(.*)$", term)
    if m:
        return "=", m.group(1).lower(), m.group(2)
    qual = "+"
    if term[:1] in "+-~?":
        qual, term = term[0], term[1:]
    name, _, value = term.partition(":")
    if "/" in name and not value:  # a/24, mx/24
        name, _, value = name.partition("/")
        value = "/" + value
    return qual, name.lower(), value


def count_spf_lookups(record: str, resolver: Optional[Resolver], depth: int = 0,
                      seen: Optional[set] = None) -> Tuple[int, List[str]]:
    """Count DNS-querying terms the way RFC 7208 4.6.4 does, following include/redirect when a resolver is given."""
    seen = set() if seen is None else seen
    count, notes = 0, []
    for term in spf_terms(record):
        qual, name, value = _term_parts(term)
        if qual == "=" and name == "redirect":
            count += 1
            target = value
        elif qual != "=" and name in SPF_LOOKUP_TERMS:
            count += 1
            target = value if name == "include" else None
        else:
            continue
        if not target:
            continue
        if resolver is None:
            notes.append(f"not followed: {target}")
            continue
        if target in seen or depth >= 10:
            notes.append(f"loop or too deep at {target}")
            continue
        seen.add(target)
        child = [r for r in resolver(target) if classify(r) == "spf"]
        if not child:
            notes.append(f"no SPF record at {target}")
            continue
        sub, sub_notes = count_spf_lookups(child[0], resolver, depth + 1, seen)
        count += sub
        notes += sub_notes
    return count, notes


def check_spf(records: List[str], resolver: Optional[Resolver] = None) -> Tuple[List[Dict[str, str]], Optional[int]]:
    if not records:
        return [finding("EML-001", "medium", "No SPF record",
                        "Receivers cannot tell which servers may send for this domain.",
                        "Publish one TXT record, e.g. v=spf1 include:<your mail provider> -all (or v=spf1 -all if the domain sends no mail).",
                        "SPF")], None
    if len(records) > 1:
        return [finding("EML-002", "high", "More than one SPF record",
                        f"{len(records)} records start with v=spf1. RFC 7208 makes that a permerror, so SPF fails everywhere.",
                        "Merge them into a single v=spf1 record.", "SPF")], None
    rec = records[0]
    out = []
    terms = spf_terms(rec)
    all_qual = None
    has_redirect = False
    for term in terms:
        qual, name, value = _term_parts(term)
        if qual == "=":
            if name == "redirect":
                has_redirect = True
            continue
        if name not in SPF_MECHANISMS:
            out.append(finding("EML-003", "high", f"Unknown SPF mechanism '{term}'",
                               "An unknown mechanism is a permerror: receivers treat the whole record as broken.",
                               "Fix the typo or remove the term.", "SPF"))
            continue
        if name == "all":
            all_qual = qual
        if name == "ptr":
            out.append(finding("EML-008", "low", "SPF uses the ptr mechanism",
                               "RFC 7208 says ptr SHOULD NOT be used: it is slow, costs lookups and some receivers ignore it.",
                               "Replace ptr with ip4/ip6 ranges or an include from the sending service.", "SPF"))
        if name in ("ip4", "ip6") and "/" in value:
            try:
                prefix = int(value.rsplit("/", 1)[1])
            except ValueError:
                prefix = -1
            limit = 16 if name == "ip4" else 32
            if 0 <= prefix < limit:
                out.append(finding("EML-012", "high", f"SPF authorizes a very large range ({term})",
                                   f"A /{prefix} {name} range covers far more addresses than any one sender uses. "
                                   "Anyone renting a server in that range can pass SPF as this domain.",
                                   f"List the exact sending addresses or ranges (narrower than /{limit}), or use the "
                                   "include published by the mail provider.", "SPF"))
    if all_qual == "+":
        out.append(finding("EML-004", "critical", "SPF ends in +all",
                           "+all (or a bare 'all') authorizes every server on the internet to send as this domain.",
                           "End the record with -all (or ~all while you roll out DMARC).", "SPF"))
    elif all_qual == "?":
        out.append(finding("EML-005", "medium", "SPF ends in ?all (neutral)",
                           "Neutral gives receivers no signal, so spoofed mail is treated like unauthenticated mail.",
                           "Use -all once every legitimate sender is listed, or ~all during rollout.", "SPF"))
    elif all_qual == "~":
        out.append(finding("EML-006", "info", "SPF ends in ~all (softfail)",
                           "Fine when DMARC is at quarantine or reject; on its own softfail rarely blocks spoofing.",
                           "Keep ~all with an enforcing DMARC policy, or move to -all.", "SPF"))
    elif all_qual is None and not has_redirect:
        out.append(finding("EML-007", "medium", "SPF has no 'all' mechanism or redirect",
                           "Mail from unlisted servers gets a neutral result, the same as ?all.",
                           "Add -all (or ~all) at the end of the record.", "SPF"))
    lookups, notes = count_spf_lookups(rec, resolver)
    if lookups > 10:
        out.append(finding("EML-009", "high", f"SPF needs {lookups} DNS lookups (limit 10)",
                           "Past 10 lookups receivers return permerror and SPF fails for all mail.",
                           "Flatten includes you control, drop unused senders, or move bulk senders to a subdomain.", "SPF"))
    unfollowed = [n for n in notes if n.startswith("not followed")]
    if unfollowed and lookups <= 10:
        out.append(finding("EML-010", "info", "Nested SPF includes not counted",
                           f"Counted {lookups} lookup(s) at the top level only; {len(unfollowed)} include/redirect target(s) were not resolved.",
                           "Run live (pass the domain) or add the include targets' TXT records to the --file input for a full count.", "SPF"))
    for note in notes:
        if note.startswith("no SPF record at"):
            out.append(finding("EML-011", "high", f"SPF include target has no SPF record ({note[17:]})",
                               "An include that returns no SPF record is a permerror (RFC 7208 5.2).",
                               "Remove the include or fix the target name.", "SPF"))
    return out, lookups


# ---------------------------------------------------------------- DMARC

def parse_tags(record: str) -> Dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags.setdefault(k.strip().lower(), v.strip())
    return tags


def check_dmarc(records: List[str]) -> List[Dict[str, str]]:
    if not records:
        return [finding("DMR-001", "high", "No DMARC record",
                        "Nothing tells receivers what to do with mail that fails SPF and DKIM, so the From address can be spoofed.",
                        "Publish _dmarc TXT: v=DMARC1; p=none; rua=mailto:dmarc@<domain>, read the reports, then move to quarantine and reject.",
                        "DMARC")]
    if len(records) > 1:
        return [finding("DMR-002", "high", "More than one DMARC record",
                        "RFC 7489 and RFC 9989 both say receivers ignore DMARC entirely when several records exist.",
                        "Keep exactly one v=DMARC1 record at _dmarc.", "DMARC")]
    rec = records[0]
    tags = parse_tags(rec)
    out = []
    if not re.match(r"^\s*v\s*=\s*DMARC1\s*(;|$)", rec):
        out.append(finding("DMR-003", "high", "DMARC record does not start with v=DMARC1",
                           "Receivers discard a record whose first tag is not exactly v=DMARC1.",
                           "Start the record with v=DMARC1;", "DMARC"))
    rua_uris = _dmarc_uris(tags.get("rua", ""))
    ruf_uris = _dmarc_uris(tags.get("ruf", ""))
    has_mailto_rua = any(u.lower().startswith("mailto:") for u in rua_uris)
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        if has_mailto_rua:
            out.append(finding("DMR-004", "medium", "DMARC policy tag p is missing or invalid",
                               f"p={p or '(missing)'}. RFC 9989 treats a record with a valid rua but no valid p as p=none, "
                               "so this domain is only monitored. Older RFC 7489 receivers may ignore the record.",
                               "Set p explicitly: p=none while reading reports, then quarantine, then reject.", "DMARC"))
        else:
            out.append(finding("DMR-004", "high", "DMARC policy tag p is missing or invalid",
                               f"p={p or '(missing)'}. Without a valid p or a valid mailto rua the record applies no policy.",
                               "Set p=none to start monitoring, then quarantine, then reject.", "DMARC"))
    elif p == "none":
        out.append(finding("DMR-005", "medium", "DMARC is monitor-only (p=none)",
                           "Spoofed mail that fails DMARC is still delivered.",
                           "Once reports show your real senders pass, move to p=quarantine and then p=reject.", "DMARC"))
    enforcing = p in ("quarantine", "reject")
    sp = tags.get("sp", "").lower()
    if enforcing and sp == "none":
        out.append(finding("DMR-006", "medium", "Subdomain policy is none (sp=none)",
                           "Attackers can spoof any subdomain (billing.<domain>) even though the main domain is protected.",
                           "Remove sp (it inherits p) or set sp=reject.", "DMARC"))
    pct = tags.get("pct")
    if pct is not None:
        try:
            pct_v = int(pct)
        except ValueError:
            pct_v = -1
        if pct_v < 0 or pct_v > 100:
            out.append(finding("DMR-007", "medium", f"DMARC pct is invalid ({pct})",
                               "pct must be an integer from 0 to 100. RFC 9989 removed pct entirely.",
                               "Remove pct (use t=y for a staged rollout instead).", "DMARC"))
        elif pct_v < 100 and enforcing:
            out.append(finding("DMR-008", "low", f"DMARC policy applies to {pct_v}% of failing mail",
                               "Under RFC 7489 the rest of the failing mail gets the next weaker policy. RFC 9989 (May 2026) "
                               "removed pct: updated receivers ignore it and apply the full policy, so behavior now differs "
                               "between receivers.",
                               "Drop pct once the reports look clean. For a staged rollout use t=y (RFC 9989 test mode).",
                               "DMARC"))
    if enforcing and tags.get("t", "").strip().lower() == "y":
        lower = "none" if p == "quarantine" else "quarantine"
        out.append(finding("DMR-010", "low", "DMARC is in test mode (t=y)",
                           f"RFC 9989 test mode tells receivers to apply one level less than p={p}, so failing mail "
                           f"gets {lower} treatment.",
                           "Remove t=y (default n) once the reports show every real sender passes.", "DMARC"))
    np_v = tags.get("np", "").lower()
    if np_v == "none" and enforcing and sp != "none":
        out.append(finding("DMR-011", "medium", "Non-existent subdomain policy is none (np=none)",
                           "np covers subdomains that do not exist in DNS. With np=none an attacker can send as "
                           "random.<domain>, a name nobody watches, while the rest of the domain enforces.",
                           "Remove np (it falls back to sp, then p) or set np=reject.", "DMARC"))
    bad = [u for u in rua_uris + ruf_uris if not u.lower().startswith("mailto:")]
    if bad:
        out.append(finding("DMR-012", "low", "DMARC report address is not a mailto: URI",
                           f"{', '.join(bad[:3])}. Receivers only have to support mailto: and ignore other schemes, "
                           "so these reports are lost.",
                           "Use rua=mailto:<address> (and ruf=mailto:<address> if you want failure reports).", "DMARC"))
    if "rua" not in tags:
        out.append(finding("DMR-009", "low", "No DMARC aggregate reports (rua)",
                           "You cannot see who sends mail as your domain, so moving to enforcement is guesswork.",
                           "Add rua=mailto:dmarc-reports@<domain> or a DMARC report service address.", "DMARC"))
    return out


def _dmarc_uris(value: str) -> List[str]:
    return [u.strip() for u in value.split(",") if u.strip()]


# ---------------------------------------------------------------- DKIM

def _der_read(buf: bytes, pos: int) -> Tuple[int, bytes, int]:
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, buf[pos:pos + length], pos + length


def rsa_key_bits(b64: str) -> int:
    """Modulus size of a DKIM RSA key (SubjectPublicKeyInfo or bare PKCS#1). Raises ValueError if unreadable."""
    try:
        der = base64.b64decode(re.sub(r"\s+", "", b64) + "=" * (-len(b64) % 4))
        tag, body, _ = _der_read(der, 0)
        if tag != 0x30:
            raise ValueError("not a DER sequence")
        tag1, inner, nxt = _der_read(body, 0)
        if tag1 == 0x02:  # PKCS#1 RSAPublicKey: first element is the modulus
            return int.from_bytes(inner, "big").bit_length()
        tag2, bits, _ = _der_read(body, nxt)
        if tag2 != 0x03:
            raise ValueError("no BIT STRING in key")
        _, seq, _ = _der_read(bits[1:], 0)
        tag3, modulus, _ = _der_read(seq, 0)
        if tag3 != 0x02:
            raise ValueError("no modulus in key")
        return int.from_bytes(modulus, "big").bit_length()
    except (IndexError, binascii.Error) as err:
        raise ValueError(f"cannot parse key: {err}")


def check_dkim(selectors: Dict[str, str], looked_up: bool = False) -> List[Dict[str, str]]:
    out = []
    if not selectors:
        if looked_up:
            out.append(finding("DKM-001", "info", "No DKIM key found at the selectors tried",
                               "DKIM selectors cannot be listed from DNS. The domain may still sign with another selector.",
                               "Check a real message's DKIM-Signature header for s=<selector> and rerun with --selector.", "DKIM"))
        return out
    for sel, rec in sorted(selectors.items()):
        loc = f"DKIM {sel}"
        tags = parse_tags(rec)
        key = re.sub(r"\s+", "", tags.get("p", ""))
        if "p" in tags and key == "":
            out.append(finding("DKM-002", "info", f"Selector {sel} is revoked (empty p=)",
                               "An empty key means this selector was retired on purpose.",
                               "Nothing to do unless mail still signs with it.", loc))
            continue
        if not key:
            out.append(finding("DKM-003", "high", f"Selector {sel} has no p= key",
                               "Without a public key every signature with this selector fails.",
                               "Publish the key from your mail provider.", loc))
            continue
        if tags.get("k", "rsa").lower() == "rsa":
            try:
                bits = rsa_key_bits(key)
            except ValueError as err:
                out.append(finding("DKM-004", "medium", f"Selector {sel} key cannot be parsed",
                                   str(err), "Re-copy the key from your mail provider; TXT strings may have been split wrong.", loc))
                bits = None
            if bits is not None and bits < 1024:
                out.append(finding("DKM-005", "high", f"Selector {sel} RSA key is {bits} bits",
                                   "RFC 8301 requires verifiers to reject keys under 1024 bits; short keys can be factored.",
                                   "Rotate to a 2048-bit key.", loc))
            elif bits is not None and bits < 2048:
                out.append(finding("DKM-006", "medium", f"Selector {sel} RSA key is {bits} bits",
                                   "1024-bit RSA is the legal minimum and falling behind; RFC 8301 says signers should use 2048.",
                                   "Rotate to a 2048-bit key at your mail provider.", loc))
        flags = [f.strip() for f in tags.get("t", "").split(":")]
        if "y" in flags:
            out.append(finding("DKM-007", "low", f"Selector {sel} is in test mode (t=y)",
                               "Receivers may treat signatures from a testing key as unsigned.",
                               "Drop t=y once signing works.", loc))
    return out


# ---------------------------------------------------------------- MTA-STS / TLS-RPT

def parse_sts_policy(text: str) -> Dict[str, object]:
    policy: Dict[str, object] = {"mx": []}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "mx":
            policy["mx"].append(v)  # type: ignore[union-attr]
        else:
            policy[k] = v
    return policy


def check_mta_sts(records: List[str], policy_text: Optional[str] = None) -> List[Dict[str, str]]:
    if not records:
        return [finding("MTS-001", "low", "No MTA-STS record",
                        "Sending servers fall back to opportunistic TLS, which an active attacker can strip.",
                        "Publish _mta-sts TXT 'v=STSv1; id=<date>' and a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt.",
                        "MTA-STS")]
    out = []
    tags = parse_tags(records[0])
    if len(records) > 1:
        out.append(finding("MTS-002", "medium", "More than one MTA-STS record",
                           "RFC 8461 says senders treat several records as no policy.", "Keep a single v=STSv1 record.", "MTA-STS"))
    if not re.match(r"^[A-Za-z0-9]{1,32}$", tags.get("id", "")):
        out.append(finding("MTS-003", "medium", "MTA-STS record has no valid id",
                           "id must be 1-32 letters or digits; senders use it to notice policy changes.",
                           "Set id to something like 20250101T000000.", "MTA-STS"))
    if policy_text is None:
        return out
    pol = parse_sts_policy(policy_text)
    mode = str(pol.get("mode", "")).lower()
    if pol.get("version") != "STSv1" or mode not in ("enforce", "testing", "none"):
        out.append(finding("MTS-004", "medium", "MTA-STS policy file is invalid",
                           f"version={pol.get('version')!r}, mode={mode or '(missing)'}.",
                           "The policy needs 'version: STSv1', 'mode: enforce|testing|none', mx lines and max_age.", "MTA-STS policy"))
    elif mode == "testing":
        out.append(finding("MTS-005", "low", "MTA-STS policy is in testing mode",
                           "Senders report failures but still deliver over plain or unverified TLS.",
                           "Switch to mode: enforce once TLS-RPT reports are clean.", "MTA-STS policy"))
    elif mode == "none":
        out.append(finding("MTS-006", "medium", "MTA-STS policy mode is none",
                           "The policy is switched off.", "Use mode: testing, then enforce.", "MTA-STS policy"))
    if mode in ("enforce", "testing") and not pol["mx"]:
        out.append(finding("MTS-007", "medium", "MTA-STS policy lists no mx hosts",
                           "With no mx patterns no MX can match, so enforce mode would block delivery.",
                           "Add one 'mx:' line per MX host (wildcards like *.mail.example.com are allowed).", "MTA-STS policy"))
    try:
        max_age = int(str(pol.get("max_age", "0")))
    except ValueError:
        max_age = 0
    if max_age < 86400:
        out.append(finding("MTS-008", "low", f"MTA-STS max_age is {max_age}s",
                           "A short max_age lets the cached policy lapse between visits; RFC 8461 suggests weeks.",
                           "Use max_age: 604800 or longer (up to 31557600).", "MTA-STS policy"))
    elif max_age > 31557600:
        out.append(finding("MTS-009", "low", f"MTA-STS max_age is {max_age}s (above the RFC 8461 maximum)",
                           "RFC 8461 caps max_age at 31557600 seconds (about one year). Senders may reject or clamp "
                           "the value, and a mistake in the policy stays cached for a very long time.",
                           "Use max_age: 604800 to 31557600.", "MTA-STS policy"))
    return out


def check_tls_rpt(records: List[str]) -> List[Dict[str, str]]:
    if not records:
        return [finding("TRP-001", "info", "No TLS-RPT record",
                        "You will not hear about TLS delivery failures to your domain.",
                        "Publish _smtp._tls TXT 'v=TLSRPTv1; rua=mailto:tls-reports@<domain>'.", "TLS-RPT")]
    tags = parse_tags(records[0])
    if not tags.get("rua"):
        return [finding("TRP-002", "medium", "TLS-RPT record has no rua",
                        "rua is required; without it no reports are sent.",
                        "Add rua=mailto:<address> or rua=https://<endpoint>.", "TLS-RPT")]
    return []


# ---------------------------------------------------------------- BIMI

def check_bimi(records: List[str], dmarc_records: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """BIMI is optional, so this only runs when a record exists (no finding for a missing one).

    dmarc_records None means DMARC was not part of the input, so the DMARC prerequisite is skipped."""
    if not records:
        return []
    out = []
    if len(records) > 1:
        out.append(finding("BIM-004", "medium", "More than one BIMI record",
                           "Mailbox providers ignore BIMI when the selector has several v=BIMI1 records.",
                           "Keep one v=BIMI1 record at default._bimi.", "BIMI"))
    tags = parse_tags(records[0])
    logo = tags.get("l", "")
    if logo and (not logo.lower().startswith("https://") or not logo.lower().split("?")[0].endswith(".svg")):
        out.append(finding("BIM-002", "medium", "BIMI logo is not an HTTPS SVG",
                           f"l={logo}. The logo must be served over HTTPS as an SVG Tiny Portable/Secure file.",
                           "Host the logo as an SVG Tiny PS file at an https:// URL and point l= at it.", "BIMI"))
    elif "l" not in tags:
        out.append(finding("BIM-004", "medium", "BIMI record has no l= tag",
                           "Without l= the record publishes no logo (an empty l= is only valid to opt out).",
                           "Add l=https://<host>/logo.svg, or remove the record.", "BIMI"))
    if logo and not tags.get("a"):
        out.append(finding("BIM-003", "info", "BIMI record has no mark certificate (a=)",
                           "Gmail and Apple Mail only show the logo with a Verified Mark Certificate; Gmail also accepts a "
                           "Common Mark Certificate. Without a= most large providers show nothing.",
                           "Get a VMC or CMC from a mark verifying authority and add a=https://<host>/cert.pem.", "BIMI"))
    if dmarc_records is None:
        return out
    if len(dmarc_records) == 1:
        d = parse_tags(dmarc_records[0])
        p = d.get("p", "").lower()
        sp = d.get("sp", "").lower()
        weak = []
        if p not in ("quarantine", "reject"):
            weak.append(f"p={p or '(missing)'}")
        if sp == "none":
            weak.append("sp=none")
        if d.get("pct", "100").strip() != "100":
            weak.append(f"pct={d.get('pct')}")
        if weak:
            out.append(finding("BIM-001", "medium", "BIMI is published but DMARC is not strong enough for it",
                               f"BIMI needs DMARC at quarantine or reject for the whole domain; found {', '.join(weak)}. "
                               "Providers will not show the logo.",
                               "Move DMARC to p=quarantine or p=reject with no sp=none and no pct below 100.", "BIMI"))
    elif not dmarc_records:
        out.append(finding("BIM-001", "medium", "BIMI is published but there is no DMARC record",
                           "BIMI needs an enforcing DMARC policy (quarantine or reject).",
                           "Publish DMARC and move it to p=quarantine or p=reject.", "BIMI"))
    return out


# ---------------------------------------------------------------- orchestration

def collect_from_pairs(pairs: List[Tuple[Optional[str], str]], domain: Optional[str]) -> Dict[str, object]:
    """Sort parsed records into kinds. The apex SPF is the one at --domain, or one no other SPF includes."""
    spf_pairs = [(n, t) for n, t in pairs if classify(t) == "spf"]
    if domain:
        apex = [t for n, t in spf_pairs if n in (None, domain.lower())]
    else:
        targets = set()
        for _, t in spf_pairs:
            for term in spf_terms(t):
                q, name, value = _term_parts(term)
                if name in ("include", "redirect"):
                    targets.add(value.lower())
        apex = [t for n, t in spf_pairs if n is None or n not in targets]
    rec: Dict[str, object] = {"spf": apex, "dmarc": [], "dkim": {}, "mta_sts": [], "tls_rpt": [], "bimi": []}
    for name, text in pairs:
        kind = classify(text)
        if kind == "dkim":
            sel = name.split("._domainkey")[0] if name and "._domainkey" in name else f"record{len(rec['dkim']) + 1}"
            rec["dkim"][sel] = text  # type: ignore[index]
        elif kind in ("dmarc", "mta_sts", "tls_rpt", "bimi"):
            rec[kind].append(text)  # type: ignore[union-attr]
    return rec


def collect_live(domain: str, selectors: List[str], lookup: Resolver) -> Dict[str, object]:
    pick = lambda name, kind: [t for t in lookup(name) if classify(t) == kind]
    dkim = {}
    for sel in selectors:
        found = [t for t in lookup(f"{sel}._domainkey.{domain}") if classify(t) == "dkim"]
        if found:
            dkim[sel] = found[0]
    return {"spf": pick(domain, "spf"), "dmarc": pick(f"_dmarc.{domain}", "dmarc"), "dkim": dkim,
            "mta_sts": pick(f"_mta-sts.{domain}", "mta_sts"), "tls_rpt": pick(f"_smtp._tls.{domain}", "tls_rpt"),
            "bimi": pick(f"default._bimi.{domain}", "bimi")}


def fetch_sts_policy(domain: str, timeout: float) -> Optional[str]:
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "claude-security-skills-email-auth/1.0"}),
                                    timeout=timeout) as resp:
            return resp.read(65536).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def audit(records: Dict[str, object], checks: set, resolver: Optional[Resolver] = None,
          sts_policy: Optional[str] = None, dkim_looked_up: bool = False) -> Tuple[List[Dict[str, str]], Optional[int]]:
    findings: List[Dict[str, str]] = []
    lookups = None
    if "spf" in checks:
        f, lookups = check_spf(records.get("spf", []), resolver)  # type: ignore[arg-type]
        findings += f
    if "dmarc" in checks:
        findings += check_dmarc(records.get("dmarc", []))  # type: ignore[arg-type]
    if "dkim" in checks:
        findings += check_dkim(records.get("dkim", {}), dkim_looked_up)  # type: ignore[arg-type]
    if "mta_sts" in checks:
        findings += check_mta_sts(records.get("mta_sts", []), sts_policy)  # type: ignore[arg-type]
    if "tls_rpt" in checks:
        findings += check_tls_rpt(records.get("tls_rpt", []))  # type: ignore[arg-type]
    if "bimi" in checks:
        findings += check_bimi(records.get("bimi", []),  # type: ignore[arg-type]
                               records.get("dmarc", []) if "dmarc" in checks else None)  # type: ignore[arg-type]
    findings.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return findings, lookups


def score(findings: List[Dict[str, str]]) -> Tuple[int, str]:
    points = max(0, 100 - sum(SEVERITY_PENALTY[f["severity"]] for f in findings))
    for limit, grade in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if points >= limit:
            return points, grade
    return points, "F"


def render_text(target: str, records, findings, lookups, points, grade) -> str:
    lines = [f"Email auth audit: {target}", f"Score {points}/100, grade {grade}, {len(findings)} finding(s)"]
    if lookups is not None:
        lines.append(f"SPF DNS lookups: {lookups}/10")
    lines.append("")
    for kind in ("spf", "dmarc", "mta_sts", "tls_rpt", "bimi"):
        for r in records.get(kind, []):
            lines.append(f"  {kind:8} {r}")
    for sel, r in records.get("dkim", {}).items():
        lines.append(f"  dkim     {sel}: {r[:70]}{'...' if len(r) > 70 else ''}")
    lines.append("")
    if not findings:
        lines.append("No issues found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Grade SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI records.")
    ap.add_argument("domain", nargs="?", help="domain to look up live with dig (read-only DNS queries)")
    ap.add_argument("--file", help="saved TXT records (dig/zone lines or bare record text); '-' for stdin")
    ap.add_argument("--spf", help="SPF record text")
    ap.add_argument("--dmarc", help="DMARC record text")
    ap.add_argument("--dkim", action="append", default=[], metavar="[SELECTOR=]TEXT", help="DKIM record text (repeatable)")
    ap.add_argument("--mta-sts", help="MTA-STS TXT record text")
    ap.add_argument("--tls-rpt", help="TLS-RPT TXT record text")
    ap.add_argument("--bimi", help="BIMI TXT record text (default._bimi)")
    ap.add_argument("--mta-sts-policy", help="saved mta-sts.txt policy file")
    ap.add_argument("--selector", action="append", default=[], help="DKIM selector to look up live (repeatable)")
    ap.add_argument("--no-policy-fetch", action="store_true", help="live mode: do not fetch the MTA-STS policy over HTTPS")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    inline = {k: getattr(args, k) for k in ("spf", "dmarc", "mta_sts", "tls_rpt", "bimi") if getattr(args, k)}
    if not (args.domain or args.file or inline or args.dkim):
        ap.print_usage(sys.stderr)
        print("error: pass a domain, --file, or record text (--spf/--dmarc/...)", file=sys.stderr)
        return 2

    policy = None
    try:
        if args.mta_sts_policy:
            with open(args.mta_sts_policy, encoding="utf-8", errors="replace") as fh:
                policy = fh.read()
        if args.file:
            raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8", errors="replace").read()
            pairs = parse_record_lines(raw)
            if not any(classify(t) for _, t in pairs):
                print("error: no SPF/DMARC/DKIM/MTA-STS/TLS-RPT/BIMI records found in input", file=sys.stderr)
                return 2
            records = collect_from_pairs(pairs, args.domain)
            resolver = file_resolver(pairs)
            checks = {"spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi"}
            target, dkim_looked_up = args.domain or args.file, False
        elif args.domain and not inline and not args.dkim:
            domain = args.domain.strip().rstrip(".").lower()
            lookup = lambda n: dig_txt(n, args.timeout)
            records = collect_live(domain, args.selector or COMMON_SELECTORS, lookup)
            resolver = lookup
            checks = {"spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi"}
            if records["mta_sts"] and policy is None and not args.no_policy_fetch:
                policy = fetch_sts_policy(domain, args.timeout)
            target, dkim_looked_up = domain, True
        else:
            records = {"spf": [inline["spf"]] if "spf" in inline else [],
                       "dmarc": [inline["dmarc"]] if "dmarc" in inline else [],
                       "mta_sts": [inline["mta_sts"]] if "mta_sts" in inline else [],
                       "tls_rpt": [inline["tls_rpt"]] if "tls_rpt" in inline else [],
                       "bimi": [inline["bimi"]] if "bimi" in inline else [], "dkim": {}}
            for i, item in enumerate(args.dkim, 1):
                sel, sep, text = item.partition("=")
                if sep and re.match(r"^[A-Za-z0-9_.-]+$", sel) and sel.lower() not in ("v", "k", "p", "t", "h", "s", "n"):
                    records["dkim"][sel] = text
                else:
                    records["dkim"][f"cli{i}"] = item
            checks = set(inline) | ({"dkim"} if args.dkim else set())
            resolver, target, dkim_looked_up = None, args.domain or "(record text)", False
    except (OSError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    findings, lookups = audit(records, checks, resolver, policy, dkim_looked_up)
    points, grade = score(findings)
    if args.json:
        print(json.dumps({"target": target, "records": records, "spf_lookups": lookups, "score": points,
                          "grade": grade, "findings": findings}, indent=2))
    else:
        print(render_text(target, records, findings, lookups, points, grade))

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
