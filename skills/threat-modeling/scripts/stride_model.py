#!/usr/bin/env python3
"""Generate a STRIDE threat model, risk flags and a Mermaid data-flow diagram from a system description.

Input is JSON or a small YAML subset with components (id, type, zone, logging),
optional zones (name -> trust level) and data flows (from, to, protocol, auth,
encrypted, data). Element threats follow STRIDE-per-element; flow threats are
generated for flows that cross a trust boundary. Flags call out unauthenticated
boundary crossings, plaintext sensitive data and missing logging.

Usage:
  stride_model.py system.yaml
  stride_model.py system.json --json
  stride_model.py system.yaml --mermaid-only > dfd.mmd
  stride_model.py system.yaml --output threat-model.md --fail-on never
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
COMPONENT_TYPES = {
    "user": "external", "external": "external",
    "web": "process", "api": "process", "mobile": "process", "llm": "process", "service": "process",
    "db": "store", "storage": "store", "queue": "store",
}
DEFAULT_TRUST = {"internet": 0, "public": 0, "external": 0, "third-party": 0, "third_party": 0, "untrusted": 0,
                 "device": 0, "client": 0, "partner": 1, "dmz": 1, "edge": 1, "internal": 2, "corp": 2, "app": 2,
                 "private": 2, "cloud": 2, "data": 3, "restricted": 3, "admin": 3, "secure": 3}
DATA_LEVEL = {"public": 0, "none": 0, "internal": 1, "confidential": 2, "pii": 2, "personal": 2, "financial": 2,
              "secret": 3, "secrets": 3, "credentials": 3, "payment": 3, "pci": 3, "phi": 3, "health": 3,
              "restricted": 3}
ENCRYPTED_PROTOCOLS = {"https", "tls", "mtls", "wss", "sftp", "ssh", "ftps", "grpcs", "amqps", "mqtts", "ldaps",
                       "smtps", "imaps", "ipsec", "wireguard", "vpn", "postgres+tls", "mysql+tls", "redis+tls", "kafka+tls"}
PLAINTEXT_PROTOCOLS = {"http", "ws", "ftp", "telnet", "amqp", "mqtt", "ldap", "tcp", "udp", "smtp", "imap", "pop3",
                       "redis", "memcached", "snmp", "syslog"}
NO_AUTH = {"none", "no", "anonymous", "unauthenticated", "false", "public"}

# ---------------------------------------------------------------- tiny YAML subset


KEY_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_ .-]*?)\s*:(?:\s+(.*))?$")


def _strip_comment(line: str) -> str:
    quote = None
    for idx, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (idx == 0 or line[idx - 1] in " \t"):
            return line[:idx]
    return line


def _scalar(text: str) -> Any:
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        return t[1:-1]
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        return [_scalar(p) for p in inner.split(",")] if inner else []
    low = t.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    return t


def _is_dash(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _parse_block(lines, i, indent):
    if _is_dash(lines[i][1]):
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_list(lines, i, indent):
    out = []
    while i < len(lines) and lines[i][0] == indent and _is_dash(lines[i][1]):
        raw = lines[i][1]
        content = raw[1:].strip()
        if not content:
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                val, i = _parse_block(lines, i + 1, lines[i + 1][0])
                out.append(val)
            else:
                out.append(None)
                i += 1
            continue
        if KEY_RE.match(content) and content[0] not in "[\"'":
            key_indent = indent + 1 + (len(raw) - 1 - len(raw[1:].lstrip()))
            lines[i] = [key_indent, content, lines[i][2]]
            val, i = _parse_map(lines, i, key_indent)
            out.append(val)
            continue
        out.append(_scalar(content))
        i += 1
    return out, i


def _parse_map(lines, i, indent):
    out: Dict[str, Any] = {}
    while i < len(lines) and lines[i][0] == indent and not _is_dash(lines[i][1]):
        content, num = lines[i][1], lines[i][2]
        m = KEY_RE.match(content)
        if not m:
            raise ValueError(f"line {num}: expected 'key: value', got {content!r}")
        key, rest = m.group(1).strip(), m.group(2)
        i += 1
        if rest is None or not rest.strip():
            if i < len(lines) and (lines[i][0] > indent or (lines[i][0] == indent and _is_dash(lines[i][1]))):
                val, i = _parse_block(lines, i, lines[i][0])
            else:
                val = None
        else:
            val = _scalar(rest)
        out[key] = val
    return out, i


def parse_simple_yaml(text: str) -> Any:
    """Parse the small YAML subset used by scope files: maps, lists, scalars, inline [a, b]."""
    lines = []
    for num, raw in enumerate(text.splitlines(), 1):
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip() or stripped.strip() == "---":
            continue
        lead = stripped[: len(stripped) - len(stripped.lstrip())]
        if "\t" in lead:
            raise ValueError(f"line {num}: indent with spaces, not tabs")
        lines.append([len(lead), stripped.strip(), num])
    if not lines:
        return {}
    value, i = _parse_block(lines, 0, lines[0][0])
    if i != len(lines):
        raise ValueError(f"line {lines[i][2]}: unexpected indentation")
    return value



# ---------------------------------------------------------------- model loading


def _as_bool(value) -> Optional[bool]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    v = str(value).strip().lower()
    if v in ("yes", "true", "on", "y", "1"):
        return True
    if v in ("no", "false", "off", "n", "0", "none"):
        return False
    return None


def _labels(value) -> List[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v).strip().lower() for v in value if str(v).strip()]
    return [p.strip().lower() for p in re.split(r"[,;/]", str(value)) if p.strip()]


def load_model(text: str) -> Dict[str, Any]:
    """Parse and validate a system description. Raises ValueError on structural problems."""
    stripped = text.strip()
    if not stripped:
        raise ValueError("model file is empty")
    data = json.loads(stripped) if stripped[0] in "{[" else parse_simple_yaml(stripped)
    if not isinstance(data, dict):
        raise ValueError("model must be a mapping with components and flows")
    warnings: List[str] = []
    trust: Dict[str, int] = {}
    zones = data.get("zones") or {}
    if isinstance(zones, list):
        for z in zones:
            if isinstance(z, dict) and z.get("name") is not None:
                trust[str(z["name"]).lower()] = int(z.get("trust", 2))
    elif isinstance(zones, dict):
        for k, v in zones.items():
            trust[str(k).lower()] = int(v.get("trust", 2)) if isinstance(v, dict) else int(v)
    comps: Dict[str, Dict[str, Any]] = {}
    raw_comps = data.get("components") or []
    if not isinstance(raw_comps, list) or not raw_comps:
        raise ValueError("model needs a non-empty components list")
    for n, c in enumerate(raw_comps, 1):
        if not isinstance(c, dict) or not c.get("id"):
            raise ValueError(f"component #{n} needs an id")
        cid = str(c["id"])
        if cid in comps:
            raise ValueError(f"component id {cid!r} is used twice")
        ctype = str(c.get("type") or "").lower()
        if ctype not in COMPONENT_TYPES:
            raise ValueError(f"component {cid!r}: type must be one of {', '.join(sorted(COMPONENT_TYPES))}")
        zone = str(c.get("zone") or "").lower()
        if not zone:
            zone = "internet" if COMPONENT_TYPES[ctype] == "external" else "internal"
            warnings.append(f"component {cid!r} has no zone, assumed {zone}")
        if zone not in trust:
            if zone in DEFAULT_TRUST:
                trust[zone] = DEFAULT_TRUST[zone]
            else:
                trust[zone] = 2
                warnings.append(f"zone {zone!r} has no trust level, assumed 2 (internal); list it under zones")
        comps[cid] = {"id": cid, "name": str(c.get("name") or cid), "type": ctype, "kind": COMPONENT_TYPES[ctype],
                      "zone": zone, "logging": _as_bool(c.get("logging")), "notes": str(c.get("notes") or "")}
    flows = []
    for n, f in enumerate(data.get("flows") or [], 1):
        if not isinstance(f, dict) or not f.get("from") or not f.get("to"):
            raise ValueError(f"flow #{n} needs from and to")
        src, dst = str(f["from"]), str(f["to"])
        for end in (src, dst):
            if end not in comps:
                raise ValueError(f"flow #{n} ({src} -> {dst}) points at unknown component {end!r}")
        auth_raw = f.get("auth")
        flows.append({"id": str(f.get("id") or f.get("name") or ""), "from": src, "to": dst,
                      "protocol": str(f.get("protocol") or "").lower(),
                      "auth": "" if auth_raw is None else ("none" if auth_raw is False else
                                                           "yes" if auth_raw is True else str(auth_raw).lower()),
                      "encrypted": _as_bool(f.get("encrypted")), "data": _labels(f.get("data")),
                      "label": str(f.get("label") or f.get("name") or "")})
    if not flows:
        warnings.append("model has no flows; only element threats are generated")
    _key_flows(flows)
    return {"name": str(data.get("name") or "System"), "trust": trust, "components": comps, "flows": flows,
            "warnings": warnings}


def _key_flows(flows: List[Dict[str, Any]]) -> None:
    """Give each flow a stable key: its id, or from->to (with a counter when a pair repeats)."""
    seen: Dict[str, int] = {}
    for f in flows:
        base = f["id"] or f"{f['from']}->{f['to']}"
        seen[base] = seen.get(base, 0) + 1
        f["key"] = base if seen[base] == 1 else f"{base}#{seen[base]}"


def analyze_flow(flow: Dict[str, Any], model: Dict[str, Any]) -> Dict[str, Any]:
    """Derived facts for a flow: boundary crossing, direction, encryption, auth, data sensitivity."""
    comps, trust = model["components"], model["trust"]
    src, dst = comps[flow["from"]], comps[flow["to"]]
    t_src, t_dst = trust[src["zone"]], trust[dst["zone"]]
    enc = flow["encrypted"]
    if enc is None:
        proto = flow["protocol"]
        if proto in ENCRYPTED_PROTOCOLS or proto.endswith("+tls") or proto.endswith("s+tls"):
            enc = True
        elif proto in PLAINTEXT_PROTOCOLS:
            enc = False
    auth = flow["auth"]
    authenticated = None if not auth else (False if auth in NO_AUTH else True)
    levels = [DATA_LEVEL.get(d, 1) for d in flow["data"]]
    level = max(levels) if levels else 1
    return {"key": flow["key"], "from": src["id"], "to": dst["id"], "from_zone": src["zone"], "to_zone": dst["zone"],
            "crosses_boundary": src["zone"] != dst["zone"], "inbound": t_dst > t_src,
            "from_trust": t_src, "to_trust": t_dst, "encrypted": enc, "authenticated": authenticated,
            "data_level": level, "sensitive": level >= 2, "data": flow["data"], "protocol": flow["protocol"],
            "auth": auth}


# ---------------------------------------------------------------- threat catalog

def _sev(likelihood: int, impact: int) -> str:
    """Generic STRIDE threats: 9 high, 4-6 medium, 1-3 low (flags carry the sharper signal)."""
    score = likelihood * impact
    return "high" if score >= 9 else "medium" if score >= 4 else "low"


def _impact_for(level: int) -> int:
    return {0: 1, 1: 2, 2: 3, 3: 3}[level]


def threat(rule, stride, title, detail, fix, location, likelihood, impact, kind="threat", severity=None):
    likelihood, impact = max(1, min(3, likelihood)), max(1, min(3, impact))
    return {"id": rule, "severity": severity or _sev(likelihood, impact), "title": title, "detail": detail,
            "fix": fix, "location": location, "kind": kind, "stride": stride,
            "likelihood": likelihood, "impact": impact}


PROCESS_THREATS = [
    ("STR-S01", "S", "Caller identity spoofed", "A caller of {name} pretends to be another user or service.",
     "Authenticate every inbound request (sessions/OIDC for users, mTLS or signed tokens for services); never trust source IP alone."),
    ("STR-T01", "T", "Input tampering and injection", "Untrusted input changes what {name} does (SQL/command/template injection, mass assignment).",
     "Validate input against an allow-list schema, use parameterized queries, encode output for its context."),
    ("STR-R01", "R", "Actions cannot be traced", "Without audit logs nobody can show who did what through {name}.",
     "Log actor, action, target, time and source to an append-only store with synced clocks; alert on log gaps."),
    ("STR-I01", "I", "Data leaks through responses or errors", "{name} returns more than needed: stack traces, internal fields, other users' records.",
     "Return explicit response schemas, generic errors, and check object ownership before returning data."),
    ("STR-D01", "D", "Resource exhaustion", "Floods or expensive requests take {name} down.",
     "Rate limits per user and IP, timeouts, request size caps, autoscaling with budget alarms."),
    ("STR-E01", "E", "Missing authorization", "A normal user reaches admin functions or other tenants' data through {name}.",
     "Deny by default; check role and object ownership server-side on every request; test it with two accounts."),
]
TYPE_THREATS = {
    "web": [
        ("WEB-T01", "T", "Cross-site scripting", "User content rendered by {name} runs as script in other users' browsers.",
         "Context-aware output encoding, a strict Content-Security-Policy, no raw HTML sinks (innerHTML, v-html)."),
        ("WEB-E01", "E", "Cross-site request forgery", "Another site makes a logged-in user's browser send state-changing requests to {name}.",
         "SameSite=Lax or Strict session cookies plus CSRF tokens or Origin checks on state-changing requests."),
    ],
    "api": [
        ("API-E01", "E", "Broken object level authorization", "Swapping an id in a request to {name} returns or changes another user's object.",
         "Scope every query by the caller's identity or tenant; never trust ids from the client alone."),
    ],
    "mobile": [
        ("MOB-I01", "I", "Sensitive data stored on the device", "{name} keeps tokens or personal data in plain files, logs or backups.",
         "Store secrets in the Keychain / Android Keystore, exclude sensitive files from backups, no secrets in logs."),
        ("MOB-T01", "T", "Client modified or repackaged", "An attacker patches {name} to skip client-side checks or calls its backend directly.",
         "Enforce every rule server-side; treat the app as untrusted; use platform attestation where it matters."),
    ],
    "llm": [
        ("LLM-T01", "T", "Prompt injection", "Text from users, documents, web pages or tool results steers {name} into ignoring its instructions.",
         "Treat all model input as untrusted, keep instructions and data separate, filter tool output, require confirmation for risky actions."),
        ("LLM-I01", "I", "Sensitive data disclosed by the model", "{name} reveals system prompts, other users' data or secrets placed in its context.",
         "Keep secrets out of prompts, filter retrieval by the caller's permissions, scan outputs for sensitive data."),
        ("LLM-E01", "E", "Excessive agency", "{name} can call tools or APIs with more rights than the user who asked.",
         "Give tools least privilege and the end user's permissions, allow-list actions, human approval for destructive or costly ones."),
        ("LLM-D01", "D", "Cost and token exhaustion", "Long or looping requests to {name} burn tokens and money or block other users.",
         "Per-user token and request quotas, max input and output length, loop limits on agents, spend alerts."),
    ],
}
STORE_THREATS = [
    ("STR-T10", "T", "Stored data tampered with", "Someone with write access, or an injection upstream, changes records in {name}.",
     "Least-privilege service accounts, no shared admin credentials, integrity checks or audit tables, tested backups."),
    ("STR-I10", "I", "Stored data disclosed", "{name} is read by someone who should not see it (stolen credentials, misconfigured access, backups).",
     "Encryption at rest with managed keys, network restriction, per-service accounts, encrypted backups."),
    ("STR-D10", "D", "Data store unavailable or lost", "{name} fills up, is deleted or is encrypted by ransomware.",
     "Capacity alerts, replicas, point-in-time recovery, immutable backups with tested restores."),
]
STORE_TYPE_THREATS = {
    "storage": [("STO-I01", "I", "Publicly readable objects", "Objects or listings in {name} are reachable without credentials.",
                 "Block public access at account level, use short-lived signed URLs for sharing, alert on policy changes.")],
    "queue": [
        ("Q-S01", "S", "Forged messages", "Anyone who can reach {name} publishes messages that consumers trust.",
         "Authenticate publishers, restrict topics per producer, sign or validate message payloads."),
        ("Q-D01", "D", "Poison or flood messages", "Malformed or huge messages in {name} crash or stall consumers.",
         "Schema validation in consumers, size limits, dead-letter queues, retry limits."),
    ],
}
EXTERNAL_THREATS = [
    ("STR-S20", "S", "Entity impersonated", "Someone pretends to be {name} (stolen password, forged webhook, fake partner).",
     "MFA for people, signed requests or mTLS for systems, verify webhook signatures and timestamps."),
    ("STR-R20", "R", "Entity denies an action", "{name} claims it never made a request or approved a change.",
     "Keep signed or authenticated audit records with timestamps; send receipts for important actions."),
]
FLOW_THREATS = [
    ("STR-T30", "T", "Data modified in transit", "Traffic on {name} is altered by someone on the network path.",
     "TLS 1.2+ with certificate validation (mTLS between services), signed payloads for high-value messages."),
    ("STR-I30", "I", "Data read in transit", "Traffic on {name} is captured on the network path.",
     "Encrypt in transit, keep secrets and personal data out of URLs and query strings."),
    ("STR-D30", "D", "Flow interrupted or flooded", "{name} is blocked or flooded, so the receiving side stalls.",
     "Timeouts, retries with backoff, rate limits and circuit breakers on the receiving side."),
]


def element_threats(model, analyses) -> List[Dict[str, Any]]:
    out = []
    trust = model["trust"]
    for c in model["components"].values():
        inbound = [a for a in analyses if a["to"] == c["id"]]
        touching = [a for a in analyses if a["to"] == c["id"] or a["from"] == c["id"]]
        exposed = trust[c["zone"]] == 0 or any(a["from_trust"] == 0 and a["crosses_boundary"] for a in inbound)
        base = 3 if exposed else 2 if any(a["crosses_boundary"] for a in inbound) else 1
        level = max([a["data_level"] for a in touching], default=1)
        imp = _impact_for(level)
        unauth_in = any(a["crosses_boundary"] and a["authenticated"] is False for a in inbound)
        loc = f"{c['name']} ({c['type']}, {c['zone']})"
        fmt = lambda s: s.format(name=c["name"])
        if c["kind"] == "external":
            for rule, letter, title, detail, fix in EXTERNAL_THREATS:
                lik = 2
                if rule == "STR-S20" and any(a["from"] == c["id"] and a["authenticated"] is False for a in analyses):
                    lik = 3
                out.append(threat(rule, letter, title, fmt(detail), fix, loc, lik, imp))
            if c["type"] == "external" and any(a["to"] == c["id"] and a["sensitive"] for a in analyses):
                out.append(threat("EXT-I01", "I", "Sensitive data shared with a third party",
                                  f"{c['name']} receives sensitive data; its breach is your breach.",
                                  "Data processing agreement, send the minimum fields, check the vendor's security report (SOC 2 / ISO).",
                                  loc, 2, 3))
            continue
        if c["kind"] == "process":
            for rule, letter, title, detail, fix in PROCESS_THREATS:
                if rule == "STR-D01" and c["type"] in ("llm",):
                    continue  # covered by LLM-D01
                lik = base
                if rule == "STR-S01" and unauth_in:
                    lik = 3
                if rule == "STR-R01":
                    lik = {False: 3, None: 2, True: 1}[c["logging"]]
                out.append(threat(rule, letter, title, fmt(detail), fix, loc, lik, imp))
            for rule, letter, title, detail, fix in TYPE_THREATS.get(c["type"], []):
                lik = base
                if rule == "LLM-T01":
                    lik = max(base, 2)
                if rule == "LLM-E01":
                    calls = [a for a in analyses if a["from"] == c["id"]
                             and model["components"][a["to"]]["kind"] in ("process", "store", "external")]
                    lik = 3 if calls else 1
                out.append(threat(rule, letter, title, fmt(detail), fix, loc, lik, imp))
            continue
        # data stores
        for rule, letter, title, detail, fix in STORE_THREATS + STORE_TYPE_THREATS.get(c["type"], []):
            lik = base
            if rule == "Q-S01" and any(a["authenticated"] is False for a in inbound):
                lik = 3
            out.append(threat(rule, letter, title, fmt(detail), fix, loc, lik, imp))
    return out


def flow_threats(model, analyses) -> List[Dict[str, Any]]:
    out = []
    for a in analyses:
        if not a["crosses_boundary"]:
            continue
        loc = f"flow {a['key']} ({a['from_zone']} -> {a['to_zone']})"
        imp = _impact_for(a["data_level"])
        for rule, letter, title, detail, fix in FLOW_THREATS:
            lik = 2
            if rule in ("STR-T30", "STR-I30"):
                lik = {True: 1, None: 2, False: 3}[a["encrypted"]]
            out.append(threat(rule, letter, title, detail.format(name=a["key"]), fix, loc, lik,
                              imp if rule != "STR-D30" else 2))
    return out


def flags(model, analyses) -> List[Dict[str, Any]]:
    """High-signal design problems, separate from the generic STRIDE list."""
    out = []
    comps, trust = model["components"], model["trust"]

    def flag(rule, severity, title, detail, fix, location):
        out.append({"id": rule, "severity": severity, "title": title, "detail": detail, "fix": fix,
                    "location": location, "kind": "flag", "stride": "", "likelihood": None, "impact": None})

    for a in analyses:
        loc = f"flow {a['key']} ({a['from_zone']} -> {a['to_zone']})"
        data = ", ".join(a["data"]) or "unclassified"
        if a["crosses_boundary"] and a["inbound"] and a["authenticated"] is False:
            public = a["data_level"] == 0
            flag("FLOW-001", "low" if public else "high", "Unauthenticated flow into a more trusted zone",
                 f"{a['from']} -> {a['to']} crosses from {a['from_zone']} (trust {a['from_trust']}) to {a['to_zone']} "
                 f"(trust {a['to_trust']}) with no authentication. Data: {data}.",
                 "Authenticate the caller (user session, OAuth token, mTLS, signed webhook) or document why the endpoint is public.",
                 loc)
        if a["encrypted"] is False and a["sensitive"]:
            internet = a["crosses_boundary"] and min(a["from_trust"], a["to_trust"]) == 0
            flag("FLOW-002", "critical" if internet else "high", "Sensitive data sent in plaintext",
                 f"{a['from']} -> {a['to']} carries {data} over {a['protocol'] or 'an unencrypted channel'}"
                 + (" across the internet." if internet else "."),
                 "Switch to TLS 1.2+ (or mTLS internally); for databases and queues turn on their TLS mode.", loc)
        elif a["encrypted"] is False and a["crosses_boundary"]:
            flag("FLOW-003", "medium", "Plaintext flow crosses a trust boundary",
                 f"{a['from']} -> {a['to']} uses {a['protocol'] or 'no encryption'} between {a['from_zone']} and {a['to_zone']}.",
                 "Encrypt it; data that looks harmless today (ids, tokens in headers) often is not.", loc)
        if a["crosses_boundary"] and a["inbound"] and a["authenticated"] is None:
            flag("FLOW-004", "low", "Authentication not stated for a boundary crossing",
                 f"{a['from']} -> {a['to']} enters a more trusted zone but the model does not say how it is authenticated.",
                 "Add auth: (session, oauth, mtls, apikey, iam, none) to the flow.", loc)
        if a["crosses_boundary"] and a["sensitive"] and a["encrypted"] is None:
            flag("FLOW-005", "low", "Encryption not stated for sensitive data",
                 f"{a['from']} -> {a['to']} carries {data} and the model does not say whether it is encrypted "
                 f"(protocol: {a['protocol'] or 'not given'}).",
                 "Add protocol: (https, mtls, postgres+tls...) or encrypted: yes/no.", loc)
        if comps[a["to"]]["kind"] == "store" and a["from_trust"] == 0 and comps[a["from"]]["kind"] != "store":
            flag("FLOW-006", "high", "Data store reached directly from an untrusted zone",
                 f"{a['from']} in {a['from_zone']} talks straight to {a['to']} with no service in between.",
                 "Put an API that authenticates and authorizes each request in front of the store; use short-lived scoped credentials if direct access is required.",
                 loc)
    for c in comps.values():
        loc = f"{c['name']} ({c['type']}, {c['zone']})"
        if c["kind"] == "external":
            continue
        crossing_in = any(a["to"] == c["id"] and a["crosses_boundary"] for a in analyses)
        if c["logging"] is False:
            flag("ELEM-001", "medium" if crossing_in else "low", "Security logging is off",
                 f"{c['name']} has logging: no" + (" and receives traffic from another trust zone." if crossing_in else "."),
                 "Log authentication, authorization failures and admin or data-changing actions to a central store.", loc)
        elif c["logging"] is None and crossing_in:
            flag("ELEM-001", "low", "Logging not stated",
                 f"{c['name']} receives traffic from another trust zone but the model does not say it logs security events.",
                 "Add logging: yes/no to the component and confirm what gets logged.", loc)
        if c["kind"] == "store" and trust[c["zone"]] <= 1:
            flag("ELEM-002", "high", "Data store in a low-trust zone",
                 f"{c['name']} sits in {c['zone']} (trust {trust[c['zone']]}).",
                 "Move data stores into a private zone reachable only from the services that need them.", loc)
        if not any(a["to"] == c["id"] or a["from"] == c["id"] for a in analyses):
            flag("ELEM-003", "info", "Component has no data flows",
                 f"{c['name']} is not connected to anything in the model.",
                 "Add its flows or remove it; unmodelled flows are where surprises live.", loc)
    return out


def build(model) -> Dict[str, Any]:
    analyses = [analyze_flow(f, model) for f in model["flows"]]
    flagged = flags(model, analyses)
    threats = element_threats(model, analyses) + flow_threats(model, analyses)
    findings = flagged + threats
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f["kind"] != "flag"))
    by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in reversed(SEVERITY_ORDER)}
    return {"name": model["name"], "analyses": analyses, "findings": findings, "warnings": model["warnings"],
            "summary": {"components": len(model["components"]), "flows": len(model["flows"]),
                        "boundary_crossings": sum(1 for a in analyses if a["crosses_boundary"]),
                        "flags": len(flagged), "threats": len(threats), "by_severity": by_sev},
            "mermaid": mermaid(model, analyses, flagged)}


# ---------------------------------------------------------------- rendering


def _mid(text: str) -> str:
    """Mermaid-safe node id; the prefix avoids reserved words such as end or graph."""
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", text)


def _mlabel(text: str) -> str:
    return text.replace('"', "#quot;")


SHAPES = {"user": '(["{}"])', "external": '["{}"]', "db": '[("{}")]', "storage": '[("{}")]', "queue": '[["{}"]]'}


def mermaid(model, analyses, flagged) -> str:
    comps, trust = model["components"], model["trust"]
    lines = ["flowchart LR"]
    zones = sorted({c["zone"] for c in comps.values()}, key=lambda z: (trust[z], z))
    for z in zones:
        lines.append(f'  subgraph zone_{re.sub(r"[^A-Za-z0-9_]", "_", z)}["{_mlabel(z)} (trust {trust[z]})"]')
        for c in comps.values():
            if c["zone"] == z:
                shape = SHAPES.get(c["type"], '("{}")')
                lines.append(f"    {_mid(c['id'])}{shape.format(_mlabel(c['name']))}")
        lines.append("  end")
    bad_keys = {f["location"][5:].rsplit(" (", 1)[0] for f in flagged
                if f["id"] in ("FLOW-001", "FLOW-002", "FLOW-003", "FLOW-006") and f["severity"] != "low"}
    red = []
    for n, a in enumerate(analyses):
        parts = [p for p in (a["protocol"].upper() if a["protocol"] else "",
                             ("auth: " + a["auth"]) if a["auth"] else "", ", ".join(a["data"])) if p]
        label = " / ".join(parts)
        arrow = f' -->|"{_mlabel(label)}"| ' if label else " --> "
        lines.append(f"  {_mid(a['from'])}{arrow}{_mid(a['to'])}")
        if a["key"] in bad_keys:
            red.append(n)
    if red:
        lines.append(f"  linkStyle {','.join(map(str, red))} stroke:#d62728,stroke-width:2px")
    return "\n".join(lines)


def _cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(result) -> str:
    s = result["summary"]
    sev = ", ".join(f"{n} {k}" for k, n in s["by_severity"].items() if n)
    L = [f"# Threat model: {result['name']}", "",
         f"{s['components']} components, {s['flows']} flows, {s['boundary_crossings']} cross a trust boundary. "
         f"{s['flags']} design flags and {s['threats']} STRIDE threats ({sev or 'none'}).", "",
         "## Data-flow diagram", "", "```mermaid", result["mermaid"], "```", "",
         "Red arrows carry a medium or worse flag below.", "", "## Design flags", ""]
    fl = [f for f in result["findings"] if f["kind"] == "flag"]
    if fl:
        L += ["| Severity | ID | Where | Issue | Fix |", "|---|---|---|---|---|"]
        L += [f"| {f['severity']} | {f['id']} | {_cell(f['location'])} | {_cell(f['title'] + ': ' + f['detail'])} | {_cell(f['fix'])} |" for f in fl]
    else:
        L.append("None.")
    L += ["", "## STRIDE threats", "",
          "L and I are 1-3 defaults derived from exposure and data sensitivity; adjust them in the session.", "",
          "| Severity | ID | Where | STRIDE | Threat | L | I | Mitigation |", "|---|---|---|---|---|---|---|---|"]
    for f in result["findings"]:
        if f["kind"] != "threat":
            continue
        L.append(f"| {f['severity']} | {f['id']} | {_cell(f['location'])} | {f['stride']} | "
                 f"{_cell(f['title'] + ': ' + f['detail'])} | {f['likelihood']} | {f['impact']} | {_cell(f['fix'])} |")
    if result["warnings"]:
        L += ["", "## Assumptions", ""] + [f"- {w}" for w in result["warnings"]]
    L += ["", "## Next", "",
          "- Mark each threat: mitigated (name the control), to do (owner, date), accepted (who), not applicable (why)",
          "- Re-run after design changes and compare with `model_diff.py`"]
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="STRIDE threats, design flags and a Mermaid DFD from a system description.")
    ap.add_argument("file", help="system description (JSON or simple YAML); '-' for stdin")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--mermaid-only", action="store_true", help="print only the Mermaid diagram")
    ap.add_argument("--output", help="write the Markdown report to this file")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any flag or threat is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    try:
        text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
        model = load_model(text)
    except (OSError, ValueError, json.JSONDecodeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    result = build(model)
    if args.json:
        print(json.dumps({k: result[k] for k in ("name", "summary", "warnings", "findings", "mermaid")}
                         | {"flows": result["analyses"]}, indent=2))
    elif args.mermaid_only:
        print(result["mermaid"])
    else:
        md = render_markdown(result)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(md)
            print(f"wrote {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(md)
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
