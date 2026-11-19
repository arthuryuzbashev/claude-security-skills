#!/usr/bin/env python3
"""Triage auth, web, cloud and JSON logs fast: brute force, spraying, scanners,
injection probes, risky cloud sign-ins and audit tampering.

Auto-detects each line: Linux auth.log / secure (sshd, sudo), nginx/apache
combined or common access logs, AWS CloudTrail records (one per line or a
whole {"Records": [...]} file on one line), Microsoft Entra ID sign-in logs
(Log Analytics / Sentinel export, Graph API signIns, Azure diagnostic export)
and generic JSON lines (map field names with --field). Prints a summary,
findings and top talkers.

Usage:
  log_triage.py /var/log/auth.log
  log_triage.py access.log --json
  log_triage.py events.jsonl --field ip=source.ip --field user=user.name --field outcome=event.outcome
  zcat auth.log.2.gz | log_triage.py --file - --year 2026 --fail-on medium
  log_triage.py auth.log --sudo-users alice,ops --window 600 --brute-threshold 20
  log_triage.py cloudtrail.jsonl --fail-on high
  log_triage.py entra_signins.jsonl --mfa-threshold 5
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional
from urllib.parse import unquote_plus, urlsplit, parse_qsl

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

RE_SYSLOG = re.compile(
    r"^(?:(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+(?P<host>\S+)\s+(?P<prog>[\w./-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")
RE_SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
RE_SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
RE_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.*)$")
RE_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+|-)(?: (?P<path>\S+))?(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')

SCANNER_UA = re.compile(r"(sqlmap|nikto|nuclei|wpscan|masscan|zgrab|gobuster|dirbuster|feroxbuster|ffuf|wfuzz|acunetix|nessus|openvas|nmap scripting engine|whatweb|joomscan|hydra)", re.I)
SENSITIVE_PATHS = re.compile(
    r"(/\.env\b|/\.git(/|$)|/\.svn/|/\.hg/|/\.aws/|/\.ssh/|/\.htpasswd|/\.htaccess|/\.ds_store|/id_rsa|"
    r"/wp-admin|/wp-login\.php|/xmlrpc\.php|/phpmyadmin|/pma/|/server-status|/server-info|/actuator|"
    r"/vendor/phpunit|/cgi-bin/|/config\.(php|json|yml|yaml)|/web\.config|/backup|\.(sql|bak|old|swp)$|/boaform|/console/?$|/manager/html)", re.I)
EXPOSURE_PATHS = re.compile(r"(/\.env\b|/\.git/|/\.aws/|/\.ssh/|/\.htpasswd|/id_rsa|\.sql$|\.bak$)", re.I)
SQLI = re.compile(
    r"(union(\s|/\*.*?\*/)+(all(\s|/\*.*?\*/)+)?select\b|'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|"
    r"\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\bwaitfor\s+delay\b|information_schema|\bextractvalue\s*\(|"
    r"\bupdatexml\s*\(|;\s*(drop|shutdown|truncate)\s|'\s*(--|#)|\bselect\s.+\sfrom\s)", re.I)
XSS = re.compile(r"(<\s*script|javascript\s*:|\bon(error|load|mouseover|focus|click)\s*=|<\s*svg[\s/>]|<\s*iframe|<\s*img[^>]+src|alert\s*\(|document\.cookie|prompt\s*\()", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e|\.\.%2f|%c0%ae|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|/proc/self/)", re.I)
SECRET_PARAM = re.compile(r"(token|key|secret|pass(word)?|pwd|sig(nature)?|session|auth|code)", re.I)

DEFAULT_FIELDS = {
    "ts": ["@timestamp", "timestamp", "time", "ts", "date", "eventTime"],
    "ip": ["source.ip", "src_ip", "client_ip", "clientip", "remote_addr", "ip", "src", "ipAddress", "sourceIPAddress"],
    "user": ["user.name", "user", "username", "userName", "account", "usr"],
    "outcome": ["event.outcome", "outcome", "result", "status_text", "action"],
    "path": ["url.original", "url.path", "request_uri", "uri", "path", "url", "request"],
    "method": ["http.request.method", "method", "verb"],
    "status": ["http.response.status_code", "status", "status_code", "response"],
    "ua": ["user_agent.original", "user_agent", "http_user_agent", "ua", "useragent"],
}


# Entra ID sign-in result codes (AADSTS numbers without the prefix).
ENTRA_PASSWORD_FAIL = {"50126": "invalid username or password", "50053": "account locked or sign-in blocked",
                       "50034": "account not found", "50055": "password expired",
                       "50056": "invalid or null password", "50057": "account disabled"}
ENTRA_MFA_DENIED = {"500121"}
ENTRA_MFA_INTERRUPT = {"50074", "50076", "50079", "50072", "50158"}
CLOUDTRAIL_TAMPER = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "PutInsightSelectors",
                     "DeleteEventDataStore", "StopEventDataStoreIngestion"}
CLOUDTRAIL_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                     "Client.UnauthorizedOperation", "UnauthorizedAccess"}
CLOUDTRAIL_CRED_EVENTS = {"CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile"}


def finding(fid, severity, title, detail, fix, location=None):
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def mask_path(path: str) -> str:
    """Mask secret-looking query values (first 4 chars kept)."""
    if not path or "?" not in path:
        return path
    base, query = path.split("?", 1)
    parts = []
    for k, v in parse_qsl(query, keep_blank_values=True):
        if SECRET_PARAM.search(k) and len(v) > 4:
            v = v[:4] + "..."
        parts.append(f"{k}={v}")
    return base + "?" + "&".join(parts) if parts else path


# ---------------------------------------------------------------- parsing

def _parse_ts(s: str) -> Optional[datetime]:
    s = s.strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            d = datetime.strptime(s.replace("Z", "+0000") if s.endswith("Z") else s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:  # epoch seconds or milliseconds
        v = float(s)
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_syslog(line: str, year: int) -> Optional[Dict]:
    m = RE_SYSLOG.match(line)
    if not m:
        return None
    if m.group("iso"):
        ts = _parse_ts(m.group("iso"))
    else:
        try:
            ts = datetime.strptime(f"{year} {MONTHS[m.group('mon')]} {m.group('day')} {m.group('time')}",
                                   "%Y %m %d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            ts = None
    prog, msg = m.group("prog"), m.group("msg")
    base = {"ts": ts, "host": m.group("host"), "prog": prog}
    if prog.startswith("sshd"):
        f = RE_SSH_FAIL.search(msg)
        if f:
            return dict(base, kind="auth", outcome="failed", user=f.group("user") or "?", ip=f.group("ip"))
        a = RE_SSH_OK.search(msg)
        if a:
            return dict(base, kind="auth", outcome="accepted", user=a.group("user"), ip=a.group("ip"), method=a.group("method"))
        return dict(base, kind="other")
    if prog == "sudo":
        s = RE_SUDO.match(msg)
        if s and "pam_unix" not in msg:
            rest = s.group("rest")
            fields = dict(p.split("=", 1) for p in (x.strip() for x in rest.split(";")) if "=" in p)
            denied = ("NOT in sudoers" in rest or "incorrect password" in rest
                      or "command not allowed" in rest)
            return dict(base, kind="sudo", user=s.group("user"), target=fields.get("USER", "root"),
                        command=fields.get("COMMAND", ""), ok=not denied, reason=rest.split(";")[0].strip() if denied else "")
        return dict(base, kind="other")
    return dict(base, kind="other")


def parse_access(line: str) -> Optional[Dict]:
    m = RE_ACCESS.match(line)
    if not m:
        return None
    return {"kind": "web", "ts": _parse_ts(m.group("ts")), "ip": m.group("ip"), "method": m.group("method"),
            "path": m.group("path") or "", "status": int(m.group("status")), "ua": m.group("ua") or "",
            "user": None if m.group("user") == "-" else m.group("user")}


def _get(obj, dotted: str):
    if dotted in obj:
        return obj[dotted]
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def parse_json(line: str, fields: Dict[str, List[str]]) -> Optional[Dict]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    vals = {}
    for key, candidates in fields.items():
        for c in candidates:
            v = _get(obj, c)
            if v not in (None, ""):
                vals[key] = v
                break
    ts = _parse_ts(str(vals["ts"])) if "ts" in vals else None
    ip = str(vals["ip"]) if "ip" in vals else None
    user = str(vals["user"]) if "user" in vals else None
    if "path" in vals:
        try:
            status = int(vals.get("status", 0))
        except (TypeError, ValueError):
            status = 0
        path = str(vals["path"])
        if path.startswith(("http://", "https://")):
            sp = urlsplit(path)
            path = sp.path + ("?" + sp.query if sp.query else "")
        return {"kind": "web", "ts": ts, "ip": ip, "method": str(vals.get("method", "")), "path": path,
                "status": status, "ua": str(vals.get("ua", "")), "user": user}
    if "outcome" in vals:
        o = str(vals["outcome"]).lower()
        if re.search(r"fail|denied|deny|reject|invalid|error", o):
            outcome = "failed"
        elif re.search(r"success|accept|allow|ok|granted", o):
            outcome = "accepted"
        else:
            outcome = None
        if outcome:
            return {"kind": "auth", "ts": ts, "ip": ip, "user": user or "?", "outcome": outcome}
    return {"kind": "other", "ts": ts, "ip": ip, "user": user}


def _first(obj, paths):
    for path in paths:
        v = _get(obj, path)
        if v not in (None, ""):
            return v
    return None


def _cloudtrail_event(rec: Dict) -> Dict:
    ident = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
    itype = str(ident.get("type") or "")
    arn = str(ident.get("arn") or "")
    if itype == "Root":
        user = "root"
    else:
        user = str(ident.get("userName") or _get(ident, "sessionContext.sessionIssuer.userName")
                   or (arn.rsplit("/", 1)[-1] if arn else "") or ident.get("principalId") or itype or "?")
    params = rec.get("requestParameters") if isinstance(rec.get("requestParameters"), dict) else {}
    ev = {"kind": "cloud", "source": "cloudtrail", "ts": _parse_ts(str(rec.get("eventTime", ""))),
          "ip": str(rec.get("sourceIPAddress") or "") or None, "user": user, "identity_type": itype,
          "event_name": str(rec.get("eventName") or ""), "event_source": str(rec.get("eventSource") or ""),
          "error": str(rec.get("errorCode") or ""), "params": params,
          "invoked_by": str(ident.get("invokedBy") or ""),
          "console": str(_get(rec, "responseElements.ConsoleLogin") or ""),
          "mfa": str(_get(rec, "additionalEventData.MFAUsed") or "")}
    if ev["event_name"] == "ConsoleLogin":
        if ev["console"] == "Success" and not ev["error"]:
            ev.update(kind="auth", outcome="accepted")
        elif ev["console"] == "Failure" or ev["error"]:
            ev.update(kind="auth", outcome="failed")
    return ev


def _is_cloudtrail(obj: Dict) -> bool:
    return "eventName" in obj and "eventSource" in obj and ("userIdentity" in obj or "eventVersion" in obj)


def _entra_event(obj: Optional[Dict]) -> Optional[Dict]:
    if not isinstance(obj, dict):
        return None
    rec = obj
    if isinstance(obj.get("properties"), dict) and str(obj.get("category", "")).lower().endswith("signinlogs"):
        rec = dict(obj["properties"], **{k: v for k, v in obj.items() if k != "properties"})
    code = _first(rec, ["ResultType", "status.errorCode", "resultType"])
    user = _first(rec, ["UserPrincipalName", "userPrincipalName"])
    if code is None or user is None:
        return None
    code = str(code)
    ev = {"source": "entra", "ts": _parse_ts(str(_first(rec, ["TimeGenerated", "createdDateTime", "time"]) or "")),
          "ip": str(_first(rec, ["IPAddress", "ipAddress", "callerIpAddress"]) or "") or None,
          "user": str(user), "code": code,
          "app": str(_first(rec, ["AppDisplayName", "appDisplayName"]) or ""),
          "protocol": str(_first(rec, ["AuthenticationProtocol", "authenticationProtocol"]) or "")}
    if code == "0":
        ev.update(kind="auth", outcome="accepted")
    elif code in ENTRA_PASSWORD_FAIL:
        ev.update(kind="auth", outcome="failed")
    else:
        ev.update(kind="signin", outcome="other")
    return ev


def parse_cloud(line: str):
    """Return (format label, [events]) for CloudTrail or Entra sign-in JSON, else None."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("Records"), list):
        recs = [r for r in obj["Records"] if isinstance(r, dict) and _is_cloudtrail(r)]
        return ("cloudtrail", [_cloudtrail_event(r) for r in recs]) if recs else None
    if _is_cloudtrail(obj):
        return "cloudtrail", [_cloudtrail_event(obj)]
    if isinstance(obj.get("value"), list):
        evs = [e for e in (_entra_event(v) for v in obj["value"]) if e]
        return ("entra", evs) if evs else None
    ev = _entra_event(obj)
    return ("entra", [ev]) if ev else None


def parse_lines(lines: Iterable[str], fmt: str = "auto", year: Optional[int] = None,
                fields: Optional[Dict[str, List[str]]] = None) -> Dict:
    year = year or datetime.now(timezone.utc).year
    fields = fields or DEFAULT_FIELDS
    events, skipped = [], 0
    formats = Counter()
    for no, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        ev = None
        if fmt in ("auto", "json") and line.lstrip().startswith("{"):
            cloud = parse_cloud(line)
            if cloud is not None:
                label, evs = cloud
                for c in evs:
                    c["line"] = no
                    events.append(c)
                formats[label] += len(evs)
                continue
            ev, kind = parse_json(line, fields), "json"
        if ev is None and fmt in ("auto", "web"):
            ev, kind = parse_access(line), "web"
        if ev is None and fmt in ("auto", "auth"):
            ev, kind = parse_syslog(line, year), "auth"
        if ev is None:
            skipped += 1
            continue
        formats[kind] += 1
        ev["line"] = no
        events.append(ev)
    return {"events": events, "skipped": skipped, "formats": dict(formats)}


# ---------------------------------------------------------------- detections

def _max_in_window(times: List[Optional[datetime]], window: int):
    """Largest number of events inside any `window` seconds. Events without time count together."""
    stamps = sorted(t for t in times if t is not None)
    if len(stamps) < len(times):
        return len(times), None, None
    best, best_i, best_j, i = 0, 0, 0, 0
    for j in range(len(stamps)):
        while (stamps[j] - stamps[i]).total_seconds() > window:
            i += 1
        if j - i + 1 > best:
            best, best_i, best_j = j - i + 1, i, j
    return best, stamps[best_i], stamps[best_j]


def _span(a, b):
    if a is None:
        return ""
    return f"{a.isoformat()} to {b.isoformat()}"


def _lines(evs, limit=6):
    nums = [e["line"] for e in evs]
    s = ", ".join(map(str, nums[:limit]))
    return "lines " + s + (f" (+{len(nums) - limit} more)" if len(nums) > limit else "")


def detect_auth(events: List[Dict], cfg) -> List[Dict]:
    out = []
    fails = defaultdict(list)
    for e in events:
        if e["kind"] == "auth" and e["outcome"] == "failed" and e.get("ip"):
            fails[e["ip"]].append(e)
    brute_ips = set()
    for ip, evs in fails.items():
        n, a, b = _max_in_window([e["ts"] for e in evs], cfg.window)
        if n >= cfg.brute_threshold:
            brute_ips.add(ip)
            users = Counter(e["user"] for e in evs)
            out.append(finding("AUTH-001", "high", f"Brute force from {ip}",
                               f"{n} failed logins within {cfg.window}s ({len(evs)} total). {_span(a, b)}. "
                               f"Top users tried: {', '.join(f'{u}({c})' for u, c in users.most_common(5))}.",
                               "Block the source, move to keys or MFA (for SSH: PasswordAuthentication no), and add rate limits or fail2ban.",
                               f"{ip}, {_lines(evs)}"))
        # spray: many distinct users from one IP inside the window
        best = 0
        by_time = sorted((e for e in evs if e["ts"]), key=lambda e: e["ts"])
        if len(by_time) < len(evs):
            best = len({e["user"] for e in evs})
        else:
            i = 0
            for j in range(len(by_time)):
                while (by_time[j]["ts"] - by_time[i]["ts"]).total_seconds() > cfg.window:
                    i += 1
                best = max(best, len({e["user"] for e in by_time[i:j + 1]}))
        if best >= cfg.spray_users:
            out.append(finding("AUTH-002", "high", f"Password spray from {ip}",
                               f"{best} different usernames tried within {cfg.window}s. Spraying tries a few common passwords against many accounts.",
                               "Block the source, check whether any of those accounts logged in successfully, enforce MFA and lockout policies.",
                               f"{ip}, {_lines(evs)}"))
    for e in events:
        if e["kind"] == "auth" and e["outcome"] == "accepted" and e.get("ip") in fails:
            prior = [f for f in fails[e["ip"]]
                     if (f["ts"] is None or e["ts"] is None or
                         0 <= (e["ts"] - f["ts"]).total_seconds() <= cfg.success_lookback)
                     and f["line"] < e["line"]]
            if len(prior) >= cfg.success_after:
                tried_user = any(f["user"] == e["user"] for f in prior)
                sev = "critical" if (e["ip"] in brute_ips or tried_user) else "high"
                out.append(finding("AUTH-003", sev, f"Login success for {e['user']} after failures from {e['ip']}",
                                   f"{len(prior)} failed attempts from the same source before this successful login"
                                   + (" for the same account" if tried_user else "") + ". This is how a guessed password looks.",
                                   "Treat the account as compromised until proven otherwise: check what the session did, rotate the credential, review authorized_keys and cron.",
                                   f"{e['ip']}, line {e['line']}"))
    # sudo
    sudo = [e for e in events if e["kind"] == "sudo"]
    denied = [e for e in sudo if not e["ok"]]
    for user in sorted({e["user"] for e in denied}):
        evs = [e for e in denied if e["user"] == user]
        out.append(finding("AUTH-005", "medium", f"Denied sudo attempts by {user}",
                           f"{len(evs)} denied sudo event(s): {evs[0]['reason']}. Commands: "
                           + "; ".join(sorted({e['command'] for e in evs if e['command']})[:3]) + ".",
                           "Confirm with the user. Denied sudo for sensitive files (/etc/shadow) often means someone is probing after getting a shell.",
                           _lines(evs)))
    ok_root = [e for e in sudo if e["ok"] and e["target"] == "root"]
    if cfg.sudo_users is not None:
        for user in sorted({e["user"] for e in ok_root} - set(cfg.sudo_users)):
            evs = [e for e in ok_root if e["user"] == user]
            out.append(finding("AUTH-004", "medium", f"sudo to root by unexpected user {user}",
                               f"{len(evs)} root command(s), not in the expected sudo users list. Commands: "
                               + "; ".join(sorted({e['command'] for e in evs})[:3]) + ".",
                               "Check whether this user should have sudo. Remove the sudoers entry if not and review what ran.",
                               _lines(evs)))
    elif ok_root:
        users = Counter(e["user"] for e in ok_root)
        out.append(finding("AUTH-006", "info", "sudo to root seen",
                           "Users: " + ", ".join(f"{u}({c})" for u, c in users.most_common()) + ".",
                           "Pass --sudo-users with the expected admins to flag everyone else.",
                           _lines(ok_root)))
    return out


def detect_web(events: List[Dict], cfg) -> List[Dict]:
    out = []
    web = [e for e in events if e["kind"] == "web"]
    groups = defaultdict(list)
    for e in web:
        raw = e["path"] or ""
        decoded = unquote_plus(raw)
        ip = e.get("ip") or "?"
        if e["ua"] and SCANNER_UA.search(e["ua"]):
            groups[("WEB-001", ip)].append(e)
        if SENSITIVE_PATHS.search(decoded.split("?", 1)[0]):
            if EXPOSURE_PATHS.search(decoded.split("?", 1)[0]) and 200 <= e["status"] < 300:
                groups[("WEB-007", ip)].append(e)
            else:
                groups[("WEB-003", ip)].append(e)
        if SQLI.search(decoded):
            groups[("WEB-004", ip)].append(e)
        if XSS.search(decoded):
            groups[("WEB-005", ip)].append(e)
        if TRAVERSAL.search(raw) or TRAVERSAL.search(decoded):
            groups[("WEB-006", ip)].append(e)
    meta = {
        "WEB-001": ("medium", "Scanner user agent from {ip}", "Requests carry a known scanning tool user agent ({ua}).",
                    "If this is not your own authorized scan, block the source and review what returned 200."),
        "WEB-003": ("medium", "Probing for sensitive paths from {ip}", "Requests for files and admin paths that should never be public.",
                    "Make sure these paths return 404/403. Ignore /wp-admin hits if the site is WordPress and the user is an editor."),
        "WEB-004": ("medium", "SQL injection attempts from {ip}", "URLs contain SQL injection patterns.",
                    "Check the matching endpoints use parameterized queries. Any 200 or 500 response needs a closer look."),
        "WEB-005": ("medium", "XSS attempts from {ip}", "URLs contain script injection patterns.",
                    "Check output encoding on those endpoints and that a Content-Security-Policy is set."),
        "WEB-006": ("medium", "Path traversal attempts from {ip}", "URLs try to climb out of the web root or read system files.",
                    "Make sure file paths are never built from user input; normalise and allow-list."),
        "WEB-007": ("high", "Sensitive file served to {ip}", "A request for a secret-bearing file (.env, .git, keys, dumps) got a 2xx answer.",
                    "Fetch it yourself to confirm. If real: remove it from the web root, rotate every secret inside, and check who else downloaded it."),
    }
    for (fid, ip), evs in sorted(groups.items()):
        sev, title, detail, fix = meta[fid]
        statuses = Counter(e["status"] for e in evs)
        samples = sorted({mask_path(e["path"]) for e in evs})[:3]
        ua = evs[0]["ua"][:60]
        sev_now = sev
        if fid in ("WEB-004", "WEB-006") and any(e["status"] == 200 for e in evs):
            sev_now = "high"
        out.append(finding(fid, sev_now, title.format(ip=ip),
                           detail.format(ua=ua) + f" {len(evs)} request(s), status codes "
                           + ", ".join(f"{s}x{c}" for s, c in statuses.most_common()) + ". Samples: " + " | ".join(samples),
                           fix + (" Some returned 200, verify by hand." if sev_now != sev else ""),
                           f"{ip}, {_lines(evs)}"))
    not_found = defaultdict(list)
    for e in web:
        if e["status"] == 404:
            not_found[e.get("ip") or "?"].append(e)
    for ip, evs in sorted(not_found.items()):
        n, a, b = _max_in_window([e["ts"] for e in evs], cfg.web_window)
        if n >= cfg.notfound_threshold:
            out.append(finding("WEB-002", "medium", f"404 burst from {ip}",
                               f"{n} not-found responses within {cfg.web_window}s ({len(evs)} total). {_span(a, b)}. Typical of directory brute forcing.",
                               "Rate limit or block the source; review the few requests from it that did not 404.",
                               f"{ip}, {_lines(evs)}"))
    return out


def detect_cloud(events: List[Dict], cfg) -> List[Dict]:
    out = []
    ct = [e for e in events if e.get("source") == "cloudtrail"]
    # CLOUD-001 / 002: risky console sign-ins
    for e in ct:
        if e["event_name"] != "ConsoleLogin" or e.get("outcome") != "accepted":
            continue
        where = f"{e.get('ip') or '?'}, line {e['line']}"
        if e["identity_type"] == "Root":
            no_mfa = e["mfa"] == "No"
            out.append(finding("CLOUD-001", "critical" if no_mfa else "high", "AWS root account console sign-in",
                               "The root user signed in to the console" + (" without MFA" if no_mfa else "")
                               + ". Root should only be used for the few tasks that need it.",
                               "Confirm with the account owner. If unexpected: reset the root password, check root MFA, "
                               "review everything the session did in CloudTrail and set a root sign-in alarm.", where))
        elif e["mfa"] == "No" and e["identity_type"] == "IAMUser":
            out.append(finding("CLOUD-002", "medium", f"AWS console sign-in without MFA by {e['user']}",
                               "An IAM user signed in to the console with a password only.",
                               "Require MFA for console users (IAM policy with aws:MultiFactorAuthPresent) or move them to IAM Identity Center.",
                               where))
    # CLOUD-003: audit trail tampering
    for e in ct:
        if e["event_name"] in CLOUDTRAIL_TAMPER and (e["event_source"] in ("", "cloudtrail.amazonaws.com")):
            target = e["params"].get("name") or e["params"].get("trailName") or e["params"].get("eventDataStore") or "?"
            ok = not e["error"]
            out.append(finding("CLOUD-003", "high" if ok else "medium",
                               f"CloudTrail {e['event_name']} by {e['user']}" + ("" if ok else " (failed)"),
                               f"Trail or event data store '{target}' was changed or stopped"
                               + ("" if ok else f", the call failed with {e['error']}") + ". Attackers turn off logging before acting (ATT&CK T1685.002).",
                               "Check the trail is logging again (GetTrailStatus), find who made the call and why, and protect trails with an SCP that denies StopLogging and DeleteTrail.",
                               f"{e.get('ip') or '?'}, line {e['line']}"))
    # CLOUD-004: new credentials for an IAM user
    for e in ct:
        if e["event_name"] in CLOUDTRAIL_CRED_EVENTS and not e["error"]:
            target = str(e["params"].get("userName") or e["user"])
            other = target != e["user"]
            out.append(finding("CLOUD-004", "medium" if other else "low",
                               f"{e['event_name']} for {target}" + (f" by {e['user']}" if other else ""),
                               ("New credentials were created for a different user. " if other else "A user created credentials for itself. ")
                               + "Extra access keys or console passwords keep access alive after a password reset (ATT&CK T1098.001).",
                               "Confirm the change was requested. If not: delete the new key or login profile, then review what the caller did.",
                               f"{e.get('ip') or '?'}, line {e['line']}"))
    # CLOUD-007: many denied API calls from one identity (stolen key recon)
    denied = defaultdict(list)
    for e in ct:
        if e["error"] in CLOUDTRAIL_DENIED:
            denied[e["user"]].append(e)
    for user, evs in sorted(denied.items()):
        n, a, b = _max_in_window([e["ts"] for e in evs], cfg.window)
        if n >= cfg.denied_threshold:
            calls = Counter(e["event_name"] for e in evs)
            out.append(finding("CLOUD-007", "medium", f"Burst of denied AWS API calls by {user}",
                               f"{n} access denied errors within {cfg.window}s ({len(evs)} total). {_span(a, b)}. "
                               f"Calls: {', '.join(f'{c}({k})' for c, k in calls.most_common(5))}. Stolen keys often probe what they can do.",
                               "Check where the calls came from and whether the key owner made them. Rotate the key if not.",
                               f"{user}, {_lines(evs)}"))
    en = [e for e in events if e.get("source") == "entra"]
    # CLOUD-005: MFA push fatigue
    by_user = defaultdict(list)
    for e in en:
        if e["code"] in ENTRA_MFA_DENIED:
            by_user[e["user"]].append(e)
    for user, evs in sorted(by_user.items()):
        n, a, b = _max_in_window([e["ts"] for e in evs], cfg.mfa_window)
        if n < cfg.mfa_threshold:
            continue
        last = max(e["line"] for e in evs)
        success = [e for e in en if e["user"] == user and e["code"] == "0" and e["line"] > last]
        ips = sorted({e["ip"] for e in evs if e.get("ip")})
        out.append(finding("CLOUD-005", "critical" if success else "high", f"MFA fatigue against {user}",
                           f"{n} MFA requests denied by the user within {cfg.mfa_window}s ({len(evs)} total). {_span(a, b)}. "
                           f"Sources: {', '.join(ips[:5]) or '?'}."
                           + (f" A successful sign-in followed on line {success[0]['line']}." if success else "")
                           + " Repeated pushes mean someone already has the password (ATT&CK T1621).",
                           "Reset the password, revoke sessions (revokeSignInSessions), turn on number matching, and ask the user whether they approved a prompt.",
                           f"{user}, {_lines(evs)}"))
    # CLOUD-006: device code sign-ins
    dev = defaultdict(list)
    for e in en:
        if e["protocol"].lower() == "devicecode" and e["code"] == "0":
            dev[e["user"]].append(e)
    for user, evs in sorted(dev.items()):
        apps = sorted({e["app"] for e in evs if e["app"]})
        out.append(finding("CLOUD-006", "medium", f"Device code sign-in by {user}",
                           f"{len(evs)} successful sign-in(s) with the device code flow to {', '.join(apps[:3]) or 'an app'}. "
                           "Device code phishing tricks users into approving an attacker's session (ATT&CK T1528).",
                           "Confirm the user signed in on a TV, CLI or kiosk. If not, revoke sessions. Block the device code flow with Conditional Access where it is not needed.",
                           f"{user}, {_lines(evs)}"))
    return out


def top_talkers(events: List[Dict], n: int = 5) -> List[Dict]:
    stats = defaultdict(lambda: {"events": 0, "auth_failed": 0, "auth_ok": 0, "web": 0, "errors_4xx_5xx": 0})
    for e in events:
        ip = e.get("ip")
        if not ip:
            continue
        s = stats[ip]
        s["events"] += 1
        if e["kind"] == "auth":
            s["auth_failed" if e["outcome"] == "failed" else "auth_ok"] += 1
        elif e["kind"] == "web":
            s["web"] += 1
            if e["status"] >= 400:
                s["errors_4xx_5xx"] += 1
    ranked = sorted(stats.items(), key=lambda kv: (-kv[1]["events"], kv[0]))[:n]
    return [dict(ip=ip, **s) for ip, s in ranked]


class Config:
    def __init__(self, window=300, brute_threshold=10, spray_users=5, success_after=3,
                 success_lookback=3600, web_window=60, notfound_threshold=20, sudo_users=None,
                 mfa_threshold=3, mfa_window=3600, denied_threshold=10):
        self.window = window
        self.brute_threshold = brute_threshold
        self.spray_users = spray_users
        self.success_after = success_after
        self.success_lookback = success_lookback
        self.web_window = web_window
        self.notfound_threshold = notfound_threshold
        self.sudo_users = sudo_users
        self.mfa_threshold = mfa_threshold
        self.mfa_window = mfa_window
        self.denied_threshold = denied_threshold


def triage(lines: Iterable[str], cfg: Optional[Config] = None, fmt: str = "auto",
           year: Optional[int] = None, fields=None) -> Dict:
    cfg = cfg or Config()
    parsed = parse_lines(lines, fmt, year, fields)
    events = parsed["events"]
    findings = detect_auth(events, cfg) + detect_web(events, cfg) + detect_cloud(events, cfg)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f["id"]))
    stamps = sorted(e["ts"] for e in events if e.get("ts"))
    return {
        "events_parsed": len(events),
        "skipped_lines": parsed["skipped"],
        "formats": parsed["formats"],
        "time_range": [stamps[0].isoformat(), stamps[-1].isoformat()] if stamps else None,
        "findings": findings,
        "top_talkers": top_talkers(events),
    }


def render_text(source: str, r: Dict) -> str:
    out = [f"Log triage: {source}",
           f"{r['events_parsed']} event(s) parsed, {r['skipped_lines']} line(s) skipped, formats: "
           + (", ".join(f"{k}={v}" for k, v in r["formats"].items()) or "none"),
           ("Time range: " + " to ".join(r["time_range"])) if r["time_range"] else "Time range: unknown", ""]
    if not r["findings"]:
        out.append("No findings.")
    for f in r["findings"]:
        out.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        out.append(f"           {f['detail']}")
        if f.get("location"):
            out.append(f"           where: {f['location']}")
        out.append(f"           fix: {f['fix']}")
    if r["top_talkers"]:
        out += ["", "Top talkers:", f"  {'ip':40} events  auth_fail  auth_ok  web  4xx/5xx"]
        for t in r["top_talkers"]:
            out.append(f"  {t['ip']:40} {t['events']:6}  {t['auth_failed']:9}  {t['auth_ok']:7}  {t['web']:3}  {t['errors_4xx_5xx']:7}")
    return "\n".join(out)


def parse_field_args(pairs: List[str]) -> Dict[str, List[str]]:
    fields = {k: list(v) for k, v in DEFAULT_FIELDS.items()}
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError(f"--field expects name=json.path, got '{pair}'")
        k, v = pair.split("=", 1)
        if k not in fields:
            raise ValueError(f"--field name must be one of {', '.join(fields)}")
        fields[k] = [v] + fields[k]
    return fields


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Triage auth.log, web access logs, CloudTrail, Entra ID sign-ins and JSON lines for attacks.")
    ap.add_argument("path", nargs="?", help="log file")
    ap.add_argument("--file", help="log file; '-' for stdin")
    ap.add_argument("--format", choices=["auto", "auth", "web", "json"], default="auto")
    ap.add_argument("--field", action="append", metavar="NAME=PATH",
                    help="JSON field mapping, NAME in ts, ip, user, outcome, path, method, status, ua (repeatable)")
    ap.add_argument("--year", type=int, help="year for syslog lines without one (default: current year)")
    ap.add_argument("--window", type=int, default=300, help="auth window in seconds (default 300)")
    ap.add_argument("--brute-threshold", type=int, default=10, help="failures per IP in window (default 10)")
    ap.add_argument("--spray-users", type=int, default=5, help="distinct users per IP in window (default 5)")
    ap.add_argument("--success-after", type=int, default=3, help="failures before a success that count (default 3)")
    ap.add_argument("--web-window", type=int, default=60, help="404 burst window in seconds (default 60)")
    ap.add_argument("--notfound-threshold", type=int, default=20, help="404s per IP in web window (default 20)")
    ap.add_argument("--sudo-users", help="comma list of users expected to sudo to root")
    ap.add_argument("--mfa-threshold", type=int, default=3, help="Entra MFA denials per user in --mfa-window (default 3)")
    ap.add_argument("--mfa-window", type=int, default=3600, help="MFA fatigue window in seconds (default 3600)")
    ap.add_argument("--denied-threshold", type=int, default=10, help="denied AWS API calls per identity in window (default 10)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    src = args.file or args.path
    if not src:
        print("error: give a log file or --file - for stdin", file=sys.stderr)
        return 2
    try:
        fields = parse_field_args(args.field)
        lines = sys.stdin.read().splitlines() if src == "-" else open(src, encoding="utf-8", errors="replace").read().splitlines()
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    cfg = Config(args.window, args.brute_threshold, args.spray_users, args.success_after, 3600,
                 args.web_window, args.notfound_threshold,
                 {u.strip() for u in args.sudo_users.split(",") if u.strip()} if args.sudo_users else None,
                 args.mfa_threshold, args.mfa_window, args.denied_threshold)
    result = triage(lines, cfg, args.format, args.year, fields)
    if result["events_parsed"] == 0:
        print("error: no recognisable log lines (auth.log, access log, CloudTrail, Entra sign-ins or JSON lines)", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(dict(source=src, **result), indent=2))
    else:
        print(render_text(src, result))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
