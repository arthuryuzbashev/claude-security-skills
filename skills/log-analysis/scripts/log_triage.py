#!/usr/bin/env python3
"""Triage auth, web and JSON logs fast: brute force, spraying, scanners, injection probes.

Auto-detects each line: Linux auth.log / secure (sshd, sudo), nginx/apache
combined or common access logs, and JSON lines (generic, map field names with
--field). Prints a summary, findings and top talkers.

Usage:
  log_triage.py /var/log/auth.log
  log_triage.py access.log --json
  log_triage.py events.jsonl --field ip=source.ip --field user=user.name --field outcome=event.outcome
  zcat auth.log.2.gz | log_triage.py --file - --year 2026 --fail-on medium
  log_triage.py auth.log --sudo-users alice,ops --window 600 --brute-threshold 20
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
                 success_lookback=3600, web_window=60, notfound_threshold=20, sudo_users=None):
        self.window = window
        self.brute_threshold = brute_threshold
        self.spray_users = spray_users
        self.success_after = success_after
        self.success_lookback = success_lookback
        self.web_window = web_window
        self.notfound_threshold = notfound_threshold
        self.sudo_users = sudo_users


def triage(lines: Iterable[str], cfg: Optional[Config] = None, fmt: str = "auto",
           year: Optional[int] = None, fields=None) -> Dict:
    cfg = cfg or Config()
    parsed = parse_lines(lines, fmt, year, fields)
    events = parsed["events"]
    findings = detect_auth(events, cfg) + detect_web(events, cfg)
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
    ap = argparse.ArgumentParser(description="Triage auth.log, web access logs and JSON lines for attacks.")
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
                 {u.strip() for u in args.sudo_users.split(",") if u.strip()} if args.sudo_users else None)
    result = triage(lines, cfg, args.format, args.year, fields)
    if result["events_parsed"] == 0:
        print("error: no recognisable log lines (auth.log, access log or JSON lines)", file=sys.stderr)
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
