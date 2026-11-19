#!/usr/bin/env python3
"""Print ready-made hunting queries in Splunk SPL, Microsoft KQL and Elastic ES|QL / EQL.

A small library of common use cases (brute force, password spray, new admin
user, encoded PowerShell, LSASS dumping, ...). Each query names the data
source and field names it assumes; adjust index names and fields to your
environment before running it.

Usage:
  query_translate.py --list
  query_translate.py ssh-brute-force
  query_translate.py encoded-powershell --lang kql
  query_translate.py password-spray --lang all --json
  query_translate.py ssh-brute-force --threshold 20 --window 10
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Dict, List

LANGS = ["spl", "kql", "esql", "eql"]
LANG_NAMES = {"spl": "Splunk SPL", "kql": "Microsoft KQL (Sentinel / Defender)",
              "esql": "Elastic ES|QL", "eql": "Elastic EQL"}

# {threshold} and {window} (minutes) are filled in at print time.
LIBRARY: Dict[str, Dict] = {
    "ssh-brute-force": {
        "title": "SSH brute force and success after failures",
        "attack": ["T1110.001"],
        "defaults": {"threshold": 10, "window": 5},
        "sources": {"spl": "sourcetype=linux_secure (auth.log / secure)",
                    "kql": "Syslog table (Sentinel, AMA syslog)",
                    "esql": "Elastic system integration, logs-system.auth-*",
                    "eql": "Elastic system integration, ECS authentication events"},
        "spl": ('index=* sourcetype=linux_secure "Failed password"\n'
                '| rex "from (?<src_ip>\\d{{1,3}}(?:\\.\\d{{1,3}}){{3}})"\n'
                '| bin _time span={window}m\n'
                '| stats count AS failures dc(user) AS users values(user) AS tried BY _time, src_ip\n'
                '| where failures >= {threshold}\n'
                '| sort - failures'),
        "kql": ('Syslog\n'
                '| where ProcessName == "sshd" and SyslogMessage has "Failed password"\n'
                '| extend SrcIp = extract(@"from (\\d{{1,3}}(\\.\\d{{1,3}}){{3}})", 1, SyslogMessage)\n'
                '| summarize Failures = count() by SrcIp, bin(TimeGenerated, {window}m)\n'
                '| where Failures >= {threshold}\n'
                '| order by Failures desc'),
        "esql": ('FROM logs-system.auth-*\n'
                 '| WHERE process.name == "sshd" AND event.outcome == "failure"\n'
                 '| EVAL bucket = DATE_TRUNC({window} minutes, @timestamp)\n'
                 '| STATS failures = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip, bucket\n'
                 '| WHERE failures >= {threshold}\n'
                 '| SORT failures DESC'),
        "eql": ('sequence by source.ip with maxspan={window}m\n'
                '  [authentication where event.outcome == "failure"] with runs={threshold}\n'
                '  [authentication where event.outcome == "success"]'),
    },
    "password-spray": {
        "title": "Password spray against Windows accounts (one source, many users)",
        "attack": ["T1110.003"],
        "defaults": {"threshold": 10, "window": 10},
        "sources": {"spl": "Windows Security log, XmlWinEventLog field names",
                    "kql": "SecurityEvent table",
                    "esql": "Elastic windows/system integration, logs-system.security-*",
                    "eql": "not a good fit for EQL (needs distinct counts); use ES|QL"},
        "spl": ('index=wineventlog EventCode=4625\n'
                '| bin _time span={window}m\n'
                '| stats dc(TargetUserName) AS users count AS attempts BY _time, IpAddress\n'
                '| where users >= {threshold}\n'
                '| sort - users'),
        "kql": ('SecurityEvent\n'
                '| where EventID == 4625\n'
                '| summarize Users = dcount(TargetUserName), Attempts = count() by IpAddress, bin(TimeGenerated, {window}m)\n'
                '| where Users >= {threshold}\n'
                '| order by Users desc'),
        "esql": ('FROM logs-system.security-*\n'
                 '| WHERE event.code == "4625"\n'
                 '| EVAL bucket = DATE_TRUNC({window} minutes, @timestamp)\n'
                 '| STATS users = COUNT_DISTINCT(user.name), attempts = COUNT(*) BY source.ip, bucket\n'
                 '| WHERE users >= {threshold}\n'
                 '| SORT users DESC'),
        "eql": None,
    },
    "new-admin-user": {
        "title": "New account created or added to an admin group (Windows)",
        "attack": ["T1136.001", "T1098"],
        "defaults": {},
        "sources": {"spl": "Windows Security log (4720 user created, 4728/4732/4756 member added to group)",
                    "kql": "SecurityEvent table",
                    "esql": "Elastic system integration, logs-system.security-*",
                    "eql": "Elastic system integration, ECS iam events"},
        "spl": ('index=wineventlog EventCode IN (4720, 4728, 4732, 4756)\n'
                '| eval action=case(EventCode==4720, "user created", true(), "added to group")\n'
                '| table _time, host, EventCode, action, SubjectUserName, TargetUserName, MemberName\n'
                '| sort - _time'),
        "kql": ('SecurityEvent\n'
                '| where EventID in (4720, 4728, 4732, 4756)\n'
                '| extend Action = iff(EventID == 4720, "user created", "added to group")\n'
                '| project TimeGenerated, Computer, EventID, Action, SubjectUserName, TargetUserName, MemberName\n'
                '| order by TimeGenerated desc'),
        "esql": ('FROM logs-system.security-*\n'
                 '| WHERE event.code IN ("4720", "4728", "4732", "4756")\n'
                 '| EVAL action = CASE(event.code == "4720", "user created", "added to group")\n'
                 '| KEEP @timestamp, host.name, event.code, action, user.name, user.target.name, group.name\n'
                 '| SORT @timestamp DESC'),
        "eql": 'iam where event.code in ("4720", "4728", "4732", "4756")',
    },
    "encoded-powershell": {
        "title": "PowerShell started with an encoded command",
        "attack": ["T1059.001", "T1027"],
        "defaults": {},
        "sources": {"spl": "Sysmon event 1 (process creation)",
                    "kql": "Defender for Endpoint DeviceProcessEvents",
                    "esql": "Elastic Defend, logs-endpoint.events.process-*",
                    "eql": "Elastic Defend or Sysmon via ECS, process events"},
        "spl": ('index=sysmon EventCode=1 (Image="*\\\\powershell.exe" OR Image="*\\\\pwsh.exe")\n'
                '  (CommandLine="* -e *" OR CommandLine="* -ec *" OR CommandLine="* -en*" OR CommandLine="*-EncodedCommand*")\n'
                '| table _time, host, User, ParentImage, CommandLine'),
        "kql": ('DeviceProcessEvents\n'
                '| where FileName in~ ("powershell.exe", "pwsh.exe")\n'
                '| where ProcessCommandLine matches regex @"(?i)\\s[-/]e(c|n[a-z]*)?\\s"\n'
                '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine'),
        "esql": ('FROM logs-endpoint.events.process-*\n'
                 '| WHERE event.type == "start" AND process.name IN ("powershell.exe", "pwsh.exe")\n'
                 '| EVAL cmd = TO_LOWER(process.command_line)\n'
                 '| WHERE cmd LIKE "* -e *" OR cmd LIKE "* -ec *" OR cmd LIKE "* -en*" OR cmd LIKE "*-encodedcommand*"\n'
                 '| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line'),
        "eql": ('process where event.type == "start" and process.name in~ ("powershell.exe", "pwsh.exe") and\n'
                '  process.args : ("-e", "-ec", "-en", "-enc", "-encodedcommand", "/e", "/enc")'),
    },
    "lsass-dump": {
        "title": "LSASS memory dumped with comsvcs.dll or procdump",
        "attack": ["T1003.001"],
        "defaults": {},
        "sources": {"spl": "Sysmon event 1 (process creation)",
                    "kql": "Defender for Endpoint DeviceProcessEvents",
                    "esql": "Elastic Defend, logs-endpoint.events.process-*",
                    "eql": "Elastic Defend or Sysmon via ECS, process events"},
        "spl": ('index=sysmon EventCode=1\n'
                '  ((CommandLine="*comsvcs*" CommandLine="*MiniDump*") OR (CommandLine="*procdump*" CommandLine="*lsass*"))\n'
                '| table _time, host, User, ParentImage, Image, CommandLine'),
        "kql": ('DeviceProcessEvents\n'
                '| where (ProcessCommandLine contains "comsvcs" and ProcessCommandLine contains "MiniDump")\n'
                '    or (ProcessCommandLine contains "procdump" and ProcessCommandLine contains "lsass")\n'
                '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine'),
        "esql": ('FROM logs-endpoint.events.process-*\n'
                 '| WHERE event.type == "start"\n'
                 '| EVAL cmd = TO_LOWER(process.command_line)\n'
                 '| WHERE (cmd LIKE "*comsvcs*" AND cmd LIKE "*minidump*") OR (cmd LIKE "*procdump*" AND cmd LIKE "*lsass*")\n'
                 '| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line'),
        "eql": ('process where event.type == "start" and\n'
                '  ((process.command_line : "*comsvcs*" and process.command_line : "*MiniDump*") or\n'
                '   (process.command_line : "*procdump*" and process.command_line : "*lsass*"))'),
    },
    "office-child-process": {
        "title": "Office application spawning a shell or script host",
        "attack": ["T1204.002", "T1059"],
        "defaults": {},
        "sources": {"spl": "Sysmon event 1 (process creation)",
                    "kql": "Defender for Endpoint DeviceProcessEvents",
                    "esql": "Elastic Defend, logs-endpoint.events.process-*",
                    "eql": "Elastic Defend or Sysmon via ECS, process events"},
        "spl": ('index=sysmon EventCode=1\n'
                '  (ParentImage="*\\\\winword.exe" OR ParentImage="*\\\\excel.exe" OR ParentImage="*\\\\powerpnt.exe" OR ParentImage="*\\\\outlook.exe")\n'
                '  (Image="*\\\\powershell.exe" OR Image="*\\\\cmd.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\rundll32.exe")\n'
                '| table _time, host, User, ParentImage, Image, CommandLine'),
        "kql": ('DeviceProcessEvents\n'
                '| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")\n'
                '| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe")\n'
                '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine'),
        "esql": ('FROM logs-endpoint.events.process-*\n'
                 '| WHERE event.type == "start"\n'
                 '| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name)\n'
                 '| WHERE parent IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")\n'
                 '    AND child IN ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe")\n'
                 '| KEEP @timestamp, host.name, user.name, process.parent.name, process.name, process.command_line'),
        "eql": ('process where event.type == "start" and\n'
                '  process.parent.name : ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe") and\n'
                '  process.name : ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe")'),
    },
    "scheduled-task": {
        "title": "Scheduled task created from the command line",
        "attack": ["T1053.005"],
        "defaults": {},
        "sources": {"spl": "Sysmon event 1 (process creation)",
                    "kql": "Defender for Endpoint DeviceProcessEvents",
                    "esql": "Elastic Defend, logs-endpoint.events.process-*",
                    "eql": "Elastic Defend or Sysmon via ECS, process events"},
        "spl": ('index=sysmon EventCode=1 Image="*\\\\schtasks.exe" CommandLine="*/create*"\n'
                '| table _time, host, User, ParentImage, CommandLine'),
        "kql": ('DeviceProcessEvents\n'
                '| where FileName =~ "schtasks.exe" and ProcessCommandLine contains "/create"\n'
                '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine'),
        "esql": ('FROM logs-endpoint.events.process-*\n'
                 '| WHERE event.type == "start" AND TO_LOWER(process.name) == "schtasks.exe"\n'
                 '    AND TO_LOWER(process.command_line) LIKE "*/create*"\n'
                 '| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line'),
        "eql": 'process where event.type == "start" and process.name : "schtasks.exe" and process.args : "/create"',
    },
    "new-service": {
        "title": "New Windows service installed",
        "attack": ["T1543.003", "T1569.002"],
        "defaults": {},
        "sources": {"spl": "Windows System log, event 7045",
                    "kql": "Defender for Endpoint DeviceEvents",
                    "esql": "Elastic system integration, logs-system.system-*",
                    "eql": "Elastic system integration, ECS events"},
        "spl": ('index=wineventlog source="WinEventLog:System" EventCode=7045\n'
                '| table _time, host, ServiceName, ImagePath, ServiceType, StartType, AccountName'),
        "kql": ('DeviceEvents\n'
                '| where ActionType == "ServiceInstalled"\n'
                '| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, AdditionalFields'),
        "esql": ('FROM logs-system.system-*\n'
                 '| WHERE event.code == "7045"\n'
                 '| KEEP @timestamp, host.name, winlog.event_data.ServiceName, winlog.event_data.ImagePath'),
        "eql": 'any where event.code == "7045"',
    },
    "log-cleared": {
        "title": "Windows event log cleared",
        "attack": ["T1070.001"],
        "defaults": {},
        "sources": {"spl": "Windows Security (1102) and System (104) logs",
                    "kql": "SecurityEvent (1102) and Event (System 104) tables",
                    "esql": "Elastic system integration, logs-system.*",
                    "eql": "Elastic system integration, ECS events"},
        "spl": ('index=wineventlog (EventCode=1102 OR (source="WinEventLog:System" EventCode=104))\n'
                '| table _time, host, EventCode, user, Message'),
        "kql": ('union\n'
                '  (SecurityEvent | where EventID == 1102 | project TimeGenerated, Computer, EventID, Activity),\n'
                '  (Event | where EventLog == "System" and EventID == 104 | project TimeGenerated, Computer, EventID, Activity = RenderedDescription)\n'
                '| order by TimeGenerated desc'),
        "esql": ('FROM logs-system.*\n'
                 '| WHERE event.code IN ("1102", "104")\n'
                 '| KEEP @timestamp, host.name, event.code, winlog.channel, user.name\n'
                 '| SORT @timestamp DESC'),
        "eql": 'any where event.code in ("1102", "104")',
    },
    "web-scanner": {
        "title": "Web vulnerability scanners by user agent",
        "attack": ["T1595.002"],
        "defaults": {"threshold": 1},
        "sources": {"spl": "sourcetype=access_combined (nginx/apache)",
                    "kql": "W3CIISLog table (IIS)",
                    "esql": "Elastic nginx integration, logs-nginx.access-*",
                    "eql": "Elastic nginx/apache integration, ECS web events"},
        "spl": ('index=web sourcetype=access_combined\n'
                '| where match(useragent, "(?i)sqlmap|nikto|nuclei|wpscan|gobuster|ffuf|feroxbuster")\n'
                '| stats count AS hits dc(uri) AS paths values(status) AS statuses BY clientip, useragent\n'
                '| where hits >= {threshold}\n'
                '| sort - hits'),
        "kql": ('W3CIISLog\n'
                '| where csUserAgent matches regex @"(?i)sqlmap|nikto|nuclei|wpscan|gobuster|ffuf|feroxbuster"\n'
                '| summarize Hits = count(), Paths = dcount(csUriStem) by cIP, csUserAgent\n'
                '| where Hits >= {threshold}\n'
                '| order by Hits desc'),
        "esql": ('FROM logs-nginx.access-*\n'
                 '| EVAL ua = TO_LOWER(user_agent.original)\n'
                 '| WHERE ua RLIKE ".*(sqlmap|nikto|nuclei|wpscan|gobuster|ffuf|feroxbuster).*"\n'
                 '| STATS hits = COUNT(*), paths = COUNT_DISTINCT(url.original) BY source.ip, ua\n'
                 '| WHERE hits >= {threshold}\n'
                 '| SORT hits DESC'),
        "eql": 'any where user_agent.original : ("*sqlmap*", "*nikto*", "*nuclei*", "*wpscan*", "*gobuster*", "*ffuf*", "*feroxbuster*")',
    },
}

LEADING = {
    "spl": re.compile(r"^(index=|search |sourcetype=|\|)"),
    "kql": re.compile(r"^(union\b|[A-Z][A-Za-z0-9_]*\s*($|\n|\|))"),
    "esql": re.compile(r"^(FROM|ROW|SHOW)\s"),
    "eql": re.compile(r"^(sequence|sample|any|process|network|file|registry|authentication|iam|library|dns)\b"),
}


def render_query(use_case: str, lang: str, threshold=None, window=None) -> str:
    uc = LIBRARY[use_case]
    q = uc.get(lang)
    if q is None:
        return None
    params = dict(uc.get("defaults", {}))
    if threshold is not None:
        params["threshold"] = threshold
    if window is not None:
        params["window"] = window
    params.setdefault("threshold", 10)
    params.setdefault("window", 5)
    return q.format(**params)


def lint_query(query: str, lang: str) -> List[str]:
    """Cheap structural checks: balanced brackets and quotes, sensible first keyword."""
    problems = []
    if not LEADING[lang].match(query.strip()):
        problems.append(f"{lang}: unexpected first token '{query.split()[0] if query.split() else ''}'")
    stack, pairs = [], {")": "(", "]": "[", "}": "{"}
    in_str, i = False, 0
    while i < len(query):
        c = query[i]
        if in_str:
            if c == "\\" and lang != "kql":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "([{":
            stack.append(c)
        elif c in ")]}":
            if not stack or stack.pop() != pairs[c]:
                problems.append(f"{lang}: unbalanced '{c}' at offset {i}")
                return problems
        i += 1
    if in_str:
        problems.append(f"{lang}: unterminated string")
    if stack:
        problems.append(f"{lang}: unclosed '{stack[-1]}'")
    if "{" in query and re.search(r"\{(threshold|window)\}", query):
        problems.append(f"{lang}: unfilled placeholder")
    return problems


def build(use_case: str, langs: List[str], threshold=None, window=None) -> Dict:
    uc = LIBRARY[use_case]
    queries = {}
    for lang in langs:
        q = render_query(use_case, lang, threshold, window)
        queries[lang] = {"query": q, "source": uc["sources"].get(lang, ""),
                         "available": q is not None}
    return {"use_case": use_case, "title": uc["title"], "attack": uc["attack"], "queries": queries}


def render_text(result: Dict) -> str:
    out = [f"{result['use_case']}: {result['title']}", f"ATT&CK: {', '.join(result['attack'])}", ""]
    for lang, q in result["queries"].items():
        out.append(f"--- {LANG_NAMES[lang]}  (data: {q['source']})")
        out.append(q["query"] if q["available"] else "(no query for this language)")
        out.append("")
    return "\n".join(out).rstrip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Print hunting queries in Splunk SPL, Microsoft KQL and Elastic ES|QL/EQL.")
    ap.add_argument("use_case", nargs="?", help="use case name (see --list)")
    ap.add_argument("--lang", default="all", choices=LANGS + ["all"])
    ap.add_argument("--threshold", type=int, help="override the count threshold where the query has one")
    ap.add_argument("--window", type=int, help="override the time window in minutes where the query has one")
    ap.add_argument("--list", action="store_true", help="list use cases")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    if args.list or not args.use_case:
        if args.json:
            print(json.dumps([{"use_case": k, "title": v["title"], "attack": v["attack"]} for k, v in LIBRARY.items()], indent=2))
        else:
            for k, v in LIBRARY.items():
                print(f"{k:22} {v['title']}  [{', '.join(v['attack'])}]")
        return 0 if args.list else 2
    if args.use_case not in LIBRARY:
        print(f"error: unknown use case '{args.use_case}'. Try --list.", file=sys.stderr)
        return 2
    for name, val in (("threshold", args.threshold), ("window", args.window)):
        if val is not None and val < 1:
            print(f"error: --{name} must be 1 or more", file=sys.stderr)
            return 2
    langs = LANGS if args.lang == "all" else [args.lang]
    result = build(args.use_case, langs, args.threshold, args.window)
    print(json.dumps(result, indent=2) if args.json else render_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
