#!/usr/bin/env python3
"""Map behaviour notes or detection names to MITRE ATT&CK Enterprise techniques.

Reads free text (one observation or detection name per line), matches it
against an embedded keyword table of well-known techniques, and prints the
matches plus coverage per tactic. Technique IDs written in the text
(T1059.001) are picked up directly. Can write an ATT&CK Navigator layer.

The table is a curated subset (~90 techniques), not the full matrix. A line
with no match means "not in this table", not "not malicious".

Usage:
  attack_mapper.py notes.txt
  attack_mapper.py --file - < detections.txt --json
  attack_mapper.py notes.txt --navigator layer.json --layer-name "IR-114"
  attack_mapper.py --list
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Dict, List

TACTICS = [
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
]
TACTIC_NAME = {short: name for _, short, name in TACTICS}

PE = "privilege-escalation"
DE = "defense-evasion"

# (id, name, tactics, keyword regexes). Names follow ATT&CK Enterprise; sub-technique
# names are shown as "Parent: Sub" like the ATT&CK site does.
TECHNIQUES = [
    # Reconnaissance
    ("T1595", "Active Scanning", ["reconnaissance"], [r"\bactive scan", r"\bmasscan\b", r"\bzmap\b", r"internet[- ]wide scan"]),
    ("T1595.002", "Active Scanning: Vulnerability Scanning", ["reconnaissance"], [r"vulnerability scan", r"\bnikto\b", r"\bnuclei\b", r"\bsqlmap\b", r"\bwpscan\b"]),
    # Resource development
    ("T1583.001", "Acquire Infrastructure: Domains", ["resource-development"], [r"(newly|recently) registered domain", r"lookalike domain", r"typosquat"]),
    # Initial access
    ("T1566.001", "Phishing: Spearphishing Attachment", ["initial-access"], [r"phish\w* (email )?attachment", r"malicious attachment", r"macro[- ]enabled (doc|document|attachment)", r"\.docm\b", r"\.xlsm\b", r"attachment opened"]),
    ("T1566.002", "Phishing: Spearphishing Link", ["initial-access"], [r"phish\w* (email )?link", r"malicious link", r"clicked (a |the )?link", r"credential harvest"]),
    ("T1190", "Exploit Public-Facing Application", ["initial-access"], [r"exploit\w* (a |the )?(public|internet)[- ]facing", r"exploit\w* (the )?(vpn|web server|web app|appliance|exchange|citrix|confluence)", r"\brce\b on", r"web exploit"]),
    ("T1133", "External Remote Services", ["persistence", "initial-access"], [r"external remote service", r"\bvpn (login|logon|access)", r"exposed rdp", r"citrix gateway login"]),
    ("T1078", "Valid Accounts", [DE, "persistence", PE, "initial-access"], [r"valid (account|credential)", r"stolen credential", r"compromised account", r"legitimate credential"]),
    ("T1189", "Drive-by Compromise", ["initial-access"], [r"drive[- ]by", r"watering hole", r"malvertising"]),
    ("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", ["initial-access"], [r"supply[- ]chain", r"trojani[sz]ed (update|installer|package)", r"malicious (npm|pypi) package"]),
    # Execution
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", ["execution"], [r"powershell", r"\bpwsh\b", r"-enc(odedcommand)?\b", r"invoke-expression", r"\biex\b"]),
    ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", ["execution"], [r"\bcmd(\.exe)? /c\b", r"windows command shell", r"\bcmd\.exe\b", r"batch (file|script)"]),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell", ["execution"], [r"\bbash -c\b", r"\bsh -c\b", r"unix shell", r"reverse shell", r"/bin/(ba)?sh\b"]),
    ("T1059.005", "Command and Scripting Interpreter: Visual Basic", ["execution"], [r"\bvba\b", r"\bvbscript\b", r"\bmacro\b", r"\bwscript\b", r"\bcscript\b", r"\.vbs\b"]),
    ("T1059.006", "Command and Scripting Interpreter: Python", ["execution"], [r"python -c\b", r"malicious python", r"python script (ran|executed)"]),
    ("T1059.007", "Command and Scripting Interpreter: JavaScript", ["execution"], [r"\bjscript\b", r"\.js(e)? (file|attachment|dropper)", r"malicious javascript"]),
    ("T1047", "Windows Management Instrumentation", ["execution"], [r"\bwmic\b", r"\bwmi\b(?! event)", r"win32_process", r"invoke-wmimethod"]),
    ("T1204.002", "User Execution: Malicious File", ["execution"], [r"user (opened|ran|executed|double[- ]clicked)", r"opened (the )?(attachment|file|document)", r"enabled? (content|macros?)"]),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", ["execution", "persistence", PE], [r"schtasks", r"scheduled task", r"register-scheduledtask", r"\bat\.exe\b"]),
    ("T1053.003", "Scheduled Task/Job: Cron", ["execution", "persistence", PE], [r"\bcron(tab)?\b", r"/etc/cron"]),
    ("T1569.002", "System Services: Service Execution", ["execution"], [r"\bpsexec\b", r"\bsc(\.exe)? (start|create)\b", r"service execution", r"remcom"]),
    # Persistence
    ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", ["persistence", PE], [r"currentversion\\\\?run", r"\brun key", r"runonce", r"startup folder", r"registry run"]),
    ("T1543.003", "Create or Modify System Process: Windows Service", ["persistence", PE], [r"new service (installed|created)", r"service install", r"event ?id 7045", r"\b7045\b", r"sc(\.exe)? create", r"new-service"]),
    ("T1543.002", "Create or Modify System Process: Systemd Service", ["persistence", PE], [r"systemd (service|unit)", r"systemctl enable", r"/etc/systemd/system"]),
    ("T1136.001", "Create Account: Local Account", ["persistence"], [r"(new|created?) local (user|account)", r"net user \S+ \S+ /add", r"\buseradd\b", r"\badduser\b", r"event ?id 4720", r"\b4720\b"]),
    ("T1098", "Account Manipulation", ["persistence", PE], [r"added to (the )?(local )?(admin|administrators|domain admins|sudo)", r"group membership change", r"net localgroup administrators", r"\b4732\b", r"\b4728\b", r"\busermod -ag\b"]),
    ("T1098.004", "Account Manipulation: SSH Authorized Keys", ["persistence", PE], [r"authorized_keys"]),
    ("T1505.003", "Server Software Component: Web Shell", ["persistence"], [r"web ?shell", r"china ?chopper", r"\.aspx dropped", r"\.jsp dropped"]),
    ("T1546.003", "Event Triggered Execution: Windows Management Instrumentation Event Subscription", ["persistence", PE], [r"wmi (event )?subscription", r"__eventfilter", r"commandlineeventconsumer", r"wmi persistence"]),
    ("T1197", "BITS Jobs", [DE, "persistence"], [r"\bbitsadmin\b", r"bits job", r"start-bitstransfer"]),
    # Privilege escalation
    ("T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control", [PE, DE], [r"\buac bypass", r"bypass(ed)? uac", r"fodhelper", r"eventvwr\.exe.*(hijack|bypass)"]),
    ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", [PE, DE], [r"sudo (abuse|caching|misconfig)", r"\bsudoers\b", r"timestamp_timeout"]),
    ("T1068", "Exploitation for Privilege Escalation", [PE], [r"privilege escalation exploit", r"local privilege escalation", r"\blpe\b", r"kernel exploit", r"exploit\w* .*to (gain )?(system|root)"]),
    ("T1134", "Access Token Manipulation", [DE, PE], [r"token (impersonation|manipulation|theft)", r"impersonat\w+ token", r"\bsedebugprivilege\b", r"make_token", r"steal_token"]),
    # Defense evasion
    ("T1027", "Obfuscated Files or Information", [DE], [r"obfuscat", r"base64[- ]encoded (payload|command|script)", r"-enc(odedcommand)?\b", r"packed (binary|executable)", r"xor[- ]encoded"]),
    ("T1140", "Deobfuscate/Decode Files or Information", [DE], [r"certutil.*-decode", r"frombase64string", r"decod\w+ (the )?payload", r"base64 -d\b"]),
    ("T1070.001", "Indicator Removal: Clear Windows Event Logs", [DE], [r"(cleared|clear|wiped?) (the )?(security |windows |event )?(event )?logs?", r"wevtutil (cl|clear-log)", r"\b1102\b", r"clear-eventlog"]),
    ("T1070.004", "Indicator Removal: File Deletion", [DE], [r"(deleted|removed|wiped) (the )?(dropper|payload|tools|binary|artifacts?)", r"sdelete", r"self[- ]delet"]),
    ("T1070.003", "Indicator Removal: Clear Command History", [DE], [r"bash_history", r"history -c\b", r"unset histfile", r"clear(ed)? (command|shell) history"]),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", [DE], [r"(disabled?|tamper\w*|stopp?ed|kill\w*) (windows )?(defender|antivirus|av|edr|sysmon|security tool)", r"set-mppreference", r"disablerealtimemonitoring", r"defender exclusion"]),
    ("T1218.011", "System Binary Proxy Execution: Rundll32", [DE], [r"\brundll32\b"]),
    ("T1218.005", "System Binary Proxy Execution: Mshta", [DE], [r"\bmshta\b", r"\.hta\b"]),
    ("T1218.010", "System Binary Proxy Execution: Regsvr32", [DE], [r"\bregsvr32\b", r"squiblydoo"]),
    ("T1055", "Process Injection", [DE, PE], [r"process injection", r"inject\w* into", r"createremotethread", r"process hollowing", r"reflective(ly)? (dll )?load"]),
    ("T1036", "Masquerading", [DE], [r"masquerad", r"renamed (binary|executable|tool)", r"fake (svchost|lsass|explorer)", r"mimic\w* (a )?(legit|system)"]),
    ("T1112", "Modify Registry", [DE], [r"(modif\w+|changed|set) (a )?registry (key|value)", r"\breg(\.exe)? add\b", r"set-itemproperty .*hk(lm|cu)"]),
    # Credential access
    ("T1003.001", "OS Credential Dumping: LSASS Memory", ["credential-access"], [r"\blsass\b", r"mimikatz", r"sekurlsa", r"comsvcs(\.dll)?.*minidump", r"procdump.*lsass"]),
    ("T1003.002", "OS Credential Dumping: Security Account Manager", ["credential-access"], [r"\bsam (hive|database|dump)", r"reg(\.exe)? save hklm\\\\?sam", r"hklm\\\\?sam\b"]),
    ("T1003.003", "OS Credential Dumping: NTDS", ["credential-access"], [r"ntds\.dit", r"ntdsutil", r"\bifm\b.*ntds"]),
    ("T1003.006", "OS Credential Dumping: DCSync", ["credential-access"], [r"dcsync", r"lsadump::dcsync", r"drsuapi", r"directory replication"]),
    ("T1110.001", "Brute Force: Password Guessing", ["credential-access"], [r"brute[- ]?forc", r"password guessing", r"(many|multiple|repeated) failed (logins?|logons?|password)", r"\bhydra\b"]),
    ("T1110.003", "Brute Force: Password Spraying", ["credential-access"], [r"password spray", r"spray\w* (attack|passwords?)", r"one password (against|across) many"]),
    ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", ["credential-access"], [r"kerberoast", r"\b4769\b.*rc4", r"rc4.*\b4769\b", r"getuserspns"]),
    ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", ["credential-access"], [r"browser (credential|password)s?", r"login data", r"chrome (passwords|credentials)", r"infostealer"]),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", ["credential-access"], [r"credentials? in (files?|config|scripts?)", r"plaintext password", r"\.env file", r"unattend\.xml", r"findstr .*password"]),
    ("T1056.001", "Input Capture: Keylogging", ["collection", "credential-access"], [r"keylog"]),
    # Discovery
    ("T1087.002", "Account Discovery: Domain Account", ["discovery"], [r"net user /domain", r"get-aduser", r"domain (user|account) (enum|discovery)", r"\bbloodhound\b", r"\bsharphound\b", r"\badfind\b"]),
    ("T1069.002", "Permission Groups Discovery: Domain Groups", ["discovery"], [r"net group .*/domain", r"get-adgroup", r"domain admins? (group )?enum"]),
    ("T1082", "System Information Discovery", ["discovery"], [r"\bsysteminfo\b", r"\buname -a\b", r"system information discovery", r"hostnamectl"]),
    ("T1083", "File and Directory Discovery", ["discovery"], [r"\bdir /s\b", r"file (and directory )?discovery", r"\btree /f\b", r"enumerat\w+ (files|shares and files)"]),
    ("T1046", "Network Service Discovery", ["discovery"], [r"port scan", r"internal scan", r"\bnmap\b", r"network service discovery", r"advanced ip scanner"]),
    ("T1057", "Process Discovery", ["discovery"], [r"\btasklist\b", r"\bps aux\b", r"process (list|discovery|enumeration)", r"get-process"]),
    ("T1018", "Remote System Discovery", ["discovery"], [r"net view", r"remote system discovery", r"ping sweep", r"\bnltest\b.*dclist", r"arp -a"]),
    ("T1016", "System Network Configuration Discovery", ["discovery"], [r"\bipconfig\b", r"\bifconfig\b", r"\broute print\b", r"\bip addr\b"]),
    ("T1033", "System Owner/User Discovery", ["discovery"], [r"\bwhoami\b", r"\bquery user\b", r"\bquser\b"]),
    # Lateral movement
    ("T1021.001", "Remote Services: Remote Desktop Protocol", ["lateral-movement"], [r"\brdp\b", r"remote desktop", r"\bmstsc\b", r"logon type 10"]),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", ["lateral-movement"], [r"\badmin\$", r"\bc\$", r"admin shares?", r"\bsmb\b.*(lateral|copy|exec)"]),
    ("T1021.004", "Remote Services: SSH", ["lateral-movement"], [r"ssh(ed)? (to|into) (another|internal|other)", r"lateral\w* .*ssh", r"ssh lateral"]),
    ("T1021.006", "Remote Services: Windows Remote Management", ["lateral-movement"], [r"\bwinrm\b", r"enter-pssession", r"invoke-command -computername", r"evil-winrm", r"wsmprovhost"]),
    ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", [DE, "lateral-movement"], [r"pass[- ]the[- ]hash", r"\bpth\b", r"sekurlsa::pth", r"overpass"]),
    ("T1570", "Lateral Tool Transfer", ["lateral-movement"], [r"lateral tool transfer", r"copied (the )?(tool|binary|payload) to (other|remote|another) host"]),
    # Collection
    ("T1560.001", "Archive Collected Data: Archive via Utility", ["collection"], [r"\b(7z|7za|rar|winrar)\b.* a ", r"archiv\w+ (data|files) (with|using)", r"\btar (-)?czf\b", r"zipped up"]),
    ("T1005", "Data from Local System", ["collection"], [r"data from local system", r"collected (local )?files", r"staged (documents|files)"]),
    ("T1114", "Email Collection", ["collection"], [r"email collection", r"mailbox (export|access|search)", r"new-mailboxexportrequest", r"\.pst\b"]),
    ("T1113", "Screen Capture", ["collection"], [r"screenshot", r"screen capture"]),
    # Command and control
    ("T1071.001", "Application Layer Protocol: Web Protocols", ["command-and-control"], [r"beacon\w* (over|via) https?", r"http(s)? c2", r"c2 over http", r"\bcobalt strike\b", r"beacon\w* to"]),
    ("T1071.004", "Application Layer Protocol: DNS", ["command-and-control"], [r"dns c2", r"dns tunnel", r"c2 over dns", r"txt record (beacon|c2)"]),
    ("T1105", "Ingress Tool Transfer", ["command-and-control"], [r"download\w* (a |the )?(second stage|payload|tool|binary)", r"pulled (a )?(second stage|payload)", r"certutil.*-urlcache", r"\bwget\b", r"\bcurl\b.*(-o|\|\s*sh)", r"invoke-webrequest", r"downloadstring", r"downloadfile"]),
    ("T1572", "Protocol Tunneling", ["command-and-control"], [r"protocol tunnel", r"\bngrok\b", r"\bchisel\b", r"ssh tunnel", r"\bplink\b.*-r"]),
    ("T1090", "Proxy", ["command-and-control"], [r"\bproxy (chain|hop)", r"\bsocks (proxy|tunnel)", r"\btor\b (network|exit|node)"]),
    ("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", ["command-and-control"], [r"\bdga\b", r"domain generation algorithm"]),
    ("T1573", "Encrypted Channel", ["command-and-control"], [r"encrypted channel", r"custom encrypt\w+ c2"]),
    # Exfiltration
    ("T1041", "Exfiltration Over C2 Channel", ["exfiltration"], [r"exfil\w* (over|via|through) (the )?(c2|beacon)"]),
    ("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", ["exfiltration"], [r"\brclone\b", r"exfil\w* to (mega|dropbox|google drive|onedrive|s3|cloud storage)", r"mega\.nz"]),
    ("T1048", "Exfiltration Over Alternative Protocol", ["exfiltration"], [r"exfil\w* (over|via) (ftp|dns|smtp|icmp)"]),
    ("T1020", "Automated Exfiltration", ["exfiltration"], [r"automated exfil"]),
    # Impact
    ("T1486", "Data Encrypted for Impact", ["impact"], [r"ransomware", r"encrypted (files|data|the file server)", r"ransom note", r"files? renamed with .* extension"]),
    ("T1490", "Inhibit System Recovery", ["impact"], [r"vssadmin.*delete", r"delete shadows", r"shadow cop(y|ies) (deleted|removed)", r"bcdedit.*recoveryenabled", r"wbadmin delete"]),
    ("T1489", "Service Stop", ["impact"], [r"stopp?ed (the )?(database|sql|backup|exchange) service", r"\bnet stop\b", r"service stop"]),
    ("T1485", "Data Destruction", ["impact"], [r"data destruction", r"\bwiper\b", r"wiped (the )?(disk|drives?|data)"]),
    ("T1496", "Resource Hijacking", ["impact"], [r"crypto ?min", r"\bxmrig\b", r"\bminer\b", r"resource hijack"]),
    ("T1531", "Account Access Removal", ["impact"], [r"account access removal", r"(changed|reset) (all |admin )?passwords? to lock", r"locked out (all|admins)"]),
]

_COMPILED = [(tid, name, tactics, [re.compile(k, re.I) for k in kws]) for tid, name, tactics, kws in TECHNIQUES]
BY_ID = {t[0]: t for t in TECHNIQUES}
RE_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def map_line(line: str) -> List[Dict]:
    """Return the techniques one line of text points at, with the keyword that matched."""
    hits: Dict[str, Dict] = {}
    for tid in RE_TID.findall(line):
        if tid in BY_ID:
            _, name, tactics, _ = BY_ID[tid]
            hits[tid] = {"id": tid, "name": name, "tactics": tactics, "matched": tid}
        else:
            hits[tid] = {"id": tid, "name": None, "tactics": [], "matched": tid,
                         "note": "ID not in the embedded table; check it on attack.mitre.org"}
    for tid, name, tactics, patterns in _COMPILED:
        if tid in hits:
            continue
        for p in patterns:
            m = p.search(line)
            if m:
                hits[tid] = {"id": tid, "name": name, "tactics": tactics, "matched": m.group(0)}
                break
    return sorted(hits.values(), key=lambda h: h["id"])


def map_text(text: str) -> Dict:
    lines_out = []
    techniques: Dict[str, Dict] = {}
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        hits = map_line(line)
        lines_out.append({"line": no, "text": line, "techniques": [h["id"] for h in hits]})
        for h in hits:
            entry = techniques.setdefault(h["id"], dict(h, lines=[]))
            entry["lines"].append(no)
    return {"lines": lines_out, "techniques": sorted(techniques.values(), key=lambda t: t["id"]),
            "coverage": coverage(techniques)}


def coverage(techniques: Dict[str, Dict]) -> List[Dict]:
    out = []
    for ta_id, short, name in TACTICS:
        in_table = [t for t in TECHNIQUES if short in t[2]]
        seen = sorted(tid for tid, t in techniques.items() if short in t["tactics"])
        out.append({"tactic": name, "tactic_id": ta_id, "shortname": short,
                    "matched": len(seen), "in_table": len(in_table), "techniques": seen})
    return out


def navigator_layer(result: Dict, name: str = "claude-security-skills attack_mapper") -> Dict:
    """ATT&CK Navigator layer (format 4.5). Score = number of lines that hit the technique."""
    techs = []
    for t in result["techniques"]:
        if not t.get("name"):
            continue
        techs.append({"techniqueID": t["id"], "score": len(t["lines"]), "color": "",
                      "comment": f"matched '{t['matched']}' on line(s) {', '.join(map(str, t['lines']))}",
                      "enabled": True, "showSubtechniques": False})
    top = max([t["score"] for t in techs] or [1])
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": "Generated by claude-security-skills threat-hunting/attack_mapper.py from free-text notes",
        "techniques": techs,
        "gradient": {"colors": ["#fff3b0", "#e4572e"], "minValue": 0, "maxValue": top},
        "legendItems": [],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "hideDisabled": False,
    }


def render_text(result: Dict) -> str:
    out = [f"{len(result['techniques'])} technique(s) from {len(result['lines'])} line(s)", ""]
    for t in result["techniques"]:
        if t.get("name"):
            tactics = ", ".join(TACTIC_NAME[x] for x in t["tactics"])
            out.append(f"{t['id']:10} {t['name']}  [{tactics}]")
            out.append(f"           matched '{t['matched']}' on line(s) {', '.join(map(str, t['lines']))}")
        else:
            out.append(f"{t['id']:10} (unknown to this table, verify on attack.mitre.org)")
    unmatched = [l for l in result["lines"] if not l["techniques"]]
    if unmatched:
        out += ["", "No match (map by hand or extend the table):"]
        out += [f"  line {l['line']}: {l['text'][:100]}" for l in unmatched]
    out += ["", "Coverage per tactic (matched / techniques in table):"]
    for c in result["coverage"]:
        bar = "#" * c["matched"]
        out.append(f"  {c['tactic']:22} {c['matched']:2}/{c['in_table']:<3} {bar}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Map free-text behaviour notes or detection names to MITRE ATT&CK techniques.")
    ap.add_argument("path", nargs="?", help="text file, one observation per line")
    ap.add_argument("--file", help="text file; '-' for stdin")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--navigator", metavar="OUT.json", help="also write an ATT&CK Navigator layer to this file")
    ap.add_argument("--layer-name", default="claude-security-skills attack_mapper")
    ap.add_argument("--list", action="store_true", help="print the embedded technique table and exit")
    args = ap.parse_args(argv)

    if args.list:
        for tid, name, tactics, _ in TECHNIQUES:
            print(f"{tid:10} {name}  [{', '.join(TACTIC_NAME[t] for t in tactics)}]")
        return 0
    src = args.file or args.path
    if not src:
        print("error: give a file path, --file - for stdin, or --list", file=sys.stderr)
        return 2
    try:
        text = sys.stdin.read() if src == "-" else open(src, encoding="utf-8", errors="replace").read()
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if not text.strip():
        print("error: input is empty", file=sys.stderr)
        return 2

    result = map_text(text)
    if args.navigator:
        try:
            with open(args.navigator, "w", encoding="utf-8") as fh:
                json.dump(navigator_layer(result, args.layer_name), fh, indent=2)
        except OSError as err:
            print(f"error: {err}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_text(result))
        if args.navigator:
            print(f"\nNavigator layer written to {args.navigator}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
