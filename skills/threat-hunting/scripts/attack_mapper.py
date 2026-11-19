#!/usr/bin/env python3
"""Map behaviour notes or detection names to MITRE ATT&CK Enterprise techniques.

Reads free text (one observation or detection name per line), matches it
against an embedded keyword table of well-known techniques, and prints the
matches plus coverage per tactic. Technique IDs written in the text
(T1059.001) are picked up directly and checked against the full ATT&CK
Enterprise v20.1 ID list: revoked IDs are mapped to their current technique
(T1070.001 becomes T1685.005), deprecated and made-up IDs are flagged.
Can write an ATT&CK Navigator layer.

The keyword table is a curated subset (~140 techniques, Windows, Linux,
identity and cloud), not the full matrix. A line with no match means "not in
this table", not "not malicious".

ATT&CK v19 (April 2026) split the old Defense Evasion tactic: TA0005 is now
"Stealth" and the new TA0112 "Defense Impairment" holds the techniques that
switch defenses off (T1562 Impair Defenses became T1685, T1686 and others).

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

ATTACK_VERSION = "20.1"
NAVIGATOR_VERSION = "5.3.2"
LAYER_FORMAT = "4.5"

# Enterprise tactics in matrix order (ATT&CK v20.1).
TACTICS = [
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "stealth", "Stealth"),
    ("TA0112", "defense-impairment", "Defense Impairment"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
]
TACTIC_NAME = {short: name for _, short, name in TACTICS}
# Old shortnames still seen in notes, rules and older layers.
LEGACY_TACTICS = {"defense-evasion": "stealth"}

# (id, name, tactics, keyword regexes). Names and tactics follow ATT&CK Enterprise
# v20.1; sub-technique names are shown as "Parent: Sub" like the ATT&CK site does.
TECHNIQUES = [
    # Reconnaissance
    ("T1595", "Active Scanning", ["reconnaissance"], [r"\bactive scan", r"\bmasscan\b", r"\bzmap\b", r"internet[- ]wide scan"]),
    ("T1595.002", "Active Scanning: Vulnerability Scanning", ["reconnaissance"], [r"vulnerability scan", r"\bnikto\b", r"\bnuclei\b", r"\bsqlmap\b", r"\bwpscan\b"]),
    # Resource development
    ("T1583.001", "Acquire Infrastructure: Domains", ["resource-development"], [r"(newly|recently) registered domain", r"lookalike domain", r"typosquat"]),
    # Initial access
    ("T1566.001", "Phishing: Spearphishing Attachment", ["initial-access"], [r"phish\w* (email )?attachment", r"malicious attachment", r"macro[- ]enabled (doc|document|attachment)", r"\.docm\b", r"\.xlsm\b", r"attachment opened"]),
    ("T1566.002", "Phishing: Spearphishing Link", ["initial-access"], [r"phish\w* (email )?link", r"malicious link", r"clicked (a |the )?link", r"credential harvest"]),
    ("T1566.004", "Phishing: Spearphishing Voice", ["initial-access"], [r"\bvishing\b", r"voice phishing", r"callback phishing", r"spearphishing voice"]),
    ("T1190", "Exploit Public-Facing Application", ["initial-access"], [r"exploit\w* (a |the )?(public|internet)[- ]facing", r"exploit\w* (the )?(vpn|web server|web app|appliance|exchange|citrix|confluence)", r"\brce\b on", r"web exploit"]),
    ("T1133", "External Remote Services", ["persistence", "initial-access"], [r"external remote service", r"\bvpn (login|logon|access)", r"exposed rdp", r"citrix gateway login"]),
    ("T1078", "Valid Accounts", ["stealth", "persistence", "privilege-escalation", "initial-access"], [r"valid (account|credential)", r"stolen credential", r"compromised account", r"legitimate credential"]),
    ("T1078.004", "Valid Accounts: Cloud Accounts", ["stealth", "persistence", "privilege-escalation", "initial-access"], [r"(compromised|stolen|valid) (cloud|azure|aws|m365|microsoft 365|entra|office 365|o365|gcp|iam) (account|user|credential)s?", r"root (account|user) (console )?(login|sign[- ]?in|used)", r"console ?login .*\broot\b", r"console login without mfa", r"impossible travel"]),
    ("T1189", "Drive-by Compromise", ["initial-access"], [r"drive[- ]by", r"watering hole", r"malvertising"]),
    ("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", ["initial-access"], [r"supply[- ]chain", r"trojani[sz]ed (update|installer|package)", r"malicious (npm|pypi) package"]),
    ("T1199", "Trusted Relationship", ["initial-access"], [r"trusted relationship", r"(msp|managed service provider|it provider|vendor|supplier)('s)? (account|access|tenant) (was )?(compromised|abused|used)", r"via (the|a|an) (msp|it provider|vendor) (account|connection|tool)"]),
    # Execution
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", ["execution"], [r"powershell", r"\bpwsh\b", r"-enc(odedcommand)?\b", r"invoke-expression", r"\biex\b"]),
    ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", ["execution"], [r"\bcmd(\.exe)? /c\b", r"windows command shell", r"\bcmd\.exe\b", r"batch (file|script)"]),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell", ["execution"], [r"\bbash -c\b", r"\bsh -c\b", r"unix shell", r"reverse shell", r"/bin/(ba)?sh\b"]),
    ("T1059.005", "Command and Scripting Interpreter: Visual Basic", ["execution"], [r"\bvba\b", r"\bvbscript\b", r"\bmacro\b", r"\bwscript\b", r"\bcscript\b", r"\.vbs\b"]),
    ("T1059.006", "Command and Scripting Interpreter: Python", ["execution"], [r"python -c\b", r"malicious python", r"python script (ran|executed)"]),
    ("T1059.007", "Command and Scripting Interpreter: JavaScript", ["execution"], [r"\bjscript\b", r"\.js(e)? (file|attachment|dropper)", r"malicious javascript"]),
    ("T1047", "Windows Management Instrumentation", ["execution"], [r"\bwmic\b", r"\bwmi\b(?! event)", r"win32_process", r"invoke-wmimethod"]),
    ("T1204.002", "User Execution: Malicious File", ["execution"], [r"user (opened|ran|executed|double[- ]clicked)", r"opened (the )?(attachment|file|document)", r"enabled? (content|macros?)"]),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", ["execution", "persistence", "privilege-escalation"], [r"schtasks", r"scheduled task", r"register-scheduledtask", r"\bat\.exe\b"]),
    ("T1053.003", "Scheduled Task/Job: Cron", ["execution", "persistence", "privilege-escalation"], [r"\bcron(tab)?\b", r"/etc/cron"]),
    ("T1569.002", "System Services: Service Execution", ["execution"], [r"\bpsexec\b", r"\bsc(\.exe)? (start|create)\b", r"service execution", r"remcom"]),
    ("T1651", "Cloud Administration Command", ["execution"], [r"cloud administration command", r"\bssm send-command\b", r"\bsendcommand\b", r"invoke-azvmruncommand", r"\brun ?command\b (on|against) (the |a )?(vm|instance)"]),
    ("T1698", "Indirect Prompt Injection", ["execution"], [r"indirect prompt injection", r"prompt injection (hidden )?(in|via|through) (a |an |the )?(email|document|web ?page|file|repo|ticket|issue)"]),
    ("T1699", "Direct Prompt Injection", ["execution"], [r"direct prompt injection", r"jailbr(eak|oke)\w* (the )?(llm|model|chatbot|assistant|ai)"]),
    # Persistence
    ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", ["persistence", "privilege-escalation"], [r"currentversion\\\\?run", r"\brun key", r"runonce", r"startup folder", r"registry run"]),
    ("T1543.003", "Create or Modify System Process: Windows Service", ["persistence", "privilege-escalation"], [r"new service (installed|created)", r"service install", r"event ?id 7045", r"\b7045\b", r"sc(\.exe)? create", r"new-service"]),
    ("T1543.002", "Create or Modify System Process: Systemd Service", ["persistence", "privilege-escalation"], [r"systemd (service|unit)", r"systemctl enable", r"/etc/systemd/system"]),
    ("T1136.001", "Create Account: Local Account", ["persistence"], [r"(new|created?) local (user|account)", r"net user \S+ \S+ /add", r"\buseradd\b", r"\badduser\b", r"event ?id 4720", r"\b4720\b"]),
    ("T1136.003", "Create Account: Cloud Account", ["persistence"], [r"(new|created?) (cloud|azure|entra|aad|iam|guest) (user|account)", r"\bcreateuser\b", r"invited (a |an )?(new )?(external )?guest"]),
    ("T1098", "Account Manipulation", ["persistence", "privilege-escalation"], [r"added to (the )?(local )?(admin|administrators|domain admins|sudo)", r"group membership change", r"net localgroup administrators", r"\b4732\b", r"\b4728\b", r"\busermod -ag\b"]),
    ("T1098.001", "Account Manipulation: Additional Cloud Credentials", ["persistence", "privilege-escalation"], [r"\bcreateaccesskey\b", r"new (iam )?access key (created|issued)", r"(added|created|new) (a )?(new )?(client secret|app(lication)? secret|app password|service principal (secret|credential)|federated credential)", r"(certificates and secrets|add service principal credentials)"]),
    ("T1098.002", "Account Manipulation: Additional Email Delegate Permissions", ["persistence", "privilege-escalation"], [r"add-mailboxpermission", r"add-mailboxfolderpermission", r"fullaccess (permission|rights?) (granted|added)", r"mailbox delegat\w+ (added|granted)", r"applicationimpersonation"]),
    ("T1098.003", "Account Manipulation: Additional Cloud Roles", ["persistence", "privilege-escalation"], [r"attach(user|role|group)policy", r"administratoraccess", r"(assigned|added to|granted) (the )?(global admin(istrator)?|privileged role|owner role|company administrator)", r"add member to role"]),
    ("T1098.004", "Account Manipulation: SSH Authorized Keys", ["persistence", "privilege-escalation"], [r"authorized_keys"]),
    ("T1098.005", "Account Manipulation: Device Registration", ["persistence", "privilege-escalation"], [r"(new|rogue|unknown|attacker) device (registered|joined|enrolled)", r"device registration", r"(registered|added) (a |an )?(new )?(mfa|authenticator|security key|fido2?) (device|method|app|key)"]),
    ("T1505.003", "Server Software Component: Web Shell", ["persistence"], [r"web ?shell", r"china ?chopper", r"\.aspx dropped", r"\.jsp dropped"]),
    ("T1546.003", "Event Triggered Execution: Windows Management Instrumentation Event Subscription", ["privilege-escalation", "persistence"], [r"wmi (event )?subscription", r"__eventfilter", r"commandlineeventconsumer", r"wmi persistence"]),
    ("T1197", "BITS Jobs", ["stealth", "persistence", "execution"], [r"\bbitsadmin\b", r"bits job", r"start-bitstransfer"]),
    # Privilege escalation
    ("T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control", ["privilege-escalation"], [r"\buac bypass", r"bypass(ed)? uac", r"fodhelper", r"eventvwr\.exe.*(hijack|bypass)"]),
    ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ["privilege-escalation"], [r"sudo (abuse|caching|misconfig)", r"\bsudoers\b", r"timestamp_timeout"]),
    ("T1068", "Exploitation for Privilege Escalation", ["privilege-escalation"], [r"privilege escalation exploit", r"local privilege escalation", r"\blpe\b", r"kernel exploit", r"exploit\w* .*to (gain )?(system|root)"]),
    ("T1134", "Access Token Manipulation", ["stealth", "privilege-escalation"], [r"token (impersonation|manipulation)", r"impersonat\w+ token", r"\bsedebugprivilege\b", r"make_token", r"steal_token"]),
    # Stealth (TA0005, called Defense Evasion before ATT&CK v19)
    ("T1027", "Obfuscated Files or Information", ["stealth"], [r"obfuscat", r"base64[- ]encoded (payload|command|script)", r"-enc(odedcommand)?\b", r"packed (binary|executable)", r"xor[- ]encoded"]),
    ("T1027.018", "Obfuscated Files or Information: Invisible Unicode", ["stealth"], [r"invisible unicode", r"zero[- ]width (characters?|spaces?|joiners?)", r"unicode tag characters"]),
    ("T1140", "Deobfuscate/Decode Files or Information", ["stealth"], [r"certutil.*-decode", r"frombase64string", r"decod\w+ (the )?payload", r"base64 -d\b"]),
    ("T1070.004", "Indicator Removal: File Deletion", ["stealth"], [r"(deleted|removed|wiped) (the )?(dropper|payload|tools|binary|artifacts?)", r"sdelete", r"self[- ]delet"]),
    ("T1070.003", "Indicator Removal: Clear Command History", ["stealth"], [r"bash_history", r"history -c\b", r"clear(ed)? (the )?(command|shell) history"]),
    ("T1070.006", "Indicator Removal: Timestomp", ["stealth"], [r"timestomp", r"\btouch -\w*[rt]\b", r"(modified|changed|altered|backdated) (the )?(file )?timestamps?"]),
    ("T1218.011", "System Binary Proxy Execution: Rundll32", ["stealth"], [r"\brundll32\b"]),
    ("T1218.005", "System Binary Proxy Execution: Mshta", ["stealth"], [r"\bmshta\b", r"\.hta\b"]),
    ("T1218.010", "System Binary Proxy Execution: Regsvr32", ["stealth"], [r"\bregsvr32\b", r"squiblydoo"]),
    ("T1055", "Process Injection", ["stealth", "privilege-escalation"], [r"process injection", r"inject\w* into", r"createremotethread", r"process hollowing", r"reflective(ly)? (dll )?load"]),
    ("T1036", "Masquerading", ["stealth"], [r"masquerad", r"renamed (binary|executable|tool)", r"fake (svchost|lsass|explorer)", r"mimic\w* (a )?(legit|system)"]),
    ("T1564.008", "Hide Artifacts: Email Hiding Rules", ["stealth"], [r"(email|inbox|mailbox) hiding rule", r"inbox rule .*(delete|move\w* (to|into) (rss|archive|conversation history|deleted items)|mark\w* as read)", r"new-inboxrule .*(deletemessage|movetofolder|markasread)"]),
    ("T1535", "Unused/Unsupported Cloud Regions", ["stealth"], [r"(unused|unusual|unsupported|never[- ]used) (aws |cloud |azure |gcp )?regions?"]),
    ("T1684.001", "Social Engineering: Impersonation", ["stealth"], [r"impersonat\w* (the |a |an )?(ceo|cfo|executive|vendor|it support|help ?desk|supplier)", r"\bbec\b", r"business email compromise", r"help ?desk (social engineering|impersonation)"]),
    ("T1684.002", "Social Engineering: Email Spoofing", ["stealth"], [r"email spoofing", r"spoof\w* (the )?(email|sender|from address|sending domain)", r"(spf|dmarc|dkim) (fail|failure)"]),
    # Defense Impairment (TA0112, new in ATT&CK v19)
    ("T1685", "Disable or Modify Tools", ["defense-impairment"], [r"(disabled?|tamper\w*|stopp?ed|kill\w*) (windows )?(defender|antivirus|av|edr|sysmon|security tool|guardduty|security hub)", r"set-mppreference", r"disablerealtimemonitoring", r"defender exclusion", r"\bdeletedetector\b"]),
    ("T1685.001", "Disable or Modify Tools: Disable or Modify Windows Event Log", ["defense-impairment"], [r"auditpol .*(/clear|/remove|disable)", r"eventlog service (stopped|disabled)", r"(disabled?|stopp?ed) (the )?(windows )?event log(ging| service)", r"wevtutil sl .*/e:false"]),
    ("T1685.002", "Disable or Modify Tools: Disable or Modify Cloud Log", ["defense-impairment"], [r"\bstoplogging\b", r"\bdeletetrail\b", r"(cloudtrail|audit log(ging)?|diagnostic settings?|flow logs?)( was| were)? (disabled|deleted|stopped|turned off)", r"(disabl|delet|stopp?)\w* (the )?(cloudtrail|cloud audit log|unified audit log|diagnostic setting|vpc flow log)", r"auditlogagelimit|set-mailboxauditbypassassociation"]),
    ("T1685.004", "Disable or Modify Tools: Disable or Modify Linux Audit System Log", ["defense-impairment"], [r"auditctl -e ?0", r"auditd (was )?(stopped|disabled|killed)", r"(stopp?ed|disabled?|killed) auditd"]),
    ("T1685.005", "Disable or Modify Tools: Clear Windows Event Logs", ["defense-impairment"], [r"(cleared|clear|wiped?) (the )?(security |windows |event )?(event )?logs?", r"wevtutil (cl|clear-log)", r"\b1102\b", r"clear-eventlog"]),
    ("T1685.006", "Disable or Modify Tools: Clear Linux or Mac System Logs", ["defense-impairment"], [r"(cleared|truncated|deleted|wiped) (the )?(/var/log\S*|syslog|auth\.log|wtmp|btmp|lastlog|system logs)", r"rm -\w*f\w* /var/log", r"truncate .*-s ?0 .*/var/log"]),
    ("T1686", "Disable or Modify System Firewall", ["defense-impairment"], [r"\bufw disable\b", r"iptables -f\b", r"(disabled?|flushed|turned off) (the )?(host )?firewall"]),
    ("T1686.001", "Disable or Modify System Firewall: Cloud Firewall", ["defense-impairment"], [r"0\.0\.0\.0/0", r"authorizesecuritygroupingress", r"security group (opened|modified|changed) to (the )?(internet|world)", r"(nsg|network security group) rule (added|changed|opened)"]),
    ("T1686.003", "Disable or Modify System Firewall: Windows Host Firewall", ["defense-impairment"], [r"netsh (adv)?firewall .*(state off|disable|delete)", r"set-netfirewallprofile .*-enabled false", r"(disabled?|turned off) (the )?windows (defender )?firewall"]),
    ("T1690", "Prevent Command History Logging", ["defense-impairment"], [r"unset histfile", r"histfile=/dev/null", r"histsize=0", r"set \+o history", r"histcontrol=ignore(space|both)"]),
    ("T1112", "Modify Registry", ["defense-impairment", "persistence"], [r"(modif\w+|changed|set) (a )?registry (key|value)", r"\breg(\.exe)? add\b", r"set-itemproperty .*hk(lm|cu)"]),
    ("T1484.002", "Domain or Tenant Policy Modification: Trust Modification", ["defense-impairment", "privilege-escalation"], [r"(new|added|modified|rogue) (federated domain|domain federation|federation (trust|settings))", r"set domain authentication", r"set-msoldomainfederationsettings", r"new-msolfederateddomain", r"(domain )?(converted|changed) to federated"]),
    ("T1556.006", "Modify Authentication Process: Multi-Factor Authentication", ["defense-impairment", "persistence", "credential-access"], [r"(disabled?|removed|turned off) (per[- ]user )?mfa", r"mfa (was )?(disabled|removed|turned off)", r"(excluded|exempted) from mfa"]),
    ("T1556.009", "Modify Authentication Process: Conditional Access Policies", ["defense-impairment", "persistence", "credential-access"], [r"conditional access (policy )?(was )?(disabled|deleted|modified|changed|weakened)", r"(disabled?|deleted|modified) (a |the )?conditional access", r"(excluded|exempted) from conditional access"]),
    # Credential access
    ("T1003.001", "OS Credential Dumping: LSASS Memory", ["credential-access"], [r"\blsass\b", r"mimikatz", r"sekurlsa", r"comsvcs(\.dll)?.*minidump", r"procdump.*lsass"]),
    ("T1003.002", "OS Credential Dumping: Security Account Manager", ["credential-access"], [r"\bsam (hive|database|dump)", r"reg(\.exe)? save hklm\\\\?sam", r"hklm\\\\?sam\b"]),
    ("T1003.003", "OS Credential Dumping: NTDS", ["credential-access"], [r"ntds\.dit", r"ntdsutil", r"\bifm\b.*ntds"]),
    ("T1003.006", "OS Credential Dumping: DCSync", ["credential-access"], [r"dcsync", r"lsadump::dcsync", r"drsuapi", r"directory replication"]),
    ("T1110.001", "Brute Force: Password Guessing", ["credential-access"], [r"brute[- ]?forc", r"password guessing", r"(many|multiple|repeated) failed (logins?|logons?|password|sign[- ]?ins?)", r"\bhydra\b"]),
    ("T1110.003", "Brute Force: Password Spraying", ["credential-access"], [r"password spray", r"spray\w* (attack|passwords?)", r"one password (against|across) many"]),
    ("T1110.004", "Brute Force: Credential Stuffing", ["credential-access"], [r"credential stuffing", r"(leaked|breached) (credential|password) (list|dump|combo)", r"combo ?list"]),
    ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", ["credential-access"], [r"kerberoast", r"\b4769\b.*rc4", r"rc4.*\b4769\b", r"getuserspns"]),
    ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", ["credential-access"], [r"browser (credential|password)s?", r"login data", r"chrome (passwords|credentials)", r"infostealer"]),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", ["credential-access"], [r"credentials? in (files?|config|scripts?)", r"plaintext password", r"\.env file", r"unattend\.xml", r"findstr .*password"]),
    ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", ["credential-access"], [r"169\.254\.169\.254", r"instance metadata (api|service|endpoint)", r"\bimds\b", r"metadata\.google\.internal"]),
    ("T1056.001", "Input Capture: Keylogging", ["collection", "credential-access"], [r"keylog"]),
    ("T1528", "Steal Application Access Token", ["credential-access"], [r"(illicit|malicious|rogue|suspicious) (oauth )?(app )?consent", r"consent (phishing|grant attack)", r"oauth (token )?theft", r"(stole|stolen|steal\w*) (the |an? )?(oauth |access |refresh )token", r"\btoken theft\b", r"device code (phish|flow (abuse|phish))", r"consent to application"]),
    ("T1539", "Steal Web Session Cookie", ["credential-access"], [r"(stole|stolen|steal\w*|exfiltrat\w*) (the )?(browser |web |session |auth )?cookies?", r"session hijack", r"cookie theft"]),
    ("T1557", "Adversary-in-the-Middle", ["credential-access", "collection"], [r"\baitm\b", r"adversary[- ]in[- ]the[- ]middle", r"man[- ]in[- ]the[- ]middle", r"\bmitm\b", r"evilginx", r"llmnr (poison|spoof)"]),
    ("T1111", "Multi-Factor Authentication Interception", ["credential-access"], [r"(intercept|stole|stolen|phish|relay)\w* (the |an? )?(mfa|otp|one[- ]time|2fa|sms|totp) (code|token|passcode)", r"mfa interception"]),
    ("T1606.002", "Forge Web Credentials: SAML Tokens", ["credential-access"], [r"golden saml", r"forged saml", r"saml token forg", r"token[- ]signing (certificate|cert) (export|stolen|theft)"]),
    ("T1621", "Multi-Factor Authentication Request Generation", ["credential-access"], [r"mfa (fatigue|bomb\w*|spam|flood|push spam)", r"push (bombing|fatigue|spam)", r"(many|repeated|multiple|flood of) (mfa|push|2fa) (prompts|requests|notifications|denials)", r"mfa request generation", r"\b500121\b"]),
    ("T1697", "Steal Application Specific Passwords", ["credential-access"], [r"app(lication)?[- ]specific passwords?"]),
    # Discovery
    ("T1087.002", "Account Discovery: Domain Account", ["discovery"], [r"net user /domain", r"get-aduser", r"domain (user|account) (enum|discovery)", r"\bbloodhound\b", r"\bsharphound\b", r"\badfind\b"]),
    ("T1087.004", "Account Discovery: Cloud Account", ["discovery"], [r"get-(mg|azuread|msol)user\b", r"iam list-users", r"\blistusers\b", r"(enumerat|list)\w* (all )?(cloud|azure|entra|aad|iam) (users|accounts)"]),
    ("T1069.002", "Permission Groups Discovery: Domain Groups", ["discovery"], [r"net group .*/domain", r"get-adgroup", r"domain admins? (group )?enum"]),
    ("T1069.003", "Permission Groups Discovery: Cloud Groups", ["discovery"], [r"get-(mg|azuread|msol)group\b", r"iam list-groups", r"\blistgroups\b", r"(enumerat|list)\w* (all )?(cloud|azure|entra|aad|iam) (groups|roles|role assignments)"]),
    ("T1082", "System Information Discovery", ["discovery"], [r"\bsysteminfo\b", r"\buname -a\b", r"system information discovery", r"hostnamectl"]),
    ("T1083", "File and Directory Discovery", ["discovery"], [r"\bdir /s\b", r"file (and directory )?discovery", r"\btree /f\b", r"enumerat\w+ (files|shares and files)"]),
    ("T1046", "Network Service Discovery", ["discovery"], [r"port scan", r"internal scan", r"\bnmap\b", r"network service discovery", r"advanced ip scanner"]),
    ("T1057", "Process Discovery", ["discovery"], [r"\btasklist\b", r"\bps aux\b", r"process (list|discovery|enumeration)", r"get-process"]),
    ("T1018", "Remote System Discovery", ["discovery"], [r"net view", r"remote system discovery", r"ping sweep", r"\bnltest\b.*dclist", r"arp -a"]),
    ("T1016", "System Network Configuration Discovery", ["discovery"], [r"\bipconfig\b", r"\bifconfig\b", r"\broute print\b", r"\bip addr\b"]),
    ("T1033", "System Owner/User Discovery", ["discovery"], [r"\bwhoami\b", r"\bquery user\b", r"\bquser\b"]),
    ("T1526", "Cloud Service Discovery", ["discovery"], [r"cloud service discovery", r"\broadrecon\b", r"\bazurehound\b", r"(enumerat|list)\w* (the )?(cloud services|subscriptions|tenants)"]),
    ("T1580", "Cloud Infrastructure Discovery", ["discovery"], [r"cloud infrastructure discovery", r"\bdescribe-?instances\b", r"\blist-?buckets\b", r"(enumerat|list)\w* (the )?(ec2|vm|cloud) (instances|infrastructure|resources)"]),
    # Lateral movement
    ("T1021.001", "Remote Services: Remote Desktop Protocol", ["lateral-movement"], [r"\brdp\b", r"remote desktop", r"\bmstsc\b", r"logon type 10"]),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", ["lateral-movement"], [r"\badmin\$", r"\bc\$", r"admin shares?", r"\bsmb\b.*(lateral|copy|exec)"]),
    ("T1021.004", "Remote Services: SSH", ["lateral-movement"], [r"ssh(ed)? (to|into) (another|internal|other)", r"lateral\w* .*ssh", r"ssh lateral"]),
    ("T1021.006", "Remote Services: Windows Remote Management", ["lateral-movement"], [r"\bwinrm\b", r"enter-pssession", r"invoke-command -computername", r"evil-winrm", r"wsmprovhost"]),
    ("T1550.001", "Use Alternate Authentication Material: Application Access Token", ["lateral-movement"], [r"\btoken replay", r"replay\w* (a |the )?(stolen )?(oauth |access |refresh |primary refresh )?tokens?", r"pass[- ]the[- ](prt|token)", r"\bprt\b (theft|replay|abuse)"]),
    ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", ["lateral-movement"], [r"pass[- ]the[- ]hash", r"\bpth\b", r"sekurlsa::pth", r"overpass"]),
    ("T1550.004", "Use Alternate Authentication Material: Web Session Cookie", ["lateral-movement"], [r"pass[- ]the[- ]cookie", r"cookie replay", r"replay\w* (a |the )?(stolen )?(session )?cookies?"]),
    ("T1570", "Lateral Tool Transfer", ["lateral-movement"], [r"lateral tool transfer", r"copied (the )?(tool|binary|payload) to (other|remote|another) host"]),
    # Collection
    ("T1560.001", "Archive Collected Data: Archive via Utility", ["collection"], [r"\b(7z|7za|rar|winrar)\b.* a ", r"archiv\w+ (data|files) (with|using)", r"\btar (-)?czf\b", r"zipped up"]),
    ("T1005", "Data from Local System", ["collection"], [r"data from local system", r"collected (local )?files", r"staged (documents|files)"]),
    ("T1114", "Email Collection", ["collection"], [r"email collection", r"mailbox (export|access|search)", r"new-mailboxexportrequest", r"\.pst\b"]),
    ("T1114.002", "Email Collection: Remote Email Collection", ["collection"], [r"\bmailitemsaccessed\b", r"(ews|graph api|imap) (mail|mailbox) (access|download|sync)", r"remote email collection"]),
    ("T1114.003", "Email Collection: Email Forwarding Rule", ["collection"], [r"forwarding rule", r"auto[- ]?forward", r"forwardingsmtpaddress", r"-forwardto\b", r"-redirectto\b"]),
    ("T1113", "Screen Capture", ["collection"], [r"screenshot", r"screen capture"]),
    ("T1530", "Data from Cloud Storage", ["collection"], [r"(s3|blob|bucket|gcs) (object )?(download|access|enumeration|exfil)", r"(downloaded|copied|accessed|synced) .*(s3 bucket|blob container|storage account|sharepoint|onedrive)", r"\bgetobject\b", r"mass (file )?download"]),
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
    ("T1537", "Transfer Data to Cloud Account", ["exfiltration"], [r"transfer\w* (the )?(data|snapshots?|backups?|images?) to (another|an external|an attacker|a different|attacker) (cloud |aws |azure )?(account|subscription|tenant)", r"(snapshot|ami|image) shared (with|to) (an )?(external|unknown) account", r"modify(snapshot|image)attribute"]),
    ("T1700", "AI-Enabled Exfiltration", ["exfiltration"], [r"ai[- ]enabled exfil", r"exfil\w* (via|through|using) (an? |the )?(ai|llm|agent|chatbot|copilot|assistant)\b"]),
    # Impact
    ("T1486", "Data Encrypted for Impact", ["impact"], [r"ransomware", r"encrypted (files|data|the file server)", r"ransom note", r"files? renamed with .* extension"]),
    ("T1490", "Inhibit System Recovery", ["impact"], [r"vssadmin.*delete", r"delete shadows", r"shadow cop(y|ies) (deleted|removed)", r"bcdedit.*recoveryenabled", r"wbadmin delete"]),
    ("T1489", "Service Stop", ["impact"], [r"stopp?ed (the )?(database|sql|backup|exchange) service", r"\bnet stop\b", r"service stop"]),
    ("T1485", "Data Destruction", ["impact"], [r"data destruction", r"\bwiper\b", r"wiped (the )?(disk|drives?|data)"]),
    ("T1496", "Resource Hijacking", ["impact"], [r"resource hijack"]),
    ("T1496.001", "Resource Hijacking: Compute Hijacking", ["impact"], [r"crypto ?min", r"\bxmrig\b", r"\bminer\b", r"compute hijack", r"(gpu|large) instances? (launched|spun up)"]),
    ("T1531", "Account Access Removal", ["impact"], [r"account access removal", r"(changed|reset) (all |admin )?passwords? to lock", r"locked out (all|admins)"]),
]

_COMPILED = [(tid, name, tactics, [re.compile(k, re.I) for k in kws]) for tid, name, tactics, kws in TECHNIQUES]
BY_ID = {t[0]: t for t in TECHNIQUES}
RE_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Every live technique and sub-technique ID in ATT&CK Enterprise v20.1 (not revoked,
# not deprecated). Used to tell a real ID that is missing from the keyword table
# from a typo.
ATTACK_IDS = frozenset((
    "T1001 T1001.001 T1001.002 T1001.003 T1003 T1003.001 T1003.002 T1003.003 T1003.004 T1003.005 "
    "T1003.006 T1003.007 T1003.008 T1005 T1006 T1007 T1008 T1010 T1011 T1011.001 T1012 T1014 T1016 "
    "T1016.001 T1016.002 T1018 T1020 T1020.001 T1021 T1021.001 T1021.002 T1021.003 T1021.004 T1021.005 "
    "T1021.006 T1021.007 T1021.008 T1025 T1027 T1027.001 T1027.002 T1027.003 T1027.004 T1027.005 "
    "T1027.006 T1027.007 T1027.008 T1027.009 T1027.010 T1027.011 T1027.012 T1027.013 T1027.014 T1027.015 "
    "T1027.016 T1027.017 T1027.018 T1029 T1030 T1033 T1036 T1036.001 T1036.002 T1036.003 T1036.004 "
    "T1036.005 T1036.006 T1036.007 T1036.008 T1036.009 T1036.010 T1036.011 T1036.012 T1037 T1037.001 "
    "T1037.002 T1037.003 T1037.004 T1037.005 T1039 T1040 T1041 T1046 T1047 T1048 T1048.001 T1048.002 "
    "T1048.003 T1049 T1052 T1052.001 T1053 T1053.002 T1053.003 T1053.005 T1053.006 T1053.007 T1055 "
    "T1055.001 T1055.002 T1055.003 T1055.004 T1055.005 T1055.008 T1055.009 T1055.011 T1055.012 T1055.013 "
    "T1055.014 T1055.015 T1056 T1056.001 T1056.002 T1056.003 T1056.004 T1057 T1059 T1059.001 T1059.002 "
    "T1059.003 T1059.004 T1059.005 T1059.006 T1059.007 T1059.008 T1059.009 T1059.010 T1059.011 T1059.012 "
    "T1059.013 T1068 T1069 T1069.001 T1069.002 T1069.003 T1070 T1070.003 T1070.004 T1070.005 T1070.006 "
    "T1070.007 T1070.008 T1070.009 T1070.010 T1071 T1071.001 T1071.002 T1071.003 T1071.004 T1071.005 "
    "T1072 T1074 T1074.001 T1074.002 T1078 T1078.001 T1078.002 T1078.003 T1078.004 T1080 T1082 T1083 "
    "T1087 T1087.001 T1087.002 T1087.003 T1087.004 T1090 T1090.001 T1090.002 T1090.003 T1090.004 T1091 "
    "T1092 T1095 T1098 T1098.001 T1098.002 T1098.003 T1098.004 T1098.005 T1098.006 T1098.007 T1102 "
    "T1102.001 T1102.002 T1102.003 T1104 T1105 T1106 T1110 T1110.001 T1110.002 T1110.003 T1110.004 T1111 "
    "T1112 T1113 T1114 T1114.001 T1114.002 T1114.003 T1115 T1119 T1120 T1123 T1124 T1125 T1127 T1127.001 "
    "T1127.002 T1127.003 T1129 T1132 T1132.001 T1132.002 T1133 T1134 T1134.001 T1134.002 T1134.003 "
    "T1134.004 T1134.005 T1135 T1136 T1136.001 T1136.002 T1136.003 T1137 T1137.001 T1137.002 T1137.003 "
    "T1137.004 T1137.005 T1137.006 T1140 T1176 T1176.001 T1176.002 T1185 T1187 T1189 T1190 T1195 "
    "T1195.001 T1195.002 T1195.003 T1197 T1199 T1200 T1201 T1202 T1203 T1204 T1204.001 T1204.002 "
    "T1204.003 T1204.004 T1204.005 T1205 T1205.001 T1205.002 T1207 T1210 T1211 T1212 T1213 T1213.001 "
    "T1213.002 T1213.003 T1213.004 T1213.005 T1213.006 T1216 T1216.001 T1216.002 T1217 T1218 T1218.001 "
    "T1218.002 T1218.003 T1218.004 T1218.005 T1218.007 T1218.008 T1218.009 T1218.010 T1218.011 T1218.012 "
    "T1218.013 T1218.014 T1218.015 T1219 T1219.001 T1219.002 T1219.003 T1220 T1221 T1222 T1222.001 "
    "T1222.002 T1480 T1480.001 T1480.002 T1482 T1484 T1484.001 T1484.002 T1485 T1485.001 T1486 T1489 "
    "T1490 T1491 T1491.001 T1491.002 T1495 T1496 T1496.001 T1496.002 T1496.003 T1496.004 T1497 T1497.001 "
    "T1497.002 T1497.003 T1498 T1498.001 T1498.002 T1499 T1499.001 T1499.002 T1499.003 T1499.004 T1505 "
    "T1505.001 T1505.002 T1505.003 T1505.004 T1505.005 T1505.006 T1518 T1518.001 T1518.002 T1525 T1526 "
    "T1528 T1529 T1530 T1531 T1534 T1535 T1537 T1538 T1539 T1542 T1542.001 T1542.002 T1542.003 T1542.004 "
    "T1542.005 T1543 T1543.001 T1543.002 T1543.003 T1543.004 T1543.005 T1546 T1546.001 T1546.002 "
    "T1546.003 T1546.004 T1546.005 T1546.006 T1546.007 T1546.008 T1546.009 T1546.010 T1546.011 T1546.012 "
    "T1546.013 T1546.014 T1546.015 T1546.016 T1546.017 T1546.018 T1547 T1547.001 T1547.002 T1547.003 "
    "T1547.004 T1547.005 T1547.006 T1547.007 T1547.008 T1547.009 T1547.010 T1547.012 T1547.013 T1547.014 "
    "T1547.015 T1548 T1548.001 T1548.002 T1548.003 T1548.004 T1548.005 T1548.006 T1550 T1550.001 "
    "T1550.002 T1550.003 T1550.004 T1552 T1552.001 T1552.002 T1552.003 T1552.004 T1552.005 T1552.006 "
    "T1552.007 T1552.008 T1553 T1553.001 T1553.002 T1553.003 T1553.004 T1553.005 T1553.006 T1554 T1555 "
    "T1555.001 T1555.002 T1555.003 T1555.004 T1555.005 T1555.006 T1556 T1556.001 T1556.002 T1556.003 "
    "T1556.004 T1556.005 T1556.006 T1556.007 T1556.008 T1556.009 T1557 T1557.001 T1557.002 T1557.003 "
    "T1557.004 T1558 T1558.001 T1558.002 T1558.003 T1558.004 T1558.005 T1559 T1559.001 T1559.002 "
    "T1559.003 T1560 T1560.001 T1560.002 T1560.003 T1561 T1561.001 T1561.002 T1563 T1563.001 T1563.002 "
    "T1564 T1564.001 T1564.002 T1564.003 T1564.004 T1564.005 T1564.006 T1564.007 T1564.008 T1564.009 "
    "T1564.010 T1564.011 T1564.012 T1564.013 T1564.014 T1565 T1565.001 T1565.002 T1565.003 T1566 "
    "T1566.001 T1566.002 T1566.003 T1566.004 T1567 T1567.001 T1567.002 T1567.003 T1567.004 T1568 "
    "T1568.001 T1568.002 T1568.003 T1569 T1569.001 T1569.002 T1569.003 T1570 T1571 T1572 T1573 T1573.001 "
    "T1573.002 T1574 T1574.001 T1574.004 T1574.005 T1574.006 T1574.007 T1574.008 T1574.009 T1574.010 "
    "T1574.011 T1574.012 T1574.013 T1574.014 T1578 T1578.001 T1578.002 T1578.003 T1578.004 T1578.005 "
    "T1580 T1583 T1583.001 T1583.002 T1583.003 T1583.004 T1583.005 T1583.006 T1583.007 T1583.008 T1584 "
    "T1584.001 T1584.002 T1584.003 T1584.004 T1584.005 T1584.006 T1584.007 T1584.008 T1585 T1585.001 "
    "T1585.002 T1585.003 T1586 T1586.001 T1586.002 T1586.003 T1587 T1587.001 T1587.002 T1587.003 "
    "T1587.004 T1588 T1588.001 T1588.002 T1588.003 T1588.004 T1588.005 T1588.006 T1588.007 T1589 "
    "T1589.001 T1589.002 T1589.003 T1590 T1590.001 T1590.002 T1590.003 T1590.004 T1590.005 T1590.006 "
    "T1591 T1591.001 T1591.002 T1591.003 T1591.004 T1592 T1592.001 T1592.002 T1592.003 T1592.004 T1593 "
    "T1593.001 T1593.002 T1593.003 T1594 T1595 T1595.001 T1595.002 T1595.003 T1596 T1596.001 T1596.002 "
    "T1596.003 T1596.004 T1596.005 T1597 T1597.001 T1597.002 T1598 T1598.001 T1598.002 T1598.003 "
    "T1598.004 T1599 T1599.001 T1600 T1600.001 T1600.002 T1601 T1601.001 T1601.002 T1602 T1602.001 "
    "T1602.002 T1606 T1606.001 T1606.002 T1608 T1608.001 T1608.002 T1608.003 T1608.004 T1608.005 "
    "T1608.006 T1608.007 T1609 T1610 T1611 T1612 T1613 T1614 T1614.001 T1615 T1619 T1620 T1621 T1622 "
    "T1647 T1648 T1649 T1650 T1651 T1652 T1653 T1654 T1657 T1659 T1665 T1666 T1667 T1668 T1669 T1671 "
    "T1673 T1674 T1675 T1677 T1678 T1679 T1680 T1681 T1682 T1683 T1683.001 T1683.002 T1684 T1684.001 "
    "T1684.002 T1685 T1685.001 T1685.002 T1685.003 T1685.004 T1685.005 T1685.006 T1685.007 T1686 "
    "T1686.001 T1686.002 T1686.003 T1687 T1688 T1689 T1690 T1696 T1696.001 T1696.002 T1697 T1698 T1699 "
    "T1700 "
).split())
# Revoked ID -> current ID (chains already followed).
REVOKED = {
    "T1002": "T1560", "T1004": "T1547.004", "T1009": "T1027.001", "T1013": "T1547.010", "T1015": "T1546.008",
    "T1017": "T1072", "T1019": "T1542.001", "T1022": "T1560", "T1023": "T1547.009", "T1024": "T1573", "T1028":
    "T1021.006", "T1031": "T1543.003", "T1032": "T1573", "T1035": "T1569.002", "T1038": "T1574.001", "T1042":
    "T1546.001", "T1044": "T1574.010", "T1045": "T1027.002", "T1050": "T1543.003", "T1053.001": "T1053.002",
    "T1054": "T1685", "T1058": "T1574.011", "T1060": "T1547.001", "T1063": "T1518.001", "T1065": "T1571",
    "T1066": "T1027.005", "T1067": "T1542.003", "T1070.001": "T1685.005", "T1070.002": "T1685.006", "T1073":
    "T1574.001", "T1075": "T1550.002", "T1076": "T1021.001", "T1077": "T1021.002", "T1079": "T1573", "T1081":
    "T1552.001", "T1084": "T1546.003", "T1085": "T1218.011", "T1086": "T1059.001", "T1088": "T1548.002",
    "T1089": "T1685", "T1093": "T1055.012", "T1094": "T1095", "T1096": "T1564.004", "T1097": "T1550.003",
    "T1099": "T1070.006", "T1100": "T1505.003", "T1101": "T1547.005", "T1103": "T1546.010", "T1107":
    "T1070.004", "T1109": "T1542.002", "T1116": "T1553.002", "T1117": "T1218.010", "T1118": "T1218.004",
    "T1121": "T1218.009", "T1122": "T1546.015", "T1126": "T1070.005", "T1128": "T1546.007", "T1130":
    "T1553.004", "T1131": "T1547.002", "T1138": "T1546.011", "T1139": "T1552.003", "T1141": "T1056.002",
    "T1142": "T1555.001", "T1143": "T1564.003", "T1144": "T1553.001", "T1145": "T1552.004", "T1146":
    "T1070.003", "T1147": "T1564.002", "T1148": "T1690", "T1150": "T1647", "T1151": "T1036.006", "T1152":
    "T1569.001", "T1154": "T1546.005", "T1155": "T1059.002", "T1156": "T1546.004", "T1157": "T1574.004",
    "T1158": "T1564.001", "T1159": "T1543.001", "T1160": "T1543.004", "T1161": "T1546.006", "T1162": "T1647",
    "T1163": "T1037.004", "T1164": "T1547.007", "T1165": "T1037.005", "T1166": "T1548.001", "T1167":
    "T1555.002", "T1168": "T1053", "T1169": "T1548.003", "T1170": "T1218.005", "T1171": "T1557.001", "T1172":
    "T1090.004", "T1173": "T1559.002", "T1174": "T1556.002", "T1177": "T1547.008", "T1178": "T1134.005",
    "T1179": "T1056.004", "T1180": "T1546.002", "T1181": "T1055.011", "T1182": "T1546.009", "T1183":
    "T1546.012", "T1184": "T1563.001", "T1186": "T1055.013", "T1188": "T1090.003", "T1191": "T1218.003",
    "T1192": "T1566.002", "T1193": "T1566.001", "T1194": "T1566.003", "T1196": "T1218.002", "T1198":
    "T1553.003", "T1206": "T1548.003", "T1208": "T1558.003", "T1209": "T1547.003", "T1214": "T1552.002",
    "T1215": "T1547.006", "T1223": "T1218.001", "T1483": "T1568.002", "T1487": "T1561.002", "T1488":
    "T1561.001", "T1492": "T1565.001", "T1493": "T1565.002", "T1494": "T1565.003", "T1500": "T1027.004",
    "T1501": "T1543.002", "T1502": "T1134.004", "T1503": "T1555.003", "T1504": "T1546.013", "T1506":
    "T1550.004", "T1514": "T1548.004", "T1519": "T1546.014", "T1522": "T1552.005", "T1527": "T1550.001",
    "T1536": "T1578.004", "T1547.011": "T1647", "T1562": "T1685", "T1562.001": "T1685", "T1562.002":
    "T1685.001", "T1562.003": "T1690", "T1562.004": "T1686", "T1562.006": "T1685", "T1562.007": "T1686.001",
    "T1562.008": "T1685.002", "T1562.009": "T1688", "T1562.010": "T1689", "T1562.011": "T1685.003", "T1562.012":
    "T1685.004", "T1562.013": "T1686.002", "T1574.002": "T1574.001", "T1656": "T1684.001", "T1672": "T1684.002",
}
# Deprecated IDs with no replacement.
DEPRECATED = frozenset(['T1026', 'T1034', 'T1043', 'T1051', 'T1053.004', 'T1061', 'T1062', 'T1064', 'T1108', 'T1149', 'T1153', 'T1175'])


def resolve_id(tid: str) -> Dict:
    """Classify a technique ID: in_table, valid, revoked (with replacement), deprecated or unknown."""
    if tid in BY_ID:
        return {"status": "in_table", "id": tid}
    if tid in REVOKED:
        return {"status": "revoked", "id": REVOKED[tid]}
    if tid in DEPRECATED:
        return {"status": "deprecated", "id": tid}
    if tid in ATTACK_IDS:
        return {"status": "valid", "id": tid}
    return {"status": "unknown", "id": tid}


def _id_hit(tid: str) -> Dict:
    info = resolve_id(tid)
    cur = info["id"]
    status = info["status"]
    if status == "revoked":
        note = f"{tid} was revoked in ATT&CK; the current technique is {cur}"
        if cur in BY_ID:
            _, name, tactics, _ = BY_ID[cur]
            return {"id": cur, "name": name, "tactics": tactics, "matched": tid, "note": note, "revoked_id": tid}
        return {"id": cur, "name": None, "tactics": [], "matched": tid, "note": note, "revoked_id": tid,
                "valid": True}
    if status == "in_table":
        _, name, tactics, _ = BY_ID[cur]
        return {"id": cur, "name": name, "tactics": tactics, "matched": tid}
    if status == "valid":
        return {"id": cur, "name": None, "tactics": [], "matched": tid, "valid": True,
                "note": f"valid ATT&CK v{ATTACK_VERSION} ID that is not in the keyword table; look up its tactics on attack.mitre.org"}
    if status == "deprecated":
        return {"id": cur, "name": None, "tactics": [], "matched": tid, "valid": False,
                "note": "deprecated in ATT&CK with no replacement; map the behaviour to a current technique by hand"}
    return {"id": cur, "name": None, "tactics": [], "matched": tid, "valid": False,
            "note": f"not an ATT&CK v{ATTACK_VERSION} technique ID (typo?); check it on attack.mitre.org"}


def map_line(line: str) -> List[Dict]:
    """Return the techniques one line of text points at, with the keyword that matched."""
    hits: Dict[str, Dict] = {}
    for tid in RE_TID.findall(line):
        hit = _id_hit(tid)
        hits.setdefault(hit["id"], hit)
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
        if not t.get("name") and not t.get("valid"):
            continue
        techs.append({"techniqueID": t["id"], "score": len(t["lines"]), "color": "",
                      "comment": f"matched '{t['matched']}' on line(s) {', '.join(map(str, t['lines']))}",
                      "enabled": True, "showSubtechniques": False})
    top = max([t["score"] for t in techs] or [1])
    return {
        "name": name,
        "versions": {"attack": ATTACK_VERSION.split(".")[0], "navigator": NAVIGATOR_VERSION, "layer": LAYER_FORMAT},
        "domain": "enterprise-attack",
        "description": f"Generated by claude-security-skills threat-hunting/attack_mapper.py from free-text notes (ATT&CK v{ATTACK_VERSION})",
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
        where = f"on line(s) {', '.join(map(str, t['lines']))}"
        if t.get("name"):
            tactics = ", ".join(TACTIC_NAME[x] for x in t["tactics"])
            out.append(f"{t['id']:10} {t['name']}  [{tactics}]")
            out.append(f"           matched '{t['matched']}' {where}")
        else:
            out.append(f"{t['id']:10} ({t.get('note', 'unknown to this table, verify on attack.mitre.org')})")
            out.append(f"           seen {where}")
        if t.get("revoked_id") and t.get("name"):
            out.append(f"           note: {t['note']}")
    unmatched = [l for l in result["lines"] if not l["techniques"]]
    if unmatched:
        out += ["", "No match (map by hand or extend the table):"]
        out += [f"  line {l['line']}: {l['text'][:100]}" for l in unmatched]
    out += ["", f"Coverage per tactic, ATT&CK v{ATTACK_VERSION} (matched / techniques in table):"]
    for c in result["coverage"]:
        bar = "#" * c["matched"]
        out.append(f"  {c['tactic']:22} {c['matched']:2}/{c['in_table']:<3} {bar}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=f"Map free-text behaviour notes or detection names to MITRE ATT&CK v{ATTACK_VERSION} techniques.")
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
        if src == "-":
            text = sys.stdin.read()
        else:
            with open(src, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
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
