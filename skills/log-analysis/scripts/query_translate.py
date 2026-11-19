#!/usr/bin/env python3
"""Print ready-made hunting queries in Splunk SPL, Microsoft KQL and Elastic ES|QL / EQL.

A small library of common use cases (brute force, password spray, new admin
user, encoded PowerShell, LSASS dumping, Entra ID MFA fatigue, OAuth consent,
device code sign-ins, AWS root and no-MFA console sign-ins, CloudTrail
tampering, new access keys, ...). ATT&CK IDs follow v20. Each query names the data
source and field names it assumes; adjust index names and fields to your
environment before running it.

Usage:
  query_translate.py --list
  query_translate.py ssh-brute-force
  query_translate.py encoded-powershell --lang kql
  query_translate.py password-spray --lang all --json
  query_translate.py ssh-brute-force --threshold 20 --window 10
  query_translate.py mfa-fatigue --lang kql
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Dict, List

LANGS = ["spl", "kql", "esql", "eql"]
EQL_MAX_RUNS = 100  # Elastic EQL accepts `with runs=` from 1 to 100
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
        "attack": ["T1685.005"],
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
    "mfa-fatigue": {
        "title": "Entra ID MFA fatigue: repeated denied MFA prompts for one user",
        "attack": ["T1621"],
        "defaults": {"threshold": 3, "window": 60},
        "sources": {"spl": "Entra ID sign-in logs via Event Hub, Splunk Add-on for Microsoft Cloud Services (azure:monitor:aad)",
                    "kql": "SigninLogs table (Sentinel)",
                    "esql": "Elastic Azure integration, logs-azure.signinlogs-*",
                    "eql": "Elastic Azure integration, azure.signinlogs events"},
        "spl": ('index=* sourcetype="azure:monitor:aad" category=SignInLogs\n'
                '  (properties.status.errorCode=500121 OR properties.status.errorCode=0)\n'
                '| bin _time span={window}m\n'
                '| stats count(eval(\'properties.status.errorCode\'==500121)) AS denied\n'
                '        count(eval(\'properties.status.errorCode\'==0)) AS successes\n'
                '        values(properties.ipAddress) AS ips BY _time, properties.userPrincipalName\n'
                '| where denied >= {threshold}\n'
                '| sort - denied'),
        "kql": ('SigninLogs\n'
                '| where ResultType in ("500121", "0")\n'
                '| summarize Denied = countif(ResultType == "500121"), Successes = countif(ResultType == "0"),\n'
                '    IPs = make_set(IPAddress, 10), Apps = make_set(AppDisplayName, 10)\n'
                '    by UserPrincipalName, bin(TimeGenerated, {window}m)\n'
                '| where Denied >= {threshold}\n'
                '| order by Denied desc'),
        "esql": ('FROM logs-azure.signinlogs-*\n'
                 '| WHERE azure.signinlogs.properties.status.error_code IN (500121, 0)\n'
                 '| EVAL bucket = DATE_TRUNC({window} minutes, @timestamp),\n'
                 '       denied = CASE(azure.signinlogs.properties.status.error_code == 500121, 1, 0),\n'
                 '       ok = CASE(azure.signinlogs.properties.status.error_code == 0, 1, 0)\n'
                 '| STATS denied = SUM(denied), successes = SUM(ok) BY azure.signinlogs.properties.user_principal_name, bucket\n'
                 '| WHERE denied >= {threshold}\n'
                 '| SORT denied DESC'),
        "eql": ('sequence by azure.signinlogs.properties.user_principal_name with maxspan={window}m\n'
                '  [any where event.dataset == "azure.signinlogs" and azure.signinlogs.properties.status.error_code == 500121] with runs={threshold}\n'
                '  [any where event.dataset == "azure.signinlogs" and azure.signinlogs.properties.status.error_code == 0]'),
    },
    "oauth-consent": {
        "title": "OAuth app consent with high-risk permissions (Entra ID)",
        "attack": ["T1528"],
        "defaults": {},
        "sources": {"spl": "Entra ID audit logs via Event Hub (azure:monitor:aad)",
                    "kql": "AuditLogs table (Sentinel)",
                    "esql": "Elastic Azure integration, logs-azure.auditlogs-*",
                    "eql": "Elastic Azure integration, azure.auditlogs events"},
        "spl": ('index=* sourcetype="azure:monitor:aad" operationName="Consent to application"\n'
                '| spath output=perms path=properties.targetResources{{}}.modifiedProperties{{}}.newValue\n'
                '| where match(mvjoin(perms, " "), "(?i)Mail\\.(Read|ReadWrite|Send)|Files\\.ReadWrite\\.All|Sites\\.ReadWrite\\.All|Directory\\.ReadWrite\\.All|offline_access")\n'
                '| table _time, properties.initiatedBy.user.userPrincipalName, properties.targetResources{{}}.displayName, perms'),
        "kql": ('AuditLogs\n'
                '| where OperationName == "Consent to application"\n'
                '| extend User = tostring(InitiatedBy.user.userPrincipalName), App = tostring(TargetResources[0].displayName)\n'
                '| mv-expand Prop = TargetResources[0].modifiedProperties\n'
                '| where tostring(Prop.displayName) == "ConsentAction.Permissions"\n'
                '| extend Permissions = tostring(Prop.newValue)\n'
                '| where Permissions matches regex @"(?i)Mail\\.(Read|ReadWrite|Send)|Files\\.ReadWrite\\.All|Sites\\.ReadWrite\\.All|Directory\\.ReadWrite\\.All|offline_access"\n'
                '| project TimeGenerated, User, App, Permissions, Result'),
        "esql": ('FROM logs-azure.auditlogs-*\n'
                 '| WHERE azure.auditlogs.operation_name == "Consent to application"\n'
                 '| KEEP @timestamp, azure.auditlogs.operation_name, azure.auditlogs.properties.initiated_by.user.*,\n'
                 '    azure.auditlogs.properties.target_resources.*\n'
                 '| SORT @timestamp DESC'),
        "eql": 'any where event.dataset == "azure.auditlogs" and azure.auditlogs.operation_name == "Consent to application"',
    },
    "device-code-signin": {
        "title": "Successful sign-in with the OAuth device code flow (Entra ID)",
        "attack": ["T1528", "T1566.002"],
        "defaults": {},
        "sources": {"spl": "Entra ID sign-in logs via Event Hub (azure:monitor:aad)",
                    "kql": "SigninLogs table (Sentinel)",
                    "esql": "Elastic Azure integration, logs-azure.signinlogs-*",
                    "eql": "Elastic Azure integration, azure.signinlogs events"},
        "spl": ('index=* sourcetype="azure:monitor:aad" category=SignInLogs\n'
                '  properties.authenticationProtocol=deviceCode properties.status.errorCode=0\n'
                '| stats count values(properties.appDisplayName) AS apps values(properties.ipAddress) AS ips BY properties.userPrincipalName'),
        "kql": ('SigninLogs\n'
                '| where AuthenticationProtocol == "deviceCode" and ResultType == "0"\n'
                '| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10), IPs = make_set(IPAddress, 10),\n'
                '    First = min(TimeGenerated) by UserPrincipalName\n'
                '| order by SignIns desc'),
        "esql": ('FROM logs-azure.signinlogs-*\n'
                 '| WHERE azure.signinlogs.properties.authentication_protocol == "deviceCode"\n'
                 '    AND azure.signinlogs.properties.status.error_code == 0\n'
                 '| STATS signins = COUNT(*), apps = VALUES(azure.signinlogs.properties.app_display_name)\n'
                 '    BY azure.signinlogs.properties.user_principal_name, source.ip'),
        "eql": ('any where event.dataset == "azure.signinlogs" and\n'
                '  azure.signinlogs.properties.authentication_protocol == "deviceCode" and\n'
                '  azure.signinlogs.properties.status.error_code == 0'),
    },
    "entra-password-spray": {
        "title": "Password spray against Entra ID (one IP, many users, bad password)",
        "attack": ["T1110.003"],
        "defaults": {"threshold": 10, "window": 60},
        "sources": {"spl": "Entra ID sign-in logs via Event Hub (azure:monitor:aad)",
                    "kql": "SigninLogs table (Sentinel)",
                    "esql": "Elastic Azure integration, logs-azure.signinlogs-*",
                    "eql": "not a good fit for EQL (needs distinct counts); use ES|QL"},
        "spl": ('index=* sourcetype="azure:monitor:aad" category=SignInLogs\n'
                '  (properties.status.errorCode=50126 OR properties.status.errorCode=50053)\n'
                '| bin _time span={window}m\n'
                '| stats dc(properties.userPrincipalName) AS users count AS attempts BY _time, properties.ipAddress\n'
                '| where users >= {threshold}\n'
                '| sort - users'),
        "kql": ('SigninLogs\n'
                '| where ResultType in ("50126", "50053")\n'
                '| summarize Users = dcount(UserPrincipalName), Attempts = count(), Apps = make_set(AppDisplayName, 5)\n'
                '    by IPAddress, bin(TimeGenerated, {window}m)\n'
                '| where Users >= {threshold}\n'
                '| order by Users desc'),
        "esql": ('FROM logs-azure.signinlogs-*\n'
                 '| WHERE azure.signinlogs.properties.status.error_code IN (50126, 50053)\n'
                 '| EVAL bucket = DATE_TRUNC({window} minutes, @timestamp)\n'
                 '| STATS users = COUNT_DISTINCT(azure.signinlogs.properties.user_principal_name), attempts = COUNT(*) BY source.ip, bucket\n'
                 '| WHERE users >= {threshold}\n'
                 '| SORT users DESC'),
        "eql": None,
    },
    "aws-console-login-risk": {
        "title": "AWS console sign-in as root, or by an IAM user without MFA",
        "attack": ["T1078.004"],
        "defaults": {},
        "sources": {"spl": "AWS CloudTrail, Splunk Add-on for AWS (aws:cloudtrail)",
                    "kql": "AWSCloudTrail table (Sentinel)",
                    "esql": "Elastic AWS integration, logs-aws.cloudtrail-*",
                    "eql": "Elastic AWS integration, aws.cloudtrail events"},
        "spl": ('index=* sourcetype=aws:cloudtrail eventName=ConsoleLogin\n'
                '  (userIdentity.type=Root OR additionalEventData.MFAUsed=No)\n'
                '| table _time, userIdentity.type, userIdentity.arn, sourceIPAddress, responseElements.ConsoleLogin, additionalEventData.MFAUsed, userAgent\n'
                '| sort - _time'),
        "kql": ('AWSCloudTrail\n'
                '| where EventName == "ConsoleLogin"\n'
                '| extend Result = tostring(parse_json(ResponseElements).ConsoleLogin),\n'
                '    MfaUsed = tostring(parse_json(AdditionalEventData).MFAUsed)\n'
                '| where UserIdentityType == "Root" or (UserIdentityType == "IAMUser" and MfaUsed == "No")\n'
                '| project TimeGenerated, UserIdentityType, UserIdentityArn, SourceIpAddress, Result, MfaUsed, UserAgent\n'
                '| order by TimeGenerated desc'),
        "esql": ('FROM logs-aws.cloudtrail-*\n'
                 '| WHERE event.action == "ConsoleLogin"\n'
                 '    AND (aws.cloudtrail.user_identity.type == "Root"\n'
                 '         OR aws.cloudtrail.console_login.additional_eventdata.mfa_used == false)\n'
                 '| KEEP @timestamp, aws.cloudtrail.user_identity.type, aws.cloudtrail.user_identity.arn, source.ip, event.outcome\n'
                 '| SORT @timestamp DESC'),
        "eql": ('any where event.dataset == "aws.cloudtrail" and event.action == "ConsoleLogin" and\n'
                '  (aws.cloudtrail.user_identity.type == "Root" or aws.cloudtrail.console_login.additional_eventdata.mfa_used == false)'),
    },
    "cloudtrail-tampering": {
        "title": "CloudTrail logging stopped, deleted or changed",
        "attack": ["T1685.002"],
        "defaults": {},
        "sources": {"spl": "AWS CloudTrail, Splunk Add-on for AWS (aws:cloudtrail)",
                    "kql": "AWSCloudTrail table (Sentinel)",
                    "esql": "Elastic AWS integration, logs-aws.cloudtrail-*",
                    "eql": "Elastic AWS integration, aws.cloudtrail events"},
        "spl": ('index=* sourcetype=aws:cloudtrail eventSource=cloudtrail.amazonaws.com\n'
                '  eventName IN (StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors, DeleteEventDataStore, StopEventDataStoreIngestion)\n'
                '| table _time, eventName, userIdentity.arn, sourceIPAddress, requestParameters.name, errorCode\n'
                '| sort - _time'),
        "kql": ('AWSCloudTrail\n'
                '| where EventSource == "cloudtrail.amazonaws.com"\n'
                '| where EventName in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteEventDataStore", "StopEventDataStoreIngestion")\n'
                '| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, RequestParameters, ErrorCode\n'
                '| order by TimeGenerated desc'),
        "esql": ('FROM logs-aws.cloudtrail-*\n'
                 '| WHERE event.provider == "cloudtrail.amazonaws.com"\n'
                 '    AND event.action IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteEventDataStore", "StopEventDataStoreIngestion")\n'
                 '| KEEP @timestamp, event.action, aws.cloudtrail.user_identity.arn, source.ip, event.outcome\n'
                 '| SORT @timestamp DESC'),
        "eql": ('any where event.dataset == "aws.cloudtrail" and event.provider == "cloudtrail.amazonaws.com" and\n'
                '  event.action in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteEventDataStore", "StopEventDataStoreIngestion")'),
    },
    "aws-access-key-created": {
        "title": "New IAM access key or console password created (AWS)",
        "attack": ["T1098.001"],
        "defaults": {},
        "sources": {"spl": "AWS CloudTrail, Splunk Add-on for AWS (aws:cloudtrail)",
                    "kql": "AWSCloudTrail table (Sentinel)",
                    "esql": "Elastic AWS integration, logs-aws.cloudtrail-*",
                    "eql": "Elastic AWS integration, aws.cloudtrail events"},
        "spl": ('index=* sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com\n'
                '  eventName IN (CreateAccessKey, CreateLoginProfile, UpdateLoginProfile) NOT errorCode=*\n'
                '| eval target=coalesce(\'requestParameters.userName\', \'userIdentity.userName\')\n'
                '| eval for_other=if(target!=\'userIdentity.userName\', "yes", "no")\n'
                '| table _time, eventName, userIdentity.arn, target, for_other, sourceIPAddress'),
        "kql": ('AWSCloudTrail\n'
                '| where EventSource == "iam.amazonaws.com"\n'
                '| where EventName in ("CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile") and isempty(ErrorCode)\n'
                '| extend Target = tostring(parse_json(RequestParameters).userName)\n'
                '| extend ForOther = isnotempty(Target) and Target != UserIdentityUserName\n'
                '| project TimeGenerated, EventName, UserIdentityArn, Target, ForOther, SourceIpAddress\n'
                '| order by TimeGenerated desc'),
        "esql": ('FROM logs-aws.cloudtrail-*\n'
                 '| WHERE event.provider == "iam.amazonaws.com"\n'
                 '    AND event.action IN ("CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile")\n'
                 '    AND event.outcome == "success"\n'
                 '| KEEP @timestamp, event.action, aws.cloudtrail.user_identity.arn, aws.cloudtrail.request_parameters, source.ip\n'
                 '| SORT @timestamp DESC'),
        "eql": ('any where event.dataset == "aws.cloudtrail" and event.provider == "iam.amazonaws.com" and\n'
                '  event.action in ("CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile") and event.outcome == "success"'),
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


def eql_runs_note(use_case: str, threshold=None):
    """EQL `with runs=` only accepts 1 to 100. Return a note when the threshold goes past that."""
    q = LIBRARY[use_case].get("eql")
    if not q or "runs={threshold}" not in q:
        return None
    value = threshold if threshold is not None else LIBRARY[use_case].get("defaults", {}).get("threshold", 10)
    if value > EQL_MAX_RUNS:
        return (f"EQL `with runs=` accepts 1 to {EQL_MAX_RUNS}; threshold {value} is too high. "
                "Use the ES|QL query, or lower --threshold.")
    return None


def build(use_case: str, langs: List[str], threshold=None, window=None) -> Dict:
    uc = LIBRARY[use_case]
    queries = {}
    for lang in langs:
        note = eql_runs_note(use_case, threshold) if lang == "eql" else None
        q = None if note else render_query(use_case, lang, threshold, window)
        queries[lang] = {"query": q, "source": uc["sources"].get(lang, ""),
                         "available": q is not None}
        if note:
            queries[lang]["note"] = note
    return {"use_case": use_case, "title": uc["title"], "attack": uc["attack"], "queries": queries}


def render_text(result: Dict) -> str:
    out = [f"{result['use_case']}: {result['title']}", f"ATT&CK: {', '.join(result['attack'])}", ""]
    for lang, q in result["queries"].items():
        out.append(f"--- {LANG_NAMES[lang]}  (data: {q['source']})")
        out.append(q["query"] if q["available"] else "(no query for this language" + (": " + q["note"] if q.get("note") else "") + ")")
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
                print(f"{k:24} {v['title']}  [{', '.join(v['attack'])}]")
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
