# Hunt playbook

Contents: hypothesis template, the hunt loop, data source quick map, hunt ideas by technique (endpoint, then identity and cloud), ATT&CK v19/v20 ID changes, stacking checklist.

## Hypothesis template

> Because of **[intel, gap or incident]**, we think **[actor or behaviour]** may have **[done what]** on **[which systems]**, which would show up as **[observable]** in **[data source]** between **[time range]**.

Good hypotheses are testable with data you have. "We might be breached" is not a hypothesis. "A phished user ran encoded PowerShell from Word on a finance laptop in the last 14 days, visible as WINWORD.EXE parent of powershell.exe in Sysmon event 1" is.

## The hunt loop (PEAK-style: Prepare, Execute, Act)

1. **Prepare**: hypothesis, scope (hosts, time range), data sources, and a check that those sources exist and are complete for the range
2. **Execute**: search indicators first, then behaviour. Baseline before judging: how often does this happen normally? Stack counts (rare parent/child pairs, rare destinations) beat eyeballing
3. **Act**: write down the verdict, open an incident for real hits, turn repeatable logic into a detection, file the logging gaps
4. Record negative results. "Looked for X in Y over Z days, nothing" is useful next quarter

## Data source quick map

| Data | What it proves | Key IDs / fields |
|---|---|---|
| Sysmon | process, network, registry, file activity | 1 process create, 3 network connection, 7 image load, 8 CreateRemoteThread, 10 process access, 11 file create, 12/13/14 registry, 22 DNS query |
| Windows Security log | logons, accounts, policy | 4624/4625 logon ok/failed, 4648 explicit creds, 4672 admin logon, 4688 process creation, 4698 scheduled task created, 4720 user created, 4728/4732/4756 added to group, 4769 Kerberos service ticket, 1102 log cleared (T1685.005) |
| Windows System log | services | 7045 new service installed |
| PowerShell Operational | script content | 4104 script block logging |
| Linux auth.log / secure | SSH, sudo, su | `Failed password`, `Accepted`, `sudo: ... COMMAND=` |
| auditd | Linux process and file activity | `execve`, watches on `/etc/passwd`, `/root/.ssh` |
| Proxy / DNS logs | C2, downloads, exfil | rare domains, long-lived connections, byte ratios |
| Web server access logs | exploitation, web shells | POST to new script files, scanner user agents, 200s on odd paths |
| Entra ID sign-in logs (`SigninLogs`, `AADNonInteractiveUserSignInLogs`) | cloud logons, MFA, token use | `ResultType` ("0" = success, 50126 bad password, 50053 locked, 50074/50076 MFA required, 500121 MFA failed or denied, 53003 blocked by Conditional Access), `UserPrincipalName`, `IPAddress`, `AppDisplayName`, `AuthenticationProtocol` (`deviceCode`, `ropc`), `IncomingTokenType`, `SessionId`, `UniqueTokenIdentifier`, `RiskEventTypes_V2` |
| Entra ID audit logs (`AuditLogs`) | consent, app credentials, roles, devices | `OperationName`: "Consent to application", "Add OAuth2PermissionGrant", "Add service principal credentials", "Update application - Certificates and secrets management", "Add member to role", "Register device", "Set domain authentication" |
| Microsoft 365 unified audit log (`OfficeActivity`, `CloudAppEvents`) | mailbox rules, delegation, mail access | `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox` (forwarding), `Add-MailboxPermission`, `MailItemsAccessed` |
| AWS CloudTrail | API calls and console sign-ins | `eventSource`, `eventName`, `userIdentity.type` (`Root`, `IAMUser`, `AssumedRole`), `sourceIPAddress`, `errorCode`, `responseElements.ConsoleLogin`, `additionalEventData.MFAUsed` |

## Hunt ideas by technique

### T1059.001 PowerShell
- Encoded commands: command line contains `-enc`, `-e `, `-ec `, `-EncodedCommand`
- Office or browser processes as parent of `powershell.exe` / `pwsh.exe`
- 4104 script blocks with `FromBase64String`, `IEX`, `DownloadString`, `Net.WebClient`, `-bxor`
- Baseline: which service accounts run PowerShell daily? Hunt the rest

### T1003.001 LSASS Memory
- Sysmon 10 with `TargetImage` ending `\lsass.exe` from a process that is not AV/EDR, especially `GrantedAccess` 0x1010 or 0x1fffff
- `rundll32 ... comsvcs.dll, MiniDump` or `procdump -ma lsass`
- New `.dmp` files in temp folders (Sysmon 11)

### T1053.005 Scheduled Task / T1543.003 Windows Service
- 4698 and 7045 on servers where nobody deploys software
- Task actions or service paths in `\Users\`, `\AppData\`, `\ProgramData\`, `\Temp\`
- Stack task names across the fleet; a name on 1-2 hosts is interesting

### T1547.001 Run Keys
- Sysmon 13 on `...\CurrentVersion\Run` and `RunOnce` with values pointing at user-writable paths or script hosts

### T1078 Valid Accounts / T1110 Brute Force
- 4625 bursts per source, then a 4624 from the same source (success after failures)
- Logons at odd hours, from new countries or new devices for that account
- Service accounts with interactive logons (type 2 or 10)

### T1021 Remote Services
- RDP (logon type 10) between workstations; admins usually go workstation to server
- WinRM: `wsmprovhost.exe` spawning shells
- SMB: 5145 access to `ADMIN$` / `C$` followed by 7045 on the target (PsExec pattern)

### T1003.006 DCSync
- 4662 on a domain controller with the replication rights GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes) or `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes-All) from an account that is not a DC

### T1558.003 Kerberoasting
- 4769 with ticket encryption type `0x17` (RC4) for many service names from one account in a short window

### T1071 / T1105 C2 and tool transfer
- Beaconing: regular intervals to one destination (low jitter), small and similar request sizes
- Rare domains: seen by 1-2 hosts in the fleet, newly registered, or on cheap TLDs
- `certutil -urlcache`, `bitsadmin /transfer`, `curl`/`wget` from servers that never browse

### T1486 / T1490 Ransomware precursors
- `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set {default} recoveryenabled no`
- Mass file renames with one new extension (Sysmon 11 volume per process)

## Identity and cloud hunts

Most current intrusions start with an identity, not a binary. These hunts run on the sign-in, audit and cloud API logs above.

### T1621 MFA Request Generation (MFA fatigue)
- Per user, count sign-ins with `ResultType` 500121 or 50074 in a short window (10-60 min). Three or more prompts from one IP is the pattern Microsoft's own Sentinel content uses
- The real alarm is a burst of denials or timeouts followed by a success (`ResultType` "0") from the same IP or a new device
- Users who report "random MFA prompts" are a lead, not noise: their password is already known

### T1528 Steal Application Access Token (illicit consent, device code phishing)
- `AuditLogs` "Consent to application" by a regular user, then read `ConsentAction.Permissions` in `modifiedProperties`. High-risk scopes: `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, `full_access_as_app`, `EWS.AccessAsUser.All`, `offline_access` together with mail or file scopes
- The app is new to the tenant (an "Add service principal" just before), has a generic or lookalike name, and a reply URL on a domain you do not know
- Device code phishing: sign-ins with `AuthenticationProtocol == "deviceCode"` (or `OriginalTransferMethod` "deviceCodeFlow") for users who never use that flow, especially from an IP the user has not used before

### T1550.001 Application Access Token / T1539 and T1550.004 session cookies (token and cookie replay)
- One `SessionId` or `UniqueTokenIdentifier` seen from two IPs or ASNs within minutes
- Non-interactive sign-ins (`AADNonInteractiveUserSignInLogs`) from an IP that never did an interactive sign-in for that user
- AiTM kits (T1557) leave a sign-in from the phishing proxy IP right before the replay: hunt the first IP, then everything that came from it

### T1078.004 Cloud Accounts
- CloudTrail `ConsoleLogin` with `userIdentity.type` `Root`: should be close to zero. Root sign-ins land in us-east-1 (or us-east-2 / us-west-2), so search all three
- `ConsoleLogin` with `additionalEventData.MFAUsed` "No" for human users
- Entra sign-ins from new countries, hosting providers or VPN ASNs for an account, and impossible travel between consecutive sign-ins

### T1098.001 / T1098.003 / T1098.005 Cloud persistence
- AWS `CreateAccessKey`, `CreateLoginProfile`, `AttachUserPolicy` / `AttachRolePolicy` with `AdministratorAccess`, `PutUserPolicy`
- Entra "Add service principal credentials", "Update application - Certificates and secrets management", "Add member to role" (Global Administrator, Privileged Role Administrator, Application Administrator)
- "Register device" or a new MFA method right after a risky sign-in: the attacker is keeping access after the password reset

### T1114.003 / T1564.008 Mailbox rules (BEC)
- `New-InboxRule` / `Set-InboxRule` with `ForwardTo`, `RedirectTo` or `ForwardAsAttachmentTo` an outside domain, or `Set-Mailbox -ForwardingSmtpAddress`
- Rules that delete, mark as read or move into RSS Subscriptions, Archive or Conversation History, often with keywords like invoice, payment, wire, bank

### T1685.002 Disable or Modify Cloud Log / T1686.001 Cloud Firewall
- CloudTrail `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` that drop management events, GuardDuty `DeleteDetector`, `DeleteFlowLogs`
- Entra or Azure diagnostic setting deletes, `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false`
- `AuthorizeSecurityGroupIngress` that opens 0.0.0.0/0 on admin ports (22, 3389, 5985)

### T1552.005 Cloud Instance Metadata API
- Requests to `169.254.169.254` from web application processes or containers, especially paths under `/latest/meta-data/iam/security-credentials/`
- Then the credentials of that instance role used from an IP outside the cloud provider

## ATT&CK v19 and v20 ID changes

ATT&CK v19 (April 2026) split Defense Evasion. TA0005 is now **Stealth** (`stealth`) and the new TA0112 **Defense Impairment** (`defense-impairment`) holds the techniques that switch defenses off. v20 (October 2026) kept that layout. Old IDs in detections, reports and Sigma tags need updating. `attack_mapper.py` remaps these by itself when it sees them:

| Old ID | Old name | Current ID |
|---|---|---|
| T1562.001 | Impair Defenses: Disable or Modify Tools | T1685 |
| T1562.002 | Disable Windows Event Logging | T1685.001 |
| T1562.008 | Disable or Modify Cloud Logs | T1685.002 |
| T1562.012 | Disable or Modify Linux Audit System | T1685.004 |
| T1070.001 | Clear Windows Event Logs | T1685.005 |
| T1070.002 | Clear Linux or Mac System Logs | T1685.006 |
| T1562.004 | Disable or Modify System Firewall | T1686 |
| T1562.007 | Disable or Modify Cloud Firewall | T1686.001 |
| T1562.003 | Impair Command History Logging | T1690 |
| T1562.009 | Safe Mode Boot | T1688 |
| T1562.010 | Downgrade Attack | T1689 |
| T1656 | Impersonation | T1684.001 |

Older revocations still turn up too (T1086 is T1059.001, T1574.002 is T1574.001). Always check an ID you did not get from the script on attack.mitre.org.

## Stacking checklist

- Parent / child process pairs, count by pair, read the bottom 1%
- Process paths: binaries running from `Temp`, `AppData`, `ProgramData`, `Public`
- Network: destinations by number of distinct internal hosts (rare = interesting)
- Accounts: logons per account per host type
- Persistence: run keys, services, tasks, cron, systemd units, `authorized_keys` compared across hosts
