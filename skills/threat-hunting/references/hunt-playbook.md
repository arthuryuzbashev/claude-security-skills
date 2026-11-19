# Hunt playbook

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
| Windows Security log | logons, accounts, policy | 4624/4625 logon ok/failed, 4648 explicit creds, 4672 admin logon, 4688 process creation, 4698 scheduled task created, 4720 user created, 4728/4732/4756 added to group, 4769 Kerberos service ticket, 1102 log cleared |
| Windows System log | services | 7045 new service installed |
| PowerShell Operational | script content | 4104 script block logging |
| Linux auth.log / secure | SSH, sudo, su | `Failed password`, `Accepted`, `sudo: ... COMMAND=` |
| auditd | Linux process and file activity | `execve`, watches on `/etc/passwd`, `/root/.ssh` |
| Proxy / DNS logs | C2, downloads, exfil | rare domains, long-lived connections, byte ratios |
| Web server access logs | exploitation, web shells | POST to new script files, scanner user agents, 200s on odd paths |

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

## Stacking checklist

- Parent / child process pairs, count by pair, read the bottom 1%
- Process paths: binaries running from `Temp`, `AppData`, `ProgramData`, `Public`
- Network: destinations by number of distinct internal hosts (rare = interesting)
- Accounts: logons per account per host type
- Persistence: run keys, services, tasks, cron, systemd units, `authorized_keys` compared across hosts
