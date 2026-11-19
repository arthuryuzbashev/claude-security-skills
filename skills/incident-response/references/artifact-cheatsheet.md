# Evidence artifact cheat sheet

Where to look, by platform. Collect copies; never edit originals.

## Order of volatility (RFC 3227)

1. CPU registers and cache (rarely practical)
2. Routing table, ARP cache, process table, kernel statistics, memory
3. Temporary file systems
4. Disk
5. Remote logging and monitoring data
6. Physical configuration, network topology
7. Archival media

## Linux

| Artifact | Location / command |
|---|---|
| Auth and sudo | `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL family) |
| Logins | `/var/log/wtmp` (`last`), `/var/log/btmp` (`lastb`, failed), `/var/log/lastlog` (`lastlog`) |
| Journal | `journalctl -o short-iso --since ...` |
| Audit | `/var/log/audit/audit.log` (`ausearch -i`) |
| Shell history | `~/.bash_history`, `~/.zsh_history` (attackers often unset or clear it) |
| Cron | `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/` |
| systemd units | `/etc/systemd/system/`, `/lib/systemd/system/`, `~/.config/systemd/user/` |
| Other autoruns | `/etc/rc.local`, `/etc/profile.d/`, `~/.bashrc`, `/etc/ld.so.preload` (should normally not exist) |
| SSH | `~/.ssh/authorized_keys`, `/etc/ssh/sshd_config` |
| Staging dirs | `/tmp`, `/var/tmp`, `/dev/shm` |
| Running deleted binaries | `ls -l /proc/*/exe 2>/dev/null \| grep deleted` |
| Web servers | `/var/log/nginx/`, `/var/log/apache2/` or `/var/log/httpd/` |

## macOS

| Artifact | Location / command |
|---|---|
| Unified log | `log show --style syslog --start "YYYY-MM-DD HH:MM:SS"`, `sudo log collect --output x.logarchive` |
| Install history | `/var/log/install.log`, `/Library/Receipts/InstallHistory.plist` |
| Launch items | `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents` |
| Background items (macOS 13+) | `sudo sfltool dumpbtm` |
| Configuration profiles | `sudo profiles show -type configuration` |
| Download origin | `xattr -l <file>` (com.apple.quarantine), `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` (SQLite) |
| Privacy permissions | `~/Library/Application Support/com.apple.TCC/TCC.db` and `/Library/Application Support/com.apple.TCC/TCC.db` |
| File system events | `/.fseventsd/` |
| Shell history | `~/.zsh_history`, `~/.bash_history` |
| Code signing | `codesign -dv --verbose=4 <app>`, `spctl -a -vv <app>` |

## Windows

| Artifact | Location / command |
|---|---|
| Event logs | `C:\Windows\System32\winevt\Logs\*.evtx`, export with `wevtutil epl <log> <file>` |
| Autoruns | Run/RunOnce keys (HKLM and HKCU), services, scheduled tasks (`C:\Windows\System32\Tasks`), Startup folders, WMI subscriptions |
| Execution traces | Prefetch `C:\Windows\Prefetch` (workstations), Amcache `C:\Windows\appcompat\Programs\Amcache.hve`, ShimCache in the SYSTEM hive |
| PowerShell | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, Operational log event 4104 |
| USB history | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` |
| Download origin | `Zone.Identifier` alternate data stream |
| Shadow copies | `vssadmin list shadows` |
| IIS | `C:\inetpub\logs\LogFiles` |

### Security log event IDs

| ID | Meaning |
|---|---|
| 4624 / 4625 | Logon success / failure |
| 4634 / 4647 | Logoff / user-initiated logoff |
| 4648 | Logon with explicit credentials (runas, lateral movement) |
| 4672 | Special privileges assigned (admin logon) |
| 4688 | Process created (command line only if that policy is enabled) |
| 4697 | Service installed |
| 4698 / 4699 / 4702 | Scheduled task created / deleted / updated |
| 4720 / 4722 / 4724 | Account created / enabled / password reset attempt |
| 4728 / 4732 / 4756 | Member added to global / local / universal security group |
| 4740 | Account locked out |
| 4768 / 4769 / 4771 | Kerberos TGT requested / service ticket requested / pre-auth failed |
| 4776 | NTLM credential validation |
| 5140 / 5145 | Network share accessed / share object access check |
| 1102 | Security audit log cleared |

### Other logs

| Log | ID | Meaning |
|---|---|---|
| System | 7045 | New service installed |
| System | 104 | Event log cleared |
| PowerShell/Operational | 4103 / 4104 | Module logging / script block logging |
| TerminalServices-LocalSessionManager/Operational | 21 / 24 / 25 | RDP session logon / disconnect / reconnect |
| TerminalServices-RemoteConnectionManager/Operational | 1149 | RDP network authentication succeeded |
| Windows Defender/Operational | 1116 / 1117 | Malware detected / action taken |
| Sysmon | 1, 3, 11, 22 | Process create, network connection, file create, DNS query |

### Logon types (4624)

2 interactive, 3 network (SMB, mapped drives), 4 batch (scheduled task), 5 service, 7 unlock, 8 network cleartext, 9 new credentials (runas /netonly), 10 remote interactive (RDP), 11 cached interactive.
