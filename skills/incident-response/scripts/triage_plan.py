#!/usr/bin/env python3
"""Print a prioritized evidence collection and containment checklist for an incident.

Evidence steps are read-only and follow the order of volatility (RFC 3227):
what disappears first (memory, network state, processes) is collected first.
Containment steps change state; they are marked [APPROVAL] and use reversible
actions (isolate, disable, revoke) rather than delete or wipe.

Usage:
  triage_plan.py ransomware --platform windows
  triage_plan.py bec --platform windows --json
  triage_plan.py web-compromise --platform linux --report > incident.md
  triage_plan.py --list
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List

PLATFORMS = ["linux", "macos", "windows"]
INCIDENTS = {
    "ransomware": "Files encrypted or a ransom note found",
    "bec": "Business email compromise: mailbox taken over or payment fraud by email",
    "account-takeover": "A user, admin or cloud account used by someone else",
    "web-compromise": "Website or web server altered, web shell, defacement, injected scripts",
    "malware": "Suspicious program, EDR/AV alert, unknown process or persistence",
    "data-leak": "Data exposed or exfiltrated (public bucket, leaked dump, mis-sent file)",
    "insider": "A current or former employee or contractor misusing access",
    "lost-device": "Laptop or phone lost or stolen",
    "cloud-compromise": "Cloud account or keys abused: leaked access keys, odd API calls, crypto mining, new IAM users",
}

# Evidence goes to external media or a network share, never the suspect disk.
OUT = {"linux": "/mnt/evidence", "macos": "/Volumes/EVIDENCE", "windows": "E:\\evidence"}


def step(phase: str, title: str, why: str, commands: Dict[str, List[str]] = None,
         approval: bool = False) -> Dict:
    return {"phase": phase, "title": title, "why": why, "commands": commands or {}, "approval": approval}


# ---------------------------------------------------------------- shared steps

PREPARE = [
    step("prepare", "Open an incident log and set the clock",
         "Every later decision is judged against this log. Write times in UTC, note who did what and from which machine.",
         {"linux": ["date -u", "hostname; uptime"],
          "macos": ["date -u", "hostname; uptime"],
          "windows": ["Get-Date -Format o; [DateTime]::UtcNow.ToString('o')",
                      "hostname; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime"]}),
    step("prepare", "Do not power off, reboot, reimage or run cleanup tools yet",
         "Memory holds running malware, network connections, decrypted keys and attacker sessions. "
         "A reboot or AV 'clean' destroys them and rewrites file timestamps."),
    step("prepare", "Save evidence to external media or a share, then hash it",
         f"Writing output to the suspect disk overwrites deleted data. Use e.g. {OUT['linux']} / {OUT['macos']} / {OUT['windows']} "
         "and record a SHA-256 of every file you collect (chain of custody).",
         {"linux": [f"sha256sum {OUT['linux']}/* > {OUT['linux']}/SHA256SUMS"],
          "macos": [f"shasum -a 256 {OUT['macos']}/* > {OUT['macos']}/SHA256SUMS"],
          "windows": [f"Get-FileHash -Algorithm SHA256 {OUT['windows']}\\* | Export-Csv {OUT['windows']}\\sha256.csv -NoTypeInformation"]}),
]

VOLATILE = [
    step("volatile", "Capture memory first if the host is still running",
         "Memory is the most volatile evidence. Use a trusted capture tool from external media "
         "(Linux: AVML or LiME; Windows: WinPmem, Magnet RAM Capture or your EDR's memory collection; "
         "macOS: memory capture usually needs a commercial tool, so prioritise the live-state steps below)."),
    step("volatile", "Network state: connections, listeners, routes, ARP, DNS",
         "Shows live attacker sessions and command-and-control, and disappears when processes exit.",
         {"linux": [f"ss -tunap > {OUT['linux']}/ss.txt", f"{{ ip addr; ip route; ip neigh; }} > {OUT['linux']}/ip.txt",
                    "cat /etc/resolv.conf /etc/hosts"],
          "macos": [f"lsof -nP -i > {OUT['macos']}/lsof_net.txt", "netstat -an", "netstat -rn", "arp -an",
                    "scutil --dns", "cat /etc/hosts"],
          "windows": ["Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess"
                      f" | Export-Csv {OUT['windows']}\\tcp.csv -NoTypeInformation",
                      f"netstat -anob > {OUT['windows']}\\netstat.txt", "Get-DnsClientCache", "arp -a",
                      "ipconfig /all", "route print"]}),
    step("volatile", "Processes with command lines and parents",
         "Malware hides behind normal names; the command line, parent and path give it away.",
         {"linux": [f"ps auxwwf > {OUT['linux']}/ps.txt", "ls -l /proc/*/exe 2>/dev/null | grep deleted",
                    f"lsof -nP > {OUT['linux']}/lsof.txt"],
          "macos": [f"ps auxww > {OUT['macos']}/ps.txt", f"lsof -nP > {OUT['macos']}/lsof.txt"],
          "windows": ["Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine"
                      f" | Export-Csv {OUT['windows']}\\processes.csv -NoTypeInformation",
                      "tasklist /v /fo csv"]}),
    step("volatile", "Logged-in users and sessions",
         "Tells you whether the attacker is still on the box and under which account.",
         {"linux": ["w", "last -Faiw | head -100", "sudo lastb | head -100"],
          "macos": ["who", "last | head -100"],
          "windows": ["query user", "net session", "Get-LocalUser | Select Name,Enabled,LastLogon",
                      "Get-LocalGroupMember Administrators"]}),
]

PERSISTENCE = {
    "linux": ["crontab -l; sudo ls -la /etc/cron* /var/spool/cron", "systemctl list-unit-files --state=enabled",
              "systemctl list-units --type=service --state=running", "ls -la ~/.ssh; cat ~/.ssh/authorized_keys",
              "sudo find /etc /usr/local/bin /tmp /var/tmp /dev/shm -xdev -type f -mtime -7 -ls",
              "lsmod", "cat /etc/passwd | awk -F: '$3 == 0'"],
    "macos": ["ls -la /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents", "launchctl list",
              "sudo sfltool dumpbtm", "crontab -l", "sudo profiles show -type configuration",
              "ls -la ~/.ssh; cat ~/.ssh/authorized_keys"],
    "windows": ["Get-ScheduledTask | Select TaskPath,TaskName,State",
                "Get-CimInstance Win32_Service | Select Name,State,StartMode,PathName",
                "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"",
                "Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter",
                "Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer",
                "Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding"],
}

LOGS = {
    "linux": ["sudo journalctl --since '-7 days' -o short-iso > " + OUT["linux"] + "/journal.txt",
              f"sudo cp -a /var/log {OUT['linux']}/var_log", "sudo grep -hE 'Accepted|Failed|sudo:' /var/log/auth.log* /var/log/secure* 2>/dev/null"],
    "macos": [f"sudo log collect --last 7d --output {OUT['macos']}/system.logarchive",
              "log show --last 1d --style syslog --predicate 'process == \"sshd\" OR process == \"sudo\"'"],
    "windows": [f"wevtutil epl Security {OUT['windows']}\\Security.evtx",
                f"wevtutil epl System {OUT['windows']}\\System.evtx",
                f"wevtutil epl Microsoft-Windows-PowerShell/Operational {OUT['windows']}\\PowerShell.evtx",
                "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4672,4688,4698,4720,4732,1102; "
                "StartTime=(Get-Date).AddDays(-7)} | Select TimeCreated,Id,Message"],
}

COLLECT = [
    step("evidence", "Persistence: what will run again after a reboot",
         "Attackers rarely rely on one foothold. Every autorun you miss is a way back in.", PERSISTENCE),
    step("evidence", "Export logs before they rotate or get cleared",
         "Copies are read from the live logs without changing them. On Windows look for 1102 (Security log cleared) and "
         "104 (System log cleared), on Linux for gaps in auth.log.", LOGS),
]

CLOSE = [
    step("recover", "Build the timeline and confirm scope before you clean up",
         "Merge every log you exported into one UTC timeline (timeline_build.py). Find the first malicious event "
         "(patient zero) and every account and host it touched. Cleaning before you know the scope means doing it twice."),
    step("recover", "Rebuild or restore from known-good, then watch",
         "Prefer rebuilding a compromised host over cleaning it. Restore data from backups taken before the first malicious "
         "event, rotate every credential the attacker could have seen, and monitor closely for at least two weeks."),
]

# ---------------------------------------------------------------- type-specific

TYPE_STEPS: Dict[str, List[Dict]] = {
    "ransomware": [
        step("contain", "Isolate affected hosts from the network, keep them powered on",
             "Stops encryption spreading to shares and stops exfiltration while keeping memory (which may hold keys). "
             "Use EDR network containment or pull the cable / disable the switch port. Do not shut down.",
             {"windows": ["(EDR) network-contain the host", "Get-SmbOpenFile | Select ClientComputerName,ClientUserName,Path"
                          "   # on file servers: which client is writing"],
              "linux": ["(EDR) network-contain the host, or disable the switch port"],
              "macos": ["(EDR) network-contain the host, or disable Wi-Fi and unplug Ethernet"]}, approval=True),
        step("contain", "Protect backups now",
             "Ransomware operators go after backups and snapshots first. Take backup systems offline or make them immutable, "
             "and check they were not already deleted or encrypted.",
             {"windows": ["vssadmin list shadows", "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='VSS'} -MaxEvents 50"]},
             approval=True),
        step("evidence", "Collect the ransom note, one encrypted file and the extension",
             "Identifies the family (ID Ransomware, No More Ransom list free decryptors) and its known TTPs. "
             "Copy, do not open, files from the suspect host.",
             {"linux": ["find / -xdev -type f -mmin -240 -iname '*readme*' 2>/dev/null | head"],
              "macos": ["find / -xdev -type f -mmin -240 -iname '*readme*' 2>/dev/null | head"],
              "windows": ["Get-ChildItem C:\\ -Recurse -Include *readme*,*decrypt*,*restore* -ErrorAction SilentlyContinue "
                          "| Where LastWriteTime -gt (Get-Date).AddHours(-24) | Select FullName,LastWriteTime"]}),
        step("evidence", "Check for data theft before the encryption (double extortion)",
             "Most ransomware crews steal data first. Look for archive tools (7z, rar, WinRAR), rclone, MEGA or cloud sync "
             "clients, and large outbound transfers in firewall or proxy logs in the days before encryption.",
             {"windows": ["Get-ChildItem C:\\Windows\\Prefetch | Where Name -match 'RCLONE|7Z|RAR|MEGA|WINSCP|PSEXEC' "
                          "| Select Name,LastWriteTime"]}),
        step("evidence", "Domain controllers and admin accounts",
             "Wide encryption usually means domain admin was taken. Review new admins, GPO changes and scheduled tasks pushed by GPO.",
             {"windows": ["Get-ADGroupMember 'Domain Admins' | Select SamAccountName",
                          "Get-ADUser -Filter * -Properties whenCreated | Where whenCreated -gt (Get-Date).AddDays(-14) "
                          "| Select SamAccountName,whenCreated",
                          "Get-GPO -All | Sort ModificationTime -Descending | Select -First 10 DisplayName,ModificationTime"]}),
        step("evidence", "Hypervisors, NAS and backup consoles",
             "Many crews encrypt VMware ESXi datastores or NAS shares directly, which no Windows EDR sees. Check the "
             "management plane for new local accounts, SSH being enabled and shell activity. Read only, from the console or SSH.",
             {"any": ["ESXi: esxcli system account list; esxcli network ip connection list",
                      "ESXi: copy /var/log/shell.log, /var/log/hostd.log and /var/log/auth.log to evidence media",
                      "vCenter / NAS / backup console: export the audit or event log for the last 14 days"]}),
        step("notify", "Legal, insurance and authorities before any contact with the attacker",
             "Paying may be illegal if the group is sanctioned, and insurers usually require notice before negotiation. "
             "Personal data involved can trigger breach notification deadlines (GDPR: 72 hours to the authority)."),
    ],
    "bec": [
        step("evidence", "Mailbox rules and forwarding",
             "Attackers add rules that forward or hide mail (move to RSS Feeds / Archive, mark as read) so the victim never sees replies.",
             {"any": ["Exchange Online: Get-InboxRule -Mailbox user@example.test | Select Name,Enabled,ForwardTo,RedirectTo,MoveToFolder,DeleteMessage",
                      "Exchange Online: Get-Mailbox user@example.test | Select ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward",
                      "Google Workspace: Admin console > Reporting > Audit and investigation > Gmail log events (filter on the user)"]}),
        step("evidence", "Sign-ins, MFA changes and app consents",
             "Find the attacker's IPs and user agents, new MFA methods they registered, and OAuth apps that keep access after a password reset.",
             {"any": ["Entra ID: Sign-in logs and Audit logs for the user (portal or Graph)",
                      "Graph: Get-MgUserAuthenticationMethod -UserId user@example.test",
                      "Graph: Get-MgUserOauth2PermissionGrant -UserId user@example.test",
                      "Exchange Online: Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) "
                      "-UserIds user@example.test -ResultSize 5000",
                      "Google Workspace: Admin console > Reporting > Audit and investigation > User log events and OAuth log events"]}),
        step("evidence", "What did the attacker read and send",
             "Message trace and sent items show which partners were targeted and which invoices or bank details were changed.",
             {"any": ["Exchange Online: Get-MessageTraceV2 (or Get-MessageTrace on older tenants) -SenderAddress user@example.test -StartDate (Get-Date).AddDays(-10) -EndDate (Get-Date)",
                      "Purview audit: MailItemsAccessed events (needs audit logging that records it)"]}),
        step("contain", "Lock the account and kill sessions",
             "A password reset alone does not end existing sessions or remove app tokens. Reset, revoke sessions, remove unknown MFA "
             "methods and the malicious rules (after you exported them).",
             {"any": ["Graph: Revoke-MgUserSignInSession -UserId user@example.test",
                      "Entra ID / Google Workspace admin: reset password, require MFA re-registration",
                      "Exchange Online: Disable-InboxRule -Mailbox user@example.test -Identity '<rule name>'"]}, approval=True),
        step("notify", "Money first: call the bank within hours",
             "Fraudulent wires can sometimes be recalled if the bank is told fast. Warn the partners the attacker emailed, "
             "by phone, and report to the police or national fraud reporting service."),
    ],
    "account-takeover": [
        step("evidence", "Sign-in history and the attacker's footprint",
             "Collect IPs, user agents, countries and times of suspicious sign-ins, plus everything changed from them.",
             {"any": ["Identity provider sign-in and audit logs (Entra ID, Okta System Log, Google Workspace, AWS CloudTrail ConsoleLogin)",
                      "AWS: aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<user> --max-results 50"],
              "linux": ["last -Faiw <user>", "sudo grep -h '<user>' /var/log/auth.log* /var/log/secure* 2>/dev/null",
                        "cat /home/<user>/.ssh/authorized_keys"],
              "macos": ["last <user>", "log show --last 7d --predicate 'eventMessage CONTAINS \"<user>\"' --style syslog | head -200"],
              "windows": ["Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648} -MaxEvents 2000 "
                          "| Where Message -match '<user>' | Select TimeCreated,Id,Message"]}),
        step("evidence", "New credentials and persistence on the account",
             "Attackers add MFA devices, API keys, access keys, SSH keys, app passwords or OAuth grants to come back later.",
             {"any": ["AWS: aws iam list-access-keys --user-name <user>; aws iam list-mfa-devices --user-name <user>",
                      "GitHub org: audit log for the user (personal access tokens, SSH keys, OAuth apps)",
                      "Graph: Get-MgUserAuthenticationMethod -UserId <user>"]}),
        step("contain", "Disable or lock the account, revoke sessions and keys",
             "Disable rather than delete, so its history and ownership stay intact for the investigation.",
             {"any": ["AWS: aws iam update-access-key --user-name <user> --access-key-id <id> --status Inactive",
                      "Graph: Update-MgUser -UserId <user> -AccountEnabled:$false; Revoke-MgUserSignInSession -UserId <user>"],
              "linux": ["sudo usermod -L <user>   # lock password; also move unknown keys out of authorized_keys"],
              "windows": ["Disable-LocalUser -Name <user>   # or Disable-ADAccount -Identity <user>"]}, approval=True),
        step("recover", "Find how the credentials were lost",
             "Phishing, password reuse from another breach, an infostealer on the user's machine or a leaked token in a repo. "
             "If an infostealer is suspected, treat every credential and cookie on that machine as stolen."),
    ],
    "web-compromise": [
        step("evidence", "Web server and application logs",
             "Find the first malicious request: the vulnerable endpoint, upload, or admin login that started it.",
             {"linux": [f"sudo cp -a /var/log/nginx /var/log/apache2 /var/log/httpd {OUT['linux']}/ 2>/dev/null",
                        "sudo grep -hE 'POST .*\\.(php|jsp|aspx)' /var/log/nginx/access.log* /var/log/apache2/access.log* 2>/dev/null | tail -200"],
              "windows": [f"Copy-Item -Recurse C:\\inetpub\\logs\\LogFiles {OUT['windows']}\\iis_logs"],
              "macos": ["Copy the web server's access and error logs (path from its config) to evidence media"]}),
        step("evidence", "Recently changed files and web shells in the web root",
             "Web shells are small script files in upload or cache folders, often with eval/base64/system calls.",
             {"linux": ["sudo find /var/www -type f -mtime -14 -ls",
                        "sudo grep -rlE 'eval\\(|base64_decode\\(|assert\\(|system\\(|passthru\\(|shell_exec\\(' /var/www --include=*.php",
                        "sudo find /var/www -type f -path '*uploads*' -name '*.php'"],
              "macos": ["find <webroot> -type f -mtime -14 -ls"],
              "windows": ["Get-ChildItem C:\\inetpub\\wwwroot -Recurse -Include *.aspx,*.ashx,*.asmx,*.asp,*.php "
                          "| Where LastWriteTime -gt (Get-Date).AddDays(-14) | Select FullName,LastWriteTime,Length"]}),
        step("evidence", "Application admin users, plugins and database changes",
             "CMS takeovers add admin users, install plugins or inject scripts into stored content. Export, do not edit.",
             {"any": ["WordPress: wp user list --role=administrator; wp plugin list   (WP-CLI, read-only)",
                      "Check integrity against the release: wp core verify-checksums; wp plugin verify-checksums --all",
                      "Database: export user and options tables to evidence before any cleanup"]}),
        step("contain", "Take the site into maintenance or block the entry point",
             "Put up a static maintenance page or WAF rule for the abused endpoint. Keep the compromised server running "
             "(or snapshot it) for analysis instead of wiping it.", approval=True),
        step("recover", "Rotate every secret the web app holds",
             "Database passwords, API keys, cloud keys, session signing keys and SMTP credentials in config files were readable "
             "by the attacker."),
    ],
    "malware": [
        step("evidence", "Collect the sample safely",
             "Hash it, copy it into a password-protected zip (password 'infected' by convention) and never run it on a normal "
             "machine. Do not upload confidential files to public sandboxes: anything uploaded becomes visible to others.",
             {"linux": ["sha256sum <file>", "zip -P infected sample.zip <file>"],
              "macos": ["shasum -a 256 <file>", "codesign -dv --verbose=4 <file>", "spctl -a -vv <file>",
                        "xattr -l <file>   # com.apple.quarantine shows where it came from",
                        "sqlite3 -readonly ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 "
                        "'select datetime(LSQuarantineTimeStamp+978307200,\"unixepoch\"),LSQuarantineAgentName,LSQuarantineDataURLString "
                        "from LSQuarantineEvent order by LSQuarantineTimeStamp desc limit 20'"],
              "windows": ["Get-FileHash -Algorithm SHA256 <file>", "Get-AuthenticodeSignature <file>",
                          "Get-Item <file> -Stream Zone.Identifier -ErrorAction SilentlyContinue | Get-Content"]}),
        step("evidence", "Security tool detections and execution traces",
             "AV/EDR history, Prefetch and PowerShell logs show when it first ran and what it launched.",
             {"windows": ["Get-MpThreatDetection", "Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated",
                          "Get-ChildItem C:\\Windows\\Prefetch | Sort LastWriteTime -Descending | Select -First 30 Name,LastWriteTime",
                          "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 200"],
              "macos": ["log show --last 3d --predicate 'eventMessage CONTAINS[c] \"xprotect\"' --style syslog | tail -100"],
              "linux": ["sudo journalctl --since '-3 days' | grep -iE 'clamav|falcon|defender|osquery' | tail -100"]}),
        step("evidence", "Static triage and indicators",
             "Run static triage on the sample (hashes, type, imports, strings, URLs) and turn what you find into IOCs to sweep other hosts."),
        step("contain", "Isolate the host and block the indicators",
             "Network-contain the host via EDR, then block the C2 domains/IPs and the file hash across the fleet.", approval=True),
    ],
    "data-leak": [
        step("evidence", "Pin down what was exposed, where and since when",
             "Exact data set, record count, data types (personal, payment, health, secrets), the exposure window and who accessed it.",
             {"any": ["AWS S3: check bucket policy/ACL history in CloudTrail (PutBucketPolicy, PutBucketAcl, PutPublicAccessBlock)",
                      "AWS S3: server access logs or CloudTrail data events for GetObject from unknown principals or IPs",
                      "Google Cloud Storage: Cloud Audit Logs (Data Access) for the bucket",
                      "Leaked dump online: save a copy and its URL with a timestamp; do not redistribute it"]}),
        step("contain", "Close the exposure without destroying evidence",
             "Make the resource private or block public access, revoke shared links, and keep logs and a copy of the exposed state.",
             {"any": ["AWS: aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration "
                      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"]},
             approval=True),
        step("contain", "Rotate any credentials in the exposed data",
             "Keys, passwords, tokens or connection strings inside the leaked data must be treated as public."),
        step("notify", "Notification clock",
             "Involve legal and the privacy lead now. Under GDPR a personal data breach goes to the supervisory authority within "
             "72 hours of becoming aware unless it is unlikely to result in a risk; other laws and contracts set their own deadlines."),
    ],
    "insider": [
        step("prepare", "Involve HR and legal, keep it need-to-know",
             "Insider cases end in discipline or court, so evidence handling and privacy rules matter more than speed. "
             "Do not alert the person, and do not let their manager investigate on their own."),
        step("evidence", "Preserve accounts and mailboxes as they are",
             "Put mailbox and cloud drive on legal hold, keep the account and its devices intact. Never delete or wipe them, "
             "even after the person leaves.",
             {"any": ["Microsoft 365: Purview eDiscovery hold / litigation hold on the mailbox and OneDrive",
                      "Google Workspace: Vault hold on the user's Gmail and Drive"]}),
        step("evidence", "Data movement: downloads, USB, personal email, cloud sync",
             "Look for bulk downloads, forwarding to personal addresses, uploads to personal cloud storage and USB copies.",
             {"windows": ["Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' | Select FriendlyName,PSChildName",
                          "Get-WinEvent -LogName 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue"],
              "macos": ["log show --last 30d --predicate 'eventMessage CONTAINS[c] \"USBMSC\"' --style syslog | tail -100"],
              "linux": ["sudo journalctl -k --since '-30 days' | grep -i 'usb-storage\\|new usb device' | tail -100"],
              "any": ["DLP, CASB and proxy logs for the user", "Cloud drive audit: bulk download or external sharing events"]}),
        step("contain", "Remove access at a time agreed with HR",
             "Disable accounts, revoke sessions, collect devices and badges in one coordinated step, ideally during the exit meeting.",
             approval=True),
    ],
    "lost-device": [
        step("evidence", "Confirm encryption and what was on the device",
             "If the disk was encrypted and the device was locked, the risk is mostly the sessions and tokens it held. "
             "Check the MDM or inventory record rather than guessing.",
             {"any": ["MDM / inventory: encryption status, last check-in, last user, installed apps"],
              "macos": ["(on a sibling Mac, for reference) fdesetup status"],
              "windows": ["(from the recovery record) manage-bde -status   # BitLocker key escrow in Entra ID / AD"],
              "linux": ["(from the build record) lsblk -f   # crypto_LUKS on the root volume"]}),
        step("contain", "Lock the device and revoke its sessions",
             "Remote lock via MDM / Find My, revoke the user's sessions and the device's certificates or tokens. "
             "Wipe only after a decision: a wipe ends any chance of locating it.",
             {"any": ["MDM: remote lock, then remote wipe once approved", "Identity provider: revoke sessions and remove the device"]},
             approval=True),
        step("contain", "Rotate credentials that lived on the device",
             "SSH keys, VPN profiles, API tokens, saved browser passwords and password manager sessions."),
        step("notify", "Police report and data protection check",
             "A police report number is often needed for insurance. Unencrypted personal data on the device may be a notifiable breach."),
    ],
    "cloud-compromise": [
        step("contain", "Cut the abused credential, keep its history",
             "Leaked cloud keys get used within minutes, often to start mining instances in every region or to copy data. "
             "Deactivate (not delete) the key or attach a deny-all policy, and revoke sessions already issued from it.",
             {"any": ["AWS: aws iam update-access-key --user-name <user> --access-key-id <key-id> --status Inactive",
                      "AWS: aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AWSDenyAll",
                      "AWS role: IAM console > Roles > <role> > Revoke active sessions (denies tokens issued before now)",
                      "Azure: disable the service principal or user in Entra ID; Graph: Revoke-MgUserSignInSession -UserId <user>",
                      "Google Cloud: gcloud iam service-accounts keys disable <key-id> --iam-account <sa-email>"]},
             approval=True),
        step("evidence", "Everything the identity did, in every region",
             "The control-plane audit log is the timeline. CloudTrail event history covers 90 days per region; a trail or "
             "CloudTrail Lake keeps more. Export before anyone changes the account.",
             {"any": ["AWS: aws ec2 describe-regions --query 'Regions[].RegionName' --output text",
                      "AWS: aws cloudtrail lookup-events --region <region> --lookup-attributes "
                      "AttributeKey=AccessKeyId,AttributeValue=<key-id> --max-results 50",
                      "AWS: aws guardduty list-detectors; aws guardduty list-findings --detector-id <id>",
                      "Azure: az monitor activity-log list --caller <user-or-app-id> --offset 7d",
                      "Google Cloud: gcloud logging read 'protoPayload.authenticationInfo.principalEmail=\"<sa-email>\"' "
                      "--freshness=7d --format=json"]}),
        step("evidence", "New identities, keys, trust and sharing",
             "Attackers create IAM users, access keys, login profiles and role trust policies to come back, and share "
             "snapshots, AMIs or buckets with accounts they own. Search the audit log for these calls.",
             {"any": ["AWS calls to look for: CreateUser, CreateAccessKey, CreateLoginProfile, AttachUserPolicy, PutUserPolicy, "
                      "UpdateAssumeRolePolicy, CreateRole, ModifySnapshotAttribute, ModifyImageAttribute, PutBucketPolicy, "
                      "StopLogging, DeleteTrail, DeleteDetector",
                      "AWS: aws iam generate-credential-report; aws iam get-credential-report --query Content --output text "
                      "| base64 --decode",
                      "Azure: Entra audit log for new app credentials (Add service principal credentials) and role assignments",
                      "Google Cloud: IAM policy changes (SetIamPolicy) and new service account keys (CreateServiceAccountKey)"]}),
        step("evidence", "Resources the attacker started or touched",
             "Crypto mining shows up as large instances or GPU quotas in regions you never use; data theft as snapshot "
             "copies, new users on databases or big GetObject runs. Note the instance ids before you stop anything.",
             {"any": ["AWS: aws ec2 describe-instances --region <region> --query "
                      "'Reservations[].Instances[].[InstanceId,InstanceType,LaunchTime,State.Name]' --output table",
                      "AWS: aws ce get-cost-and-usage --time-period Start=<yyyy-mm-dd>,End=<yyyy-mm-dd> --granularity DAILY "
                      "--metrics UnblendedCost --group-by Type=DIMENSION,Key=REGION",
                      "Azure / Google Cloud: list compute in all regions and the billing report by region and SKU"]}),
        step("notify", "Open a case with the cloud provider",
             "Providers help with abuse cleanup and sometimes with the bill. AWS may already have attached a compromised-key "
             "quarantine policy and emailed the root address; read those notices before changing anything."),
        step("recover", "Find where the key leaked and stop it happening again",
             "Usual sources: a public or internal repo, CI logs, a container image, a laptop infostealer. Scan the git history "
             "with a secrets scanner, move workloads to short-lived credentials (roles, workload identity federation) "
             "and add billing and GuardDuty or Defender alerts."),
    ],
}


def build_plan(incident: str, platform: str) -> List[Dict]:
    """Return the ordered checklist for one incident type and platform."""
    if incident not in INCIDENTS:
        raise ValueError(f"unknown incident type: {incident}")
    if platform not in PLATFORMS:
        raise ValueError(f"unknown platform: {platform}")
    host_based = incident not in ("bec", "data-leak", "lost-device", "cloud-compromise")
    steps = list(PREPARE)
    if host_based:
        steps += VOLATILE
    specific = TYPE_STEPS[incident]
    order = {"prepare": 0, "volatile": 1, "contain": 2, "evidence": 3, "notify": 4, "recover": 5}
    # Containment that stops active damage (ransomware spread) goes before slower evidence work.
    urgent = [s for s in specific if s["phase"] == "contain" and incident in ("ransomware", "data-leak", "lost-device", "cloud-compromise")]
    rest = [s for s in specific if s not in urgent]
    steps += [s for s in rest if s["phase"] == "prepare"]
    if urgent:  # stop active damage first; isolation keeps memory, it only drops live connections
        steps = steps[:len(PREPARE)] + urgent + steps[len(PREPARE):]
    steps += [s for s in rest if s["phase"] == "evidence"]
    if host_based:
        steps += COLLECT
    steps += sorted([s for s in rest if s["phase"] not in ("prepare", "evidence")], key=lambda s: order[s["phase"]])
    steps += CLOSE
    plan = []
    for i, s in enumerate(steps, 1):
        cmds = list(s["commands"].get("any", [])) + list(s["commands"].get(platform, []))
        plan.append({"priority": i, "phase": s["phase"], "title": s["title"], "why": s["why"],
                     "commands": cmds, "approval": s["approval"]})
    return plan


def report_skeleton(incident: str, platform: str) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"""# Incident report: {incident} ({platform})

| Field | Value |
|---|---|
| Incident ID | IR-{today.replace('-', '')}-01 |
| Status | open / contained / eradicated / closed |
| Severity | critical / high / medium / low |
| Reported by / at (UTC) | |
| Incident lead | |
| Detection source | EDR / SIEM alert, user report, provider notice, third party |
| Initial access (ATT&CK technique ID) | |
| Last updated (UTC) | {today} |

## Summary
What happened, in three sentences a manager can read: what, impact, current state.

## Timeline (UTC)
| Time (UTC) | Source | Event | Who / what |
|---|---|---|---|
| | | First malicious event (patient zero) | |
| | | Detection | |
| | | Containment | |

## Scope
- Hosts:
- Accounts:
- Data:
- Still unknown:

## Impact
Business impact, data affected (types, record count), downtime, money lost or at risk.

## Evidence
| Item | Source host | Collected by | Time (UTC) | SHA-256 | Stored at |
|---|---|---|---|---|---|

## Indicators of compromise
| Type | Value (defanged) | Context | First seen |
|---|---|---|---|

## Actions taken
| Time (UTC) | Action | By | Approved by | Reversible? |
|---|---|---|---|---|

## Root cause
How they got in and why it worked.

## Notifications
| Who (authority, customers, insurer, partners) | Required by | Deadline | Sent (UTC) |
|---|---|---|---|

## Lessons learned and follow-ups
CSF 2.0 Function per fix (NIST SP 800-61 Rev. 3): GV govern, ID identify, PR protect, DE detect, RS respond, RC recover.

| Fix | CSF 2.0 Function | Owner | Due |
|---|---|---|---|
"""


def render_text(incident: str, platform: str, plan: List[Dict]) -> str:
    lines = [f"Triage plan: {incident} on {platform}", INCIDENTS[incident],
             "Evidence steps are read-only. [APPROVAL] steps change state: get sign-off and log them.", ""]
    for s in plan:
        tag = " [APPROVAL]" if s["approval"] else ""
        lines.append(f"[ ] {s['priority']:>2}. ({s['phase']}) {s['title']}{tag}")
        lines.append(f"       {s['why']}")
        for c in s["commands"]:
            lines.append(f"       $ {c}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Prioritized, read-only incident triage checklist (order of volatility).")
    ap.add_argument("incident", nargs="?", choices=list(INCIDENTS), help="incident type")
    ap.add_argument("--platform", choices=PLATFORMS, default="linux", help="affected platform (default linux)")
    ap.add_argument("--report", action="store_true", help="print a fill-in incident report skeleton instead of the checklist")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--list", action="store_true", help="list incident types")
    args = ap.parse_args(argv)

    if args.list:
        for name, desc in INCIDENTS.items():
            print(f"{name:18} {desc}")
        return 0
    if not args.incident:
        print("error: give an incident type (see --list)", file=sys.stderr)
        return 2
    if args.report:
        text = report_skeleton(args.incident, args.platform)
        print(json.dumps({"incident": args.incident, "platform": args.platform, "report": text}, indent=2)
              if args.json else text)
        return 0
    plan = build_plan(args.incident, args.platform)
    if args.json:
        print(json.dumps({"incident": args.incident, "platform": args.platform,
                          "description": INCIDENTS[args.incident], "steps": plan}, indent=2))
    else:
        print(render_text(args.incident, args.platform, plan))
    return 0


if __name__ == "__main__":
    sys.exit(main())
