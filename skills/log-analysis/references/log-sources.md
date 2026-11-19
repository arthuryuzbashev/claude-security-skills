# Log sources and triage checklist

## Where the logs are

| Log | Debian / Ubuntu | RHEL / Fedora / Amazon Linux | systemd journal |
|---|---|---|---|
| SSH, sudo, su | `/var/log/auth.log` | `/var/log/secure` | `journalctl -u ssh` (Debian) / `-u sshd` (RHEL), `journalctl _COMM=sudo` |
| nginx | `/var/log/nginx/access.log`, `error.log` | same | - |
| apache | `/var/log/apache2/access.log` | `/var/log/httpd/access_log` | - |
| Login history | `last`, `lastb` (`/var/log/wtmp`, `/var/log/btmp`) | same | - |
| auditd | `/var/log/audit/audit.log` | same | `ausearch`, `aureport` |

Rotated files: `auth.log.1`, `auth.log.2.gz`. Read gzip with `zcat file.gz | log_triage.py --file -`.

## auth.log lines that matter

| Line | Meaning |
|---|---|
| `Failed password for root from IP` | wrong password for an existing account |
| `Failed password for invalid user test from IP` | the account does not exist (typical of bots) |
| `Invalid user test from IP` | same attempt, logged before the password check; do not count it twice |
| `Accepted password for X from IP` | password login succeeded. On key-only servers this alone is suspicious |
| `Accepted publickey for X from IP ... SHA256:...` | key login; the fingerprint tells you which key |
| `Connection closed by authenticating user root IP [preauth]` | client gave up before finishing auth |
| `maximum authentication attempts exceeded` | one connection tried too many keys/passwords |
| `sudo: alice : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=...` | sudo succeeded; COMMAND is what ran |
| `sudo: bob : user NOT in sudoers ; ...` | sudo denied, user has no rights |
| `sudo: bob : 3 incorrect password attempts ; ...` | sudo password failures |
| `su: (to root) alice on pts/0` / `pam_unix(su:session): session opened` | someone became root with su |
| `useradd[...]: new user: name=...` / `usermod` / `passwd` | account changes |

## Access log format

nginx and apache "combined":

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
203.0.113.9 - - [19/Nov/2026:10:01:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0 ..."
```

Behind a load balancer or CDN, `$remote_addr` is the proxy. Real client IPs need `X-Forwarded-For` logged (and only trusted from your own proxies).

Status codes during triage:
- `200` on an attack pattern: look closer, the request may have worked (or the app returns 200 for everything)
- `500` on SQL injection probes: often a database error, a strong sign the parameter reaches SQL unsafely
- `401`/`403` bursts: credential stuffing against a login API
- `404` bursts: directory brute forcing, usually noise unless something in the same burst got a `200`
- Big response sizes for one IP on an export or API endpoint: possible scraping or data theft

## Windows logon types (4624 / 4625)

| Type | Meaning |
|---|---|
| 2 | Interactive (console) |
| 3 | Network (SMB, most remote access) |
| 4 | Batch (scheduled tasks) |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext (password sent in clear, e.g. basic auth) |
| 9 | NewCredentials (runas /netonly) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive (cached domain creds) |

## 4625 failure status codes

| Status / SubStatus | Meaning |
|---|---|
| `0xC000006A` | correct user, wrong password |
| `0xC0000064` | user does not exist |
| `0xC0000234` | account locked out |
| `0xC0000072` | account disabled |
| `0xC000006F` | logon outside allowed hours |
| `0xC0000070` | workstation restriction |
| `0xC0000071` | password expired |
| `0xC0000193` | account expired |

Many `0xC0000064` from one source = guessing usernames. Many `0xC000006A` across many users = spraying a real user list.

## Triage checklist

- [ ] Copy the logs, record file names, sizes, hashes (`sha256sum`) and the time range covered
- [ ] Confirm the timezone of each source (syslog often local time, web servers often UTC)
- [ ] Check for gaps: missing hours, a sudden stop, rotated files that are gone (log clearing is a finding)
- [ ] Brute force and spray sources: did any of them get a success?
- [ ] For every suspicious success: what did that session do next (sudo, new users, cron, authorized_keys, outbound connections)?
- [ ] Web: anything with an attack pattern that answered `200` or `500`
- [ ] Web: requests to files that should not exist (`.env`, `.git`, backups) answered `200`
- [ ] Compare against known-good: your own scanners, monitoring, CI deploy users
- [ ] Write down what you did not check
