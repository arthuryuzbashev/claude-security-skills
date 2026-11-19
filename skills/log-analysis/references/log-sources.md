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

## AWS CloudTrail

Each record is JSON. A trail file in S3 is one object `{"Records": [...]}`; `log_triage.py` reads that on one line, or flatten it first with `jq -c '.Records[]'`.

| Field | Meaning |
|---|---|
| `eventTime`, `eventSource`, `eventName` | when, which service (`iam.amazonaws.com`), which API call |
| `userIdentity.type` | `Root`, `IAMUser`, `AssumedRole`, `FederatedUser`, `AWSService` |
| `userIdentity.arn`, `userName`, `accessKeyId` | who; `sessionContext.sessionIssuer` names the role behind an assumed role |
| `sourceIPAddress`, `userAgent` | where from; an AWS service name instead of an IP means the service called on your behalf |
| `errorCode` | present only on failure (`AccessDenied`, `UnauthorizedOperation`) |
| `responseElements.ConsoleLogin` | `Success` or `Failure` for `ConsoleLogin` events |
| `additionalEventData.MFAUsed` | `Yes` or `No` for `ConsoleLogin` events |

| Events | Why they matter |
|---|---|
| `ConsoleLogin` by `Root` | root should almost never sign in; alert on every one |
| `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` | audit trail turned off or narrowed (T1685.002) |
| `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile` | new long-lived credentials (T1098.001), worst when made for another user |
| `AttachUserPolicy`, `PutUserPolicy`, `AddUserToGroup` | privilege change |
| `GetCallerIdentity` followed by many `AccessDenied` | a stolen key checking what it can do |
| `DeleteDetector` (GuardDuty), `DisableSecurityHub` | security tooling turned off |

Failed console logins for user names that do not exist show `HIDDEN_DUE_TO_SECURITY_REASONS` as the user.

## Microsoft Entra ID sign-in logs

Columns as in Sentinel `SigninLogs`; the Graph API `signIns` resource uses camelCase (`userPrincipalName`, `status.errorCode`), the Azure diagnostic export nests them under `properties`.

| `ResultType` | Meaning |
|---|---|
| `0` | success |
| `50126` | invalid username or password |
| `50053` | account locked (smart lockout) or sign-in from a blocked IP |
| `50034` | account does not exist in the tenant |
| `50057` / `50055` | account disabled / password expired |
| `50074` / `50076` | MFA required; an interrupt, normal before a successful MFA sign-in |
| `500121` | MFA failed, including the user denying the push or reporting it |
| `53003` | blocked by Conditional Access |

| Pattern | Meaning |
|---|---|
| many `50126` across many users from one IP | password spray (T1110.003) |
| repeated `500121` for one user, then `0` | MFA fatigue that worked (T1621) |
| `AuthenticationProtocol == "deviceCode"` for a user who never uses a TV or CLI | device code phishing (T1528) |
| `AuditLogs` `Consent to application` with mail or file scopes | illicit consent grant (T1528) |
| `AuditLogs` `Add service principal credentials` / `Update application - Certificates and secrets management` | backdoor credentials on an app (T1098.001) |

## Triage checklist

- [ ] Copy the logs, record file names, sizes, hashes (`sha256sum`) and the time range covered
- [ ] Confirm the timezone of each source (syslog often local time, web servers often UTC)
- [ ] Check for gaps: missing hours, a sudden stop, rotated files that are gone (log clearing is a finding)
- [ ] Brute force and spray sources: did any of them get a success?
- [ ] For every suspicious success: what did that session do next (sudo, new users, cron, authorized_keys, outbound connections)?
- [ ] Web: anything with an attack pattern that answered `200` or `500`
- [ ] Web: requests to files that should not exist (`.env`, `.git`, backups) answered `200`
- [ ] Cloud: root or no-MFA console sign-ins, trail changes, new access keys, MFA denials followed by a success
- [ ] Compare against known-good: your own scanners, monitoring, CI deploy users
- [ ] Write down what you did not check
