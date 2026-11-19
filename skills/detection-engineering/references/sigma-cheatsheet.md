# Sigma cheat sheet

A compact reference for writing Sigma rules by hand. It follows the Sigma specification v2.1.0 (released 2025-08-02) and pySigma 2.x.

Contents: rule fields, detection logic, value modifiers, conditions, tags, correlation rules, filter rules, common logsources.

## Rule fields

| Field | Required | Notes |
|---|---|---|
| `title` | yes | Short, says what is detected. Under 256 characters |
| `id` | strongly recommended | Random UUID (version 4). Never reuse one; a big rewrite gets a new id plus `related` |
| `related` | no | List of `{id, type}`, type is derived, obsolete, merged, renamed or similar |
| `status` | recommended | `stable`, `test`, `experimental`, `deprecated`, `unsupported` |
| `description` | recommended | What it detects and why it matters, one or two sentences |
| `references` | no | URLs to reports or docs that explain the behaviour |
| `author` | no | Name or handle |
| `date` | recommended | Creation date, `YYYY-MM-DD` (older rules used `YYYY/MM/DD`) |
| `modified` | no | Last change, same format |
| `tags` | recommended | `attack.<tactic>`, `attack.t1234`, `attack.t1234.001`, `attack.g0001`, `attack.s0001`, `cve.2021-44228`, `car.2016-04-005`, `tlp.amber`, `detection.threat-hunting` |
| `logsource` | yes | At least one of `category`, `product`, `service` |
| `detection` | yes | Named selections plus `condition` |
| `fields` | no | Fields an analyst wants to see on the alert |
| `falsepositives` | recommended | List of known benign causes, or `Unknown` |
| `level` | recommended | `informational`, `low`, `medium`, `high`, `critical` |

## Tags

Tags are `namespace.value`, lowercase, hyphens inside the value.

| Namespace | Example | Notes |
|---|---|---|
| `attack` | `attack.t1059.001`, `attack.execution`, `attack.g0016`, `attack.s0002` | Technique, tactic, group, software |
| `car` | `car.2016-04-005` | MITRE CAR analytic |
| `cve` | `cve.2021-44228` | |
| `detection` | `detection.threat-hunting`, `detection.emerging-threats`, `detection.dfir` | Rule purpose |
| `tlp` | `tlp.amber` | |
| `stp` | `stp.2a` | Summiting the Pyramid score |

ATT&CK v19 (April 2026) renamed and split tactics, and v20 kept them. Use the current names:

| Old tag | Current tag |
|---|---|
| `attack.defense-evasion` | `attack.stealth` (hiding) or `attack.defense-impairment` (turning defenses off) |
| `attack.t1562.001` disable tools | `attack.t1685` |
| `attack.t1562.002` disable event logging | `attack.t1685.001` |
| `attack.t1562.008` disable cloud logs | `attack.t1685.002` |
| `attack.t1070.001` clear Windows event logs | `attack.t1685.005` |
| `attack.t1070.002` clear Linux or Mac logs | `attack.t1685.006` |
| `attack.t1562.004` disable firewall | `attack.t1686` |

pySigma checks attack tags against the live ATT&CK data, so a revoked technique ID breaks conversion in strict pipelines.

## Detection logic

```yaml
detection:
  selection:            # keys in one map are ANDed
    Image|endswith: '\rundll32.exe'
    CommandLine|contains:   # values in a list are ORed
      - 'comsvcs'
      - 'minidump'
  selection_alt:        # a list of maps: any map can match (OR)
    - ParentImage|endswith: '\winword.exe'
    - ParentImage|endswith: '\excel.exe'
  keywords:             # a plain list of strings searches all fields
    - 'mimikatz'
  filter_main:
    User|startswith: 'NT AUTHORITY\'
  condition: (selection or selection_alt) and not filter_main
```

- Matching is case-insensitive by default. Use `|cased` or `|re` when case matters
- `*` matches any characters, `?` one character. Escape them as `\*`, `\?`. A single `\` is literal unless it comes before `*`, `?` or `\`, so a path separator followed by a wildcard is written `\\*` (`C:\Users\\*\AppData`)
- `null` means the field is empty or missing; `''` means an empty string
- `|all` turns the value list from OR into AND (`CommandLine|contains|all`)

## Value modifiers

| Modifier | Effect |
|---|---|
| `contains` | substring |
| `startswith` / `endswith` | prefix / suffix |
| `all` | every value in the list must match |
| `re` | regular expression (PCRE-like); add `i`, `m`, `s` for flags |
| `cased` | case-sensitive match |
| `neq` | field exists and differs from every value (new in 2.1) |
| `exists` | `true`/`false`: field present or not |
| `base64` / `base64offset` | match the base64 form of the value (offset covers all 3 alignments) |
| `utf16le` / `utf16be` / `wide` / `utf16` | encode before base64, for PowerShell `-enc` strings |
| `windash` | also match `/`, en dash, em dash and horizontal bar wherever the value has `-` |
| `cidr` | IP in a network range, IPv4 or IPv6 |
| `lt` `lte` `gt` `gte` | numeric comparisons, the value must be a number |
| `minute` `hour` `day` `week` `month` `year` | compare one part of a timestamp field (minute 0-59, hour 0-23, day 1-31, week 1-52, month 1-12) |
| `fieldref` | compare against another field's value |
| `expand` | placeholder expanded by the backend config |

Combining rules the linter enforces: `i`, `m`, `s` only after `re`; `re` does not mix with contains, startswith, endswith, windash or base64; `all` needs a list; `exists` takes `true` or `false`.

`detection_test.py` in this skill implements contains, startswith, endswith, all, re (with i/m/s), cased, exists, neq, windash, cidr, lt, lte, gt and gte.

## Conditions

| Form | Meaning |
|---|---|
| `selection and not filter` | basic |
| `1 of selection_*` | at least one selection whose name matches |
| `all of selection_*` | every matching selection |
| `1 of them` / `all of them` | over every selection in the rule |
| `(a or b) and not (c or d)` | parentheses group; precedence is not > and > or |

Pipe aggregations (`| count() by SourceIp > 10`) are deprecated. Sigma 2 moves thresholds and sequences into separate correlation rules.

## Correlation rules

A correlation rule has no `detection` or `logsource`. It points at other rules by `name` or `id` and counts or orders their hits.

```yaml
title: Many failed logons from one source
id: <uuid>
status: test
level: high
correlation:
  type: event_count        # see table
  rules:
    - failed_logon         # the base rule's name: or id:
  group-by:
    - IpAddress
  timespan: 10m            # number plus s, m, h or d
  condition:
    gte: 10
```

| type | Meaning | condition |
|---|---|---|
| `event_count` | number of matching events | required |
| `value_count` | distinct values of `condition.field` | required, with `field` |
| `value_sum` / `value_avg` / `value_percentile` | sum, average or percentile of `condition.field` | required, with `field` |
| `temporal` | all listed rules fire inside the timespan, any order | none, needs 2+ rules |
| `temporal_ordered` | same, in the listed order | none, needs 2+ rules |

`condition` holds one operator (`gt`, `gte`, `lt`, `lte`, `eq`, `neq`) or two for a range (`gt: 10` plus `lte: 100`). `aliases` maps one field name to the per-rule field names when the base rules disagree. Base rules set `generate: false` (or leave it out) when they should not alert on their own.

## Filter rules

Filters (Sigma 2.1) tune existing rules for one environment without editing them.

```yaml
title: Exclude the backup service account
logsource:
  category: process_creation
  product: windows
filter:
  rules:
    - <id of the rule to tune>
  selection:
    User: 'CORP\svc_backup'
  condition: not selection
```

`title`, `logsource` and `filter.rules` are required; `id` is optional; there is no `status` or `level`.

## Common logsources

| category / service | product | Typical source | Key fields |
|---|---|---|---|
| `process_creation` | windows | Sysmon 1, Security 4688 | Image, CommandLine, ParentImage, OriginalFileName, User, IntegrityLevel |
| `network_connection` | windows | Sysmon 3 | Image, DestinationIp, DestinationPort, DestinationHostname, Initiated |
| `file_event` | windows | Sysmon 11 | Image, TargetFilename |
| `registry_set` | windows | Sysmon 13 | Image, TargetObject, Details |
| `image_load` | windows | Sysmon 7 | Image, ImageLoaded, Signed |
| `process_access` | windows | Sysmon 10 | SourceImage, TargetImage, GrantedAccess |
| `ps_script` | windows | PowerShell 4104 | ScriptBlockText |
| service `security` | windows | Security log | EventID, TargetUserName, LogonType, IpAddress |
| service `sysmon` | windows | Sysmon by EventID | EventID plus the fields above |
| `process_creation` | linux | auditd, Sysmon for Linux | Image, CommandLine, ParentImage, User |
| service `sshd` | linux | auth.log / secure | free text, keyword rules |
| `webserver` | any | access logs | cs-method, cs-uri-query, cs-uri-stem, sc-status, c-ip, cs-user-agent |
| `proxy` | any | web proxy | c-uri, cs-host, c-useragent, cs-method, r-dns |
| `dns` | any | DNS resolver logs | query, answer, record_type |
| service `cloudtrail` | aws | AWS CloudTrail | eventSource, eventName, userIdentity.type, userIdentity.arn, sourceIPAddress, errorCode |
| service `signinlogs` | azure | Entra ID sign-in logs | ResultType, UserPrincipalName, AppDisplayName, IPAddress, AuthenticationRequirement |
| service `auditlogs` | azure | Entra ID audit logs | OperationName, Result, InitiatedBy, TargetResources |
| service `audit` | m365 | Microsoft 365 unified audit | Operation, Workload, UserId, ClientIP |

Field names are Sigma's taxonomy. The SIEM backend config maps them to the real field names (for example `CommandLine` to `process.command_line` in ECS).
