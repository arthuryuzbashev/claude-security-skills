# Sigma cheat sheet

A compact reference for writing Sigma rules by hand. It covers the rule format as used by the Sigma 2 specification and most current tooling.

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

ATT&CK tags are lowercase: `attack.t1059.001`, `attack.credential-access` (tactic names use hyphens).

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
| `exists` | `true`/`false`: field present or not |
| `base64` / `base64offset` | match the base64 form of the value (offset covers all 3 alignments) |
| `utf16le` / `utf16be` / `wide` / `utf16` | encode before base64, for PowerShell `-enc` strings |
| `windash` | also match `-`, `/` and Unicode dash variants of a flag |
| `cidr` | IP in a network range |
| `lt` `lte` `gt` `gte` | numeric comparisons |
| `fieldref` | compare against another field's value |
| `expand` | placeholder expanded by the backend config |

`detection_test.py` in this skill implements contains, startswith, endswith, all, re (with i/m/s), cased and exists.

## Conditions

| Form | Meaning |
|---|---|
| `selection and not filter` | basic |
| `1 of selection_*` | at least one selection whose name matches |
| `all of selection_*` | every matching selection |
| `1 of them` / `all of them` | over every selection in the rule |
| `(a or b) and not (c or d)` | parentheses group; precedence is not > and > or |

Pipe aggregations (`| count() by SourceIp > 10`) are deprecated. Sigma 2 moves thresholds and sequences into separate correlation rules.

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

Field names are Sigma's taxonomy. The SIEM backend config maps them to the real field names (for example `CommandLine` to `process.command_line` in ECS).
