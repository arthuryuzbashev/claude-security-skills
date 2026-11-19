# Query cheat sheet: SPL, KQL, ES|QL, EQL

Same operation in each language. Field names are examples.

| Task | Splunk SPL | Microsoft KQL | Elastic ES|QL | Elastic EQL |
|---|---|---|---|---|
| Pick data | `index=wineventlog sourcetype=...` | `SecurityEvent` (table name first) | `FROM logs-system.security-*` | event category first: `process where ...` |
| Time range | time picker or `earliest=-24h` | `where TimeGenerated > ago(24h)` | `WHERE @timestamp > NOW() - 24 hours` | set in the request filter or Kibana time picker |
| Equals | `EventCode=4625` | `EventID == 4625` | `event.code == "4625"` | `event.code == "4625"` |
| Case-insensitive equals | search terms are case-insensitive; `where lower(x)="y"` | `x =~ "y"` | `TO_LOWER(x) == "y"` | `x : "y"` |
| Contains | `CommandLine="*mimikatz*"` | `x contains "mimikatz"` (or `has` for whole terms, faster) | `x LIKE "*mimikatz*"` | `x : "*mimikatz*"` |
| In a list | `x IN ("a","b")` | `x in ("a","b")`, `in~` ignores case | `x IN ("a", "b")` | `x in ("a", "b")`, `in~` ignores case |
| Regex | `\| regex x="..."` or `where match(x, "...")` | `x matches regex @"..."` | `x RLIKE "..."` (Lucene regex, whole value must match, no `\d` / `\s`) | `x regex "..."`, `regex~` ignores case |
| Count by | `\| stats count BY x` | `\| summarize count() by x` | `\| STATS c = COUNT(*) BY x` | not supported (use ES|QL) |
| Distinct count | `dc(x)` | `dcount(x)` (approximate) | `COUNT_DISTINCT(x)` (approximate) | - |
| Time buckets | `\| bin _time span=5m` | `bin(TimeGenerated, 5m)` | `DATE_TRUNC(5 minutes, @timestamp)` | - |
| New field | `\| eval y=lower(x)` | `\| extend y = tolower(x)` | `\| EVAL y = TO_LOWER(x)` | - |
| Pick columns | `\| table a, b` | `\| project a, b` | `\| KEEP a, b` | - |
| Sort | `\| sort - count` | `\| order by count desc` | `\| SORT count DESC` | - (results come back in time order) |
| First N rows | `\| head 10` | `\| take 10` | `\| LIMIT 10` | `\| head 10` |
| A then B | `transaction` or `streamstats` | `join` / `scan` operator | not built for sequences | `sequence by host.id with maxspan=5m [..] [..]` |

## Pitfalls

### SPL
- Searches before the first pipe are case-insensitive for values; `where` and `eval` comparisons are case-sensitive
- Backslashes in quoted search terms must be doubled: `Image="*\\powershell.exe"`
- Field names depend on the add-on (Splunk Add-on for Windows uses different names for classic vs XML logs). Check with `| fieldsummary` before trusting a zero-result search

### KQL
- `has` matches whole terms and uses the index; `contains` matches substrings and is slower. `has` will miss `mimikatz` inside `xmimikatz.exe`
- `==` is case-sensitive, `=~` is not
- Use verbatim strings `@"C:\Windows"` for regex and paths so backslashes are not escapes
- Sentinel (`TimeGenerated`) and Defender advanced hunting (`Timestamp`) use different time columns

### ES|QL
- Text fields need `.keyword` or a keyword mapping for exact matches in some indices; ECS fields from Elastic integrations are usually keyword already
- `LIKE` uses `*` and `?` wildcards; `RLIKE` uses Lucene regex (anchored to the whole value, no `\d`, `\s` or lookarounds)
- Default result limit is 1000 rows; add `LIMIT` explicitly when you need more or fewer

### EQL
- `==` is case-sensitive; `:` and `in~` are not
- `sequence ... with runs=N` repeats one step N times in a row (N up to 100)
- Every query starts with an event category (`process`, `network`, `file`, `registry`, `authentication`, `iam`, `any`) mapped to `event.category`

## Turning a hunt into a detection

1. Get the query to run clean over 30 days and count the hits
2. Explain every hit; allow-list the known-good ones by exact field values (not by wildcards)
3. Write it as a Sigma rule (detection-engineering skill) so it is portable, then convert to the SIEM
4. Schedule it with a window that overlaps the run interval (run every 5 min, look back 10) so late events are not missed
