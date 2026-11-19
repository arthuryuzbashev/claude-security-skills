# Detection lifecycle and testing

How a detection goes from an idea to a trusted alert, and how to keep it trusted.

## Lifecycle

| Stage | What happens | Exit criteria |
|---|---|---|
| Idea | From a hunt result, incident, threat report, red team finding or ATT&CK gap | Behaviour and technique written in one line |
| Research | Find how the behaviour shows up in your logs; replay it in a lab if you can | Example true positive event in hand, fields confirmed |
| Write | Sigma rule, `status: experimental` | Lint clean (no high or medium) |
| Unit test | True positive, near-miss and filter events | `detection_test.py --expect` passes |
| Backtest | Run the converted query over 7 to 30 days of real data | Alert volume known, every hit triaged |
| Tune | Narrow filters for benign patterns, documented in `falsepositives` | Volume the SOC can handle, no blind spot added |
| Deploy | Alert in production, owner and runbook set | `status: test`, then `stable` after a quiet month with good hits |
| Review | Every 6 to 12 months or when the log source changes | Still fires on the test events, noise still acceptable |
| Retire | Behaviour gone, log source gone, or replaced | `status: deprecated`, `related` points at the replacement |

## Designing test events

For each rule write at least:

- True positive: the attacker behaviour as it really appears (field names and casing from the real log)
- Variant: the same behaviour written differently (short flags like `-enc` vs `-EncodedCommand`, other path, renamed binary if you use `OriginalFileName`)
- Near miss: the same tool used normally (procdump on a SQL server process, schtasks `/query`)
- Filter case: the benign pattern your filter excludes, so you prove the filter works and does not exclude more than intended

Keep the events next to the rule (`rule.yml` + `rule.tests.jsonl`) and run them in CI with `--expect`.

## Writing rules that last

- Anchor on things attackers cannot change cheaply: parent-child relations, API access rights, command line structure. Avoid file names and hashes alone
- Use `OriginalFileName` or `Image|endswith` plus command line content, so a renamed binary is still caught
- Prefer `|endswith: '\tool.exe'` over `|contains: 'tool'` (fewer accidental hits)
- Short and long flag forms: `-enc`, `-ec`, `-EncodedCommand`, and `/` or `-` prefixes for Windows tools (`windash` in backends that support it)
- One behaviour per rule. Two unrelated detections in one rule make tuning and triage harder

## Tuning without blind spots

- Filter on several fields together (parent plus user plus path), not one broad field
- Never filter on something the attacker controls easily (a task name, a window title, a command line comment)
- Exclusions for a host or user group need an owner and an expiry date
- Track alert volume and true positive rate per rule; a rule nobody reads is worse than no rule

## Keeping rules current

Re-lint the whole rule set after each ATT&CK release (April and October). v19 revoked most of T1562 and T1070.001/.002 and split defense evasion into stealth and defense impairment; `sigma_lint.py` flags those tags (SIG-033, SIG-034) and names the replacement.

## Review checklist

- [ ] Title says what is detected; description says why it matters
- [ ] UUID id, valid status and level, date in `YYYY-MM-DD`
- [ ] ATT&CK tags are live in the current version and lowercase (tactic plus technique); no `defense-evasion` or revoked IDs after the v19 split
- [ ] Thresholds and sequences live in a correlation rule with a `timespan` and `group-by`, not a pipe aggregation
- [ ] Environment-specific exclusions live in a filter rule when the base rule is shared
- [ ] logsource matches where the fields come from
- [ ] Every selection is used; condition reads correctly out loud
- [ ] Filters are narrow and explained in `falsepositives`
- [ ] Test events: true positive, variant, near miss, filter case, all passing
- [ ] Backtest result recorded (window, hits, true positives)
- [ ] Level matches impact and confidence (a noisy rule is not critical)
- [ ] Runbook or triage notes exist for the analyst who gets the alert

## Severity guide

| Level | Use for |
|---|---|
| critical | Near-certain malicious activity with high impact (LSASS dumping, known ransomware behaviour) |
| high | Strong signal that needs action the same day |
| medium | Suspicious, needs context; often tuned per environment |
| low | Weak signal, useful for hunting and correlation |
| informational | Context only, not an alert |
