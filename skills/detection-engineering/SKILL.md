---
name: detection-engineering
description: Write, lint and test Sigma detection rules before they reach the SIEM. Checks rule structure (title, UUID id, status, level, logsource, detection, condition), catches conditions that name selections which do not exist, unused selections, misspelled modifiers, bad ATT&CK tags and dates, then runs the rules offline against sample JSON-lines events to show exactly which events fire and why. Use whenever someone writes or reviews a Sigma rule, asks "is this rule valid", "why does my rule not fire", "will this catch X", "test this detection", "reduce false positives", converts an idea or a hunt result into a detection, or builds a detection-as-code pipeline or rule review checklist.
---

# Detection Engineering

Turn a behaviour into a Sigma rule that is valid, fires on the bad event, stays quiet on the normal ones, and comes with a test that proves both.

## When to use

- Writing a new Sigma rule from a hunt result, an incident or a threat report
- Reviewing or linting rules before a merge (single files or a whole folder)
- "Why does this rule not fire?" or "why does it fire on everything?"
- Building true positive and false positive test events for a rule
- Setting up a detection-as-code check in CI (lint plus tests, exit codes)

## Ground rules

- Test events are synthetic or scrubbed. Never paste real user names, hosts or secrets from production logs into examples or tickets without the user's OK
- Write detections for behaviour, not one sample: a hash or one exact command line is an IOC, not a rule
- Every rule needs at least one event it must match and one similar event it must not match. A rule with no negative test is not done
- `detection_test.py` is a local evaluator for the common Sigma subset. It is a fast check, not proof the SIEM backend behaves the same. Run the converted query in the real SIEM before calling a rule production ready
- Do not add filters that silence a whole user, host or path just to make noise go away. Filter the narrowest benign pattern and say why in `falsepositives`
- ATT&CK tags must be real IDs. If you are not sure of a technique ID, check attack.mitre.org or leave the tag out

## Workflow

1. State the behaviour in one line: which process or log does what, and why it matters (ATT&CK technique)
2. Pick the logsource (`category`/`product`/`service`) and confirm the fields exist in that log (`references/sigma-cheatsheet.md`)
3. Write the rule: positive selections first, then narrow filters, then the condition. Start `status: experimental`
4. Write events: at least one true positive, one near miss (same tool, benign use) and one from the filter you added
5. Lint: `python3 scripts/sigma_lint.py rule.yml`. Fix every high and medium finding
6. Test: `python3 scripts/detection_test.py rule.yml --events tests.jsonl --expect 1,4`. Exit 1 means the rule hit the wrong lines
7. Convert and run in the real SIEM over a past window (7 to 30 days) to measure noise. Tune, re-test, then promote `status` (`references/detection-lifecycle.md`)

## Tools

### sigma_lint.py

Lints Sigma rules in YAML or JSON, one file, several files or whole folders. It ships its own small YAML reader that covers what Sigma rules use (mappings, lists, lists of mappings, quoted and block scalars, `[a, b]`, multiple `---` documents).

```bash
python3 scripts/sigma_lint.py examples/rules/
python3 scripts/sigma_lint.py examples/bad_rule.yml
python3 scripts/sigma_lint.py rules/ --json --fail-on medium
```

| ID | Severity | Check |
|---|---|---|
| SIG-000 | high | file cannot be parsed, or the document is not a mapping |
| SIG-001 | high | `title` missing (SIG-004 low: title over 256 chars) |
| SIG-002 | medium | `id` missing or not a UUID |
| SIG-003 | medium | the same `id` in two rules |
| SIG-010 | medium | `status` missing or not stable/test/experimental/deprecated/unsupported |
| SIG-011 | medium | `level` not informational/low/medium/high/critical (low when missing) |
| SIG-012 | info | no `description` |
| SIG-020 | high | `detection` missing, or the condition names a selection or `1 of x*` pattern that does not exist |
| SIG-021 / 022 / 023 | high | no condition, no selections, unbalanced parentheses |
| SIG-024 | low | selection defined but never used |
| SIG-025 | medium | empty selection |
| SIG-026 / 027 | low | condition is a list, or uses a `\|` aggregation (deprecated in Sigma 2) |
| SIG-030 / 031 | low | ATT&CK tag not like `attack.t1059.001` / `attack.execution`, other tags not `namespace.value` |
| SIG-032 | info | no ATT&CK tags |
| SIG-040 | low | no `falsepositives` |
| SIG-050 | low / medium | `date`/`modified` in old `YYYY/MM/DD` (low) or invalid (medium); missing date is info |
| SIG-060 | high | `logsource` missing or without category, product or service |
| SIG-070 | medium | unknown value modifier (`endwith`, `contain`) |
| SIG-071 | high | `\|re` value is not a valid regular expression |

Text output shows FAIL/ok per rule with detail and fix. `--json` gives `{"rules": [{"file", "title", "findings": [{"id", "severity", "title", "detail", "fix", "location"}]}], "summary": {severity: count}}`. Exit `0` clean, `1` findings at or above `--fail-on` (default `high`, `never` to disable), `2` no rule files found.

### detection_test.py

Runs rules against JSON-lines events (one JSON object per line) and lists the matching line numbers, which selections were true, and a short summary of each event.

```bash
python3 scripts/detection_test.py examples/rules/ --events examples/events.jsonl
python3 scripts/detection_test.py examples/rules/proc_creation_win_lsass_dump_tools.yml --events examples/events.jsonl --expect 4,6
python3 scripts/detection_test.py rule.yml --events events.jsonl --json
```

Supported: field lists (OR), keys in a map (AND), lists of maps (OR), keyword lists, `|contains`, `|startswith`, `|endswith`, `|all`, `|re` (with `|i`, `|m`, `|s`), `|exists`, `|cased`, `*` and `?` wildcards, `null`, numbers, dotted field paths (`process.command_line`), and conditions with `and`, `or`, `not`, parentheses, `1 of selection_*`, `all of filter_*`, `1 of them`. Matching is case-insensitive like Sigma, except `|re` and `|cased`. Not supported (exit 2 with a message): pipe aggregations, correlation rules, `base64offset`, `windash`, `cidr` and other modifiers outside the list.

`--expect 4,6` (or `none`) makes every rule given match exactly those event lines, so test one rule per call when using it. `--json` gives `{"events", "bad_lines", "rules": [{"file", "title", "id", "level", "condition", "matched", "matches": [{"line", "selections", "summary"}]}], "expect", "expect_ok"}`. Exit `0` ok, `1` an `--expect` mismatch, `2` bad rule, unsupported feature or no events.

## Output

For a new or reviewed rule, hand back:

1. The rule (YAML, ready to commit)
2. Lint result: clean, or the findings left with a reason
3. Test table:

| Event | Expected | Got | Why |
|---|---|---|---|

4. Known false positives and what the filter excludes
5. Next steps: SIEM backtest window and result, status to promote to

## References

- `references/sigma-cheatsheet.md` rule fields, valid values, modifiers, condition syntax, common logsource categories and their key fields
- `references/detection-lifecycle.md` the idea to retirement lifecycle, test event design, tuning without blind spots, and a review checklist
- `examples/rules/` three valid rules (encoded PowerShell, LSASS dump tools, schtasks from user-writable paths), `examples/bad_rule.yml` (lint practice) and `examples/events.jsonl` (10 events; lines 1, 4, 6 and 8 are the true positives)
