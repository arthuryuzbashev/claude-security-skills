# Skill standard

Every skill in this repo follows the same contract, so people can trust any of them the same way.
`python3 tools/validate.py` enforces the parts a machine can check.

## Folder layout

```
skills/<skill-name>/
├── SKILL.md              required, frontmatter + instructions for Claude
├── scripts/              stdlib-only Python 3.9+ CLI tools (at least one)
├── references/           checklists and cheat sheets Claude reads on demand
└── examples/             realistic sample input the scripts can run against
tests/test_<skill_name>.py   unittest tests for every script (snake_case of the folder)
```

- The folder name is the skill name: lowercase, digits and hyphens, max 64 chars
- A skill must work when its folder alone is copied into `~/.claude/skills/`. No imports from other skills or from the repo root
- No third-party packages. Standard library only, so `git clone` + `python3` is the whole install

## SKILL.md

Frontmatter:

```yaml
---
name: <skill-name>            # same as the folder
description: <what it does + when to use it, 1-3 sentences, under 1024 chars>
---
```

The description is what makes Claude pick the skill, so name the concrete triggers
(file types, tool names, phrases people say). Be a bit pushy: "Use whenever...".

Body sections, in this order:

1. `# <Title>` and one line on what the skill is for
2. `## When to use` short list of situations
3. `## Ground rules` authorization, safety and evidence rules for this domain (keep it practical, not legal boilerplate)
4. `## Workflow` numbered steps Claude follows
5. `## Tools` one block per script: what it does, the exact command, what the output means
6. `## Output` the report shape Claude should hand back
7. `## References` links to the files in `references/` with one line on when to open each

Keep SKILL.md under ~250 lines. Long material goes in `references/`.
Write in plain, direct English. No marketing words.

## Scripts

- Shebang `#!/usr/bin/env python3`, module docstring with one-line purpose and usage examples
- `argparse` CLI. `--help` must work and exit 0
- Text output for humans by default, `--json` for machines (stable keys, documented in SKILL.md)
- Exit codes: `0` ran fine and nothing at/above the fail threshold, `1` findings at/above `--fail-on` (default `high` where severities exist), `2` usage or input error
- Severities, when used: `critical`, `high`, `medium`, `low`, `info`
- Findings carry: `id` (stable rule id like `HDR-001`), `severity`, `title`, `detail`, `fix` (and `location` when it applies)
- Read-only by default. Nothing that writes outside `--output`, nothing destructive, no exploit payloads
- Network access only when the user passes a target, with a timeout, and every script must also work on saved input (a file or stdin) so it can be tested offline
- Logic lives in importable functions; `main()` only parses args and prints. Tests import the functions
- No secrets in output: mask anything that looks like a credential (show the first 4 chars)

## Tests

- `tests/test_<skill_name>.py` with `unittest`. Load the script by path with `importlib` (see the existing tests for the helper)
- Cover: the main detection paths (a positive and a negative case each), `--json` shape, exit codes, and running against the files in `examples/`
- Tests must run offline and finish in a few seconds
- Run everything: `python3 -m unittest discover -s tests -v`
