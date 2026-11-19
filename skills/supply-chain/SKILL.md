---
name: supply-chain
description: Software supply chain security review. Audits GitHub Actions workflows (actions not pinned to a commit SHA, pwn requests through pull_request_target, workflow_run or issue_comment, the checkout allow-unsafe-pr-checkout override, script injection through ${{ github.event.* }}, GITHUB_ENV writes, secrets inherit, broad token permissions, self-hosted runners on PR triggers, previously compromised actions and Shai-Hulud worm traces) and checks dependencies in requirements.txt, pyproject.toml, package.json and package-lock.json for typosquats, install hooks, known malicious versions and dependency confusion. Use whenever someone shares a .github/workflows file, asks "is my CI safe", "pin my actions", "is this package legit", "were we hit by" a compromised npm or PyPI package, mentions a typosquat, dependency confusion, lockfiles, npm tokens or trusted publishing, SBOM, SLSA or provenance, or before adding a new dependency or a release pipeline.
---

# Supply chain

Catch the ways code you did not write ends up running in your build: hijacked actions, injected workflow input, look-alike packages and install hooks.

## When to use

- Reviewing or writing a GitHub Actions workflow, especially release, deploy or PR-comment bots
- "Is this package safe?", a new dependency in a PR, or a suspected typosquat
- A news item about a compromised action or package and the question "are we affected?"
- Setting up private packages (dependency confusion), lockfiles, SBOMs or provenance

## Ground rules

- Offline and read-only. The scripts read files; they never install packages, query registries or call the GitHub API
- Never install a suspected malicious package to "see what it does". If behavior analysis is needed, say it belongs in an isolated sandbox and stop there
- A typosquat hit is a lead, not a verdict. Before calling a package malicious, check the registry page, publisher, repository link, download counts and first-publish date, and say what you checked
- Do not post secrets found in workflows or logs back in full; mask them (first 4 chars)
- If a real compromise is suspected (malicious package installed, leaked token), the order is: rotate credentials, then investigate, then clean up

## Workflow

Copy this checklist and tick it off:

```
- [ ] 1. ci_audit.py on the repo, critical and high fixed
- [ ] 2. Actions pinned to SHAs, Dependabot or Renovate on github-actions
- [ ] 3. typosquat_check.py on manifests and package-lock.json
- [ ] 4. Lockfiles committed, CI installs from them
- [ ] 5. Incident question answered with the files searched
- [ ] 6. Both scripts re-run after fixes
```

1. Workflows: run `ci_audit.py <repo>`. Fix critical and high first: GHA-002, GHA-004, GHA-005 and GHA-010 lead to code execution with your secrets. A GHA-045 hit means an active compromise: rotate tokens before anything else
2. Pin actions to full SHAs (GHA-001) and turn on Dependabot or Renovate for `github-actions` so pins stay current
3. Dependencies: run `typosquat_check.py <repo> --internal-prefix <your-org>`. Check every TYPO-001/002 by hand on the registry before changing anything. TYPO-011 or TYPO-012 means a known malicious release: follow the incident order in Ground rules
4. Check lockfiles exist and CI installs from them (`npm ci`, `pip install --require-hashes`, `poetry install --sync`); see `references/dependency-hygiene.md`
5. For a "were we hit by package X version Y" question, search lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `requirements*.txt`) for the exact name and version, and say which files you searched
6. Report with fixes as diffs; re-run both scripts after changes

## Tools

### ci_audit.py

Audits GitHub Actions workflow YAML.

```bash
python3 scripts/ci_audit.py .                                   # .github/workflows/*.yml
python3 scripts/ci_audit.py .github/workflows/release.yml --json
python3 scripts/ci_audit.py . --fail-on medium                  # CI gate
```

| ID | Severity | Check |
|---|---|---|
| GHA-001 | high/medium/low | `uses:` not pinned to a 40-char SHA (branch = high, third-party tag = medium, `actions/*` tag = low); docker:// without digest |
| GHA-002 | critical | `pull_request_target` or `workflow_run` that checks out the PR head |
| GHA-003 | low | `pull_request_target` present (review needed) |
| GHA-004 | critical/high | `allow-unsafe-pr-checkout: true` turns off the checkout v7 fork PR guard |
| GHA-005 | high | PR code fetched around the guard: `issue_comment` checkout of a PR ref, `gh pr checkout`, `git fetch ... pull/`, `refs/pull/` under a privileged trigger |
| GHA-010 | high | untrusted context (`github.event.issue.title`, `pull_request.body`, `comment.body`, `discussion.*`, `head_ref`, commit messages, `inputs.*`) inside `run:` or `github-script` |
| GHA-011 | high | write to `$GITHUB_ENV` or `$GITHUB_PATH` under a privileged trigger |
| GHA-020 | high | `permissions: write-all` |
| GHA-021 | medium | no `permissions:` block |
| GHA-022 | medium | `secrets: inherit` on a reusable workflow call |
| GHA-030 | high | secret echoed/printed, or `toJSON(secrets)` |
| GHA-031 | high | self-hosted runner on a PR-type trigger |
| GHA-032 | medium | `workflow_run` that downloads artifacts (artifact poisoning review) |
| GHA-040 | medium | `curl ... \| sh` |
| GHA-041 | medium | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` |
| GHA-042 | high/critical | previously compromised action (`tj-actions/changed-files`, `reviewdog/action-setup@v1`); critical on the malicious SHA |
| GHA-043 | high | literal registry password in `container:` or `services:` credentials |
| GHA-044 | medium | `curl`/`wget` over plain `http://` |
| GHA-045 | critical | Shai-Hulud traces: `shai-hulud-workflow.yml`, `discussion.yaml` worm file, `SHA1HULUD` runner label |

### typosquat_check.py

Checks dependency names against an embedded list of about 190 popular PyPI and npm packages.

```bash
python3 scripts/typosquat_check.py .                                   # requirements*.txt, pyproject.toml, package.json, package-lock.json
python3 scripts/typosquat_check.py package.json --internal-prefix acme
python3 scripts/typosquat_check.py requirements.txt --allow some-verified-name --json
```

| ID | Severity | Check |
|---|---|---|
| TYPO-001 | high/medium | one edit (high) or two edits (medium, names of 7+ chars) from a popular package, using Damerau-Levenshtein; npm separator swaps (`cross_env` vs `cross-env`) |
| TYPO-002 | medium | popular name with a prefix or suffix (`python-`, `py-`, `node-`, `-js`, `.js`) |
| TYPO-003 | high | non-ASCII characters in a package name |
| TYPO-010 | high/medium | npm `preinstall` / `install` / `postinstall` script (high when it downloads or evals) |
| TYPO-011 | critical | install hook runs `setup_bun.js` / `bun_environment.js` (Shai-Hulud 2.0 loader) |
| TYPO-012 | critical | exact version on the embedded known-malicious list (chalk/debug 2025-09-08, `@ctrl/tinycolor`, `ultralytics`), from pins or lockfiles |
| TYPO-020 | high/medium | name matches `--internal-prefix` but is an unscoped npm package, or a PyPI name (high with `--extra-index-url`) |
| TYPO-021 | medium | `--extra-index-url` in requirements |

PyPI names are compared after PEP 503 normalization, so `typing_extensions` and `typing-extensions` count as the same project (pip treats them as one). On npm they are different packages, so separator swaps are flagged.
The popular and malicious lists are snapshots, not registry queries. A clean result means "no look-alike of a well-known name and no headline bad version", not "safe". For a full check run `osv-scanner` on the lockfile.

Both tools: `--json` prints `{..., "count", "findings": [{id, severity, title, detail, fix, location}]}`. Exit `0` clean, `1` a finding at or above `--fail-on` (default `high`, `never` to disable), `2` bad input or nothing to scan.

## Output

Start with one line: workflows and dependency files checked, count of critical/high, the worst issue.
Then two tables, CI and dependencies:

| Severity | ID | Where | Issue | Fix |
|---|---|---|---|---|

For pinning, give the exact replacement line (`uses: owner/repo@<sha> # vX.Y.Z`) and tell the user to resolve the SHA from the tag themselves (`git ls-remote https://github.com/owner/repo refs/tags/vX.Y.Z`), never a SHA you guessed.
For typosquats, say what you verified and what the user still has to verify. Close with what was out of scope (lockfile contents, transitive dependencies, registry metadata).

## References

- `references/github-actions-hardening.md` safe patterns for triggers, permissions, injection, pinning, OIDC and runners, with before/after YAML
- `references/dependency-hygiene.md` lockfiles, hash pinning, install scripts, dependency confusion, typosquat triage steps, SBOM and provenance
