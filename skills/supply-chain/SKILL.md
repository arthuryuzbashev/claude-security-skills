---
name: supply-chain
description: Software supply chain security review. Audits GitHub Actions workflows (actions not pinned to a commit SHA, pull_request_target that checks out PR code, script injection through ${{ github.event.* }} in run steps, write-all or missing token permissions, self-hosted runners on PR triggers, secrets echoed to logs) and checks dependencies in requirements.txt, pyproject.toml and package.json for typosquats, npm install scripts and dependency confusion. Use whenever someone shares a .github/workflows file, asks "is my CI safe", "pin my actions", "is this package legit", mentions a typosquat, a compromised npm or PyPI package, dependency confusion, lockfiles, SBOM, SLSA or provenance, or before adding a new dependency or a release pipeline.
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

1. Workflows: run `ci_audit.py <repo>`. Fix critical and high first: GHA-002 and GHA-010 lead to code execution with your secrets
2. Pin actions to full SHAs (GHA-001) and turn on Dependabot or Renovate for `github-actions` so pins stay current
3. Dependencies: run `typosquat_check.py <repo> --internal-prefix <your-org>`. Check every TYPO-001/002 by hand on the registry before changing anything
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
| GHA-010 | high | untrusted context (`github.event.issue.title`, `pull_request.body`, `comment.body`, `head_ref`, commit messages, `inputs.*`) inside `run:` or `github-script` |
| GHA-020 | high | `permissions: write-all` |
| GHA-021 | medium | no `permissions:` block |
| GHA-030 | high | secret echoed/printed, or `toJSON(secrets)` |
| GHA-031 | high | self-hosted runner on a PR-type trigger |
| GHA-040 | medium | `curl ... \| sh` |
| GHA-041 | medium | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` |

### typosquat_check.py

Checks dependency names against an embedded list of about 190 popular PyPI and npm packages.

```bash
python3 scripts/typosquat_check.py .                                   # requirements*.txt, pyproject.toml, package.json
python3 scripts/typosquat_check.py package.json --internal-prefix acme
python3 scripts/typosquat_check.py requirements.txt --allow some-verified-name --json
```

| ID | Severity | Check |
|---|---|---|
| TYPO-001 | high/medium | one edit (high) or two edits (medium, names of 7+ chars) from a popular package, using Damerau-Levenshtein; npm separator swaps (`cross_env` vs `cross-env`) |
| TYPO-002 | medium | popular name with a prefix or suffix (`python-`, `py-`, `node-`, `-js`, `.js`) |
| TYPO-003 | high | non-ASCII characters in a package name |
| TYPO-010 | high/medium | npm `preinstall` / `install` / `postinstall` script (high when it downloads or evals) |
| TYPO-020 | high/medium | name matches `--internal-prefix` but is an unscoped npm package, or a PyPI name (high with `--extra-index-url`) |
| TYPO-021 | medium | `--extra-index-url` in requirements |

PyPI names are compared after PEP 503 normalization, so `typing_extensions` and `typing-extensions` count as the same project (pip treats them as one). On npm they are different packages, so separator swaps are flagged.
The popular list is a snapshot, not a registry query. A clean result means "no look-alike of a well-known name", not "safe".

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
