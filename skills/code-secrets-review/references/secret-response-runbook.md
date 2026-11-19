# Leaked secret response runbook

Use this when `secret_scan.py` (or anyone) finds a real credential in code, logs, tickets or chat.

## 1. Contain (first hour)

1. Assume it is compromised. Bots scan public pushes within minutes, and private repos get cloned, forked and cached
2. Rotate or revoke the credential at the provider. Do this before cleaning git: a deleted line does not invalidate a key
3. Deploy the new credential from a secrets manager or the environment, not a new commit
4. Tell the owner of the system and whoever runs incident response. Share the location and the masked value only

Where to revoke the common ones:

| Type | Where |
|---|---|
| AWS access key | IAM, the user's Security credentials, deactivate then delete the key |
| GitHub token | Settings, Developer settings, tokens (org owners can also revoke from the org's token list) |
| Slack token or webhook | The Slack app's settings page, reinstall or regenerate |
| Stripe key | Dashboard, Developers, API keys, roll key |
| Google API key | Cloud console, APIs and services, Credentials, regenerate and add restrictions |
| SendGrid key | Settings, API Keys, delete |
| npm token | `npm token revoke <id>` or npmjs.com access tokens page. Classic tokens were revoked by npm in late 2025; publish from CI with trusted publishing (OIDC) instead of a stored token |
| Anthropic API key (`sk-ant-`) | Anthropic Console, API keys, delete; check usage for the window |
| OpenAI API key (`sk-proj-`, `sk-svcacct-`, `sk-admin-`) | OpenAI platform, API keys (project or organization admin keys) |
| GitLab token (`glpat-`, `gldt-`, `glrt-`...) | User or project Access tokens page; group owners can revoke from the credentials inventory |
| Hugging Face (`hf_`) | Settings, Access Tokens, invalidate |
| PyPI (`pypi-`) | Account settings, API tokens; then move the project to trusted publishing |
| Azure AD client secret (`...Q~...`) | Entra ID, App registrations, Certificates and secrets |
| Vault token (`hvs.`, `hvb.`) | `vault token revoke <accessor>` and check the audit device log |
| Terraform state or `.tfstate` | Rotate every secret the state holds (database passwords, keys), move state to an encrypted remote backend |
| SSH or TLS private key | Remove the public key from every place that trusts it (authorized_keys, deploy keys, certificates) and issue a new pair |
| Database password | Change the password for that role, check for other roles sharing it |

## 2. Investigate

- When was it first committed, and was it ever pushed or public? `git log -S '<first chars>' --all` finds the commit without printing the full value in a report
- What could it do? List the scopes and resources the key reached
- Did anyone use it? AWS CloudTrail, GitHub audit log, Stripe request logs, database connection logs, for the whole exposure window
- Is it anywhere else? CI logs, container images, build artifacts, wiki pages, backups

Write down: secret type, location, exposure window, scopes, evidence of use, rotation time.

## 3. Clean history (after rotation)

- Rewrite history with `git filter-repo` (preferred) or BFG, then force-push and ask collaborators to re-clone
- Ask the hosting provider to purge cached views and pull request refs if the repo was public
- Old forks and clones keep the value. This is why rotation comes first and history cleaning is hygiene, not the fix

## 4. Prevent

- Keep secrets in a manager (Vault, AWS Secrets Manager, GCP Secret Manager, 1Password, Doppler) or CI secret variables
- `.gitignore` every `.env*` except `.env.example`, which holds fake values only
- Pre-commit: `git diff --cached | secret_scan.py --stdin --fail-on medium`
- CI: `secret_scan.py . --json --fail-on high` on every pull request
- Turn on the hosting provider's secret scanning and push protection where available. `secret_scan.py` is a fast first pass; for git history and 200+ provider shapes run gitleaks (`gitleaks git .`) or trufflehog as well
- Keep test fixtures obviously fake (`FAKE`, `EXAMPLE`, broken prefixes) so they never look like real provider tokens to push protection
- Prefer short-lived credentials (OIDC from CI to the cloud, IAM roles) over long-lived keys

## Triage of scanner hits

| Hit | Usual call |
|---|---|
| Value contains EXAMPLE, dummy, changeme or a placeholder | False positive, add `secskills:ignore` with a note |
| Test fixture with a made-up value | Add the path to `.secskills-ignore` |
| Stripe test key (`sk_test_`) | Low, but rotate: it exposes test data and habits leak live keys next |
| High-entropy value under a secret-like name | Check with the owner; if real, treat as a leak |
| Private key block | Critical unless the file is a documented test vector |
| Committed `.env` | Read it: any real value in it is a leak |
| JWT (SEC-051) | Decode it with web-appsec `jwt_inspect.py`. A public "anon" key is fine; a service-role, admin or long-lived token is a leak |
| Credential file (SEC-031) | SSH private keys and `.git-credentials`: critical in practice. `.tfstate`: read it, it usually holds generated passwords |
