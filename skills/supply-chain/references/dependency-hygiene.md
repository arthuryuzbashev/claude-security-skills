# Dependency hygiene

## Lockfiles and reproducible installs

| Ecosystem | Lockfile | CI install |
|---|---|---|
| npm | `package-lock.json` | `npm ci` (fails if lock and package.json disagree) |
| Yarn (Berry) | `yarn.lock` | `yarn install --immutable` |
| pnpm | `pnpm-lock.yaml` | `pnpm install --frozen-lockfile` |
| pip | `requirements.txt` with hashes | `pip install --require-hashes -r requirements.txt` |
| pip-tools | `requirements.txt` from `pip-compile --generate-hashes` | as above |
| Poetry | `poetry.lock` | `poetry install --sync` |
| uv | `uv.lock` | `uv sync --locked` |
| Go | `go.sum` | `go mod verify` |
| Cargo | `Cargo.lock` | `cargo build --locked` |

- Commit lockfiles for applications. Review lockfile diffs in PRs: a new transitive package or a changed `resolved` URL deserves a look
- Version ranges (`^1.2.0`, `>=1.0`) without a lockfile mean every install can pull a new release, including a compromised one

## Install-time code (TYPO-010)

- npm runs `preinstall`, `install` and `postinstall` of every dependency, and `prepare` for git dependencies. Most malicious npm packages act here
- In CI: `npm ci --ignore-scripts`, then run builds for the few packages that need them (`npm rebuild <pkg>`). pnpm and newer package managers can allow-list packages that may run scripts
- Python: building an sdist runs `setup.py` or the build backend. `pip install --only-binary :all:` refuses sdists where wheels exist

## Dependency confusion (TYPO-020, TYPO-021)

The attack: you use a private package `acme-utils` from an internal index. Someone publishes `acme-utils` with a higher version on the public registry. A resolver that checks both picks the public one.

npm:
- Put private packages under a scope you own (`@acme/utils`) and bind it in `.npmrc`:
  ```
  @acme:registry=https://npm.internal.example.test/
  ```
- Register your scope on npmjs.com so nobody else can publish under it

pip:
- `--extra-index-url` is the classic trap: pip treats all indexes as equal and takes the highest version
- Use one index: a proxy (Artifactory, Nexus, devpi and similar) that serves internal names first and mirrors PyPI for the rest
- Pin with `--require-hashes`, which also stops a same-version swap
- Register internal names on PyPI as placeholders if a proxy is not possible

## Typosquat triage (TYPO-001, TYPO-002, TYPO-003)

When a name looks like a popular package, check before acting:

1. Registry page: publisher, maintainers, repository link, first publish date, version history
2. Downloads: a "popular-sounding" package with a few hundred downloads is suspect
3. Repository: does the linked repo exist and does its code match what is published?
4. Install scripts and obfuscated code in the published tarball (`npm pack <name>` or `pip download --no-deps <name>`, then read it, in a sandbox, without installing)
5. Known-malicious feeds: OSV (osv.dev) lists many malicious packages under `MAL-` ids; GitHub advisories too

If it is malicious and was installed anywhere:
- Treat every secret on that machine or runner as leaked: rotate cloud keys, tokens, SSH keys, npm/PyPI tokens
- Look for persistence (new cron jobs, shell profile edits, unexpected workflows in repos the token could push to)
- Report it to the registry (npm: Report malware on the package page; PyPI: the Report project as malware link)

Common tricks: missing/extra/doubled letter (`reqests`, `numpyy`), swapped letters (`lodahs`), separator swaps on npm (`cross_env`), prefixes/suffixes (`python-flask`, `axios-js`), confusable Unicode, and scope impostors (`@typescript_eslint/parser` vs `@typescript-eslint/parser`).

## Vulnerability scanning

- `npm audit`, `pip-audit`, `osv-scanner`, GitHub Dependabot alerts
- Scan the lockfile, not just the manifest, since most vulnerable code is transitive
- Fix by upgrading the direct dependency first; use overrides/resolutions only as a stopgap

## SBOM and provenance

- SBOM: a list of every component in a build. Formats: CycloneDX and SPDX. Generators: `syft`, `cdxgen`, `npm sbom`
- Provenance: signed metadata saying which source and build produced an artifact
  - npm: `npm publish --provenance` from GitHub Actions or GitLab CI, verify with `npm audit signatures`
  - PyPI: Trusted Publishing (OIDC from CI, no long-lived token) and attestations
  - Containers: `cosign sign` / `cosign verify` (Sigstore)
- SLSA (slsa.dev) defines levels for build integrity; Build L2 and above require signed provenance from a hosted build platform

## Maintainer account hygiene

- 2FA on registry and GitHub accounts, hardware keys for maintainers of widely used packages
- Granular, short-lived publish tokens scoped to one package; prefer CI trusted publishing over tokens on laptops
- Review who has publish rights at least yearly
