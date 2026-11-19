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
- Cooldown: most hijacked releases in 2025 were found and pulled within hours to days. A minimum release age before adoption (Renovate `minimumReleaseAge`, Dependabot `cooldown`, pnpm `minimumReleaseAge`, uv `--exclude-newer`) keeps a fresh malicious version out of your lockfile
- `typosquat_check.py` reads `package-lock.json` and `npm-shrinkwrap.json` and flags exact versions from its known-malicious list (TYPO-012)

## Install-time code (TYPO-010)

- npm runs `preinstall`, `install` and `postinstall` of every dependency, and `prepare` for git dependencies. Most malicious npm packages act here
- In CI: `npm ci --ignore-scripts`, then run builds for the few packages that need them (`npm rebuild <pkg>`). pnpm and newer package managers can allow-list packages that may run scripts
- Python: building an sdist runs `setup.py` or the build backend. `pip install --only-binary :all:` refuses sdists where wheels exist
- TYPO-011 (critical): a `preinstall` or `postinstall` that runs `setup_bun.js` or `bun_environment.js`, the Shai-Hulud 2.0 loader. Treat the machine as compromised, not just the package

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

## Known compromised releases (TYPO-012)

`typosquat_check.py` carries a short offline list of versions that were published by attackers. It is a quick "were we hit" check for headline incidents, not a malware feed; OSV `MAL-` ids are the full source.

| Incident | Date | Packages | Source |
|---|---|---|---|
| chalk/debug maintainer phishing | 2025-09-08 | 18 packages incl. `chalk` 5.6.1, `debug` 4.4.2, `ansi-styles` 6.2.2, `strip-ansi` 7.1.1, `color-convert` 3.1.1, `wrap-ansi` 9.0.1 | StepSecurity, npm advisories |
| Shai-Hulud | 2025-09-15 | started with `@ctrl/tinycolor` 4.1.1 and 4.1.2, then hundreds more | OSV MAL-2025-47141, CISA alert 2025-09-23 |
| Shai-Hulud 2.0 | 2025-11-24 | hundreds of packages (about 800 in public counts), `setup_bun.js` preinstall | Microsoft (2025-12-09), StepSecurity |
| ultralytics (PyPI) | 2024-12 | 8.3.41, 8.3.42, 8.3.45, 8.3.46 | PyPI blog 2024-12-11 |

For worm incidents the list cannot hold every package. Search lockfiles for the hook file names and run `osv-scanner` against the lockfile.

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

- 2FA on registry and GitHub accounts, hardware keys (WebAuthn) for maintainers of widely used packages. The 2025 chalk/debug compromise started with a phishing mail from a look-alike `npmjs.help` domain that captured a TOTP code
- npm changed tokens in late 2025: classic tokens can no longer be created (2025-11-05) and were revoked (changelog 2025-12-09); granular tokens with write access default to 7 days and max out at 90. Any CI that still uses an `NPM_TOKEN` secret needs a granular token or, better, trusted publishing
- Trusted publishing (OIDC from GitHub Actions or GitLab CI) exists on both npm and PyPI: no long-lived token to steal, and provenance comes for free
- Review who has publish rights at least yearly
- Review who has publish rights at least yearly
