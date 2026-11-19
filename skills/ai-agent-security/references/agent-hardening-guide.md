# Agent hardening guide

Contents: 1 three-leg rule; 2 Claude Code settings; 3 sandbox; 4 hooks; 5 MCP server vetting; 6 untrusted content; 7 isolation; 8 if an agent was hijacked.
Claude Code facts below were checked against code.claude.com/docs (settings reference, hooks) on 2026-11-19. Settings change often; re-check the key names there.

## 1. The three-leg rule

An agent becomes an exfiltration tool when it has all three:

1. Untrusted input (web pages, issues, emails, third-party files, tool results)
2. Access to private data (source code, secrets, mail, customer data)
3. A way to send data out (web fetch, rendered images or links, email, git push, any network tool, an MCP server that talks to the internet)

You cannot reliably stop the model from obeying injected text. You can remove a leg: read untrusted content in a session with no secrets, or with no outbound tools, or require approval for every outbound action.

## 2. Claude Code settings

Files, from highest to lowest precedence: managed settings (set by an admin), command-line arguments, `.claude/settings.local.json` (personal, git-ignored), `.claude/settings.json` (shared, committed), `~/.claude/settings.json` (user). Deny rules win over ask and allow rules.

Hardened project settings:

```json
{
  "permissions": {
    "defaultMode": "default",
    "allow": [
      "Bash(npm run test:*)",
      "Bash(npm run lint)",
      "Bash(git diff:*)",
      "Bash(git status)",
      "WebFetch(domain:docs.example.test)"
    ],
    "ask": ["Bash(git push:*)"],
    "deny": [
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(./secrets/**)",
      "Bash(curl:*)",
      "Bash(wget:*)"
    ]
  },
  "enabledMcpjsonServers": ["github"]
}
```

Notes:
- `defaultMode` values: `default`, `acceptEdits`, `plan`, `bypassPermissions`. Use `bypassPermissions` only inside a disposable container or VM with no credentials
- Allow rules match prefixes: `Bash(npm run test:*)` allows `npm run test` with any arguments, nothing else. `Bash(curl:*)` allows every curl call, which is an open door for data
- Shell operators are understood: an allow for `npm test` does not cover `npm test && curl ...`. Still, do not rely on clever patterns to restrict network tools; deny them or sandbox
- Read and Edit deny rules apply to Claude's file tools. A shell command like `cat .env` is a Bash call, so keep Bash narrow too, or use the sandbox
- `additionalDirectories` widens file access; never add your home folder
- Keep `enableAllProjectMcpServers` off and approve servers by name (`enabledMcpjsonServers`). A cloned repo's `.mcp.json` is untrusted until you read it
- Organizations can push managed settings and set `permissions.disableBypassPermissionsMode` to `"disable"`
- Since Claude Code 2.1.257, `defaultMode` values `bypassPermissions` and `auto` only take effect from user or managed settings (or `--permission-mode`), not from a repo file. Older versions applied them from any file, so a hostile repo still matters for anyone on an old build
- `skipDangerousModePermissionPrompt: true` skips the confirmation before bypass mode. It applies from user, local and managed settings; an untrusted repo cannot set it for you. Leave it unset
- A repo's `permissions.allow`, `additionalDirectories` and most `env` values wait until you trust the folder; `deny` and `ask` rules apply at once. In `-p` (headless) mode there is no trust dialog, so project `env` applies at start: review a repo's `.claude/settings.json` before running it headless in CI
- `env` redirects: `ANTHROPIC_BASE_URL`, provider `*_BASE_URL` variables and `HTTPS_PROXY` send prompts, code and the API key to another host. CVE-2026-21852 (CVSS 7.5, fixed in Claude Code 2.0.65): a project file that set `ANTHROPIC_BASE_URL` made Claude Code send API requests, with the key, before the trust prompt. Keep gateways and proxies in user or managed settings
- `NODE_TLS_REJECT_UNAUTHORIZED=0` in any `env` block turns off certificate checks for everything that environment runs. Add a corporate CA with `NODE_EXTRA_CA_CERTS` instead

## 3. Sandbox

Sandboxed Bash (`sandbox.enabled`) isolates the commands Claude runs at the OS level (Seatbelt on macOS, bubblewrap on Linux and WSL2). It is the strongest local control after narrow permissions, and every setting that widens it is a way around it.

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "network": { "allowedDomains": ["github.com", "registry.npmjs.org"] },
    "filesystem": { "denyRead": ["~/.aws/credentials", "~/.ssh"] }
  }
}
```

- `allowUnsandboxedCommands: false` stops Claude from retrying a blocked command outside the sandbox (strict mode)
- `failIfUnavailable: true` makes Claude Code refuse to start instead of running unsandboxed when the sandbox cannot start
- Never allow `"*"` in `network.allowedDomains`; list hosts, optionally with a port (`api.example.com:443`)
- `network.allowUnixSockets` with `/var/run/docker.sock` hands out the Docker daemon, which means root on the host. `allowAllUnixSockets` opens every socket
- Keep `filesystem.allowWrite` to build folders; write access to `~`, shell rc files, `~/.ssh` or `~/.claude` lets one command plant code that runs later
- `excludedCommands` run outside the sandbox. Exclude one exact tool (`"docker *"`), never a shell or interpreter wildcard
- `enableWeakerNestedSandbox` is for use inside an unprivileged container that is itself the boundary

## 4. Hooks

Hooks run automatically on events like `PreToolUse`, `PostToolUse`, `UserPromptSubmit` and `Stop`, with your user's permissions. They receive JSON that includes tool inputs (file paths, commands, content). Types: `command` (shell or exec form with `args`), `http` (POSTs the event JSON to `url`), `mcp_tool` and prompt or agent hooks.

- Point command hooks at local, reviewed scripts in the repo (`./scripts/format-changed.sh`), never `curl ... | sh`
- Do not post hook input to remote services; it can contain secrets and file content. HTTP hooks to anything but loopback deserve the same review as a network call
- HTTP hook headers read env vars only when listed in the hook's `allowedEnvVars`: use `"Authorization": "Bearer $MY_TOKEN"` with `"allowedEnvVars": ["MY_TOKEN"]`, never an inline token
- Admins can pin hook targets with `allowedHttpHookUrls` and `httpHookAllowedEnvVars`, and run only their own hooks with `allowManagedHooksOnly`
- `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper` and `statusLine` are commands too: review them like hooks
- Review hooks in any repo before trusting its `.claude/settings.json`
- A `PreToolUse` hook can block calls (for example, refuse any Bash command that touches `.env` or `~/.ssh`): a useful extra guard

## 5. MCP server vetting

Before adding a server:

- Source: official vendor or a maintained project with a real repository? Read the code or at least the tool list
- Pin the version: `"args": ["-y", "@scope/server@1.4.2"]`, `uvx package==1.4.2`, or a container image by digest. `npx -y package` runs whatever is latest at every start
- Credentials: smallest scope possible (read-only token, one repo, one project). Reference them from the environment, never inline:
  ```json
  "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" }
  ```
  Claude Code expands `${VAR}` (and `${VAR:-default}`) in `.mcp.json`; VS Code uses `inputs` with `${input:name}`
- Transport: https for remote servers; plain http only on loopback
- Containers: no `--privileged`, no Docker socket, mount only the folders needed, read-only where possible
- Tool descriptions are prompt input too. A server can change its tool descriptions after you approved it; prefer pinned versions and re-review on update
- Start commands: a server started as `bash -c "curl ... | sh"` runs whatever that URL serves at every start. Install once from a pinned release
- Remove servers you no longer use

From the MCP specification's security best practices (spec version 2025-11-25):

- Token passthrough is forbidden: a server must only accept tokens issued for it (audience check) and must not forward the client's token to upstream APIs
- Confused deputy: a proxy server that uses a static client ID with a third-party authorization server needs per-client consent before forwarding to it
- SSRF: clients fetching OAuth metadata URLs from a server should block private, loopback and link-local addresses and require https
- Session hijacking: session IDs must be random and never used for authentication; bind them to the user
- Local server compromise: clients should show the full startup command and ask for consent before running a new local server, and run it with least privilege
- Scope minimization: request the smallest scopes first and step up only when a tool needs more

## 6. Untrusted content

- Scan inputs with `prompt_injection_scan.py` before giving them to an agent that has tools
- Strip invisible Unicode (zero-width, U+E0000 tag block, bidi controls), terminal escape sequences and hidden HTML at ingestion
- Tool descriptions and tool results are untrusted content. A description that asks the model to read `~/.ssh/id_rsa` or `mcp.json` and pass it in an argument is tool poisoning (PI-009); a server can also change its descriptions after approval
- Render agent output without remote images, or allow-list image hosts, so a reply cannot leak data through an image URL
- In RAG, keep per-user access control at retrieval time, and record the source of every chunk

## 7. Isolation

- Run agents that read untrusted content in a container, VM or devcontainer with only the project mounted
- Restrict outbound network to the hosts the task needs (proxy or firewall allow-list)
- Claude Code has a sandboxed Bash mode (filesystem and network isolation) on supported platforms; turn it on when you allow broad shell use
- Separate credentials: the agent gets its own scoped tokens, not your personal admin keys

## 8. If an agent was hijacked

1. Stop the session and revoke its tool access
2. Rotate every credential the agent could reach (env vars, config files, tokens in MCP configs, cloud CLIs logged in on that machine)
3. Review what it did: transcripts, shell history, git log and pushes, outbound requests, files changed
4. Find the source: which file, page or tool result carried the instructions. Scan it and similar inputs
5. Remove the leg that made it possible (section 1) before turning the agent back on
