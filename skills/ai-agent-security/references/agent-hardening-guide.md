# Agent hardening guide

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

## 3. Hooks

Hooks run shell commands automatically on events like `PreToolUse`, `PostToolUse`, `UserPromptSubmit` and `Stop`, with your user's permissions. They receive JSON on stdin that includes tool inputs (file paths, commands, content).

- Point hooks at local, reviewed scripts in the repo (`./scripts/format-changed.sh`), never `curl ... | sh`
- Do not post hook input to remote services; it can contain secrets and file content
- Review hooks in any repo before trusting its `.claude/settings.json`
- A `PreToolUse` hook can block calls (for example, refuse any Bash command that touches `.env` or `~/.ssh`): a useful extra guard

## 4. MCP server vetting

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
- Remove servers you no longer use

## 5. Untrusted content

- Scan inputs with `prompt_injection_scan.py` before giving them to an agent that has tools
- Strip invisible Unicode (zero-width, U+E0000 tag block, bidi controls) and hidden HTML at ingestion
- Render agent output without remote images, or allow-list image hosts, so a reply cannot leak data through an image URL
- In RAG, keep per-user access control at retrieval time, and record the source of every chunk

## 6. Isolation

- Run agents that read untrusted content in a container, VM or devcontainer with only the project mounted
- Restrict outbound network to the hosts the task needs (proxy or firewall allow-list)
- Claude Code has a sandboxed Bash mode (filesystem and network isolation) on supported platforms; turn it on when you allow broad shell use
- Separate credentials: the agent gets its own scoped tokens, not your personal admin keys

## 7. If an agent was hijacked

1. Stop the session and revoke its tool access
2. Rotate every credential the agent could reach (env vars, config files, tokens in MCP configs, cloud CLIs logged in on that machine)
3. Review what it did: transcripts, shell history, git log and pushes, outbound requests, files changed
4. Find the source: which file, page or tool result carried the instructions. Scan it and similar inputs
5. Remove the leg that made it possible (section 1) before turning the agent back on
