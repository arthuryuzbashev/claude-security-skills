---
name: host-hardening
description: Read-only security baseline audit for Linux servers and Macs you own or administer. Checks sshd_config (root login, password and keyboard-interactive auth, X11, MaxAuthTries, rhosts, user environment, weak ciphers/MACs/kex, SHA-1 RSA and DSA keys), kernel sysctls (forwarding, redirects, ASLR, ptrace, eBPF, link protection, IPv6 RA), world-writable files, unexpected SUID binaries, shadow and config file modes, sudoers (NOPASSWD ALL, !authenticate), extra UID 0 and passwordless accounts, end-of-life distro and automatic updates, host firewall, and on macOS FileVault, Gatekeeper, SIP, application firewall, automatic updates, screen lock, Remote Login and sharing services. Works on a live host, a mounted disk image or saved command output. Use whenever someone asks to harden or audit a server, VPS, EC2/droplet, laptop or Mac, review sshd_config, check "is my box secure", prepare for a CIS-style benchmark (CIS Ubuntu 24.04, CIS macOS) or SOC 2 endpoint control, or triage a host after a scare.
---

# Host Hardening

Audit a Linux server or a Mac against a practical baseline, without changing anything, and hand back the exact commands to fix what is off.

## When to use

- New VPS or cloud VM: "what should I lock down?"
- "Review my sshd_config", "is password SSH on?", "why can root log in?"
- A laptop or Mac fleet check: FileVault, firewall, Gatekeeper, screen lock
- Prepping for an audit that asks for CIS-style host baselines or endpoint controls
- After an incident scare: look for extra UID 0 users, odd SUID files, world-writable paths
- Auditing an offline disk image or a container root filesystem

## Ground rules

- Only audit machines the user owns or administers. Both scripts are read-only: they read files and run status queries, never setters
- Do not apply fixes yourself unless the user asks. When they do, change one thing at a time and keep a working session open (an SSH lockout from `PasswordAuthentication no` before keys work is the classic mistake)
- Never print password hashes, private keys or full config secrets. The scripts report that a field is empty or legacy, not its value
- Some macOS checks need admin rights. Report "needs sudo" as a gap, do not guess the value
- A config file is not the running state. sshd only reads its config on reload; sysctl values in `/etc/sysctl.d` apply at boot. Say which one you checked

## Workflow

1. Confirm the host, the access level (root, sudo, normal user) and whether this is live, an image or saved output
2. Linux: run `linux_audit.py` (as root for the shadow file and full SUID scan). For an image, `--root /mnt/image`; for another box, have the owner send `sysctl -a` output and the config files
3. macOS: run `macos_audit.py`. With `--output saved/` the raw outputs are kept for evidence; `--from-dir saved/` re-grades them anywhere
4. Read every high/critical finding in context (a router legitimately has `ip_forward=1`, a build Mac may need Remote Login)
5. Write the fix list in order of risk, with the exact command or config line from `references/linux-baseline.md` / `references/macos-baseline.md`
6. After fixes, re-run and compare. For sshd, `sshd -t` before reload and test a new session before closing the old one

Checklist before reporting:
- [ ] Said live, image or saved output, and the user it ran as (root sees shadow, sudoers and file modes)
- [ ] Every `checks_skipped` entry listed as not checked
- [ ] UPD-001 run with the right date (`--today` for an old image) and the EOL table date noted
- [ ] Accepted exceptions written down (router `ip_forward`, CI runner NOPASSWD), not silently dropped

## Tools

### linux_audit.py

Reads everything under `--root` (default `/`), so tests and offline images use the same code.

```bash
sudo python3 scripts/linux_audit.py
python3 scripts/linux_audit.py --root examples/weak_root --sysctl-file examples/sysctl_weak.txt
python3 scripts/linux_audit.py --root /mnt/image --scan-path /etc --scan-path /opt --json
python3 scripts/linux_audit.py --no-file-scan --fail-on medium
python3 scripts/linux_audit.py --root examples/hardened_root --today 2026-11-19
```

Checks:
- sshd (SSH-001..012): `PermitRootLogin yes`, `PermitEmptyPasswords yes`, password auth on (explicit or default), X11 forwarding, `MaxAuthTries` above 4, weak Ciphers/MACs/KexAlgorithms, passwords still reachable through `KbdInteractiveAuthentication` + `UsePAM yes` (009), host-based or rhosts trust (010), `PermitUserEnvironment` (011), `ssh-rsa` (SHA-1) or `ssh-dss` in the key algorithm lists (012). Follows `Include` drop-ins with sshd's first-value-wins rule and stops at the first `Match` block; the finding's `location` names the file that set the value
- sysctl (SYS-001..021): ip_forward, rp_filter, IPv4/IPv6 accept_redirects, send_redirects, accept_source_route, tcp_syncookies, randomize_va_space, kptr_restrict, dmesg_restrict, suid_dumpable, then yama.ptrace_scope, protected_symlinks/hardlinks, unprivileged_bpf_disabled, secure_redirects, log_martians, icmp_echo_ignore_broadcasts, IPv6 forwarding, accept_source_route and accept_ra (012..021). From `<root>/proc/sys` or `--sysctl-file`; absent keys are skipped
- files (FS-001/002, SUID-001): world-writable files, world-writable dirs without the sticky bit, SUID binaries not on the known-good list (high when in /tmp, /home and similar). Default paths: /etc, /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin. `--allow-suid name` to accept more
- accounts (ACC-001..004): extra UID 0 accounts, empty password field in passwd or shadow, md5crypt/DES hashes. `--shadow` takes a copy of the shadow file
- permissions (FS-003/004): shadow, gshadow or SSH host keys readable by others; passwd, group, sshd_config, sudoers, crontab or their drop-ins writable by group or others. Only root-owned files are judged, so a copied tree in a home folder shows as skipped
- sudo (SUDO-001..003): `NOPASSWD: ALL`, `Defaults !authenticate`, `!use_pty`, `!env_reset`, `timestamp_timeout` negative or above 15. Reads `/etc/sudoers` and `/etc/sudoers.d/*` (names with a dot or `~` are skipped, as sudo does)
- updates (UPD-001/002): distro past end of support from `/etc/os-release` (high when nothing is left, medium when only paid ESM/ELS remains; Ubuntu, Debian, CentOS, RHEL, dates in the reference), and no unattended-upgrades or dnf-automatic timer. `--today YYYY-MM-DD` sets the date
- firewall (FW-001): an enabled ufw, firewalld or nftables service, or saved iptables rules. Config check only

JSON keys: `root`, `checks_run`, `checks_skipped` (no data, for example no sshd_config), `firewall`, `findings`.

### macos_audit.py

Runs read-only status commands: `fdesetup status`, `spctl --status`, `csrutil status`, `socketfilterfw --getglobalstate` / `--getstealthmode`, `defaults read` of the SoftwareUpdate and loginwindow prefs, `sysadminctl -screenLock status`, `systemsetup -getremotelogin`, `launchctl print-disabled system`.

```bash
python3 scripts/macos_audit.py
python3 scripts/macos_audit.py --output ~/audit-$(hostname -s)/
python3 scripts/macos_audit.py --from-dir examples/macos_weak --json
```

Checks: FileVault (MAC-001), Gatekeeper (MAC-002), SIP (MAC-003), firewall and stealth mode (MAC-004/005), update checks, security responses, config data, auto download, auto install of macOS updates (MAC-006, 013..016), screen lock (MAC-007), Remote Login (MAC-008), Screen Sharing / File Sharing / Remote Apple Events (MAC-009, 011, 012), guest account (MAC-010).
Each check gets a status: `pass`, `fail`, `needs sudo`, `unknown` or `not collected`. `--from-dir` expects `<check>.txt` files named after the check keys (`filevault`, `gatekeeper`, `sip`, `firewall`, `stealth`, `autoupdate`, `screenlock`, `remotelogin`, `sharing`, `guest`).

JSON keys: `source`, `checks` (check, label, status, detail), `findings`.

Both tools: `--json`, exit `0` clean, `1` a finding at or above `--fail-on` (default `high`), `2` bad input (missing root dir, unreadable file, live macOS mode on another OS).

## Output

Start with one line: host, OS, how it was checked (live as root, image, saved output) and the count of high/critical findings. Then:

| Severity | ID | Issue | Fix (command or config line) |
|---|---|---|---|

Then list what was not checked (needs sudo, no shadow access, cloud firewall not visible, running state vs config) so a clean result is not over-read.

## References

- `references/linux-baseline.md` the Linux baseline with exact config lines, sysctl drop-in, sshd hardening block, and safe rollout order for SSH changes
- `references/macos-baseline.md` the macOS baseline, the command behind each check, MDM profile keys, and what needs admin rights
