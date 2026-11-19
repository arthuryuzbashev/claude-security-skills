# Linux server baseline

A practical baseline in the spirit of the CIS benchmarks (current at the last check, 2026-11-19: CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0), for internet-facing servers and VMs. Section numbers are deliberately left out; benchmarks renumber between versions.

Contents: 1 SSH, 2 kernel parameters, 3 accounts and sudo, 4 file permissions, 5 firewall, 6 updates and end of life, 7 logging, finding to fix map.

## 1. SSH

Put overrides in a drop-in that sorts first, since sshd keeps the first value it reads and most distros `Include /etc/ssh/sshd_config.d/*.conf` at the top of the main file:

```
# /etc/ssh/sshd_config.d/00-hardening.conf
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowGroups ssh-users
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
```

- `KbdInteractiveAuthentication no` matters: with `UsePAM yes` (Debian, Ubuntu and RHEL ship it) PAM can still ask for the account password even after `PasswordAuthentication no` (SSH-009). Keep it on only when PAM runs a real second factor
- OpenSSH 8.8 turned off `ssh-rsa` (SHA-1) signatures and OpenSSH 10.0 (April 2025) removed DSA entirely and made the hybrid post-quantum `mlkem768x25519-sha256` the default key exchange. A `+ssh-rsa` or `ssh-dss` line (SSH-012) is a leftover for an old client; fix the client instead
- Ubuntu 22.10 and later (24.04 included) start sshd through `ssh.socket`. `ListenAddress` and `Port` changes need `systemctl daemon-reload && systemctl restart ssh.socket`, not only a reload of `ssh.service`
- Leave `Ciphers`, `MACs`, `KexAlgorithms` and the key algorithm lists unset on OpenSSH 8.x+: the defaults are modern. If policy forces explicit lists, use `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr`, MACs ending in `-etm@openssh.com` with SHA-2, and `mlkem768x25519-sha256` (OpenSSH 9.9+) / `sntrup761x25519-sha512@openssh.com` / `curve25519-sha256` kex
- Watch for cloud-init's `50-cloud-init.conf` setting `PasswordAuthentication yes`
- Show the effective config: `sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|maxauthtries'`

Safe rollout:
1. Confirm a key login works for every admin (`ssh -o PreferredAuthentications=publickey host`)
2. `sudo sshd -t` (syntax check)
3. `sudo systemctl reload ssh` (or `sshd`)
4. Open a new session before closing the old one

## 2. Kernel parameters

```
# /etc/sysctl.d/60-hardening.conf
net.ipv4.ip_forward = 0                       # 1 only on routers, VPN gateways, container hosts
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.forwarding = 0              # same exception as ip_forward
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0               # servers with static addresses only; SLAAC clients need 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1                  # 2 = admin only, 3 = never (breaks debuggers)
kernel.unprivileged_bpf_disabled = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.suid_dumpable = 0
```

Apply with `sudo sysctl --system`, check with `sysctl net.ipv4.ip_forward`.
Docker, Kubernetes and most VPN software need `ip_forward = 1`; record that as an accepted exception instead of breaking networking.

## 3. Accounts and sudo

- Only `root` has UID 0: `awk -F: '$3 == 0 {print $1}' /etc/passwd`
- No empty password fields: `sudo awk -F: '$2 == "" {print $1}' /etc/shadow`
- Lock unused accounts: `sudo passwd -l <user>`; give service accounts `/usr/sbin/nologin`
- Modern hashes: `ENCRYPT_METHOD YESCRYPT` (or `SHA512`) in `/etc/login.defs`. `$1$` (md5crypt) and 13-character DES hashes should not exist
- sudo: named users in a group (`%sudo` / `%wheel`), no `NOPASSWD: ALL` for humans (SUDO-001; cloud images put one in `/etc/sudoers.d/90-cloud-init-users`), never `Defaults !authenticate` (SUDO-002), keep `use_pty` and `env_reset` and a `timestamp_timeout` of 15 minutes or less (SUDO-003), and `Defaults logfile=/var/log/sudo.log`. sudo 1.9.14+ turns `use_pty` on by default, so only an explicit `!use_pty` is flagged
- Edit with `visudo` (or `visudo -cf <file>` to check a drop-in); a syntax error locks everyone out of sudo

## 4. File permissions

- World-writable files: `sudo find / -xdev -type f -perm -0002 -not -path '/proc/*' 2>/dev/null`
- World-writable dirs without sticky bit: `sudo find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null`
- SUID/SGID inventory: `sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null`, then `dpkg -S <path>` / `rpm -qf <path>` for each unknown one. A SUID file that no package owns is suspicious
- Sensitive files (FS-003/004): `/etc/shadow` and `/etc/gshadow` 0640 root:shadow (or 0000 on RHEL family), host private keys 0600 root, `/etc/ssh/sshd_config` 0600 (0644 is common and fine), `/etc/sudoers` and drop-ins 0440, `/etc/passwd` and `/etc/group` 0644, `/etc/crontab` 0600 or 0644. None of them writable by group or others
- Mount `/tmp` and `/dev/shm` with `nodev,nosuid,noexec` where the software allows

## 5. Firewall

Default deny inbound, allow only what the host serves.

ufw (Debian/Ubuntu):
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 443/tcp
sudo ufw enable
```

firewalld (RHEL family): `sudo systemctl enable --now firewalld`, then `firewall-cmd --permanent --add-service=https && firewall-cmd --reload`.

Cloud security groups help but do not replace a host firewall: they do not cover traffic from inside the same network.

## 6. Updates, end of life and services

- Automatic security updates (UPD-002): `unattended-upgrades` with `APT::Periodic::Unattended-Upgrade "1";` in `/etc/apt/apt.conf.d/20auto-upgrades` (Debian/Ubuntu), or `dnf-automatic.timer` with `upgrade_type = security` (RHEL family). Fleets patched by config management can accept UPD-002 as an exception
- End of life (UPD-001). The script's table, verified 2026-11-19 against endoflife.date (re-check before relying on it):

| Release | Standard support ends | Paid extended support ends |
|---|---|---|
| Ubuntu 18.04 / 20.04 / 22.04 / 24.04 / 26.04 | 2023-05-31 / 2025-05-31 / 2027-06-01 / 2029-05-31 / 2031-05-29 | 2028-04-26 / 2030-04-23 / 2032-04-21 / 2034-04-25 / 2036-04-23 (Ubuntu Pro ESM) |
| Ubuntu interim (24.10 / 25.04 / 25.10) | 2025-07-10 / 2026-01-17 / 2026-07-01 | none |
| Debian 10 / 11 / 12 / 13 | 2024-06-30 / 2026-08-31 / 2028-06-30 / 2030-06-30 | 2029 / 2031 / 2033 / 2035 (Freexian ELS) |
| RHEL 7 / 8 / 9 / 10 | 2024-06-30 / 2029-05-31 / 2032-05-31 / 2035-05-31 | 2029 / 2033 / 2036 / 2039 (ELS add-on) |
| CentOS 7 / 8 (Linux, not Stream) | 2024-06-30 / 2021-12-31 | none |

Medium means fixes still exist but only with a paid subscription; confirm it is active (`pro status` on Ubuntu) or plan the upgrade. Rocky, Alma and others are not in the table yet; check them by hand.
- `ss -tulpn` and stop or bind to localhost anything that should not be public (databases, Redis, admin panels)
- Remove compilers and network tools from production images where practical

## 7. Logging

- `journald` persistent (`Storage=persistent`) or rsyslog shipping off-host
- `auditd` with rules for `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `sshd_config` changes
- Time sync on (`timedatectl`), or log correlation falls apart

## Finding to fix map

| Finding | Fix |
|---|---|
| SSH-001 | `PermitRootLogin no` |
| SSH-002 | `PermitEmptyPasswords no` |
| SSH-003 | `PasswordAuthentication no` after keys work |
| SSH-004/005 | `X11Forwarding no`, `MaxAuthTries 4` |
| SSH-006..008 | delete the explicit algorithm lines or use the lists above |
| SSH-009 | `KbdInteractiveAuthentication no` |
| SSH-010 | `HostbasedAuthentication no`, `IgnoreRhosts yes` |
| SSH-011 | `PermitUserEnvironment no` |
| SSH-012 | drop `ssh-rsa` / `ssh-dss` from the key algorithm lists, replace DSA keys with ed25519 |
| SYS-* | the sysctl drop-in above, `sysctl --system` |
| FS-001/002 | `chmod o-w <path>` (or `+t` for shared dirs) |
| FS-003/004 | the modes in section 4 |
| SUID-001 | identify the owner package; `chmod u-s` or remove |
| ACC-001..004 | remove/lock the account, reset with a modern hash |
| SUDO-001..003 | `visudo`: drop NOPASSWD ALL, !authenticate, !use_pty, !env_reset, long timeouts |
| UPD-001 | upgrade the release, or confirm ESM/ELS is active |
| UPD-002 | unattended-upgrades or dnf-automatic |
| FW-001 | ufw / firewalld / nftables default deny |
