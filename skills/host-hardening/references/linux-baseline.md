# Linux server baseline

A practical baseline in the spirit of the CIS benchmarks, for internet-facing servers and VMs. Section numbers are deliberately left out; benchmarks renumber between versions.

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
```

- Leave `Ciphers`, `MACs` and `KexAlgorithms` unset on OpenSSH 8.x+: the defaults are modern. If policy forces explicit lists, use `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr`, MACs ending in `-etm@openssh.com` with SHA-2, and `curve25519-sha256` / `sntrup761x25519-sha512@openssh.com` kex
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
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
```

Apply with `sudo sysctl --system`, check with `sysctl net.ipv4.ip_forward`.
Docker, Kubernetes and most VPN software need `ip_forward = 1`; record that as an accepted exception instead of breaking networking.

## 3. Accounts

- Only `root` has UID 0: `awk -F: '$3 == 0 {print $1}' /etc/passwd`
- No empty password fields: `sudo awk -F: '$2 == "" {print $1}' /etc/shadow`
- Lock unused accounts: `sudo passwd -l <user>`; give service accounts `/usr/sbin/nologin`
- Modern hashes: `ENCRYPT_METHOD YESCRYPT` (or `SHA512`) in `/etc/login.defs`. `$1$` (md5crypt) and 13-character DES hashes should not exist
- sudo: named users in a group (`%sudo` / `%wheel`), no `NOPASSWD: ALL` for humans, `Defaults use_pty` and `Defaults logfile=/var/log/sudo.log`

## 4. File permissions

- World-writable files: `sudo find / -xdev -type f -perm -0002 -not -path '/proc/*' 2>/dev/null`
- World-writable dirs without sticky bit: `sudo find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null`
- SUID/SGID inventory: `sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null`, then `dpkg -S <path>` / `rpm -qf <path>` for each unknown one. A SUID file that no package owns is suspicious
- Sensitive files: `/etc/shadow` 0640 root:shadow (or 0000 on RHEL family), `/etc/ssh/sshd_config` 0600, host keys 0600
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

## 6. Updates and services

- Automatic security updates: `unattended-upgrades` (Debian/Ubuntu) or `dnf-automatic` (RHEL family)
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
| SYS-* | the sysctl drop-in above, `sysctl --system` |
| FS-001/002 | `chmod o-w <path>` (or `+t` for shared dirs) |
| SUID-001 | identify the owner package; `chmod u-s` or remove |
| ACC-001..004 | remove/lock the account, reset with a modern hash |
| FW-001 | ufw / firewalld / nftables default deny |
