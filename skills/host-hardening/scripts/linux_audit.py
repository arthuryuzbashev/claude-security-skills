#!/usr/bin/env python3
"""Read-only Linux baseline audit: sshd, kernel sysctls, file permissions, accounts, firewall.

Every check reads files under --root (default /), so the same code can audit a live host,
a mounted disk image or a fake tree in tests. Nothing is changed, nothing is executed.

Usage:
  linux_audit.py                                   # this host, read-only
  linux_audit.py --root /mnt/image --json          # an offline disk image
  linux_audit.py --sysctl-file sysctl.txt          # use saved `sysctl -a` output
  linux_audit.py --shadow /tmp/shadow.copy --scan-path /etc --scan-path /opt
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import stat
import sys
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

SSHD_DEFAULTS = {  # OpenSSH 7.0+ defaults when a keyword is absent
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "x11forwarding": "no",
    "maxauthtries": "6",
}
WEAK_SSH = {
    "ciphers": {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc",
                "arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se"},
    "macs": {"hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
             "hmac-sha1", "hmac-sha1-96", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
             "umac-64@openssh.com", "umac-64-etm@openssh.com", "hmac-ripemd160", "hmac-ripemd160@openssh.com"},
    "kexalgorithms": {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                      "diffie-hellman-group-exchange-sha1"},
}

# (id, key, wanted values, severity if not wanted, title, why, fix)
SYSCTL_RULES = [
    ("SYS-001", "net.ipv4.ip_forward", {"0"}, "medium", "IPv4 forwarding is on",
     "The host routes packets between interfaces. Only routers, VPN gateways and container hosts need this.",
     "sysctl -w net.ipv4.ip_forward=0 (persist in /etc/sysctl.d/), unless this box is a router or runs containers"),
    ("SYS-002", "net.ipv4.conf.all.rp_filter", {"1", "2"}, "low", "Reverse path filtering is off",
     "Spoofed source addresses are accepted on every interface.",
     "net.ipv4.conf.all.rp_filter = 1 (strict) or 2 (loose, for asymmetric routing)"),
    ("SYS-003", "net.ipv4.conf.all.accept_redirects", {"0"}, "medium", "ICMP redirects accepted (IPv4)",
     "A host on the LAN can rewrite this machine's routes with forged redirects.",
     "net.ipv4.conf.all.accept_redirects = 0 and net.ipv4.conf.default.accept_redirects = 0"),
    ("SYS-004", "net.ipv6.conf.all.accept_redirects", {"0"}, "medium", "ICMP redirects accepted (IPv6)",
     "Same as IPv4: forged redirects can reroute traffic.",
     "net.ipv6.conf.all.accept_redirects = 0"),
    ("SYS-005", "net.ipv4.conf.all.send_redirects", {"0"}, "low", "Host sends ICMP redirects",
     "Only routers should send redirects.",
     "net.ipv4.conf.all.send_redirects = 0"),
    ("SYS-006", "net.ipv4.conf.all.accept_source_route", {"0"}, "medium", "Source-routed packets accepted",
     "The sender chooses the route, which helps bypass network filtering.",
     "net.ipv4.conf.all.accept_source_route = 0"),
    ("SYS-007", "net.ipv4.tcp_syncookies", {"1"}, "low", "TCP SYN cookies off",
     "The host is easier to knock over with a SYN flood.",
     "net.ipv4.tcp_syncookies = 1"),
    ("SYS-008", "kernel.randomize_va_space", {"2"}, None, "ASLR is not fully on",
     "Memory layout randomization makes memory-corruption exploits much harder.",
     "kernel.randomize_va_space = 2"),
    ("SYS-009", "kernel.kptr_restrict", {"1", "2"}, "low", "Kernel pointers visible to users",
     "Leaked kernel addresses help defeat KASLR in local exploits.",
     "kernel.kptr_restrict = 1 (or 2)"),
    ("SYS-010", "kernel.dmesg_restrict", {"1"}, "low", "Any user can read the kernel log",
     "dmesg can leak addresses and hardware details useful to local attackers.",
     "kernel.dmesg_restrict = 1"),
    ("SYS-011", "fs.suid_dumpable", {"0"}, "low", "SUID programs may dump core",
     "Core dumps of privileged programs can contain secrets such as password hashes.",
     "fs.suid_dumpable = 0"),
]

KNOWN_SUID = {
    "passwd", "sudo", "su", "mount", "umount", "chsh", "chfn", "newgrp", "gpasswd", "pkexec", "ping", "ping6",
    "fusermount", "fusermount3", "newuidmap", "newgidmap", "dbus-daemon-launch-helper", "ssh-keysign",
    "polkit-agent-helper-1", "Xorg.wrap", "unix_chkpwd", "pam_timestamp_check", "crontab", "at", "staprun",
    "chage", "expiry", "write", "wall", "ssh-agent", "mount.nfs", "mount.cifs", "userhelper", "snap-confine",
    "chrome-sandbox", "traceroute6.iputils", "sg", "doas",
}
SYSTEM_PREFIXES = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib", "/usr/libexec/", "/usr/local/bin/",
                   "/usr/local/sbin/", "/snap/", "/opt/google/")
RISKY_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/")
DEFAULT_SCAN = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]
MAX_FILE_FINDINGS = 25


def finding(fid, severity, title, detail, fix, location=None):
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def rooted(root: str, path: str) -> str:
    return os.path.join(root, path.lstrip("/"))


def read_text(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


# ---------------------------------------------------------------- sshd

def parse_sshd(root: str, path: str = "/etc/ssh/sshd_config", _seen=None,
               sources: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return effective global settings (lowercase keys). First value wins, like sshd; Match blocks are skipped.

    If `sources` is given it is filled with keyword -> file that set it.
    """
    seen = _seen if _seen is not None else set()
    sources = sources if sources is not None else {}
    settings: Dict[str, str] = {}
    text = read_text(rooted(root, path))
    if text is None or path in seen:
        return settings
    seen.add(path)
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.replace("=", " ", 1).split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if key == "match":
            break  # everything after Match is conditional
        if key == "include":
            for pattern in value.split():
                if not pattern.startswith("/"):
                    pattern = "/etc/ssh/" + pattern
                for inc in sorted(glob.glob(rooted(root, pattern))):
                    rel = "/" + os.path.relpath(inc, root) if root not in ("", "/") else inc
                    for k, v in parse_sshd(root, rel, seen, sources).items():
                        settings.setdefault(k, v)
            continue
        if key not in settings:
            settings[key] = value
            sources.setdefault(key, path)
    return settings


def check_sshd(root: str) -> Tuple[List[Dict], bool]:
    if read_text(rooted(root, "/etc/ssh/sshd_config")) is None:
        return [], False
    sources: Dict[str, str] = {}
    cfg = parse_sshd(root, sources=sources)
    eff = dict(SSHD_DEFAULTS)
    eff.update(cfg)
    out = []

    def where(key):
        return sources.get(key, "/etc/ssh/sshd_config")

    root_login = eff["permitrootlogin"].lower()
    if root_login == "yes":
        out.append(finding("SSH-001", "high", "Root login over SSH allowed (PermitRootLogin yes)",
                           "PermitRootLogin yes lets attackers brute-force the one account that owns everything.",
                           "PermitRootLogin no (or prohibit-password if root keys are truly needed)", where("permitrootlogin")))
    if eff["permitemptypasswords"].lower() == "yes":
        out.append(finding("SSH-002", "critical", "SSH accepts empty passwords",
                           "Any account without a password is open to the network.",
                           "PermitEmptyPasswords no", where("permitemptypasswords")))
    if eff["passwordauthentication"].lower() == "yes":
        how = (f"set to yes in {where('passwordauthentication')}" if "passwordauthentication" in cfg
               else "not set, and the default is yes")
        out.append(finding("SSH-003", "medium", "SSH password logins allowed",
                           f"PasswordAuthentication is {how}. Passwords can be guessed or phished; keys cannot.",
                           "PasswordAuthentication no (after confirming every admin has a working key). "
                           "Drop-ins in sshd_config.d are read first when Include sits at the top, so fix it there.",
                           where("passwordauthentication")))
    if eff["x11forwarding"].lower() == "yes":
        out.append(finding("SSH-004", "low", "X11 forwarding enabled",
                           "A compromised server can reach back into the client's X session.",
                           "X11Forwarding no", where("x11forwarding")))
    try:
        tries = int(eff["maxauthtries"])
    except ValueError:
        tries = 6
    if tries > 4:
        out.append(finding("SSH-005", "low", f"MaxAuthTries is {tries}",
                           "More attempts per connection make online guessing cheaper.",
                           "MaxAuthTries 4 (or lower)", where("maxauthtries")))
    for key, rid, label in (("ciphers", "SSH-006", "ciphers"), ("macs", "SSH-007", "MACs"),
                            ("kexalgorithms", "SSH-008", "key exchange")):
        if key not in cfg:
            continue
        algos = [a.strip().lower() for a in cfg[key].lstrip("+^-").split(",")]
        if cfg[key].startswith("-"):
            continue  # removing algorithms never weakens
        weak = [a for a in algos if a in WEAK_SSH[key]]
        if weak:
            out.append(finding(rid, "medium", f"Weak SSH {label} enabled",
                               f"{key}: {', '.join(weak)}. CBC ciphers, MD5/SHA-1 MACs and SHA-1 key exchange are legacy.",
                               f"Remove them from {cfg_name(key)}, or delete the line to use OpenSSH's modern defaults.", where(key)))
    return out, True


def cfg_name(key: str) -> str:
    return {"ciphers": "Ciphers", "macs": "MACs", "kexalgorithms": "KexAlgorithms"}[key]


# ---------------------------------------------------------------- sysctl

def parse_sysctl_text(text: str) -> Dict[str, str]:
    values = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
        elif ":" in line:  # BSD-style output
            k, v = line.split(":", 1)
        else:
            continue
        values[k.strip()] = v.strip()
    return values


def read_sysctl(root: str, keys: List[str]) -> Dict[str, str]:
    values = {}
    for key in keys:
        text = read_text(rooted(root, "/proc/sys/" + key.replace(".", "/")))
        if text is not None:
            values[key] = text.strip()
    return values


def check_sysctl(values: Dict[str, str]) -> Tuple[List[Dict], bool]:
    out = []
    for rid, key, wanted, sev, title, why, fix in SYSCTL_RULES:
        value = values.get(key)
        if value is None or value in wanted:
            continue
        severity = sev
        if key == "kernel.randomize_va_space":
            severity = "high" if value == "0" else "medium"
        out.append(finding(rid, severity, title, f"{key} = {value}. {why}", fix, key))
    return out, bool(values)


# ---------------------------------------------------------------- files

def walk_files(root: str, paths: List[str], max_files: int = 200000):
    count = 0
    for p in paths:
        base = rooted(root, p)
        if not os.path.isdir(base):
            continue
        for dirpath, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(dirpath, d))]
            yield dirpath, True
            for name in files:
                count += 1
                if count > max_files:
                    return
                yield os.path.join(dirpath, name), False


def logical(root: str, real: str) -> str:
    if root in ("", "/"):
        return real
    return "/" + os.path.relpath(real, root).replace(os.sep, "/")


def check_files(root: str, paths: List[str], extra_suid: List[str]) -> Tuple[List[Dict], bool]:
    ww_files, ww_dirs, suid = [], [], []
    for real, is_dir in walk_files(root, paths):
        try:
            st = os.lstat(real)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        path = logical(root, real)
        if st.st_mode & stat.S_IWOTH:
            if is_dir and not st.st_mode & stat.S_ISVTX:
                ww_dirs.append(path)
            elif not is_dir:
                ww_files.append(path)
        if not is_dir and st.st_mode & stat.S_ISUID:
            name = os.path.basename(path)
            known = (name in KNOWN_SUID or name in extra_suid or path in extra_suid) and path.startswith(SYSTEM_PREFIXES)
            if not known:
                suid.append((path, st.st_mode))
    out = []
    for path in ww_files[:MAX_FILE_FINDINGS]:
        out.append(finding("FS-001", "medium", "World-writable file",
                           "Any local user can change it; if root reads or runs it, that is a privilege escalation.",
                           f"chmod o-w {path}", path))
    for path in ww_dirs[:MAX_FILE_FINDINGS]:
        out.append(finding("FS-002", "medium", "World-writable directory without sticky bit",
                           "Any user can delete or replace other users' files in it.",
                           f"chmod o-w {path} (or chmod +t if it must be shared)", path))
    skipped = max(0, len(ww_files) - MAX_FILE_FINDINGS) + max(0, len(ww_dirs) - MAX_FILE_FINDINGS)
    if skipped:
        out.append(finding("FS-009", "info", f"{skipped} more world-writable paths not listed",
                           "Output capped per type.", "Re-run with a narrower --scan-path to see them all."))
    for path, mode in suid[:MAX_FILE_FINDINGS]:
        risky = path.startswith(RISKY_PREFIXES) or bool(mode & stat.S_IWOTH)
        out.append(finding("SUID-001", "high" if risky else "medium", "Unexpected SUID binary",
                           ("In a user-writable location. " if risky else "") +
                           "SUID programs run as their owner (usually root); an unknown one may be a backdoor or an exploitable tool.",
                           f"Check the package that owns it (dpkg -S / rpm -qf). If not needed: chmod u-s {path}", path))
    return out, True


# ---------------------------------------------------------------- accounts

def check_accounts(root: str, shadow_path: Optional[str]) -> Tuple[List[Dict], bool]:
    out = []
    ran = False
    passwd = read_text(rooted(root, "/etc/passwd"))
    if passwd is not None:
        ran = True
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7 or line.startswith("#"):
                continue
            user, pw, uid = parts[0], parts[1], parts[2]
            if uid == "0" and user != "root":
                out.append(finding("ACC-001", "critical", f"Extra UID 0 account: {user}",
                                   "Any account with UID 0 is root. Extra ones are a classic backdoor.",
                                   f"Remove {user} or give it a normal UID after checking who created it.", "/etc/passwd"))
            if pw == "":
                out.append(finding("ACC-002", "critical", f"Account {user} has an empty password field in /etc/passwd",
                                   "No password at all is required for this account.",
                                   f"passwd -l {user} (lock it) or set a password; keep 'x' in /etc/passwd.", "/etc/passwd"))
    shadow = read_text(shadow_path) if shadow_path else read_text(rooted(root, "/etc/shadow"))
    if shadow is not None:
        ran = True
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) < 2 or line.startswith("#"):
                continue
            user, pw = parts[0], parts[1]
            if pw == "":  # "!" / "*" / "!!" mean locked; empty means no password
                out.append(finding("ACC-003", "critical", f"Account {user} has no password",
                                   "The shadow password field is empty, so login needs no password where PAM allows it.",
                                   f"passwd -l {user} or set a strong password.", "/etc/shadow"))
            elif pw.startswith("$1$") or (len(pw) == 13 and pw.isascii() and not pw.startswith(("!", "*"))):
                out.append(finding("ACC-004", "medium", f"Account {user} uses a legacy password hash",
                                   "md5crypt or DES crypt is fast to crack if the shadow file leaks.",
                                   "Set ENCRYPT_METHOD YESCRYPT or SHA512 in /etc/login.defs and reset the password.", "/etc/shadow"))
    return out, ran


# ---------------------------------------------------------------- firewall

def check_firewall(root: str) -> Tuple[List[Dict], bool, str]:
    def wants(unit):
        return any(os.path.exists(rooted(root, f"/etc/systemd/system/{t}.wants/{unit}"))
                   for t in ("multi-user.target", "sysinit.target", "network-pre.target", "basic.target"))

    ufw = read_text(rooted(root, "/etc/ufw/ufw.conf")) or ""
    if any(l.strip().lower() == "enabled=yes" for l in ufw.splitlines()):
        return [], True, "ufw enabled"
    if wants("firewalld.service"):
        return [], True, "firewalld enabled"
    nft = read_text(rooted(root, "/etc/nftables.conf")) or ""
    if wants("nftables.service") and "chain" in nft:
        return [], True, "nftables enabled"
    for saved in ("/etc/iptables/rules.v4", "/etc/sysconfig/iptables"):
        text = read_text(rooted(root, saved)) or ""
        if "-A " in text or ":INPUT DROP" in text:
            return [], True, f"iptables rules in {saved}"
    return [finding("FW-001", "medium", "No enabled host firewall found",
                    "No enabled ufw, firewalld or nftables service and no saved iptables rules were found. "
                    "This is a config check; a cloud security group may still filter traffic.",
                    "Enable one: ufw default deny incoming && ufw allow OpenSSH && ufw enable "
                    "(or firewalld / nftables with a default-drop input chain).")], True, "none found"


# ---------------------------------------------------------------- driver

def audit(root: str = "/", sysctl_values: Optional[Dict[str, str]] = None, shadow: Optional[str] = None,
          scan_paths: Optional[List[str]] = None, extra_suid: Optional[List[str]] = None,
          skip_files: bool = False) -> Dict[str, object]:
    findings, ran, skipped = [], [], []
    f, ok = check_sshd(root)
    findings += f
    (ran if ok else skipped).append("sshd")
    values = sysctl_values if sysctl_values is not None else read_sysctl(root, [r[1] for r in SYSCTL_RULES])
    f, ok = check_sysctl(values)
    findings += f
    (ran if ok else skipped).append("sysctl")
    if skip_files:
        skipped.append("files")
    else:
        f, _ = check_files(root, scan_paths or DEFAULT_SCAN, extra_suid or [])
        findings += f
        ran.append("files")
    f, ok = check_accounts(root, shadow)
    findings += f
    (ran if ok else skipped).append("accounts")
    f, _, fw_state = check_firewall(root)
    findings += f
    ran.append("firewall")
    findings.sort(key=lambda x: -SEVERITY_ORDER.index(x["severity"]))
    return {"root": root, "checks_run": ran, "checks_skipped": skipped, "firewall": fw_state, "findings": findings}


def render_text(res) -> str:
    lines = [f"Linux audit of root {res['root']}: {len(res['findings'])} finding(s)",
             f"Checks run: {', '.join(res['checks_run'])}" +
             (f"; skipped (no data): {', '.join(res['checks_skipped'])}" if res["checks_skipped"] else ""),
             f"Firewall: {res['firewall']}", ""]
    if not res["findings"]:
        lines.append("No issues found.")
    for f in res["findings"]:
        loc = f"  ({f['location']})" if f.get("location") else ""
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}{loc}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only Linux hardening audit.")
    ap.add_argument("--root", default="/", help="filesystem root to audit (default /; use a mounted image or test tree)")
    ap.add_argument("--sysctl-file", help="saved `sysctl -a` output instead of reading <root>/proc/sys")
    ap.add_argument("--shadow", help="path to a shadow file copy (default <root>/etc/shadow if readable)")
    ap.add_argument("--scan-path", action="append", help="dir to scan for world-writable/SUID files (repeatable)")
    ap.add_argument("--allow-suid", action="append", default=[], help="extra SUID binary name or path to accept")
    ap.add_argument("--no-file-scan", action="store_true", help="skip the world-writable and SUID scan")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.root):
        print(f"error: root {args.root} is not a directory", file=sys.stderr)
        return 2
    sysctl_values = None
    if args.sysctl_file:
        text = read_text(args.sysctl_file)
        if text is None:
            print(f"error: cannot read {args.sysctl_file}", file=sys.stderr)
            return 2
        sysctl_values = parse_sysctl_text(text)
    if args.shadow and read_text(args.shadow) is None:
        print(f"error: cannot read {args.shadow}", file=sys.stderr)
        return 2

    res = audit(args.root, sysctl_values, args.shadow, args.scan_path, args.allow_suid, args.no_file_scan)
    print(json.dumps(res, indent=2) if args.json else render_text(res))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in res["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
