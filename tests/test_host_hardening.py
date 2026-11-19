import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from _helpers import call_main, load_script, run_cli, skill_path

lx = load_script("host-hardening", "linux_audit")
mac = load_script("host-hardening", "macos_audit")
EX = skill_path("host-hardening", "examples")


def ids(findings):
    return {f["id"] for f in findings}


def write(root, rel, text):
    path = Path(root) / rel.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class SshdTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_config_is_skipped(self):
        found, ran = lx.check_sshd(self.root)
        self.assertEqual(found, [])
        self.assertFalse(ran)

    def test_root_login_and_empty_passwords(self):
        write(self.root, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPermitEmptyPasswords yes\nPasswordAuthentication no\n")
        found, _ = lx.check_sshd(self.root)
        self.assertTrue({"SSH-001", "SSH-002"} <= ids(found))
        self.assertNotIn("SSH-003", ids(found))

    def test_hardened_config_is_clean(self):
        write(self.root, "/etc/ssh/sshd_config",
              "PermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\nMaxAuthTries 3\n"
              "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n")
        found, ran = lx.check_sshd(self.root)
        self.assertTrue(ran)
        self.assertEqual(found, [])

    def test_password_auth_default_is_yes(self):
        write(self.root, "/etc/ssh/sshd_config", "PermitRootLogin no\n")
        found, _ = lx.check_sshd(self.root)
        ssh3 = [f for f in found if f["id"] == "SSH-003"]
        self.assertEqual(len(ssh3), 1)
        self.assertIn("default", ssh3[0]["detail"])
        self.assertIn("SSH-005", ids(found))  # default MaxAuthTries 6

    def test_kbd_interactive_reopens_passwords(self):
        base = "PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\nUsePAM yes\n"
        write(self.root, "/etc/ssh/sshd_config", base)
        found, _ = lx.check_sshd(self.root)
        self.assertEqual(ids(found), {"SSH-009"})
        self.assertIn("default yes", found[0]["detail"])
        write(self.root, "/etc/ssh/sshd_config", base + "KbdInteractiveAuthentication no\n")
        self.assertEqual(lx.check_sshd(self.root)[0], [])
        write(self.root, "/etc/ssh/sshd_config", "PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n")
        self.assertEqual(lx.check_sshd(self.root)[0], [])  # UsePAM defaults to no upstream

    def test_hostbased_and_user_environment(self):
        clean = "PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n"
        write(self.root, "/etc/ssh/sshd_config", clean + "IgnoreRhosts no\nPermitUserEnvironment yes\n")
        self.assertEqual(ids(lx.check_sshd(self.root)[0]), {"SSH-010", "SSH-011"})
        write(self.root, "/etc/ssh/sshd_config", clean + "HostbasedAuthentication yes\n")
        self.assertEqual(ids(lx.check_sshd(self.root)[0]), {"SSH-010"})
        write(self.root, "/etc/ssh/sshd_config", clean + "IgnoreRhosts yes\nPermitUserEnvironment no\n")
        self.assertEqual(lx.check_sshd(self.root)[0], [])

    def test_sha1_rsa_and_dsa_key_algorithms(self):
        clean = "PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n"
        write(self.root, "/etc/ssh/sshd_config", clean + "PubkeyAcceptedAlgorithms +ssh-rsa,ssh-dss\n")
        found = lx.check_sshd(self.root)[0]
        self.assertEqual(ids(found), {"SSH-012"})
        self.assertIn("ssh-dss", found[0]["detail"])
        write(self.root, "/etc/ssh/sshd_config", clean + "HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n"
                                                         "CASignatureAlgorithms -ssh-rsa\n")
        self.assertEqual(lx.check_sshd(self.root)[0], [])

    def test_ripemd_etm_mac_is_weak(self):
        write(self.root, "/etc/ssh/sshd_config", "PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n"
                                                 "MACs hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com\n")
        self.assertEqual(ids(lx.check_sshd(self.root)[0]), {"SSH-007"})

    def test_include_at_top_wins(self):
        write(self.root, "/etc/ssh/sshd_config",
              "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nMaxAuthTries 3\n")
        write(self.root, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
        found, _ = lx.check_sshd(self.root)
        ssh3 = [f for f in found if f["id"] == "SSH-003"]
        self.assertEqual(len(ssh3), 1)
        self.assertEqual(ssh3[0]["location"], "/etc/ssh/sshd_config.d/50-cloud-init.conf")

    def test_include_at_bottom_loses(self):
        write(self.root, "/etc/ssh/sshd_config",
              "PasswordAuthentication no\nMaxAuthTries 3\nInclude sshd_config.d/*.conf\n")
        write(self.root, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
        found, _ = lx.check_sshd(self.root)
        self.assertNotIn("SSH-003", ids(found))

    def test_match_block_ignored(self):
        write(self.root, "/etc/ssh/sshd_config",
              "PasswordAuthentication no\nMaxAuthTries 3\nMatch User backup\n    PermitRootLogin yes\n")
        found, _ = lx.check_sshd(self.root)
        self.assertEqual(found, [])

    def test_weak_algorithms(self):
        write(self.root, "/etc/ssh/sshd_config",
              "PasswordAuthentication no\nMaxAuthTries 3\nCiphers aes128-ctr,3des-cbc\nMACs hmac-md5\n"
              "KexAlgorithms diffie-hellman-group1-sha1\n")
        found, _ = lx.check_sshd(self.root)
        self.assertTrue({"SSH-006", "SSH-007", "SSH-008"} <= ids(found))

    def test_removing_algorithms_is_fine(self):
        write(self.root, "/etc/ssh/sshd_config", "PasswordAuthentication no\nMaxAuthTries 3\nCiphers -3des-cbc\n")
        found, _ = lx.check_sshd(self.root)
        self.assertNotIn("SSH-006", ids(found))


class SysctlTests(unittest.TestCase):
    def test_parse_formats(self):
        self.assertEqual(lx.parse_sysctl_text("net.ipv4.ip_forward = 1\nkernel.x: 2\n"),
                         {"net.ipv4.ip_forward": "1", "kernel.x": "2"})

    def test_weak_values(self):
        found, ran = lx.check_sysctl({"net.ipv4.ip_forward": "1", "kernel.randomize_va_space": "0",
                                      "kernel.kptr_restrict": "0"})
        self.assertTrue(ran)
        self.assertEqual(ids(found), {"SYS-001", "SYS-008", "SYS-009"})
        aslr = [f for f in found if f["id"] == "SYS-008"][0]
        self.assertEqual(aslr["severity"], "high")

    def test_partial_aslr_is_medium(self):
        found, _ = lx.check_sysctl({"kernel.randomize_va_space": "1"})
        self.assertEqual(found[0]["severity"], "medium")

    def test_good_values(self):
        found, _ = lx.check_sysctl({"net.ipv4.ip_forward": "0", "kernel.randomize_va_space": "2",
                                    "net.ipv4.conf.all.rp_filter": "2"})
        self.assertEqual(found, [])

    def test_no_values_is_skipped(self):
        self.assertEqual(lx.check_sysctl({}), ([], False))

    NEW_BAD = {"kernel.yama.ptrace_scope": "0", "fs.protected_symlinks": "0", "fs.protected_hardlinks": "0",
               "kernel.unprivileged_bpf_disabled": "0", "net.ipv4.conf.all.secure_redirects": "1",
               "net.ipv4.conf.all.log_martians": "0", "net.ipv4.icmp_echo_ignore_broadcasts": "0",
               "net.ipv6.conf.all.forwarding": "1", "net.ipv6.conf.all.accept_source_route": "1",
               "net.ipv6.conf.all.accept_ra": "1"}

    def test_new_kernel_and_network_keys_weak(self):
        found, _ = lx.check_sysctl(self.NEW_BAD)
        self.assertEqual(ids(found), {f"SYS-{n:03d}" for n in range(12, 22)})

    def test_new_kernel_and_network_keys_good(self):
        good = {"kernel.yama.ptrace_scope": "2", "fs.protected_symlinks": "1", "fs.protected_hardlinks": "1",
                "kernel.unprivileged_bpf_disabled": "2", "net.ipv4.conf.all.secure_redirects": "0",
                "net.ipv4.conf.all.log_martians": "1", "net.ipv4.icmp_echo_ignore_broadcasts": "1",
                "net.ipv6.conf.all.forwarding": "0", "net.ipv6.conf.all.accept_source_route": "0",
                "net.ipv6.conf.all.accept_ra": "0"}
        self.assertEqual(lx.check_sysctl(good), ([], True))

    def test_proc_files(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "/proc/sys/net/ipv4/tcp_syncookies", "0\n")
            write(root, "/proc/sys/fs/suid_dumpable", "0\n")
            values = lx.read_sysctl(root, ["net.ipv4.tcp_syncookies", "fs.suid_dumpable"])
            self.assertEqual(values, {"net.ipv4.tcp_syncookies": "0", "fs.suid_dumpable": "0"})
            self.assertEqual(ids(lx.check_sysctl(values)[0]), {"SYS-007"})


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_world_writable_and_sticky(self):
        p = write(self.root, "/etc/app.conf", "x")
        os.chmod(p, 0o666)
        d = Path(self.root, "etc/dropbox")
        d.mkdir()
        os.chmod(d, 0o777)
        s = Path(self.root, "etc/shared")
        s.mkdir()
        os.chmod(s, 0o1777)
        found, _ = lx.check_files(self.root, ["/etc"], [])
        locs = {(f["id"], f["location"]) for f in found}
        self.assertIn(("FS-001", "/etc/app.conf"), locs)
        self.assertIn(("FS-002", "/etc/dropbox"), locs)
        self.assertNotIn("/etc/shared", {f["location"] for f in found})

    def test_normal_permissions_clean(self):
        p = write(self.root, "/etc/app.conf", "x")
        os.chmod(p, 0o644)
        found, _ = lx.check_files(self.root, ["/etc"], [])
        self.assertEqual(found, [])

    def test_suid(self):
        known = write(self.root, "/usr/bin/passwd", "x")
        odd = write(self.root, "/usr/bin/helper", "x")
        risky = write(self.root, "/tmp/sh", "x")
        for p in (known, odd, risky):
            os.chmod(p, 0o4755)
        found, _ = lx.check_files(self.root, ["/usr/bin", "/tmp"], [])
        by_loc = {f["location"]: f for f in found if f["id"] == "SUID-001"}
        self.assertNotIn("/usr/bin/passwd", by_loc)
        self.assertEqual(by_loc["/usr/bin/helper"]["severity"], "medium")
        self.assertEqual(by_loc["/tmp/sh"]["severity"], "high")
        found, _ = lx.check_files(self.root, ["/usr/bin"], ["helper"])
        self.assertEqual(found, [])


class AccountFirewallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_accounts_weak(self):
        write(self.root, "/etc/passwd", "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/root:/bin/sh\nopen::1001:1001::/h:/bin/sh\n")
        write(self.root, "/etc/shadow", "root:$y$j9T$FAKEFAKE:19000::::::\nopen::19000::::::\nold:$1$FAKE$FAKEFAKE:1::::::\n"
                                        "des:abFAKEFAKEFAK:1::::::\nlocked:!:1::::::\n")
        found, ran = lx.check_accounts(self.root, None)
        self.assertTrue(ran)
        self.assertEqual(ids(found), {"ACC-001", "ACC-002", "ACC-003", "ACC-004"})
        self.assertEqual(sum(f["id"] == "ACC-004" for f in found), 2)
        for f in found:  # never echo the hash
            self.assertNotIn("FAKE", f["detail"] + f["title"])

    def test_accounts_clean(self):
        write(self.root, "/etc/passwd", "root:x:0:0::/root:/bin/sh\nuser:x:1000:1000::/h:/bin/sh\n")
        write(self.root, "/etc/shadow", "root:!:1::::::\nuser:$6$FAKE$FAKE:1::::::\n")
        self.assertEqual(lx.check_accounts(self.root, None), ([], True))

    def test_accounts_missing(self):
        self.assertEqual(lx.check_accounts(self.root, None), ([], False))

    def test_firewall_missing(self):
        found, _, state = lx.check_firewall(self.root)
        self.assertEqual(ids(found), {"FW-001"})
        self.assertEqual(state, "none found")

    def test_firewall_ufw(self):
        write(self.root, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
        self.assertEqual(lx.check_firewall(self.root)[2], "ufw enabled")

    def test_firewall_ufw_disabled(self):
        write(self.root, "/etc/ufw/ufw.conf", "ENABLED=no\n")
        self.assertIn("FW-001", ids(lx.check_firewall(self.root)[0]))

    def test_firewall_firewalld_and_iptables(self):
        write(self.root, "/etc/systemd/system/multi-user.target.wants/firewalld.service", "")
        self.assertEqual(lx.check_firewall(self.root)[2], "firewalld enabled")
        with tempfile.TemporaryDirectory() as r2:
            write(r2, "/etc/iptables/rules.v4", "*filter\n:INPUT DROP [0:0]\nCOMMIT\n")
            self.assertEqual(lx.check_firewall(r2)[0], [])


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_secret_and_config_modes(self):
        os.chmod(write(self.root, "/etc/shadow", "root:!:1::::::\n"), 0o644)
        os.chmod(write(self.root, "/etc/ssh/ssh_host_ed25519_key", "FAKE-NOT-A-KEY\n"), 0o644)
        os.chmod(write(self.root, "/etc/sudoers.d/ops", "# fake\n"), 0o666)
        os.chmod(write(self.root, "/etc/passwd", "root:x:0:0::/root:/bin/sh\n"), 0o664)
        found, ran = lx.check_permissions(self.root, any_owner=True)
        self.assertTrue(ran)
        by_id = {}
        for f in found:
            by_id.setdefault(f["id"], set()).add(f["location"])
        self.assertEqual(by_id["FS-003"], {"/etc/shadow", "/etc/ssh/ssh_host_ed25519_key"})
        self.assertEqual(by_id["FS-004"], {"/etc/sudoers.d/ops", "/etc/passwd"})
        for f in found:
            self.assertNotIn("FAKE-NOT", f["detail"])

    def test_correct_modes_clean(self):
        os.chmod(write(self.root, "/etc/shadow", "root:!:1::::::\n"), 0o640)
        os.chmod(write(self.root, "/etc/ssh/ssh_host_ed25519_key", "FAKE\n"), 0o600)
        os.chmod(write(self.root, "/etc/sudoers", "# fake\n"), 0o440)
        os.chmod(write(self.root, "/etc/passwd", "root:x:0:0::/root:/bin/sh\n"), 0o644)
        self.assertEqual(lx.check_permissions(self.root, any_owner=True), ([], True))

    def test_non_root_files_are_skipped(self):
        os.chmod(write(self.root, "/etc/shadow", "root:!:1::::::\n"), 0o666)
        if os.geteuid() != 0:
            self.assertEqual(lx.check_permissions(self.root), ([], False))


class SudoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_is_skipped(self):
        self.assertEqual(lx.check_sudo(self.root), ([], False))

    def test_weak_sudoers(self):
        write(self.root, "/etc/sudoers", "Defaults\t!use_pty\nDefaults timestamp_timeout=-1\n"
                                         "Defaults:ops !authenticate\n%sudo ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n")
        write(self.root, "/etc/sudoers.d/90-cloud-init-users", "deploy ALL=(ALL) NOPASSWD:ALL\n")
        write(self.root, "/etc/sudoers.d/old.bak", "eve ALL=(ALL) NOPASSWD: ALL\n")  # sudo ignores names with a dot
        found, ran = lx.check_sudo(self.root)
        self.assertTrue(ran)
        self.assertEqual(sorted(f["id"] for f in found), ["SUDO-001", "SUDO-002", "SUDO-003", "SUDO-003"])
        self.assertIn("deploy", [f for f in found if f["id"] == "SUDO-001"][0]["title"])

    def test_good_sudoers(self):
        write(self.root, "/etc/sudoers", "Defaults env_reset\nDefaults use_pty, timestamp_timeout=5\n"
                                         "Cmnd_Alias BACKUP = /usr/local/bin/run-backup\n"
                                         "backup ALL=(root) NOPASSWD: BACKUP\n"
                                         "web ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx\n"
                                         "%admin ALL=(ALL) ALL # NOPASSWD: ALL in a comment\n")
        self.assertEqual(lx.check_sudo(self.root), ([], True))


class UpdateTests(unittest.TestCase):
    DAY = lx.dt.date(2026, 11, 19)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def os_release(self, os_id, version, like="debian"):
        write(self.root, "/etc/os-release", f'PRETTY_NAME="Test {os_id} {version}"\nID={os_id}\n'
                                            f'ID_LIKE="{like}"\nVERSION_ID="{version}"\n')

    def test_missing_is_skipped(self):
        self.assertEqual(lx.check_updates(self.root, self.DAY), ([], False))

    def test_eol_severity(self):
        self.os_release("ubuntu", "18.04")
        sev = {f["id"]: f["severity"] for f in lx.check_updates(self.root, self.DAY)[0]}
        self.assertEqual(sev["UPD-001"], "medium")  # only paid ESM left
        self.os_release("centos", "7", "rhel fedora")
        sev = {f["id"]: f["severity"] for f in lx.check_updates(self.root, self.DAY)[0]}
        self.assertEqual(sev["UPD-001"], "high")
        self.os_release("ubuntu", "24.10")
        self.assertEqual({f["severity"] for f in lx.check_updates(self.root, self.DAY)[0] if f["id"] == "UPD-001"},
                         {"high"})

    def test_supported_with_auto_updates_clean(self):
        self.os_release("debian", "12", "")
        write(self.root, "/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";\n')
        self.assertEqual(lx.check_updates(self.root, self.DAY), ([], True))
        self.os_release("rhel", "9", "fedora")
        write(self.root, "/etc/systemd/system/timers.target.wants/dnf-automatic.timer", "")
        self.assertEqual(lx.check_updates(self.root, self.DAY), ([], True))

    def test_auto_updates_off(self):
        self.os_release("debian", "12", "")
        write(self.root, "/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "0";\n')
        found = lx.check_updates(self.root, self.DAY)[0]
        self.assertEqual(ids(found), {"UPD-002"})
        self.assertIn("set to 0", found[0]["detail"])
        self.os_release("rocky", "9.4", "rhel centos fedora")
        self.assertEqual(ids(lx.check_updates(self.root, self.DAY)[0]), {"UPD-002"})


class LinuxCliTests(unittest.TestCase):
    def test_weak_example(self):
        code, out, _ = call_main(lx, ["--root", str(EX / "weak_root"), "--sysctl-file",
                                      str(EX / "sysctl_weak.txt"), "--today", "2026-11-19", "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"root", "checks_run", "checks_skipped", "firewall", "findings"})
        self.assertTrue({"SSH-001", "SSH-003", "ACC-001", "ACC-003", "FW-001", "SYS-001", "SSH-010", "SSH-011",
                         "SSH-012", "SYS-021", "SUDO-001", "SUDO-003", "UPD-001", "UPD-002"} <= ids(data["findings"]))
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))
        ssh3 = [f for f in data["findings"] if f["id"] == "SSH-003"][0]
        self.assertTrue(ssh3["location"].endswith("50-cloud-init.conf"))

    def test_hardened_example(self):
        code, out, _ = call_main(lx, ["--root", str(EX / "hardened_root"), "--today", "2026-11-19", "--json"])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertEqual(data["findings"], [])
        self.assertTrue({"sysctl", "sudo", "updates"} <= set(data["checks_run"]))

    def test_text_and_fail_on(self):
        code, out, _ = call_main(lx, ["--root", str(EX / "weak_root"), "--no-file-scan", "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertIn("SSH-001", out)
        self.assertIn("files", out)  # listed as skipped

    def test_bad_input(self):
        self.assertEqual(call_main(lx, ["--root", "/nonexistent/secskills"])[0], 2)
        self.assertEqual(call_main(lx, ["--root", str(EX / "hardened_root"), "--sysctl-file", "/nonexistent/x"])[0], 2)
        self.assertEqual(call_main(lx, ["--root", str(EX / "hardened_root"), "--shadow", "/nonexistent/x"])[0], 2)
        self.assertEqual(call_main(lx, ["--root", str(EX / "hardened_root"), "--today", "19-11-2026"])[0], 2)

    def test_help(self):
        proc = run_cli("host-hardening", "linux_audit", "--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--root", proc.stdout)


class MacParserTests(unittest.TestCase):
    def test_filevault(self):
        self.assertEqual(mac.parse_filevault("FileVault is On.\n")[0], "pass")
        self.assertEqual(ids(mac.parse_filevault("FileVault is Off.\n")[2]), {"MAC-001"})
        self.assertEqual(mac.parse_filevault("garbage")[0], "unknown")

    def test_gatekeeper(self):
        self.assertEqual(mac.parse_gatekeeper("assessments enabled\n")[0], "pass")
        self.assertEqual(ids(mac.parse_gatekeeper("assessments disabled\n")[2]), {"MAC-002"})

    def test_sip(self):
        self.assertEqual(mac.parse_sip("System Integrity Protection status: enabled.")[0], "pass")
        st, _, f = mac.parse_sip("System Integrity Protection status: disabled.")
        self.assertEqual((st, f[0]["severity"]), ("fail", "high"))
        st, _, f = mac.parse_sip("System Integrity Protection status: unknown (Custom Configuration).")
        self.assertEqual(f[0]["severity"], "medium")

    def test_firewall_and_stealth(self):
        self.assertEqual(mac.parse_firewall("Firewall is enabled. (State = 1)")[0], "pass")
        self.assertEqual(ids(mac.parse_firewall("Firewall is disabled. (State = 0)")[2]), {"MAC-004"})
        self.assertEqual(mac.parse_stealth("Firewall stealth mode is on")[0], "pass")
        self.assertEqual(ids(mac.parse_stealth("Firewall stealth mode is off")[2]), {"MAC-005"})

    def test_autoupdate(self):
        weak = "{\n    AutomaticCheckEnabled = 0;\n    CriticalUpdateInstall = 0;\n    ConfigDataInstall = 0;\n    AutomaticDownload = 0;\n}\n"
        self.assertEqual(ids(mac.parse_autoupdate(weak)[2]), {"MAC-006", "MAC-013", "MAC-014", "MAC-015"})
        good = "{\n    AutomaticCheckEnabled = 1;\n    CriticalUpdateInstall = 1;\n}\n"
        self.assertEqual(mac.parse_autoupdate(good)[0], "pass")
        self.assertEqual(ids(mac.parse_autoupdate("{\n    AutomaticallyInstallMacOSUpdates = 0;\n}\n")[2]), {"MAC-016"})
        self.assertEqual(mac.parse_autoupdate("{\n    AutomaticallyInstallMacOSUpdates = 1;\n}\n")[0], "pass")
        missing = "Domain /Library/Preferences/com.apple.SoftwareUpdate does not exist"
        self.assertEqual(mac.parse_autoupdate(missing)[0], "pass")

    def test_screenlock(self):
        self.assertEqual(mac.parse_screenlock("screenLock delay is immediate")[0], "pass")
        self.assertEqual(mac.parse_screenlock("screenLock delay is 5 seconds")[0], "pass")
        st, _, f = mac.parse_screenlock("screenLock delay is 300 seconds")
        self.assertEqual((st, f[0]["severity"]), ("fail", "low"))
        st, _, f = mac.parse_screenlock("screenLock is off")
        self.assertEqual(f[0]["severity"], "medium")

    def test_remote_login_needs_sudo(self):
        st, _, f = mac.parse_remotelogin("You need administrator access to run this tool... exiting!")
        self.assertEqual((st, f), ("needs sudo", []))
        self.assertEqual(ids(mac.parse_remotelogin("Remote Login: On")[2]), {"MAC-008"})
        self.assertEqual(mac.parse_remotelogin("Remote Login: Off")[0], "pass")

    def test_sharing(self):
        text = ('disabled services = {\n "com.apple.screensharing" => enabled\n "com.apple.smbd" => disabled\n'
                ' "com.apple.AEServer" => false\n}\n')
        self.assertEqual(ids(mac.parse_sharing(text)[2]), {"MAC-009", "MAC-012"})
        clean = 'disabled services = {\n "com.apple.screensharing" => disabled\n}\n'
        self.assertEqual(mac.parse_sharing(clean)[0], "pass")

    def test_guest(self):
        self.assertEqual(ids(mac.parse_guest("1\n")[2]), {"MAC-010"})
        self.assertEqual(mac.parse_guest("0\n")[0], "pass")

    def test_audit_dedupes_and_marks_missing(self):
        res = mac.audit({"remotelogin": "Remote Login: On",
                         "sharing": 'disabled services = {\n "com.openssh.sshd" => enabled\n}\n'})
        self.assertEqual([f["id"] for f in res["findings"]].count("MAC-008"), 1)
        statuses = {c["check"]: c["status"] for c in res["checks"]}
        self.assertEqual(statuses["filevault"], "not collected")


class MacCliTests(unittest.TestCase):
    def test_weak_example(self):
        code, out, _ = call_main(mac, ["--from-dir", str(EX / "macos_weak"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"source", "checks", "findings"})
        self.assertTrue({"MAC-001", "MAC-002", "MAC-004", "MAC-009", "MAC-016"} <= ids(data["findings"]))
        statuses = {c["check"]: c["status"] for c in data["checks"]}
        self.assertEqual(statuses["remotelogin"], "needs sudo")

    def test_hardened_example(self):
        code, out, _ = call_main(mac, ["--from-dir", str(EX / "macos_hardened")])
        self.assertEqual(code, 0, out)
        self.assertIn("No issues found", out)

    def test_bad_dirs(self):
        self.assertEqual(call_main(mac, ["--from-dir", "/nonexistent/secskills"])[0], 2)
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(call_main(mac, ["--from-dir", empty])[0], 2)

    def test_help(self):
        proc = run_cli("host-hardening", "macos_audit", "--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--from-dir", proc.stdout)


if __name__ == "__main__":
    unittest.main()
