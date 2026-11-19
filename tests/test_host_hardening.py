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


class LinuxCliTests(unittest.TestCase):
    def test_weak_example(self):
        code, out, _ = call_main(lx, ["--root", str(EX / "weak_root"), "--sysctl-file",
                                      str(EX / "sysctl_weak.txt"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"root", "checks_run", "checks_skipped", "firewall", "findings"})
        self.assertTrue({"SSH-001", "SSH-003", "ACC-001", "ACC-003", "FW-001", "SYS-001"} <= ids(data["findings"]))
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))
        ssh3 = [f for f in data["findings"] if f["id"] == "SSH-003"][0]
        self.assertTrue(ssh3["location"].endswith("50-cloud-init.conf"))

    def test_hardened_example(self):
        code, out, _ = call_main(lx, ["--root", str(EX / "hardened_root"), "--json"])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertEqual(data["findings"], [])
        self.assertIn("sysctl", data["checks_run"])

    def test_text_and_fail_on(self):
        code, out, _ = call_main(lx, ["--root", str(EX / "weak_root"), "--no-file-scan", "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertIn("SSH-001", out)
        self.assertIn("files", out)  # listed as skipped

    def test_bad_input(self):
        self.assertEqual(call_main(lx, ["--root", "/nonexistent/aegis"])[0], 2)
        self.assertEqual(call_main(lx, ["--root", str(EX / "hardened_root"), "--sysctl-file", "/nonexistent/x"])[0], 2)
        self.assertEqual(call_main(lx, ["--root", str(EX / "hardened_root"), "--shadow", "/nonexistent/x"])[0], 2)

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
        self.assertTrue({"MAC-001", "MAC-002", "MAC-004", "MAC-009"} <= ids(data["findings"]))
        statuses = {c["check"]: c["status"] for c in data["checks"]}
        self.assertEqual(statuses["remotelogin"], "needs sudo")

    def test_hardened_example(self):
        code, out, _ = call_main(mac, ["--from-dir", str(EX / "macos_hardened")])
        self.assertEqual(code, 0, out)
        self.assertIn("No issues found", out)

    def test_bad_dirs(self):
        self.assertEqual(call_main(mac, ["--from-dir", "/nonexistent/aegis"])[0], 2)
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(call_main(mac, ["--from-dir", empty])[0], 2)

    def test_help(self):
        proc = run_cli("host-hardening", "macos_audit", "--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--from-dir", proc.stdout)


if __name__ == "__main__":
    unittest.main()
