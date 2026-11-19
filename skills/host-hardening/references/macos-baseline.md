# macOS baseline

A practical baseline for Macs used for work (laptops, desktops, build machines). In the spirit of the CIS macOS benchmarks (latest at the last check, 2026-11-19: CIS Apple macOS 26 Tahoe v1.1.0) and Apple's Platform Security guide; benchmark section numbers are left out on purpose.

On managed fleets, set these with an MDM configuration profile instead of by hand, so they cannot drift. Hand fixes are for single Macs.

## Checks, commands and fixes

| Check | Read-only command | Good output | Fix |
|---|---|---|---|
| FileVault (MAC-001) | `fdesetup status` | `FileVault is On.` | System Settings > Privacy & Security > FileVault, or `sudo fdesetup enable`. Escrow the recovery key in MDM |
| Gatekeeper (MAC-002) | `spctl --status` | `assessments enabled` | `sudo spctl --global-enable` (older macOS: `--master-enable`) |
| SIP (MAC-003) | `csrutil status` | `System Integrity Protection status: enabled.` | Recovery > Terminal > `csrutil enable` (or `csrutil clear`), restart |
| Firewall (MAC-004) | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` | `Firewall is enabled. (State = 1)` | System Settings > Network > Firewall, or `sudo socketfilterfw --setglobalstate on` |
| Stealth mode (MAC-005) | `socketfilterfw --getstealthmode` | stealth mode on/enabled | Firewall > Options > Enable stealth mode |
| Update checks (MAC-006) | `defaults read /Library/Preferences/com.apple.SoftwareUpdate` | `AutomaticCheckEnabled` not 0 | Software Update > Automatic Updates |
| Security responses (MAC-013) | same | `CriticalUpdateInstall` not 0 | Automatic Updates: Install Security Responses and system files |
| Config data (MAC-014) | same | `ConfigDataInstall` not 0 | same toggle as above |
| Auto download (MAC-015) | same | `AutomaticDownload` not 0 | Automatic Updates: Download new updates when available |
| Auto install macOS updates (MAC-016) | same | `AutomaticallyInstallMacOSUpdates` not 0 | Automatic Updates: Install macOS updates |
| Screen lock (MAC-007) | `sysadminctl -screenLock status` (prints on stderr) | `screenLock delay is immediate` (or 5 s or less) | Lock Screen > Require password: Immediately |
| Remote Login (MAC-008) | `sudo systemsetup -getremotelogin` | `Remote Login: Off` | Sharing > Remote Login off, or limit to named users |
| Screen Sharing (MAC-009) | `launchctl print-disabled system` | `com.apple.screensharing` not enabled | Sharing > Screen Sharing off |
| File Sharing (MAC-011) | same | `com.apple.smbd` not enabled | Sharing > File Sharing off |
| Remote Apple Events (MAC-012) | same | `com.apple.AEServer` not enabled | Sharing > Remote Apple Events off |
| Guest (MAC-010) | `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled` | `0` or key missing | Users & Groups > Guest User off |

Missing keys in the SoftwareUpdate plist mean macOS defaults, which are on.

## What needs admin rights

- `systemsetup -getremotelogin` prints "You need administrator access to run this tool" without sudo. The script marks it `needs sudo`; the `launchctl` sharing check still sees `com.openssh.sshd`
- `sysadminctl -screenLock status` needs the logged-in user's context; run it as that user, not over SSH as another account
- Everything else in the table runs as a normal user

## Beyond the script

These are worth checking by hand or via MDM; the script does not cover them:

- macOS version still receiving security updates (Apple patches the current release fully; older ones get partial fixes)
- Admin accounts: daily user should be a standard account where practical. `dscl . -read /Groups/admin GroupMembership`
- Automatic login off: `defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser` should not exist
- Find My Mac on for personal devices, or MDM lock/wipe for fleet devices
- Firmware or recovery lock: on Apple silicon, Recovery requires an admin password by default; Intel Macs with a T2 chip can set a firmware password
- Third-party kernel/system extensions: `systemextensionsctl list`
- Login items and launch agents: `ls ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons`
- Bluetooth sharing, AirDrop "Everyone" setting, printer sharing, Internet Sharing
- Browser and Safari updates, and that the endpoint security tool (if any) reports healthy

## MDM profile hints

| Setting | Payload |
|---|---|
| FileVault | `com.apple.MCX.FileVault2` plus recovery key escrow |
| Firewall and stealth | `com.apple.security.firewall` (`EnableFirewall`, `EnableStealthMode`) |
| Gatekeeper | `com.apple.systempolicy.control` |
| Software Update | `com.apple.SoftwareUpdate` (`AutomaticCheckEnabled`, `AutomaticDownload`, `CriticalUpdateInstall`, `ConfigDataInstall`, `AutomaticallyInstallMacOSUpdates`), or a Declarative Device Management software update enforcement with a deadline |
| Screen lock | `com.apple.screensaver` (`askForPassword`, `askForPasswordDelay`) |
| Guest | `com.apple.loginwindow` (`DisableGuestAccount`) |

Check your MDM vendor's docs for the exact keys on your macOS version; Apple moves some settings into Declarative Device Management over time.

## Saving evidence

`python3 scripts/macos_audit.py --output ~/audit-<host>/` keeps each raw output as `<check>.txt`. Those files are the evidence for an audit, and `--from-dir` re-grades them later without touching the Mac. Raw outputs can include the machine's update history and service list; treat them as internal data.
