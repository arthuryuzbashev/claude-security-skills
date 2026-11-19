# Protocol cheat sheet for network forensics

Quick facts for reading captures and connection logs. Examples use documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `example.test` names.

## Ports worth knowing

| Port | Usually | Why it matters in an investigation |
|---|---|---|
| 22/tcp | SSH | brute force, tunnels (`ssh -D`, `-R`), lateral movement on Linux |
| 23/tcp, 2323/tcp | Telnet | cleartext logins; IoT botnets scan these |
| 53/udp+tcp | DNS | tunneling, DGA, lookups that name the C2 domain |
| 80/tcp | HTTP | cleartext downloads, payloads, C2 over plain HTTP |
| 135, 139, 445/tcp | RPC, NetBIOS, SMB | lateral movement, remote service creation, ransomware spreading |
| 443/tcp | HTTPS | most C2 hides here; read SNI and certificate details |
| 853/tcp | DNS over TLS | bypasses the company resolver |
| 1433, 3306, 5432/tcp | MSSQL, MySQL, PostgreSQL | database exposure, data theft |
| 3389/tcp | RDP | remote access, brute force, lateral movement |
| 4444/tcp | Metasploit default handler | test tools and lazy attackers leave it unchanged |
| 5985, 5986/tcp | WinRM | PowerShell remoting, lateral movement |
| 6667, 6697/tcp | IRC | old botnet C2 still seen on IoT |
| 9001/tcp, 9050/tcp, 9150/tcp | Tor relay, Tor SOCKS, Tor Browser SOCKS | anonymized C2 or exfiltration |
| 1337, 31337/tcp | "leet" ports | backdoors, CTF tools, test listeners |

A port number says what a service usually is, not what it is. Confirm with the protocol in the payload (HTTP verbs, TLS record header `16 03`, SSH banner `SSH-2.0-`).

## DNS

Record types in tunneling and recon:

| Type | Code | Note |
|---|---|---|
| A / AAAA | 1 / 28 | normal lookups; tunnels can encode data in the answer addresses |
| CNAME | 5 | can carry encoded replies |
| MX | 15 | used by some tunnels for larger answers |
| TXT | 16 | most common tunnel record: free-form text, large answers |
| NULL | 10 | binary payload, used by iodine-style tunnels |
| ANY | 255 | recon and amplification |

Tunneling tells:
- Many unique subdomains under one base domain (hundreds per hour from one host)
- Long labels (the DNS limit is 63 bytes per label and 253 for the full name), hex or base32/base64-looking text
- High share of TXT or NULL queries from a workstation
- Steady query rate at odd hours, or traffic volume to one resolver far above other hosts
- Queries that skip the company resolver and go straight to an external one

DGA tells:
- Bursts of NXDOMAIN answers for random-looking names across several TLDs
- One name that resolves after many failures, then traffic to the address it returned

Not tunneling, but looks like it: anti-virus and reputation lookups (hashes as labels), CDN and cloud load balancer names, DNS-based service discovery, DKIM/SPF lookups, `.arpa` reverse lookups.

## HTTP request fields

| Field | What to look for |
|---|---|
| Host | a bare IP address, a host that does not match the SNI or certificate, a newly registered domain |
| User-Agent | `curl/`, `Wget/`, `python-requests/`, `Go-http-client/`, `WindowsPowerShell/`, empty, or a browser string with an impossible OS/version combination |
| Path | `.exe`, `.dll`, `.ps1`, `.hta`, `.bin` downloads, long base64 in the path or query, the same path polled on a timer |
| Method | POST bodies to an IP on a timer (check-ins), PUT/PROPFIND to odd hosts (WebDAV) |

Never paste cookies, `Authorization` headers or session tokens into a report. Mask them to their first 4 characters.

## TLS

- The ClientHello is cleartext up to TLS 1.3: the SNI (server name) shows which site the client asked for
- Encrypted Client Hello (ECH) hides the real SNI behind an outer one; expect this to grow
- Odd signs: SNI missing on traffic to a public IP, SNI that does not match the certificate, self-signed or very new certificates, random-looking SNI
- Client fingerprints (JA3, JA4) can tie traffic to a tool family across IPs; compute them with Zeek or a dedicated tool when needed

## Capture formats

| Format | Magic (first bytes) | Notes |
|---|---|---|
| pcap, microseconds | `d4 c3 b2 a1` (little endian) or `a1 b2 c3 d4` | 24-byte global header, then 16-byte record headers |
| pcap, nanoseconds | `4d 3c b2 a1` or `a1 b2 3c 4d` | same layout, nanosecond fraction |
| pcapng | `0a 0d 0d 0a` | blocks: SHB, IDB (per interface link type and time resolution), EPB per packet |

Common link types: 1 Ethernet, 101 raw IP, 113 Linux cooked (SLL), 276 Linux cooked v2, 0 BSD loopback.

## Useful commands (run by the user on their analysis box)

```bash
shasum -a 256 capture.pcap                                # fingerprint the evidence first
capinfos capture.pcap                                     # span, packet count, link type (Wireshark suite)
tshark -r capture.pcap -q -z conv,ip                      # conversations
tshark -r capture.pcap -Y dns.flags.response==0 -T fields -e dns.qry.name | sort | uniq -c | sort -rn
tshark -r capture.pcap -Y tls.handshake.type==1 -T fields -e ip.dst -e tls.handshake.extensions_server_name
zeek -r capture.pcap                                      # writes conn.log, dns.log, http.log, ssl.log
editcap -A "2026-03-04 08:00:00" -B "2026-03-04 09:00:00" big.pcap window.pcap   # cut a time window
```
