# IOC handling cheat sheet

## Defang conventions

| Type | Live | Defanged |
|---|---|---|
| URL scheme | `http://`, `https://` | `hxxp[://]`, `hxxps[://]` |
| Dot | `evil.example.test` | `evil[.]example[.]test` |
| Email | `a@evil.example.test` | `a[@]evil[.]example[.]test` |
| IPv4 | `203.0.113.45` | `203[.]0[.]113[.]45` |

`ioc_extract.py` refangs `hxxp`, `hxxps`, `fxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `[at]`, `[@]`, `[:]`, `[://]` and `\.` on input, and writes the table above with `--defang`. Query strings are not defanged, only the scheme and host.

Rule of thumb: defanged in anything a human reads (tickets, chat, email, reports), refanged only inside tools (SIEM lookups, blocklists, TIP imports).

## Pyramid of pain (David Bianco)

From easy for the attacker to change (bottom) to hard (top):

1. Hash values (trivial: recompile, add a byte)
2. IP addresses (easy: new VPS)
3. Domain names (simple: register another)
4. Network and host artifacts (annoying: URI patterns, user agents, registry keys, file names)
5. Tools (challenging: new tooling)
6. TTPs (tough: change how they operate)

Use hashes and IPs for fast scoping of a known incident. Spend detection effort on artifacts and TTPs, they stay useful after the IOCs rot.

## IOC quality checks before sharing or blocking

- **Context**: what was it used for (C2, payload host, phishing sender)? An IOC without a role is noise
- **Age**: IPs on cloud and VPS hosting get reassigned within days. Put first-seen and last-seen dates on everything
- **Shared infrastructure**: CDNs, cloud storage, URL shorteners, mail providers and public paste sites host good and bad content. Block the full URL, not the domain
- **Sinkholes and parking**: resolve before blocking; a sinkholed domain hitting your network is still a good lead (infected host), but the IP is the researcher's
- **Benign noise**: OS update, certificate (OCSP/CRL), telemetry and schema domains appear in every sandbox report. `ioc_extract.py` drops the common ones; review the rest by hand
- **Hash type**: prefer SHA256. MD5 and SHA1 are fine for lookups but collide in theory and are weak evidence on their own
- **Private and documentation ranges**: RFC 1918, loopback and link-local IPs are internal context, not indicators; 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32 only appear in examples

## Search order for a fresh IOC list

1. DNS logs and proxy logs for domains and URLs (widest coverage)
2. Firewall / NetFlow for IPs, both directions
3. EDR for hashes, file paths, registry keys
4. Email gateway for sender addresses, subjects, attachment hashes
5. Identity logs for the users and source IPs involved

Record every search (where, time range, result) so "no hits" is defensible.

## Sharing (TLP 2.0)

| Label | Who can see it |
|---|---|
| TLP:RED | Named recipients only, no further sharing |
| TLP:AMBER+STRICT | Recipient's organisation only |
| TLP:AMBER | Recipient's organisation and its clients, need to know |
| TLP:GREEN | The wider community, not public |
| TLP:CLEAR | Anyone, public |

Strip victim details (internal hostnames, usernames, internal IPs, email addresses of staff) before sharing outside the organisation, even at TLP:AMBER.
