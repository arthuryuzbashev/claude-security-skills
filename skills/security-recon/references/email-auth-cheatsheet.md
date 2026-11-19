# Email authentication cheat sheet

SPF (RFC 7208), DKIM (RFC 6376, key sizes updated by RFC 8301), DMARC (RFC 9989, May 2026, replaces RFC 7489; reports in RFC 9990 and RFC 9991), MTA-STS (RFC 8461), TLS-RPT (RFC 8460), BIMI (IETF draft, not yet an RFC).
All are DNS TXT records (plus one HTTPS file for MTA-STS and an SVG logo for BIMI).

## Contents

- What each one does
- Mailbox provider requirements
- SPF, DMARC, DKIM, MTA-STS and TLS-RPT, BIMI
- Quick lookups

## What each one does

| Record | Lives at | Protects against | Without it |
|---|---|---|---|
| SPF | `<domain>` TXT | Unlisted servers using the envelope sender (MAIL FROM) | Any server can claim to send for you |
| DKIM | `<selector>._domainkey.<domain>` TXT | Message tampering, unsigned forgeries | No signature to align for DMARC |
| DMARC | `_dmarc.<domain>` TXT | Spoofing the visible From address | Receivers decide on their own, spoofing works |
| MTA-STS | `_mta-sts.<domain>` TXT + `https://mta-sts.<domain>/.well-known/mta-sts.txt` | TLS downgrade on mail sent to you | Senders fall back to plain or unverified TLS |
| TLS-RPT | `_smtp._tls.<domain>` TXT | Silent TLS delivery failures | You never hear about them |

## Mailbox provider requirements

- Gmail and Yahoo (since February 2024) and Outlook.com (since May 5 2025) require bulk senders (over about 5000 messages a day to their users) to have SPF and DKIM passing, a DMARC record of at least `p=none` with SPF or DKIM aligned to the From domain, and one-click unsubscribe for marketing mail. Outlook started by sending non-compliant bulk mail to junk, with rejection to follow
- All senders, bulk or not, need SPF or DKIM and valid forward and reverse DNS for the sending IP to stay out of spam

DMARC passes when SPF or DKIM passes and the passing domain aligns with the From domain. DKIM alignment survives forwarding better than SPF, so get DKIM signing right for every sender.

## SPF

```
v=spf1 include:_spf.mailprovider.example ip4:192.0.2.0/24 -all
```

- One record per name. Two `v=spf1` records = permerror
- Qualifiers: `+` pass (default when omitted), `-` fail, `~` softfail, `?` neutral. `+all` or bare `all` = anyone may send
- Lookup limit 10: `include`, `a`, `mx`, `ptr`, `exists` and `redirect` each cost one, counted recursively. `ip4`, `ip6` and `all` are free. Over 10 = permerror
- Cutting lookups: drop senders you no longer use, replace `a`/`mx` with `ip4` when the addresses are stable, move bulk mail (newsletters, CRM) to a subdomain with its own SPF, flatten only includes you control (provider IPs change)
- Domains that never send mail: `v=spf1 -all`, plus DMARC `p=reject` and a null MX (`MX 0 .`, RFC 7505)

## DMARC

```
v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=r; aspf=r
```

| Tag | Meaning | Default |
|---|---|---|
| `p` | Policy for the domain: `none`, `quarantine`, `reject` | RFC 9989: recommended. A record with a valid `rua` but no valid `p` is treated as `none` |
| `sp` | Policy for subdomains | same as `p` |
| `np` | Policy for subdomains that do not exist in DNS (new in RFC 9989) | same as `sp`, then `p` |
| `t` | Test mode (new in RFC 9989): `y` applies one level less (reject acts as quarantine, quarantine as none) | `n` |
| `psd` | `y` for public suffix operators, `n` to say this is an organizational domain, `u` unknown | `u` |
| `rua` | Where aggregate (daily XML) reports go. Receivers only have to support `mailto:` | none |
| `ruf` | Failure (forensic) reports; many receivers do not send them | none |
| `adkim` / `aspf` | Alignment, `r` relaxed (same org domain) or `s` strict (exact) | `r` |
| `fo` | When to send failure reports | `0` |
| `pct` | Removed in RFC 9989. Under RFC 7489 it was the share of failing mail the policy applied to; updated receivers ignore it | (gone) |

RFC 9989 also dropped `rf` and `ri`, and finds the organizational domain with a DNS tree walk instead of the Public Suffix List. Old tags do no harm, but do not rely on `pct` any more: some receivers still honor it and some apply the full policy.

Rollout that does not break mail:

1. `p=none; rua=...` and read reports for 2-4 weeks. List every legitimate sender
2. Fix SPF and DKIM for each sender until they pass with alignment
3. `p=quarantine; t=y` (acts as none while you watch the reports), then drop `t=y`
4. `p=reject; t=y` (acts as quarantine), then drop `t=y`. Keep reading reports; new SaaS tools show up as failures
5. Once everything passes, set `np=reject` explicitly if `sp` is softer, so made-up subdomains are rejected

`rua` addresses on another domain need that domain to publish `<yourdomain>._report._dmarc.<theirdomain>` TXT `v=DMARC1` to accept them. Report services handle this for you.

## DKIM

```
v=DKIM1; k=rsa; p=MIIBIjANBgkq...
```

- RSA 2048 bits for new keys. RFC 8301: verifiers must not accept keys under 1024 bits; signers should use at least 2048
- Ed25519 (`k=ed25519`, RFC 8463) is allowed but not every receiver verifies it, so sign with RSA too if you use it
- Long keys are split into several quoted strings in one TXT record. That is normal; DNS joins them
- Revoke an old selector by publishing an empty `p=`
- Selectors cannot be listed. Find yours in a real message header: `DKIM-Signature: ... d=example.com; s=selector1`
- Common selectors by provider: Google Workspace `google`, Microsoft 365 `selector1` / `selector2`, many ESPs `k1`, `s1`, `s2`

## MTA-STS and TLS-RPT

```
_mta-sts.example.com.   TXT "v=STSv1; id=20260101T000000"
_smtp._tls.example.com. TXT "v=TLSRPTv1; rua=mailto:tls-reports@example.com"
```

Policy file at `https://mta-sts.example.com/.well-known/mta-sts.txt` (valid public certificate required):

```
version: STSv1
mode: testing
mx: mx1.example.com
mx: *.mail.example.com
max_age: 604800
```

- Start with `mode: testing` and TLS-RPT on, read the reports, then `mode: enforce`
- Change `id` in the TXT record every time the policy file changes, or senders keep the cached one
- Every MX host must match an `mx:` line and present a valid certificate for its name, or enforce mode blocks delivery
- `max_age` is in seconds, at most 31557600 (about a year). Weeks are common

## BIMI

```
default._bimi.example.com. TXT "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem"
```

- Shows your logo next to authenticated mail. Optional, and only worth it once DMARC is enforcing
- Prerequisite: DMARC `p=quarantine` or `p=reject` for the domain, no `sp=none`, no `pct` below 100
- `l=` an HTTPS URL to an SVG Tiny Portable/Secure file. `l=` empty means opt out
- `a=` a mark certificate: Gmail needs a Verified Mark Certificate (VMC, registered trademark) or a Common Mark Certificate (CMC); Apple Mail needs a VMC. Yahoo shows logos without one for senders with good reputation
- Still an IETF draft (draft-brotman-ietf-bimi-guidance), so check provider docs before relying on a detail

## Quick lookups

```bash
dig +short TXT example.com
dig +short TXT _dmarc.example.com
dig +short TXT selector1._domainkey.example.com
dig +short TXT _mta-sts.example.com
dig +short TXT _smtp._tls.example.com
dig +short TXT default._bimi.example.com
curl -s https://mta-sts.example.com/.well-known/mta-sts.txt
```
