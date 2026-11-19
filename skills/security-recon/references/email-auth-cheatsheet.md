# Email authentication cheat sheet

SPF (RFC 7208), DKIM (RFC 6376, key sizes updated by RFC 8301), DMARC (RFC 7489), MTA-STS (RFC 8461), TLS-RPT (RFC 8460).
All five are DNS TXT records (plus one HTTPS file for MTA-STS).

## What each one does

| Record | Lives at | Protects against | Without it |
|---|---|---|---|
| SPF | `<domain>` TXT | Unlisted servers using the envelope sender (MAIL FROM) | Any server can claim to send for you |
| DKIM | `<selector>._domainkey.<domain>` TXT | Message tampering, unsigned forgeries | No signature to align for DMARC |
| DMARC | `_dmarc.<domain>` TXT | Spoofing the visible From address | Receivers decide on their own, spoofing works |
| MTA-STS | `_mta-sts.<domain>` TXT + `https://mta-sts.<domain>/.well-known/mta-sts.txt` | TLS downgrade on mail sent to you | Senders fall back to plain or unverified TLS |
| TLS-RPT | `_smtp._tls.<domain>` TXT | Silent TLS delivery failures | You never hear about them |

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
| `p` | Policy for the domain: `none`, `quarantine`, `reject` | required |
| `sp` | Policy for subdomains | same as `p` |
| `pct` | Share of failing mail the policy applies to (0-100) | 100 |
| `rua` | Where aggregate (daily XML) reports go | none |
| `ruf` | Failure (forensic) reports; many receivers do not send them | none |
| `adkim` / `aspf` | Alignment, `r` relaxed (same org domain) or `s` strict (exact) | `r` |
| `fo` | When to send failure reports | `0` |

Rollout that does not break mail:

1. `p=none; rua=...` and read reports for 2-4 weeks. List every legitimate sender
2. Fix SPF and DKIM for each sender until they pass with alignment
3. `p=quarantine; pct=25`, then raise `pct` to 100
4. `p=reject`. Keep reading reports; new SaaS tools show up as failures

`rua` addresses on another domain need that domain to publish `<yourdomain>._report._dmarc.<theirdomain>` TXT `v=DMARC1` to accept them (RFC 7489 section 7.1). Report services handle this for you.

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

## Quick lookups

```bash
dig +short TXT example.com
dig +short TXT _dmarc.example.com
dig +short TXT selector1._domainkey.example.com
dig +short TXT _mta-sts.example.com
dig +short TXT _smtp._tls.example.com
curl -s https://mta-sts.example.com/.well-known/mta-sts.txt
```
