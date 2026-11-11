# MTA-STS Checker

A free, single-page MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) checker and generator. Live at [mtasts.hbenali.ovh](https://mtasts.hbenali.ovh).

No backend, no build step, no dependencies: static HTML, CSS and one small script calling a public DNS-over-HTTPS API from the browser.

## Features

- **Lookup** of the `_mta-sts.<domain>` TXT (`v=STSv1; id=`), the `_smtp._tls.<domain>` TXT (`v=TLSRPTv1; rua=`) and the domain's MX records, with validation of each record
- **Policy validator**: paste the policy text and check `version: STSv1`, `mode` (enforce/testing/none), `mx:` patterns (with `*.` wildcard), `max_age` (warns under 1 day and above 31557600 s), and that every real MX host matches an `mx:` line and every `mx:` line matches a real host
- **curl command** and link for the policy URL, built only from the validated domain
- **Generator** for the policy file, the `_mta-sts` TXT and the `_smtp._tls` TXT, with load-from-lookup
- Cross-links to the MX, SSL, DNSSEC, DMARC, SPF, DKIM and CAA tools for the same domain
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`, `connect-src https://dns.google`)

## What a browser cannot do

The policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` cannot be fetched by the page. A cross-origin read needs CORS headers on the policy server, and in testing nearly every domain refuses (gmail.com, outlook.com, yahoo.com, fastmail.com, google.com and others fail; only a few such as proton.me allow it). Allowing it would also need `connect-src https:` in the CSP, which is not worth it. The page therefore asks you to run the curl command and paste the result. It also cannot check the policy server's certificate or the TLS of your MX hosts.

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

`?domain=example.com` runs a lookup on load.

## Data sources

- [dns.google](https://developers.google.com/speed/public-dns/docs/doh): DNS-over-HTTPS for TXT and MX lookups

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
