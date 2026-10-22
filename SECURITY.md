# Security policy

Surface fetches websites that strangers point it at, so we take reports about it seriously.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on
[getsurface/surface](https://github.com/getsurface/surface/security/advisories/new).
Do not open a public issue for security problems.

Include the input you used, what happened and what you expected. We aim to reply within 7 days.

## In scope

- Server-side request forgery: any way to make Surface connect to a private, loopback,
  link-local or cloud-metadata address, or to a port other than 80 and 443, including through
  redirects or DNS tricks.
- Anything that makes Surface send traffic beyond its few ordinary requests (one page fetch with
  up to five redirects, one plain-HTTP probe, one TLS handshake).
- Injection of report data into the page as HTML or script.
- Bypassing the rate limit or the same-origin check on `/api/scan`.

## Out of scope

- Findings about third-party sites shown in a report. Contact that site's owner.
- Volumetric denial of service against the hosting provider.
- Missing headers on surface-theta.vercel.app that the scanner itself reports as informational.
