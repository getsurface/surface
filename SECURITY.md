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
- Anything that makes Surface send traffic beyond its ordinary requests: a page fetch over HTTPS
  that follows up to five redirects (one certificate retry per hop, and one fallback to plain HTTP
  when HTTPS can't connect), plus one plain-HTTP probe of the home page.
- Injection of report data into the page as HTML or script.
- Bypassing the per-client rate limit on `/api/scan`, or making another website's visitors run
  scans from their browsers. Calling the API from your own scripts is expected and not a bug.

## Out of scope

- Findings about third-party sites shown in a report. Contact that site's owner.
- Volumetric denial of service against the hosting provider.
- Missing headers on surface-theta.vercel.app that the scanner itself reports as informational.
