# Surface

**Live:** https://surface-theta.vercel.app

A free website exposure checker. Paste a URL and see what the server reveals to any stranger (software versions, security headers, cookies, certificate), plus how to close each gap.

The check is passive: a few ordinary requests (the page over HTTPS, a plain-HTTP check and the certificate handshake). It never probes, stresses or logs in, and it doesn't even read the page body.

## Run locally

Requires Node.js 20+. There are no dependencies, so no `npm install`.

```bash
npm run dev        # http://localhost:3000
npm test           # 214 tests
```

Locally, only public sites can be scanned; internal addresses are blocked exactly as in production.
To test against your own local server there is a `SURFACE_ALLOW_PRIVATE=1` flag.
**Never enable it in production.** It turns off the protection against scanning internal networks.

## Deploy to Vercel

**Option 1: from GitHub (simplest)**
1. Push the folder to a GitHub repository.
2. On vercel.com: Add New → Project → import the repository.
3. Framework Preset: **Other**. Leave Build Command and Output Directory empty.
4. Deploy. The site is live in about a minute.

**Option 2: from the terminal**
```bash
npm i -g vercel
vercel          # preview
vercel --prod   # production
```

Custom domain: Project → Settings → Domains.

### Before launch
- **Rate limit at the Vercel level.** The built-in limit (8 scans per minute per IP) lives in one instance's memory, so it weakens as traffic spreads across instances. Add a rule: Project → Firewall → Rate Limiting → path `/api/scan`, for example 10 requests per minute per IP.
- **Scan yourself.** Paste your deployed site's address. It should get a near-clean report, because `vercel.json` sets all the security headers it needs.

## How it works

```
index.html, assets/      frontend (design, report, filters, "How to fix")
api/scan.js              serverless function: GET /api/scan?url=...
api/_lib/guard.js        address validation and SSRF protection
api/_lib/fetcher.js      safe requests to the target site → response snapshot
api/_lib/rules.js        19 rules, each with "what it means" and "how to fix"
api/_lib/analyze.js      snapshot → report, score 0–100
api/_lib/scan-core.js    rate limit → validation → requests → analysis
server.js                local dev server (not deployed to Vercel)
SPEC.md                  full spec: data formats, rules, error codes
```

### What it checks
| Group | Checks |
|---|---|
| Versions | server banner, X-Powered-By, CMS fingerprints (WordPress, Drupal, ASP.NET, generators) |
| Transport | HTTPS, HTTP→HTTPS redirect, HSTS, certificate expiry and trust |
| Headers | CSP, clickjacking protection, nosniff, Referrer-Policy, Permissions-Policy |
| Cookies | Secure, HttpOnly on session cookies, SameSite |
| CORS | open access, especially with credentials |
| Disclosure | debug profiler, internal host names, hosting/CDN, server errors |

Score: `20 × urgent + 8 × to fix + 1 × info`, capped at 100. Under 25 is Low, under 55 is Moderate, above that is High.

### How the service protects itself
- Blocks local, private, reserved and cloud-metadata addresses (IPv4 and IPv6, including tricky forms like `2130706433` and `0x7f.1`).
- DNS is validated at connect time, so swapping the address between check and request (DNS rebinding) doesn't work.
- Every redirect is re-validated, up to 5.
- Only ports 80 and 443, response bodies are never read, timeouts on every step.
- Values from third-party headers are rendered as text only, so a header can't inject a script.
- Scans can only be started from our own page (`X-Surface` header plus a `Sec-Fetch-Site` check), so other sites can't run scans through their visitors' browsers.
- Huge or crafted headers are capped and parsed in milliseconds; DNS has a hard timeout, so a silent domain can't hang the function.
- The `SURFACE_ALLOW_PRIVATE` flag is ignored on Vercel, even if set by mistake.
- Reports are not stored.

The API is closed to outside callers: a direct `curl` without the `X-Surface: 1` header gets a 403. That's expected.
