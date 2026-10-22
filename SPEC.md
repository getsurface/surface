# Surface — build spec (single source of truth)

Surface is a free, passive website exposure checker. A visitor pastes a URL; the
backend makes a few ordinary requests to that site, reads what the server sends
back (headers, banners, cookies, certificate), and returns a plain-language
report with fixes. It never probes, stresses, logs in, or sends attack payloads.

Runtime: Node 22, ESM (`"type": "module"`), **zero npm dependencies** (Node
built-ins only). Deploy target: Vercel (static `index.html` + `assets/` and one
serverless function `api/scan.js`). Local dev: `node server.js`.

## Layout and file ownership

```
surface/
  index.html            C  full HTML document (doctype, head, body)
  assets/app.css        C  all styles (no inline <style>)
  assets/app.js         C  all client logic (no inline <script>)
  api/scan.js           B  Vercel handler (also reused by server.js)
  api/_lib/guard.js     B  input normalization + SSRF protection
  api/_lib/fetcher.js   B  safe HTTP(S) client -> Snapshot
  api/_lib/scan-core.js B  runScan(): rate limit -> guard -> fetch -> analyze
  api/_lib/errors.js    B  ScanError class + code->HTTP status map
  api/_lib/rules.js     A  rule catalog
  api/_lib/analyze.js   A  analyze(snapshot) -> Report
  server.js             B  zero-dep local dev server
  test/analyze.test.js  A  node:test, uses test/fixtures/*.json
  test/guard.test.js    B  node:test
  test/fixtures/        A  snapshot fixtures
  package.json, vercel.json, README.md, SPEC.md   integrator (do not edit)
```

Only edit files you own. `api/_lib/` is excluded from Vercel routing because of
the underscore. Tests run with `node --test` from the project root.

---

## Contract 1 — Snapshot (fetcher output, analyzer input)

```js
{
  input: "example.com",                 // raw user input, trimmed
  requestedUrl: "https://example.com/", // normalized URL actually requested first
  finalUrl: "https://www.example.com/", // URL after redirects
  status: 200,                          // final HTTP status
  redirects: [ { from: "https://example.com/", to: "https://www.example.com/", status: 301 } ],
  redirectStop: null,                   // "limit" (5 redirects) | "loop" | "unfollowable" | null —
                                        // set when the final response is itself a redirect we stopped at
  headers: { "server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3" },
      // final response headers. Names lowercased. Repeated headers joined with ", ".
      // Each value capped at 8 KB. Only the first Location is kept. set-cookie is NOT in here.
  setCookies: [ "PHPSESSID=abc; path=/", "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax" ],
      // raw Set-Cookie strings from ALL hops, de-duplicated by cookie name (last wins)
  httpProbe: { result: "redirects-to-https" | "serves-http" | "no-http" | "error", status: 301 | null, location: "https://..." | null } | null,
      // result of GET http://<host>/ without following redirects. null when not run
      // (it is not run when the site itself is only reachable over plain HTTP).
  tls: {
    valid: true,                 // false when the certificate failed verification
    error: null,                 // e.g. "CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT", "ERR_TLS_CERT_ALTNAME_INVALID"
    validTo: "2027-01-14T23:59:59.000Z" | null,
    daysLeft: 84 | null,         // Math.floor((validTo - now) / 86400000)
    issuer: "Let's Encrypt" | null,  // issuer O, else CN
    protocol: "TLSv1.3" | null
  } | null,                      // null when the final URL is http:
  timingMs: 312,                 // wall time of the main request chain
  scannedAt: "2026-10-22T15:20:00.000Z"
}
```

## Contract 2 — Report (analyzer output, API payload, frontend input)

```js
{
  target: {
    input: "example.com",
    url: "https://www.example.com/",   // finalUrl
    host: "www.example.com",
    status: 200,
    timingMs: 312,
    redirects: 1,                      // redirects.length
    scannedAt: "2026-10-22T15:20:00.000Z"
  },
  score: 62,                           // exposure 0..100, higher = more exposed
  level: "low" | "moderate" | "high",
  counts: { total: 17, crit: 2, warn: 4, info: 3, ok: 8 },
  findings: [ Finding, ... ]           // sorted crit, warn, info, ok; catalog order within a severity
}
```

Finding:

```js
{
  id: "server-header",          // rule id; multi-finding rules use "<rule>:<suffix>"
  category: "versions" | "transport" | "headers" | "cookies" | "cors" | "disclosure",
  severity: "crit" | "warn" | "info" | "ok",
  title: "Server version exposed",     // plain English, <= 48 chars, sentence case, no trailing period
  desc: "The exact version is public, so anyone can look up known holes for it.",  // one sentence, owner's point of view
  evidence: "Server: nginx/1.18.0",    // <= 64 chars, shown in monospace; truncate long values with "…"
  fix: "Hide the version. Nginx: add `server_tokens off;` …"  // 1-3 sentences, concrete, may contain `code` spans
}
```

### Scoring (exact)

`points = 20 × crit + 8 × warn + 1 × info`, `score = min(100, points)`.
`level = score < 25 ? "low" : score < 55 ? "moderate" : "high"`.
`counts.total = findings.length`. A rule that is not applicable returns `null`
and produces no finding.

### Rule catalog (Agent A implements exactly these, in this order)

Evidence `—` means "header absent". Header lookups are case-insensitive (names
are already lowercased in the snapshot); compare values case-insensitively.
"Has a version" means the value matches `/\d+\.\d+/` or `/\/\s*\d/`.

**versions**
1. `server-header` — `server`. Absent → ok "Server software hidden". A hosting
   or CDN banner (cloudflare, vercel, netlify, gws, awselb/2.0, …) → info
   "Server software named", even with a build number. Has a version → crit
   "Server version exposed". Otherwise → info "Server software named".
   Fix mentions nginx `server_tokens off;`, Apache `ServerTokens Prod` + `ServerSignature Off`.
2. `powered-by` — `x-powered-by`. Absent → ok "No framework banner". Has a
   version → crit "Backend version leaked". Otherwise → warn "Backend framework named".
   Fix mentions PHP `expose_php = Off`, Express `app.disable('x-powered-by')`,
   Next.js `poweredByHeader: false`.
3. `fingerprints` — one finding per header present:
   `x-aspnet-version`, `x-aspnetmvc-version` → crit (always versioned);
   `x-generator` → crit if has a version else warn;
   `x-drupal-cache` / `x-drupal-dynamic-cache` → info "Drupal detected";
   `x-runtime` → info "Ruby runtime header";
   `link` containing `api.w.org` → info "WordPress detected".
   Ids `fingerprints:<header>`. None present → one ok `fingerprints` "No CMS fingerprints".

**transport**
4. `https` — final URL is `https:` → ok "Served over HTTPS" (evidence `TLS: ${tls.protocol ?? "on"}`);
   else crit "No HTTPS" (evidence the final URL).
5. `http-redirect` — `httpProbe` null or `result: "error"` → null.
   `redirects-to-https` → ok "HTTP redirects to HTTPS" (evidence `${status} → https`);
   `serves-http` → warn "Plain HTTP still works" (evidence `HTTP ${status}`);
   `no-http` → ok "Plain HTTP is closed" (evidence `port 80 closed`).
6. `hsts` — only when final URL is https (else null). `strict-transport-security`
   absent → warn "HSTS not enabled"; `max-age` < 15552000 (180 days) → warn
   "HSTS max-age too short"; else ok "HSTS enabled" (evidence `max-age=N` plus `; includeSubDomains` if set).
7. `certificate` — `tls` null → null. `valid === false` → crit "Certificate not trusted"
   (evidence the error code). `daysLeft < 0` → crit "Certificate expired";
   `< 14` → crit "Certificate expires in N days"; `< 30` → warn "Certificate expires soon";
   else ok "Certificate valid" (evidence `${daysLeft} days left · ${issuer}`).

**headers**
8. `csp` — `content-security-policy` absent: if `content-security-policy-report-only`
   present → info "CSP in report-only mode"; else warn "No content security policy".
   Present: effective script directive = `script-src`, else `default-src`. If it
   contains `'unsafe-inline'` and no `'nonce-` / `'sha256-` / `'sha384-` / `'sha512-`
   / `'strict-dynamic'` → info "CSP allows inline scripts". If no policy restricts
   scripts (no `script-src`/`default-src`, or only `*` / bare schemes like `https:`
   without a nonce/hash) → info "CSP doesn't restrict scripts". Else ok "Content security policy set".
9. `clickjacking` — CSP `frame-ancestors` wins when present (browsers ignore
   X-Frame-Options then): `*` or a bare scheme → warn "Clickjacking protection missing";
   anything else → ok. Without it, `x-frame-options` `DENY`/`SAMEORIGIN` → ok
   "Clickjacking protection on". Otherwise warn
   "Clickjacking protection missing" (ALLOW-FROM counts as missing; it is obsolete).
10. `nosniff` — `x-content-type-options` equals `nosniff` → ok "MIME sniffing blocked";
    else warn "MIME sniffing not blocked".
11. `referrer-policy` — absent → info "No referrer policy" (browsers default to a
    safe value, say so). Contains `unsafe-url` or `no-referrer-when-downgrade` → warn
    "Referrer policy leaks full URLs". Else ok "Referrer policy set".
12. `permissions-policy` — present → ok "Permissions policy set"; absent → info "No permissions policy".

**cookies** — parse each Set-Cookie: name = text before the first `=`, attributes
are the `;`-separated parts after the first part, matched case-insensitively.
"Sensitive" name = `/sess|sid|auth|token|jwt|login|logged|remember|csrf/i`, except
`XSRF-TOKEN` and `csrftoken`, which front-end code is designed to read.
13. `cookie-secure` — no cookies → one ok `cookies` "No cookies on first visit"
    (evidence `Set-Cookie: —`). On an https site, any cookie without `Secure` → warn
    "Cookies sent without Secure" (evidence `name (+N more)`). Else ok "Cookies marked Secure".
    On a plain-http site → null (the HTTPS finding already covers it).
14. `cookie-httponly` — no cookies → null. A sensitive cookie without `HttpOnly` →
    warn "Session cookie readable by scripts"; only non-sensitive ones missing it →
    info "Some cookies readable by scripts"; all have it → ok "Cookies are HttpOnly".
15. `cookie-samesite` — no cookies → null. Any `SameSite=None` without `Secure` →
    warn "SameSite=None without Secure"; any cookie missing `SameSite` → info
    "Cookies without SameSite"; else ok "Cookies set SameSite".

**cors**
16. `cors` — `access-control-allow-origin`: `*` together with
    `access-control-allow-credentials: true` → crit "CORS open with credentials";
    `*` → info "Open to any origin" (fine for public assets, say so);
    `null` with credentials → crit "CORS trusts the null origin"; `null` → warn "CORS allows the null origin";
    another value → ok "CORS restricted"; absent → ok "No cross-origin access" (evidence `ACAO: —`).

**disclosure**
17. `hosting` — first match wins → info "Hosting provider identified" (evidence `via: <name>`):
    `cf-ray` or server contains cloudflare → Cloudflare; `x-vercel-id` → Vercel;
    `x-nf-request-id` → Netlify; `x-amz-cf-id` → Amazon CloudFront; `x-fastly-request-id`
    or `x-served-by` containing `cache-` → Fastly; `x-github-request-id` → GitHub Pages;
    `x-azure-ref` → Azure Front Door; `fly-request-id` → Fly.io; `x-render-origin-server` → Render;
    server contains `akamaighost` → Akamai; server equals `google frontend` or `gws` → Google.
    No match → null.
18. `debug-headers` — `x-debug-token` or `x-debug-token-link` → crit "Debug profiler exposed".
    Any of `x-backend-server`, `x-server-name`, `x-upstream`, `x-real-server`,
    `x-forwarded-server`, `x-host`, `x-served-by` whose value contains a private IPv4
    (`10.`, `172.16-31.`, `192.168.`, `127.`), or `.internal`, `.local`, `.lan`,
    `localhost`, or `ip-10-` → warn "Internal host name leaked" (evidence `header: value`).
    Both present → both findings, ids `debug-headers:token` and `debug-headers:internal`.
    Neither → ok "No debug headers".
19. `status` — final status ≥ 500 → warn "Server returned an error"; 400–499 → info
    "Page returned HTTP N" (desc: results may be partial). Plus, when `redirectStop`
    is set, `status:redirects`: loop → warn "Redirect loop"; limit/unfollowable → info
    "Redirects didn't reach a page". Otherwise null.

Exports from `api/_lib/analyze.js`:
`analyze(snapshot) -> Report`, `scoreFindings(findings) -> { score, level, counts }`.
Exports from `api/_lib/rules.js`: `RULES` (array of `{ id, category, run(snapshot) }`,
where `run` returns `Finding | Finding[] | null`). Both modules are pure: no I/O,
no `Date.now()` except none needed (time comes from the snapshot).

---

## Contract 3 — HTTP API

`GET /api/scan?url=<input>` with request header `X-Surface: 1`. Same origin only:
requests without the header, or with `Sec-Fetch-Site` other than `same-origin`,
get `403 forbidden` before rate limiting. No CORS headers are ever sent, so other
sites can't add the header (the preflight fails).

Success `200`: `{ "ok": true, "report": Report }`

Error: `{ "ok": false, "error": { "code": "<code>", "message": "<plain English>" } }`

| code | HTTP | message (suggested) |
|---|---|---|
| `invalid_url` | 400 | That doesn't look like a website address. Try something like example.com. |
| `blocked_target` | 400 | That address points to a private or local network, so it can't be checked. (or the port/host specific reason) |
| `rate_limited` | 429 | Too many checks in a short time. Wait a minute and try again. |
| `dns_failed` | 422 | We couldn't find that domain. Check the spelling. |
| `unreachable` | 502 | The site didn't respond. It may be down or blocking automated checks. |
| `timeout` | 504 | The site took too long to answer. Try again in a moment. |
| `method_not_allowed` | 405 | Use GET. |
| `forbidden` | 403 | Checks can only be started from the Surface website. |
| `internal` | 500 | Something went wrong on our side. Try again. |

Response headers: `Content-Type: application/json; charset=utf-8`,
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. Never include
stack traces. The handler reads the query from `req.url`
(`new URL(req.url, "http://localhost").searchParams.get("url")`) and writes with
`res.statusCode`, `res.setHeader`, `res.end` so it runs unchanged on Vercel and
on plain `node:http`.

## Security requirements (Agent B)

- Normalize: trim, max 2048 chars, prepend `https://` when no scheme, only
  `http:`/`https:`, reject userinfo, port must be empty/80/443, drop query and
  hash (privacy), keep path. Hostname must contain a dot unless it is an IP
  literal. Reject `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.lan`,
  `*.home.arpa`, `*.intranet`, `*.corp`.
- Resolve DNS **inside the socket connect** via the `lookup` option of
  `node:http`/`node:https` `request()`, so the validated IP is the one connected
  to (defeats DNS rebinding). Block if ANY resolved address is non-public:
  IPv4 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24,
  192.88.99/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4;
  IPv6 ::/128, ::1, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32, 100::/64, and
  IPv4-mapped (`::ffff:a.b.c.d`) / NAT64 (`64:ff9b::a.b.c.d`) forms checked against
  the IPv4 list. IP-literal hosts go through the same check.
- Every redirect hop is re-validated with the same rules (scheme, port, host,
  IP). Max 5 redirects, loop detection.
- DNS goes through c-ares (`dns.Resolver`, 2.5 s × 2 tries), not getaddrinfo,
  so unresponsive nameservers can't tie up libuv's thread pool.
- Never read response bodies: capture status, headers, certificate, then
  `res.destroy()`. Header block ≤ 16 KB, each value capped at 8 KB, and every rule
  regex is linear-time on hostile input.
- Timeouts: 8 s per hop, 5 s for the HTTP probe, whole scan budget ≤ 15 s.
- HTTPS first; on connection failure (ECONNREFUSED, ECONNRESET, timeout, TLS
  protocol error) fall back to `http://` same host/path. On certificate
  verification errors, retry once with `rejectUnauthorized: false` and record
  `tls.valid = false` + the error code.
- User-Agent: `SurfaceCheck/1.0 (+passive header check)`; `Accept-Encoding: identity`.
- In-memory rate limit: 8 scans / 60 s per client IP (best effort on serverless).
  Client IP = first entry of `x-forwarded-for`, else `x-real-ip`, else socket address.
- `SURFACE_ALLOW_PRIVATE=1` env disables the IP/hostname blocklist **for local
  testing only** (port policy too). Default off, and ignored whenever `VERCEL` is set.

## Frontend requirements (Agent C)

- Keep the current design exactly: Apple palette tokens (light + dark), SF/system
  type, Geist Mono for numbers and evidence, nav, hero pills with icons, Exposure
  meter, stat tiles, segmented filter, findings table, How it works, FAQ
  accordion, CTA band, footer.
- CSP-ready: no inline `<style>`, no inline `<script>`, no `style=""` attributes,
  no inline event handlers. Dynamic widths are set with `element.style.width` in JS.
- **Never inject report data with `innerHTML`.** Header values come from arbitrary
  third-party servers — build DOM with `createElement` + `textContent`.
- On load the page shows a complete example report (a `SAMPLE_REPORT` object that
  follows Contract 2) clearly labeled as an example.
- Form: URL input + required consent checkbox ("I own this site or have
  permission to check it.") + submit. States: idle, loading (disabled button,
  spinner, "Checking…", skeleton rows, `aria-busy`), success (render, scroll to
  report), error (inline message from `error.message`; network failure / 404 /
  non-JSON → "The scanner isn't reachable from here. Deploy the project to run
  live checks.").
- Each finding row expands (click / Enter / Space, `aria-expanded`) to show
  "How to fix" with the `fix` text (render `code` spans safely as `<code>`
  elements by splitting on backticks, still using textContent).
- Segmented control: All · Urgent · To fix · Info · Good, each with its count;
  horizontally scrollable on narrow screens.
- Meter width = score%; number, pill and fill colored by level.
- Copy that promises behavior must match the backend: a few ordinary requests
  (HTTPS page, plain-HTTP check, certificate), nothing stored by us, hosting logs
  may record the checked URL.
- `?url=` query param pre-fills the input (does not auto-run).
