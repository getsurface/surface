// Surface rule catalog (SPEC.md, rules 1-19, in catalog order).
//
// Each rule is { id, category, run(snapshot) } and run() returns a Finding,
// an array of Findings, or null when the rule does not apply. Rules are pure:
// they read only the snapshot they are given and never throw on missing or
// oddly typed fields.

const MAX_EVIDENCE = 64;
const ABSENT = "—";

// "sid" only as its own word ("sid", "connect.sid"), so "sidebar_state" isn't a session cookie.
// `sid` also inside names such as SSID, APISID or __Secure-1PSID, but not visid (visitor ids) or sidebar.
const SENSITIVE_COOKIE = /sess|(?<!vi)sid(?![a-z])|auth|token|jwt|login|logged|remember|csrf/i;
// CSRF cookies that front-end code is designed to read (Angular, Laravel, Django).
const SCRIPT_READABLE_COOKIE = /^(?:xsrf-token|csrftoken)$/i;
// Linear-time on hostile input: /\d+\.\d+/ is quadratic on long digit runs.
const HAS_VERSION = [/\d\.\d/, /\/ *\d/];
const NONCE_OR_HASH = /'(?:nonce-|sha256-|sha384-|sha512-)|'strict-dynamic'/i;
const STRICT_DYNAMIC = /'strict-dynamic'/i;
const PRIVATE_IPV4 =
  /(?<![\d.])(?:10\.\d{1,3}|127\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?!\d|\.\d)/;
const INTERNAL_NAME =
  /\.(?:internal|local|lan)(?![a-z0-9.-])|(?<![a-z0-9-])localhost(?![a-z0-9-])|(?<![a-z0-9])ip-(?:10|172-(?:1[6-9]|2\d|3[01])|192-168)-/i;
const HSTS_MIN_AGE = 15552000; // 180 days
const HSTS_PRELOAD_MIN_AGE = 31536000; // one year, required by hstspreload.org
const DAY_MS = 86400000;
// Valid Referrer-Policy tokens; browsers use the last one they recognise.
const REFERRER_POLICIES = new Set([
  "no-referrer",
  "no-referrer-when-downgrade",
  "same-origin",
  "origin",
  "strict-origin",
  "origin-when-cross-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
]);
// A CSP source that allows any host: "*" or a bare scheme such as "https:".
const WIDE_SOURCE = /^(?:\*|[a-z][a-z0-9+.-]*:)$/;
const REDIRECT_STOPS = new Set(["limit", "loop", "unfollowable"]);

function isWideSourceList(sources) {
  return sources.toLowerCase().split(/\s+/).some((token) => WIDE_SOURCE.test(token));
}

const HEADER_NAMES = {
  "x-aspnet-version": "X-AspNet-Version",
  "x-aspnetmvc-version": "X-AspNetMvc-Version",
  "cf-ray": "CF-Ray",
  "x-nf-request-id": "X-NF-Request-ID",
  "x-github-request-id": "X-GitHub-Request-Id",
  "x-shopid": "X-ShopId",
};

// ---------------------------------------------------------------- helpers

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function cleanText(value) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function isHighSurrogate(code) {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code) {
  return code >= 0xdc00 && code <= 0xdfff;
}

/** Shorten to at most `max` UTF-16 units, ending with "…" when cut. */
function clip(value, max = MAX_EVIDENCE) {
  const text = cleanText(value);
  if (text.length <= max) return text;
  if (max <= 1) return "…";
  let cut = text.slice(0, max - 1);
  if (isHighSurrogate(cut.charCodeAt(cut.length - 1))) cut = cut.slice(0, -1);
  return cut.trimEnd() + "…";
}

/** Like clip(), but keeps the end of the text and drops the start. */
function clipStart(value, max = MAX_EVIDENCE) {
  const text = cleanText(value);
  if (text.length <= max) return text;
  if (max <= 1) return "…";
  let cut = text.slice(text.length - (max - 1));
  if (isLowSurrogate(cut.charCodeAt(0))) cut = cut.slice(1);
  return "…" + cut.trimStart();
}

function displayName(header) {
  if (HEADER_NAMES[header]) return HEADER_NAMES[header];
  return header
    .split("-")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join("-");
}

/** "Label: value", with the value shortened so the whole line fits. */
function labeled(label, value) {
  const room = MAX_EVIDENCE - label.length - 2;
  const shown = value === undefined || value === null || value === "" ? ABSENT : clip(value, room);
  return `${label}: ${shown}`;
}

function headerEvidence(header, value) {
  return labeled(displayName(header), value);
}

function hasVersion(value) {
  return HAS_VERSION.some((re) => re.test(value));
}

function plural(n, one, many) {
  return n === 1 ? one : many;
}

/** "name (+N more)" for a list of cookie names. */
function nameList(names) {
  const rest = names.length - 1;
  const suffix = rest > 0 ? ` (+${rest} more)` : "";
  const first = names[0] === "" || names[0] === undefined ? "(unnamed)" : names[0];
  return clip(first, MAX_EVIDENCE - suffix.length) + suffix;
}

function headerValueToString(value) {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    return value
      .filter((v) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
      .map(String)
      .join(", ");
  }
  return undefined;
}

/** Lowercased, trimmed header map. Empty values count as absent. */
function readHeaders(snapshot) {
  const out = Object.create(null);
  const raw = isObject(snapshot.headers) ? snapshot.headers : {};
  for (const key of Object.keys(raw)) {
    const value = headerValueToString(raw[key]);
    if (value === undefined) continue;
    const trimmed = value.trim();
    if (trimmed === "") continue;
    const name = key.trim().toLowerCase();
    if (!name) continue;
    out[name] = name in out ? `${out[name]}, ${trimmed}` : trimmed;
  }
  return out;
}

function parseCookie(raw) {
  const parts = raw.split(";");
  const first = parts[0];
  const eq = first.indexOf("=");
  const name = (eq === -1 ? first : first.slice(0, eq)).trim();
  const attrs = new Map();
  for (const part of parts.slice(1)) {
    const text = part.trim();
    if (!text) continue;
    const i = text.indexOf("=");
    const key = (i === -1 ? text : text.slice(0, i)).trim().toLowerCase();
    const value = i === -1 ? "" : text.slice(i + 1).trim();
    attrs.set(key, value);
  }
  const sameSiteRaw = attrs.has("samesite") ? attrs.get("samesite").toLowerCase() : null;
  return {
    name,
    secure: attrs.has("secure"),
    httpOnly: attrs.has("httponly"),
    // Only the three valid values count; browsers ignore anything else.
    sameSite: ["lax", "strict", "none"].includes(sameSiteRaw) ? sameSiteRaw : null,
    sensitive: SENSITIVE_COOKIE.test(name) && !SCRIPT_READABLE_COOKIE.test(name),
    maxAge: attrs.has("max-age") ? attrs.get("max-age") : null,
    expires: attrs.has("expires") ? attrs.get("expires") : null,
  };
}

/**
 * True for a Set-Cookie that deletes the cookie instead of setting it
 * (RFC 6265: Max-Age <= 0, or else Expires in the past). `now` is called only
 * when an Expires date has to be compared.
 */
function isDeletion(cookie, now) {
  if (cookie.maxAge !== null && /^-?\d+$/.test(cookie.maxAge)) {
    // A valid Max-Age wins over Expires.
    return Number(cookie.maxAge) <= 0;
  }
  if (cookie.expires === null) return false;
  const expires = Date.parse(cookie.expires);
  return Number.isFinite(expires) && expires < now();
}

/** Reference time for cookie expiry: the scan time, or the clock if the snapshot has none. */
function referenceTime(snapshot) {
  const scanned = typeof snapshot.scannedAt === "string" ? Date.parse(snapshot.scannedAt) : NaN;
  return () => (Number.isFinite(scanned) ? scanned : Date.now());
}

function readCookies(snapshot) {
  const list = Array.isArray(snapshot.setCookies) ? snapshot.setCookies : [];
  const now = referenceTime(snapshot);
  return list
    .filter((c) => typeof c === "string" && c.trim() !== "")
    .map(parseCookie)
    .filter((cookie) => !isDeletion(cookie, now));
}

function readUrl(snapshot) {
  for (const candidate of [snapshot.finalUrl, snapshot.requestedUrl]) {
    if (typeof candidate === "string" && candidate.trim() !== "") return candidate.trim();
  }
  return "";
}

/** "https:", "http:" or null when the scheme can't be determined. */
function readScheme(snapshot) {
  const url = readUrl(snapshot);
  if (!url) return null;
  let protocol = "";
  try {
    protocol = new URL(url).protocol;
  } catch {
    const match = /^([a-z][a-z0-9+.-]*:)/i.exec(url);
    protocol = match ? match[1].toLowerCase() : "";
  }
  return protocol === "https:" || protocol === "http:" ? protocol : null;
}

/** Normalized, read-only view of a snapshot. Never throws. */
function view(snapshot) {
  const s = isObject(snapshot) ? snapshot : {};
  return {
    headers: readHeaders(s),
    cookies: readCookies(s),
    url: readUrl(s),
    scheme: readScheme(s),
    status: Number.isFinite(s.status) ? s.status : null,
    tls: isObject(s.tls) ? s.tls : null,
    httpProbe: isObject(s.httpProbe) ? s.httpProbe : null,
    redirectStop: REDIRECT_STOPS.has(s.redirectStop) ? s.redirectStop : null,
    redirectCount: Array.isArray(s.redirects) ? s.redirects.length : 0,
  };
}

/** Split a CSP header into policies (comma-separated), each a Map of directives. */
function parseCsp(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((policy) => {
      const directives = new Map();
      for (const part of policy.split(";")) {
        const text = part.trim();
        if (!text) continue;
        const [name, ...rest] = text.split(/\s+/);
        const key = name.toLowerCase();
        // The CSP spec keeps the first occurrence of a repeated directive.
        if (!directives.has(key)) directives.set(key, rest.join(" "));
      }
      return directives;
    })
    .filter((directives) => directives.size > 0);
}

function finding(id, category, severity, title, desc, evidence, fix) {
  return { id, category, severity, title, desc, evidence: clip(evidence), fix };
}

const NOTHING_TO_CHANGE = "Nothing to change.";

// Server names set by a hosting platform or CDN, which the site owner can't change.
const PLATFORM_SERVER_NAMES = new Set([
  "cloudflare",
  "akamaighost",
  "google frontend",
  "gws",
  "vercel",
  "netlify",
  "github.com",
  "amazons3",
  "cloudfront",
  "awselb",
  "elb",
  "fly", // Fly.io's proxy: "Fly/51ee4ef9 (2024-11-06)"
]);

function platformServerName(value) {
  const text = value.toLowerCase().trim();
  if (PLATFORM_SERVER_NAMES.has(text)) return true;
  // Load balancers report their own build, e.g. "awselb/2.0". That says nothing about the site.
  const base = text.split("/")[0].trim();
  return base !== text && PLATFORM_SERVER_NAMES.has(base);
}

// ---------------------------------------------------------------- versions

function serverHeader(snapshot) {
  const { headers } = view(snapshot);
  const value = headers.server;
  const make = (severity, title, desc, fix) =>
    finding("server-header", "versions", severity, title, desc, headerEvidence("server", value), fix);

  if (value === undefined) {
    return make(
      "ok",
      "Server software hidden",
      "Your responses don't say which web server software you run.",
      "Nothing to change. Recheck after server upgrades, which can bring the default banner back."
    );
  }
  if (platformServerName(value)) {
    return make(
      "ok",
      "Hosting platform named",
      "Only your hosting platform's name is visible, nothing about your own software.",
      "Nothing to change. Your hosting or CDN provider sets this name and it can't be removed."
    );
  }
  if (hasVersion(value)) {
    return make(
      "warn",
      "Server version exposed",
      "The exact version is public, so anyone can look up known security holes for it.",
      "Hide the version number. Nginx: add `server_tokens off;` to the `http` block; Apache: set `ServerTokens Prod` and `ServerSignature Off`, then reload. IIS on Windows Server 2019 or later: add `<security><requestFiltering removeServerHeader=\"true\" /></security>` under `<system.webServer>` in web.config; older IIS needs a URL Rewrite outbound rule that blanks `RESPONSE_SERVER`."
    );
  }
  return make(
    "info",
    "Server software named",
    "Visitors can see which web server you run, but not which version.",
    "Nothing urgent, since the name alone gives little away. Keep `server_tokens off;` (nginx) or `ServerTokens Prod` and `ServerSignature Off` (Apache) so no version appears; removing the name entirely needs nginx's headers-more module (`more_clear_headers Server;`)."
  );
}

function poweredBy(snapshot) {
  const { headers } = view(snapshot);
  const value = headers["x-powered-by"];
  const fix =
    "Remove the header. PHP: set `expose_php = Off` in php.ini; Express: call `app.disable('x-powered-by')`; Next.js: set `poweredByHeader: false` in next.config.js. On IIS, add `<remove name=\"X-Powered-By\" />` under `customHeaders` in web.config.";
  const make = (severity, title, desc, fixText) =>
    finding("powered-by", "versions", severity, title, desc, headerEvidence("x-powered-by", value), fixText);

  if (value === undefined) {
    return make(
      "ok",
      "No framework banner",
      "Your responses don't name the language or framework behind your site.",
      NOTHING_TO_CHANGE
    );
  }
  if (hasVersion(value)) {
    return make(
      "warn",
      "Backend version leaked",
      "The exact backend version is public, so anyone can check it against lists of known exploits.",
      fix
    );
  }
  return make(
    "info",
    "Backend framework named",
    "Your responses name the framework behind your site, which tells attackers which exploits to try first.",
    fix
  );
}

function fingerprints(snapshot) {
  const { headers } = view(snapshot);
  const out = [];
  const add = (header, severity, title, desc, evidence, fix) =>
    out.push(finding(`fingerprints:${header}`, "versions", severity, title, desc, evidence, fix));

  if (headers["x-aspnet-version"] !== undefined) {
    add(
      "x-aspnet-version",
      "warn",
      "ASP.NET version exposed",
      "The exact .NET version is public, so anyone can look up known security holes for it.",
      headerEvidence("x-aspnet-version", headers["x-aspnet-version"]),
      "Set `<httpRuntime enableVersionHeader=\"false\" />` inside `<system.web>` in web.config."
    );
  }
  if (headers["x-aspnetmvc-version"] !== undefined) {
    add(
      "x-aspnetmvc-version",
      "warn",
      "ASP.NET MVC version exposed",
      "The exact ASP.NET MVC version is public, so anyone can look up known security holes for it.",
      headerEvidence("x-aspnetmvc-version", headers["x-aspnetmvc-version"]),
      "Add `MvcHandler.DisableMvcResponseHeader = true;` to `Application_Start` in Global.asax.cs."
    );
  }
  const generator = headers["x-generator"];
  if (generator !== undefined) {
    const generatorFix =
      "Remove the `X-Generator` header. Nginx: `fastcgi_hide_header X-Generator;` (or `proxy_hide_header X-Generator;` behind a proxy); Apache: `Header unset X-Generator`. Keep the software itself updated either way.";
    if (hasVersion(generator)) {
      add(
        "x-generator",
        "warn",
        "CMS or site builder version exposed",
        "Your pages announce the exact version of the software that builds them, so anyone can look up its known holes.",
        headerEvidence("x-generator", generator),
        generatorFix
      );
    } else {
      add(
        "x-generator",
        "info",
        "CMS or site builder named",
        "Your pages name the software that builds them, which tells attackers which exploits to try.",
        headerEvidence("x-generator", generator),
        generatorFix
      );
    }
  }
  // Drupal sends both cache headers; they are one signal, so report it once.
  const drupalHeader = ["x-drupal-cache", "x-drupal-dynamic-cache"].find((h) => headers[h] !== undefined);
  if (drupalHeader) {
    const name = displayName(drupalHeader);
    add(
      drupalHeader,
      "info",
      "Drupal detected",
      "Visitors can tell your site runs Drupal, which is low risk as long as core and modules stay updated.",
      headerEvidence(drupalHeader, headers[drupalHeader]),
      `Keep Drupal core and modules updated, since this is hard to hide fully. To drop the header, use nginx \`fastcgi_hide_header ${name};\` or Apache \`Header unset ${name}\`.`
    );
  }
  if (headers["x-runtime"] !== undefined) {
    add(
      "x-runtime",
      "info",
      "Ruby runtime header",
      "This header hints that your site runs on Ruby and shows how long each request took to process.",
      headerEvidence("x-runtime", headers["x-runtime"]),
      "Remove it with `config.middleware.delete Rack::Runtime` in config/application.rb, or strip it at nginx with `proxy_hide_header X-Runtime;`."
    );
  }
  const link = headers.link;
  if (link !== undefined && /api\.w\.org/i.test(link)) {
    let segment = cleanText(link.split(",").find((part) => /api\.w\.org/i.test(part)) ?? link);
    const room = MAX_EVIDENCE - "Link: ".length;
    if (segment.length > room) {
      // Keep the api.w.org relation visible: shorten the URL to its path first.
      segment = segment.replace(/<([^<>]*)>/, (whole, url) => {
        try {
          return `<…${new URL(url).pathname}>`;
        } catch {
          return whole;
        }
      });
    }
    add(
      "link",
      "info",
      "WordPress detected",
      "Visitors can tell your site runs WordPress, which is low risk as long as core, themes and plugins stay updated.",
      `Link: ${clipStart(segment, room)}`,
      "Keep WordPress core, themes and plugins updated, since this is hard to hide. To drop the header, add `remove_action('template_redirect', 'rest_output_link_header', 11);` to your theme's functions.php."
    );
  }

  if (out.length === 0) {
    return finding(
      "fingerprints",
      "versions",
      "ok",
      "No CMS fingerprints",
      "Your responses don't carry headers that point to a specific CMS or framework.",
      `CMS headers: ${ABSENT}`,
      NOTHING_TO_CHANGE
    );
  }
  return out;
}

// ---------------------------------------------------------------- transport

function https(snapshot) {
  const { scheme, tls, url } = view(snapshot);
  if (scheme === null) return null;
  if (scheme === "https:") {
    const protocol = tls && typeof tls.protocol === "string" && tls.protocol ? tls.protocol : "on";
    return finding(
      "https",
      "transport",
      "ok",
      "Served over HTTPS",
      "Pages travel encrypted, so nobody between your visitors and your server can read or change them.",
      `TLS: ${protocol}`,
      "Nothing to change. Keep certificate renewal automatic so HTTPS never lapses."
    );
  }
  return finding(
    "https",
    "transport",
    "crit",
    "No HTTPS",
    "Everything between your visitors and your site, including logins and cookies, travels unencrypted.",
    url,
    "Get a free certificate from Let's Encrypt (`certbot --nginx` or `certbot --apache`) or switch on HTTPS in your host's dashboard, then redirect all HTTP traffic to HTTPS. On Cloudflare, set SSL/TLS to Full (strict) and turn on Always Use HTTPS."
  );
}

function httpRedirect(snapshot) {
  const { httpProbe } = view(snapshot);
  if (!httpProbe) return null;
  const status = Number.isFinite(httpProbe.status) ? httpProbe.status : null;
  const make = (severity, title, desc, evidence, fix) =>
    finding("http-redirect", "transport", severity, title, desc, evidence, fix);

  switch (httpProbe.result) {
    case "redirects-to-https": {
      const temporary = status === 302 || status === 303 || status === 307;
      return make(
        "ok",
        "HTTP redirects to HTTPS",
        "Visitors who type your address without https:// are sent straight to the secure version.",
        `${status ?? "3xx"} → https`,
        temporary
          ? "It works, but a temporary redirect isn't remembered by browsers. Make it permanent: nginx `return 301 https://$host$request_uri;`, Apache `R=301` on the rewrite rule."
          : NOTHING_TO_CHANGE
      );
    }
    case "serves-http": {
      const location = typeof httpProbe.location === "string" ? httpProbe.location.trim() : "";
      if (status !== null && status >= 300 && status < 400 && /^http:\/\//i.test(location)) {
        return make(
          "warn",
          "HTTP redirects to another plain-HTTP address",
          "Plain HTTP sends visitors to another unencrypted address, which Surface doesn't follow, so your site may still work without encryption there.",
          `${status} → ${location}`,
          "Point the port 80 redirect straight at the final `https://` address. Nginx: `return 301 https://$host$request_uri;`; Apache: `RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`."
        );
      }
      if (status !== null && status >= 400) {
        return make(
          "info",
          "Plain HTTP answers with an error",
          "Visitors who type your address without https:// get an error page instead of your site.",
          `HTTP ${status}`,
          "Redirect every plain HTTP request to HTTPS. Nginx: `return 301 https://$host$request_uri;` in the port 80 server block; Apache: `RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`. On Cloudflare, turn on Always Use HTTPS."
        );
      }
      return make(
        "warn",
        "Plain HTTP still works",
        "Visitors who type your address without https:// get an unencrypted page that can be read or altered on the way.",
        status === null ? "HTTP: page served" : `HTTP ${status}`,
        "Redirect every plain HTTP request to HTTPS. Nginx: `return 301 https://$host$request_uri;` in the port 80 server block; Apache: `RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`. On Cloudflare, turn on Always Use HTTPS."
      );
    }
    case "no-http":
      return make(
        "ok",
        "Plain HTTP is closed",
        "Nothing answers on plain HTTP, so there is no unencrypted version of your site to fall back to.",
        "port 80 closed",
        "Nothing to change. If visitors who type your address without `https://` can't connect, open port 80 only to redirect them to HTTPS."
      );
    default:
      // "error" or anything unknown: the probe tells us nothing.
      return null;
  }
}

function hsts(snapshot) {
  const { scheme, headers } = view(snapshot);
  if (scheme !== "https:") return null;
  const value = headers["strict-transport-security"];
  const make = (severity, title, desc, evidence, fix) =>
    finding("hsts", "transport", severity, title, desc, evidence, fix);

  if (value === undefined) {
    return make(
      "warn",
      "HSTS not enabled",
      "Browsers aren't told to stick to HTTPS, so someone on public Wi-Fi can push a visitor onto an unencrypted connection.",
      `HSTS: ${ABSENT}`,
      "Send `Strict-Transport-Security: max-age=31536000` (add `; includeSubDomains` once every subdomain has HTTPS). Nginx: `add_header Strict-Transport-Security \"max-age=31536000\" always;`; Apache: `Header always set Strict-Transport-Security \"max-age=31536000\"`. On Cloudflare, turn it on under SSL/TLS, Edge Certificates."
    );
  }
  // Browsers use the first header if it was sent twice.
  const first = value.split(",")[0];
  const match = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?=;|$)/i.exec(first);
  const maxAge = match ? Number(match[1]) : null;
  const subdomains = /(?:^|;)\s*includesubdomains\s*(?=;|$)/i.test(first);
  const preload = /(?:^|;)\s*preload\s*(?=;|$)/i.test(first);

  if (maxAge === null) {
    return make(
      "warn",
      "HSTS max-age missing",
      "Browsers ignore an HSTS header without a valid max-age, so HTTPS isn't actually enforced.",
      `max-age: ${ABSENT}`,
      "Send a valid `max-age`, for example `Strict-Transport-Security: max-age=31536000`. The value must be a whole number of seconds, with `;` between directives."
    );
  }
  if (maxAge < HSTS_MIN_AGE) {
    return make(
      "warn",
      "HSTS max-age too short",
      "Browsers forget to insist on HTTPS after a short time, which reopens the gap HSTS is meant to close.",
      `max-age=${maxAge}`,
      "Raise `max-age` to at least 15552000 (180 days); 31536000 (one year) is the usual choice. Keep it low only while testing, then raise it once HTTPS works everywhere."
    );
  }
  let fix;
  if (preload && subdomains && maxAge >= HSTS_PRELOAD_MIN_AGE) {
    fix = "Nothing to change. Your header meets the HSTS preload list rules, so check your domain's status at hstspreload.org.";
  } else if (preload) {
    fix = "Nothing to change for HSTS itself. The preload list also requires `includeSubDomains` and a `max-age` of at least 31536000, so add what's missing before submitting at hstspreload.org.";
  } else if (subdomains) {
    fix = "Nothing to change. To have browsers enforce HTTPS before the very first visit, add `preload` (with a `max-age` of at least 31536000) and submit your domain at hstspreload.org.";
  } else {
    fix = "Nothing to change. Once every subdomain serves HTTPS, add `includeSubDomains` to cover them too.";
  }
  return make(
    "ok",
    "HSTS enabled",
    "Browsers remember to use HTTPS for your site, even when someone types the plain address.",
    `max-age=${maxAge}${subdomains ? "; includeSubDomains" : ""}`,
    fix
  );
}

const RENEW_FIX =
  "Renew it now: run `certbot renew` for Let's Encrypt, or reissue it in your host's dashboard, then reload the web server. Check that automatic renewal is on so it doesn't lapse again.";

const UNTRUSTED_COPY = {
  CERT_HAS_EXPIRED: {
    desc: "Your certificate has expired, so browsers show visitors a full-page security warning instead of your site.",
    fix: RENEW_FIX,
  },
  DEPTH_ZERO_SELF_SIGNED_CERT: {
    desc: "Your certificate is self-signed, so browsers warn visitors that the connection isn't private.",
    fix: "Replace it with a certificate from a public authority, such as a free one from Let's Encrypt (`certbot --nginx` or `certbot --apache`). A Cloudflare Origin CA certificate is only trusted when traffic goes through Cloudflare's proxy.",
  },
  ERR_TLS_CERT_ALTNAME_INVALID: {
    desc: "Your certificate doesn't cover this domain name, so browsers warn visitors that the site may be an impostor.",
    fix: "Issue a certificate that lists this exact host name, including the www version if you use it. With Let's Encrypt: `certbot --nginx -d example.com -d www.example.com`.",
  },
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: {
    desc: "Your server doesn't send the full certificate chain, so some browsers and apps can't verify it and refuse to connect.",
    fix: "Serve the full chain, not just your own certificate. Nginx: point `ssl_certificate` at fullchain.pem; Apache 2.4.8+: point `SSLCertificateFile` at the full chain file.",
  },
  CERT_NOT_YET_VALID: {
    desc: "Your certificate's start date is in the future, so browsers reject it until then.",
    fix: "Check the server clock and reissue the certificate if its dates are wrong.",
  },
};
UNTRUSTED_COPY.SELF_SIGNED_CERT_IN_CHAIN = UNTRUSTED_COPY.DEPTH_ZERO_SELF_SIGNED_CERT;
UNTRUSTED_COPY.UNABLE_TO_GET_ISSUER_CERT_LOCALLY = UNTRUSTED_COPY.UNABLE_TO_VERIFY_LEAF_SIGNATURE;
UNTRUSTED_COPY.UNABLE_TO_GET_ISSUER_CERT = UNTRUSTED_COPY.UNABLE_TO_VERIFY_LEAF_SIGNATURE;

const UNTRUSTED_DEFAULT = {
  desc: "Browsers can't verify your certificate, so visitors see a security warning instead of your site.",
  fix: "Install a certificate from a public authority, such as a free one from Let's Encrypt, that covers this host name and includes the full chain.",
};

/**
 * Day thresholds for "expires soon" (warn) and "expires in N days" (crit),
 * scaled to the certificate's lifetime so 45-day and 6-day certificates that
 * renew on schedule aren't flagged. 30/14 days when the lifetime is unknown.
 */
function expiryThresholds(tls) {
  const from = typeof tls.validFrom === "string" ? Date.parse(tls.validFrom) : NaN;
  const to = typeof tls.validTo === "string" ? Date.parse(tls.validTo) : NaN;
  const lifetime = (to - from) / DAY_MS;
  if (!Number.isFinite(lifetime) || lifetime <= 0) return { warnBelow: 30, critBelow: 14 };
  return { warnBelow: Math.min(30, lifetime / 4), critBelow: Math.min(14, lifetime / 10) };
}

function certificate(snapshot) {
  const { tls } = view(snapshot);
  if (!tls) return null;
  const make = (severity, title, desc, evidence, fix) =>
    finding("certificate", "transport", severity, title, desc, evidence, fix);
  const issuer = typeof tls.issuer === "string" && tls.issuer.trim() ? tls.issuer.trim() : null;
  const withIssuer = (text) => (issuer ? `${text} · ${issuer}` : text);

  const days = Number.isFinite(tls.daysLeft) ? tls.daysLeft : null;
  const expiredAgo = () => withIssuer(`expired ${-days} ${plural(-days, "day", "days")} ago`);

  if (tls.valid === false) {
    const code = typeof tls.error === "string" && tls.error.trim() ? tls.error.trim() : null;
    const copy = (code && Object.hasOwn(UNTRUSTED_COPY, code) && UNTRUSTED_COPY[code]) || UNTRUSTED_DEFAULT;
    if (code === "CERT_HAS_EXPIRED") {
      return make("crit", "Certificate expired", copy.desc, days !== null && days < 0 ? expiredAgo() : code, copy.fix);
    }
    return make("crit", "Certificate not trusted", copy.desc, code ?? "verification failed", copy.fix);
  }

  if (days === null) {
    return make(
      "ok",
      "Certificate valid",
      "Browsers trust your certificate.",
      withIssuer("trusted"),
      "Nothing to change. Keep automatic renewal on so it never lapses."
    );
  }
  if (days < 0) {
    return make(
      "crit",
      "Certificate expired",
      "Browsers show visitors a full-page security warning instead of your site.",
      expiredAgo(),
      RENEW_FIX
    );
  }
  const left = withIssuer(`${days} ${plural(days, "day", "days")} left`);
  const { warnBelow, critBelow } = expiryThresholds(tls);
  if (days < critBelow) {
    const title =
      days === 0 ? "Certificate expires today" : `Certificate expires in ${days} ${plural(days, "day", "days")}`;
    return make(
      "crit",
      title,
      "When it runs out, browsers will block visitors with a full-page security warning.",
      left,
      "Renew it now: run `certbot renew` for Let's Encrypt, or reissue it in your host's dashboard. Then confirm automatic renewal works with `certbot renew --dry-run`."
    );
  }
  if (days < warnBelow) {
    return make(
      "warn",
      "Certificate expires soon",
      "It still works, but if renewal fails, visitors will see a security warning when it runs out.",
      left,
      "Automated certificates normally renew with about a third of their lifetime left, so renewal may already be failing. Run `certbot renew --dry-run` to check, or reissue the certificate in your host's dashboard."
    );
  }
  return make(
    "ok",
    "Certificate valid",
    "Browsers trust your certificate and it has plenty of time left before it expires.",
    left,
    "Nothing to change. Keep automatic renewal on so it never lapses."
  );
}

// ---------------------------------------------------------------- headers

function csp(snapshot) {
  const { headers } = view(snapshot);
  const value = headers["content-security-policy"];
  const make = (severity, title, desc, evidence, fix) =>
    finding("csp", "headers", severity, title, desc, evidence, fix);

  if (value === undefined) {
    const reportOnly = headers["content-security-policy-report-only"];
    if (reportOnly !== undefined) {
      return make(
        "info",
        "CSP in report-only mode",
        "Your content security policy only reports problems and doesn't block anything yet.",
        labeled("CSP-Report-Only", reportOnly),
        "Once the reports look clean, rename the header to `Content-Security-Policy` so browsers enforce it."
      );
    }
    return make(
      "warn",
      "No content security policy",
      "Nothing limits which scripts can run on your pages, so a single injected script can steal data or sessions.",
      `CSP: ${ABSENT}`,
      "Start with `Content-Security-Policy: default-src 'self'` and add the domains your pages really load from. Nginx: `add_header Content-Security-Policy \"default-src 'self'\" always;`; Apache: `Header always set Content-Security-Policy \"default-src 'self'\"`; Next.js: return it from `headers()` in next.config.js. Try it as `Content-Security-Policy-Report-Only` first so nothing breaks."
    );
  }

  // Several policies are all enforced: inline scripts run only if none blocks
  // them, and scripts are restricted if at least one policy restricts them.
  let inlineDirective = null;
  let blocked = false;
  let restricts = false;
  let wideDirective = null;
  for (const policy of parseCsp(value)) {
    const name = policy.has("script-src") ? "script-src" : policy.has("default-src") ? "default-src" : null;
    if (!name) continue;
    const sources = policy.get(name).toLowerCase();
    // A nonce, hash or 'strict-dynamic' switches off 'unsafe-inline'.
    const pinned = NONCE_OR_HASH.test(sources);
    if (sources.includes("'unsafe-inline'") && !pinned) {
      inlineDirective ??= name;
    } else {
      blocked = true;
    }
    // Only 'strict-dynamic' switches off host and scheme sources such as * or https:.
    if (!STRICT_DYNAMIC.test(sources) && isWideSourceList(sources)) wideDirective ??= `${name}: ${sources}`;
    else restricts = true;
  }
  // A policy that lets scripts load from anywhere is no better than none,
  // whether or not it also allows inline scripts.
  if (!restricts) {
    return make(
      "warn",
      "CSP doesn't restrict scripts",
      "Your policy exists but still lets scripts load from any website, so it won't stop an injected script.",
      wideDirective ? labeled("CSP", wideDirective) : `CSP script-src: ${ABSENT}`,
      "Add `script-src 'self'` plus the domains you really load scripts from, or a `default-src 'self'` fallback. Avoid `*` and bare schemes such as `https:`, which allow any site. If you use nonces, add `'strict-dynamic'` so browsers ignore those wide fallbacks."
    );
  }
  if (inlineDirective && !blocked) {
    return make(
      "info",
      "CSP allows inline scripts",
      "Your policy still lets inline scripts run, which is how most script injection attacks get in.",
      `CSP ${inlineDirective}: 'unsafe-inline'`,
      "Move inline scripts into files, or allow specific ones with a nonce (`'nonce-…'`) or hash (`'sha256-…'`) instead of `'unsafe-inline'`. Next.js supports nonces through middleware."
    );
  }
  return make(
    "ok",
    "Content security policy set",
    "Your pages declare which sources scripts and other content may load from.",
    labeled("CSP", value),
    "Nothing to change. Review the policy when you add new third-party scripts."
  );
}

function clickjacking(snapshot) {
  const { headers } = view(snapshot);
  const xfo = headers["x-frame-options"];
  const make = (severity, title, desc, evidence, fix) =>
    finding("clickjacking", "headers", severity, title, desc, evidence, fix);

  const tokens = xfo === undefined ? [] : xfo.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean);
  const xfoProtects = tokens.length > 0 && tokens.every((t) => t === "deny" || t === "sameorigin");
  const ancestors = parseCsp(headers["content-security-policy"])
    .map((policy) => policy.get("frame-ancestors"))
    .find((v) => v !== undefined);

  // Browsers follow frame-ancestors over X-Frame-Options when both are set.
  if (ancestors !== undefined && isWideSourceList(ancestors)) {
    return make(
      "warn",
      "Clickjacking protection missing",
      "Your frame-ancestors rule lets any site load your page in a frame, and browsers follow it over X-Frame-Options.",
      labeled("CSP frame-ancestors", ancestors),
      "Set `frame-ancestors 'self'` (or `'none'` if your page is never framed) and list only the exact sites that may embed it. Avoid `*` and bare schemes such as `https:`."
    );
  }
  if (xfoProtects || ancestors !== undefined) {
    const evidence = ancestors !== undefined
      ? labeled("CSP frame-ancestors", ancestors || "'none'")
      : headerEvidence("x-frame-options", xfo);
    return make(
      "ok",
      "Clickjacking protection on",
      "Other sites can't load your page inside a frame to trick visitors into clicking.",
      evidence,
      "Nothing to change. Where both headers are set, modern browsers follow `frame-ancestors`."
    );
  }

  const allowFrom = tokens.some((t) => t.startsWith("allow-from"));
  return make(
    "warn",
    "Clickjacking protection missing",
    allowFrom
      ? "Browsers ignore the old ALLOW-FROM setting, so other sites can still frame your page and trick visitors into clicking."
      : "Another site can load your page in a hidden frame and trick visitors into clicking things they can't see.",
    headerEvidence("x-frame-options", xfo),
    allowFrom
      ? "Replace it with `Content-Security-Policy: frame-ancestors 'self' https://partner.example`, listing only the sites allowed to frame you."
      : "Add `Content-Security-Policy: frame-ancestors 'self'`, or `X-Frame-Options: SAMEORIGIN` for older browsers. Nginx: `add_header X-Frame-Options SAMEORIGIN always;`; Apache: `Header always set X-Frame-Options SAMEORIGIN`; Express: `res.set('X-Frame-Options', 'SAMEORIGIN')`. Next.js: return it from `headers()` in next.config.js."
  );
}

function nosniff(snapshot) {
  const { headers } = view(snapshot);
  const value = headers["x-content-type-options"];
  // Browsers only look at the first value.
  const first = value === undefined ? "" : value.split(",")[0].trim().toLowerCase();
  const evidence = headerEvidence("x-content-type-options", value);

  if (first === "nosniff") {
    return finding(
      "nosniff",
      "headers",
      "ok",
      "MIME sniffing blocked",
      "Browsers use the file types you declare instead of guessing.",
      evidence,
      NOTHING_TO_CHANGE
    );
  }
  return finding(
    "nosniff",
    "headers",
    "warn",
    "MIME sniffing not blocked",
    "Browsers may guess a file's type and run an uploaded file as a script.",
    evidence,
    "Send `X-Content-Type-Options: nosniff` on every response. Nginx: `add_header X-Content-Type-Options nosniff always;`; Apache: `Header always set X-Content-Type-Options nosniff`; Express: `res.set('X-Content-Type-Options', 'nosniff')`. Next.js: return it from `headers()` in next.config.js."
  );
}

function referrerPolicy(snapshot) {
  const { headers } = view(snapshot);
  const value = headers["referrer-policy"];
  const evidence = headerEvidence("referrer-policy", value);
  const directive =
    "Nginx: `add_header Referrer-Policy strict-origin-when-cross-origin always;`; Apache: `Header always set Referrer-Policy strict-origin-when-cross-origin`.";

  if (value === undefined) {
    return finding(
      "referrer-policy",
      "headers",
      "info",
      "No referrer policy",
      "Modern browsers default to a safe setting that hides your full page addresses from other sites, so this is low risk.",
      evidence,
      `Set it explicitly so older browsers behave the same: \`Referrer-Policy: strict-origin-when-cross-origin\`. ${directive}`
    );
  }
  // A list such as "no-referrer-when-downgrade, strict-origin-when-cross-origin"
  // is a fallback chain: browsers apply the last token they recognise.
  const effective = value
    .toLowerCase()
    .split(",")
    .map((token) => token.trim())
    .filter((token) => REFERRER_POLICIES.has(token))
    .at(-1);
  if (effective === "unsafe-url" || effective === "no-referrer-when-downgrade") {
    return finding(
      "referrer-policy",
      "headers",
      "warn",
      "Referrer policy leaks full URLs",
      "Full page addresses, including any IDs or tokens in them, are sent to every site you link to or load from.",
      evidence,
      `Switch to \`Referrer-Policy: strict-origin-when-cross-origin\`, which sends other sites only your domain name. ${directive}`
    );
  }
  return finding(
    "referrer-policy",
    "headers",
    "ok",
    "Referrer policy set",
    "You control how much of your page addresses other sites get to see.",
    evidence,
    NOTHING_TO_CHANGE
  );
}

function permissionsPolicy(snapshot) {
  const { headers } = view(snapshot);
  const value = headers["permissions-policy"];
  const evidence = headerEvidence("permissions-policy", value);

  if (value !== undefined) {
    return finding(
      "permissions-policy",
      "headers",
      "ok",
      "Permissions policy set",
      "You've limited which browser features your pages and embeds can use.",
      evidence,
      NOTHING_TO_CHANGE
    );
  }
  return finding(
    "permissions-policy",
    "headers",
    "info",
    "No permissions policy",
    "You haven't limited which browser features, such as camera or location, your pages and embeds may ask for.",
    evidence,
    "Switch off features you don't use, for example `Permissions-Policy: camera=(), microphone=(), geolocation=()`. Nginx: `add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;`; Apache: `Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"`."
  );
}

// ---------------------------------------------------------------- cookies

// nginx cookie names are tokens; anything odd is shown as a placeholder.
const NGINX_COOKIE_NAME = /^[A-Za-z0-9!#$%&'*+.^_|~-]{1,40}$/;

/**
 * The nginx part of a cookie fix. nginx applies only the first
 * proxy_cookie_flags line that matches a cookie, so every fix suggests the
 * same single line with all flags, naming the cookie.
 */
function nginxCookieFix(cookie, scheme) {
  const name = cookie?.name ?? "";
  const shown = NGINX_COOKIE_NAME.test(name) ? name : "<cookie>";
  // Only the flags this cookie lacks: `secure` only over HTTPS (browsers drop
  // Secure cookies set over plain HTTP), `samesite=lax` only when it has no
  // SameSite (never override a deliberate SameSite=None).
  const flags = [];
  if (scheme === "https:" && !cookie?.secure) flags.push("secure");
  if (cookie?.sensitive && !cookie?.httpOnly) flags.push("httponly");
  if (!cookie?.sameSite) flags.push("samesite=lax");
  if (flags.length === 0) return "";
  return `nginx 1.19.3+: put every flag a cookie needs on one line, such as \`proxy_cookie_flags ${shown} ${flags.join(" ")};\`, because nginx applies only the first line that matches a cookie.`;
}

function cookieSecure(snapshot) {
  const { cookies, scheme } = view(snapshot);
  if (cookies.length === 0) {
    return finding(
      "cookies",
      "cookies",
      "ok",
      "No cookies on first visit",
      "Your page sets no cookies on a first visit, so there is nothing here to protect.",
      `Set-Cookie: ${ABSENT}`,
      "Nothing to change. Cookies set after login aren't checked here, so make sure those use `Secure`, `HttpOnly` and `SameSite` too."
    );
  }
  if (scheme !== "https:") return null;

  const insecure = cookies.filter((c) => !c.secure);
  if (insecure.length > 0) {
    return finding(
      "cookie-secure",
      "cookies",
      "warn",
      "Cookies sent without Secure",
      "These cookies can also travel over plain HTTP, where anyone on the same network can read them.",
      nameList(insecure.map((c) => c.name)),
      `Add \`Secure\` to every cookie. PHP: \`session.cookie_secure = 1\` in php.ini; Express: \`cookie: { secure: true }\` in your session settings, plus \`app.set('trust proxy', 1)\` behind a proxy or a host such as Vercel, or the cookie is never set. ${nginxCookieFix(insecure[0], scheme).replace(/^nginx/, "Nginx")}`
    );
  }
  return finding(
    "cookie-secure",
    "cookies",
    "ok",
    "Cookies marked Secure",
    "Your cookies are only ever sent over encrypted connections.",
    `${cookies.length} ${plural(cookies.length, "cookie", "cookies")}, all Secure`,
    NOTHING_TO_CHANGE
  );
}

function cookieHttpOnly(snapshot) {
  const { cookies, scheme } = view(snapshot);
  if (cookies.length === 0) return null;

  const readable = cookies.filter((c) => !c.httpOnly);
  const sensitive = readable.filter((c) => c.sensitive);
  if (sensitive.length > 0) {
    return finding(
      "cookie-httponly",
      "cookies",
      "warn",
      "Session cookie readable by scripts",
      "If any script on your page is compromised, it can read this cookie and take over a visitor's session.",
      nameList(sensitive.map((c) => c.name)),
      `Add \`HttpOnly\` to session and login cookies. PHP: \`session.cookie_httponly = 1\`; Express: \`cookie: { httpOnly: true }\`; ${nginxCookieFix(sensitive[0], scheme)} A CSRF token cookie that your front-end must read, such as \`XSRF-TOKEN\`, is the one exception.`
    );
  }
  if (readable.length > 0) {
    return finding(
      "cookie-httponly",
      "cookies",
      "info",
      "Some cookies readable by scripts",
      "Scripts can read some cookies, which is fine for preferences but not for anything that identifies a visitor.",
      nameList(readable.map((c) => c.name)),
      "Add `HttpOnly` to every cookie your own JavaScript doesn't need to read."
    );
  }
  return finding(
    "cookie-httponly",
    "cookies",
    "ok",
    "Cookies are HttpOnly",
    "Scripts on your page can't read your cookies, which protects sessions if a script is compromised.",
    `${cookies.length} ${plural(cookies.length, "cookie", "cookies")}, all HttpOnly`,
    NOTHING_TO_CHANGE
  );
}

function cookieSameSite(snapshot) {
  const { cookies, scheme } = view(snapshot);
  if (cookies.length === 0) return null;

  const noneInsecure = cookies.filter((c) => c.sameSite === "none" && !c.secure);
  if (noneInsecure.length > 0) {
    return finding(
      "cookie-samesite",
      "cookies",
      "warn",
      "SameSite=None without Secure",
      "Modern browsers reject these cookies outright, so whatever relies on them quietly stops working.",
      nameList(noneInsecure.map((c) => c.name)),
      "Add `Secure` to every cookie marked `SameSite=None`, or use `SameSite=Lax` if it doesn't need to work inside other sites."
    );
  }
  const missing = cookies.filter((c) => c.sameSite === null);
  if (missing.length > 0) {
    return finding(
      "cookie-samesite",
      "cookies",
      "info",
      "Cookies without SameSite",
      "Chrome and Edge treat these as Lax by default but other browsers may not, so setting it yourself keeps behavior the same everywhere.",
      nameList(missing.map((c) => c.name)),
      `Add \`SameSite=Lax\` to your cookies, or \`SameSite=Strict\` for admin sessions. PHP: \`session.cookie_samesite = "Lax"\`; Express: \`cookie: { sameSite: 'lax' }\`; ${nginxCookieFix(missing[0], scheme)}`
    );
  }
  return finding(
    "cookie-samesite",
    "cookies",
    "ok",
    "Cookies set SameSite",
    "Your cookies tell browsers when they may be sent from other sites, which helps block requests forged in a visitor's name.",
    `${cookies.length} ${plural(cookies.length, "cookie", "cookies")}, all SameSite`,
    NOTHING_TO_CHANGE
  );
}

// ---------------------------------------------------------------- cors

function cors(snapshot) {
  const { headers } = view(snapshot);
  const origin = headers["access-control-allow-origin"];
  const credentials = (headers["access-control-allow-credentials"] ?? "").toLowerCase();
  const make = (severity, title, desc, evidence, fix) =>
    finding("cors", "cors", severity, title, desc, evidence, fix);

  if (origin === undefined) {
    return make(
      "ok",
      "No cross-origin access",
      "Your page sends no CORS headers to a normal request, so other websites can't read it from a visitor's browser.",
      `ACAO: ${ABSENT}`,
      NOTHING_TO_CHANGE
    );
  }
  if (origin === "*") {
    if (credentials === "true") {
      // Browsers refuse credentialed requests when the allowed origin is "*",
      // so this combination exposes nothing beyond plain public CORS.
      return make(
        "info",
        "CORS credentials flag ignored",
        "Browsers won't let other sites read credentialed responses when any origin is allowed, so this header has no effect.",
        "ACAO: *, credentials: true",
        "Remove `Access-Control-Allow-Credentials: true` if nothing needs it. If other sites must make logged-in requests, check the request's `Origin` against an explicit list of trusted sites and echo back only a match, never every origin."
      );
    }
    return make(
      "ok",
      "Public CORS, no logins",
      "Any site can read this page from a visitor's browser, but only anonymously, as any stranger could.",
      "ACAO: *",
      "Nothing to change. This is fine for public pages and files; list specific origins instead of `*` only if the response depends on the visitor's network, such as an intranet."
    );
  }
  if (origin.toLowerCase() === "null") {
    const withLogins = credentials === "true";
    return make(
      withLogins ? "crit" : "info",
      withLogins ? "CORS trusts the null origin" : "CORS allows the null origin",
      withLogins
        ? "Any site can pose as the null origin from a sandboxed frame and read responses with your visitors' logins."
        : "Any site can pose as the null origin from a sandboxed frame and read this response, though browsers won't send your visitors' logins with it.",
      withLogins ? "ACAO: null, credentials: true" : "ACAO: null",
      "Never allow `null`. Check the request's `Origin` against an explicit list of trusted sites and echo back only a match."
    );
  }
  return make(
    "ok",
    "CORS restricted",
    "Only the origins you list can read your responses from their pages.",
    labeled("ACAO", origin),
    NOTHING_TO_CHANGE
  );
}

// ---------------------------------------------------------------- disclosure

// Hosting platforms come first: many of them run behind a CDN (GitHub Pages
// on Fastly, Render and Shopify on Cloudflare), and the platform is what the
// site owner chose and controls. Each test returns the header that matched.
const HOSTING = [
  { name: "Vercel", cdn: false, test: (h) => present(h, "x-vercel-id") },
  { name: "Netlify", cdn: false, test: (h) => present(h, "x-nf-request-id") },
  { name: "GitHub Pages", cdn: false, test: (h) => present(h, "x-github-request-id") },
  { name: "Render", cdn: false, test: (h) => present(h, "x-render-origin-server") },
  { name: "Fly.io", cdn: false, test: (h) => present(h, "fly-request-id") },
  { name: "Shopify", cdn: false, test: (h) => present(h, "x-shopid") },
  { name: "Cloudflare", cdn: true, test: (h) => present(h, "cf-ray") ?? (includes(h.server, "cloudflare") ? "server" : null) },
  { name: "Amazon CloudFront", cdn: true, test: (h) => present(h, "x-amz-cf-id") },
  {
    name: "Fastly",
    cdn: true,
    test: (h) => present(h, "x-fastly-request-id") ?? (includes(h["x-served-by"], "cache-") ? "x-served-by" : null),
  },
  { name: "Azure Front Door", cdn: true, test: (h) => present(h, "x-azure-ref") },
  { name: "Akamai", cdn: true, test: (h) => (includes(h.server, "akamaighost") ? "server" : null) },
  {
    name: "Google",
    cdn: false,
    test: (h) => {
      const server = (h.server ?? "").toLowerCase();
      return server === "google frontend" || server === "gws" ? "server" : null;
    },
  },
];

function present(headers, name) {
  return headers[name] !== undefined ? name : null;
}

function includes(value, needle) {
  return typeof value === "string" && value.toLowerCase().includes(needle);
}

function hosting(snapshot) {
  const { headers } = view(snapshot);
  for (const provider of HOSTING) {
    const header = provider.test(headers);
    if (!header) continue;
    return finding(
      "hosting",
      "disclosure",
      "info",
      "Hosting provider identified",
      `Anyone can see that ${provider.name} serves your site, which is normal and gives attackers only a small hint.`,
      headerEvidence(header, headers[header]),
      provider.cdn
        ? `No action needed. Make sure your origin server only accepts traffic from ${provider.name}, so nobody can bypass it by finding the server's own address.`
        : `No action needed. This can't be hidden on ${provider.name} and reveals little on its own.`
    );
  }
  return null;
}

const INTERNAL_HEADERS = [
  "x-backend-server",
  "x-server-name",
  "x-upstream",
  "x-real-server",
  "x-forwarded-server",
  "x-host",
  "x-served-by",
];

function debugHeaders(snapshot) {
  const { headers } = view(snapshot);
  const make = (severity, title, desc, evidence, fix) =>
    finding("debug-headers", "disclosure", severity, title, desc, evidence, fix);

  const found = [];
  const debug = ["x-debug-token", "x-debug-token-link"].find((h) => headers[h] !== undefined);
  if (debug) {
    found.push(make(
      "crit",
      "Debug profiler exposed",
      "Your site is running in debug mode, and its profiler can show anyone your file paths, database queries and settings.",
      headerEvidence(debug, headers[debug]),
      "Turn off debug mode in production. Symfony: set `APP_ENV=prod` and `APP_DEBUG=0`, clear the cache, and enable the WebProfilerBundle only in the dev environment."
    ));
  }

  const leak = INTERNAL_HEADERS.find((h) => {
    const value = headers[h];
    return value !== undefined && (PRIVATE_IPV4.test(value) || INTERNAL_NAME.test(value));
  });
  if (leak) {
    const name = displayName(leak);
    found.push(make(
      "warn",
      "Internal host name leaked",
      "A header reveals the name or private address of a machine behind your site, which helps attackers map your network.",
      headerEvidence(leak, headers[leak]),
      `Stop sending \`${name}\` to visitors. Nginx: \`proxy_hide_header ${name};\`; Apache: \`Header unset ${name}\`. On Cloudflare, remove it with a response header Transform Rule.`
    ));
  }

  // Both problems are reported when both are present; ids stay unique.
  if (found.length === 2) {
    found[0].id = "debug-headers:token";
    found[1].id = "debug-headers:internal";
  }
  if (found.length) return found.length === 1 ? found[0] : found;

  return make(
    "ok",
    "No debug headers",
    "Responses don't carry debug tokens or the names of internal servers.",
    `X-Debug-Token: ${ABSENT}`,
    NOTHING_TO_CHANGE
  );
}

function redirectCaveat(snapshot) {
  const { redirectStop, redirectCount, status } = view(snapshot);
  if (!redirectStop) return null;
  const evidence = redirectStop === "loop" ? "redirect loop" : `HTTP ${status ?? "3xx"} after ${redirectCount} ${plural(redirectCount, "redirect", "redirects")}`;
  if (redirectStop === "loop") {
    return finding(
      "status:redirects",
      "disclosure",
      "warn",
      "Redirect loop",
      "Your address redirects back to itself, so visitors may never reach a page and these results describe the redirect.",
      evidence,
      "Check your redirect rules (HTTP to HTTPS, www to non-www, trailing slashes) for two rules that undo each other. On Cloudflare, an SSL/TLS mode of Flexible behind an HTTPS-only server is a common cause."
    );
  }
  return finding(
    "status:redirects",
    "disclosure",
    "info",
    "Redirects didn't reach a page",
    redirectStop === "limit"
      ? "We stopped after 5 redirects, so these results describe a redirect response rather than your page."
      : "The last redirect points somewhere we can't follow, so these results describe the redirect itself.",
    evidence,
    "Scan the final address your visitors land on, and shorten long redirect chains: each hop slows the first visit."
  );
}

function statusRule(snapshot) {
  const main = statusFinding(snapshot);
  const caveat = redirectCaveat(snapshot);
  if (main && caveat) return [main, caveat];
  return main || caveat;
}

function statusFinding(snapshot) {
  const { status } = view(snapshot);
  if (status === null) return null;
  if (status >= 500) {
    return finding(
      "status",
      "disclosure",
      "warn",
      "Server returned an error",
      "Your page answered with a server error, so visitors may be seeing a broken page and these results may be partial.",
      `HTTP ${status}`,
      "Check your server's error log for the cause. A 502 or 504 usually means the app behind the web server is down or too slow to answer."
    );
  }
  if (status >= 400) {
    let desc = "The page didn't load normally, so some of these results may be partial.";
    if (status === 401 || status === 403) {
      desc = "The page blocked our request, often because of bot protection, so some of these results may be partial.";
    } else if (status === 404) {
      desc = "The address wasn't found, so these results describe your error page and may be partial.";
    } else if (status === 429) {
      desc = "Your server asked us to slow down, so some of these results may be partial.";
    }
    return finding(
      "status",
      "disclosure",
      "info",
      `Page returned HTTP ${status}`,
      desc,
      `HTTP ${status}`,
      "Scan the exact address your visitors land on. If a firewall or bot protection blocks automated checks, this report describes its block page rather than your site."
    );
  }
  return null;
}

// ---------------------------------------------------------------- catalog

export const RULES = [
  { id: "server-header", category: "versions", run: serverHeader },
  { id: "powered-by", category: "versions", run: poweredBy },
  { id: "fingerprints", category: "versions", run: fingerprints },
  { id: "https", category: "transport", run: https },
  { id: "http-redirect", category: "transport", run: httpRedirect },
  { id: "hsts", category: "transport", run: hsts },
  { id: "certificate", category: "transport", run: certificate },
  { id: "csp", category: "headers", run: csp },
  { id: "clickjacking", category: "headers", run: clickjacking },
  { id: "nosniff", category: "headers", run: nosniff },
  { id: "referrer-policy", category: "headers", run: referrerPolicy },
  { id: "permissions-policy", category: "headers", run: permissionsPolicy },
  { id: "cookie-secure", category: "cookies", run: cookieSecure },
  { id: "cookie-httponly", category: "cookies", run: cookieHttpOnly },
  { id: "cookie-samesite", category: "cookies", run: cookieSameSite },
  { id: "cors", category: "cors", run: cors },
  { id: "hosting", category: "disclosure", run: hosting },
  { id: "debug-headers", category: "disclosure", run: debugHeaders },
  { id: "status", category: "disclosure", run: statusRule },
];
