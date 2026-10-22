import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { analyze, scoreFindings } from "../api/_lib/analyze.js";
import { RULES } from "../api/_lib/rules.js";

// ---------------------------------------------------------------- helpers

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const FIXTURES = readdirSync(FIXTURE_DIR)
  .filter((name) => name.endsWith(".json"))
  .sort();

function loadFixture(name) {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, name), "utf8"));
}

const SEVERITIES = ["crit", "warn", "info", "ok"];
const CATEGORIES = ["versions", "transport", "headers", "cookies", "cors", "disclosure"];
const FIELDS = ["category", "desc", "evidence", "fix", "id", "severity", "title"];
const SEVERITY_RANK = { crit: 0, warn: 1, info: 2, ok: 3 };

const TLS_OK = {
  valid: true,
  error: null,
  validTo: "2027-01-14T23:59:59.000Z",
  daysLeft: 84,
  issuer: "Let's Encrypt",
  protocol: "TLSv1.3",
};

/** A plain HTTPS snapshot with no headers and no cookies. */
function snap(overrides = {}) {
  return {
    input: "example.com",
    requestedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    status: 200,
    redirects: [],
    headers: {},
    setCookies: [],
    httpProbe: null,
    tls: { ...TLS_OK },
    timingMs: 120,
    scannedAt: "2026-10-22T15:20:00.000Z",
    ...overrides,
  };
}

const httpSnap = (overrides = {}) =>
  snap({ requestedUrl: "http://example.com/", finalUrl: "http://example.com/", tls: null, ...overrides });

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `rule ${id} exists`);
  return rule;
}

/** Run one rule and always get an array back. */
function run(id, snapshot) {
  const out = ruleById(id).run(snapshot);
  return out == null ? [] : Array.isArray(out) ? out : [out];
}

/** Run one rule that must return exactly one finding. */
function one(id, snapshot) {
  const list = run(id, snapshot);
  assert.equal(list.length, 1, `${id} returns one finding`);
  return list[0];
}

function expectNull(id, snapshot) {
  assert.equal(ruleById(id).run(snapshot), null, `${id} returns null`);
}

function expectFinding(f, expected) {
  for (const [key, value] of Object.entries(expected)) {
    assert.equal(f[key], value, `${f.id}.${key}`);
  }
  checkFinding(f);
}

/** Rule index for a finding id, used to check catalog order. */
function ruleIndexOf(id) {
  const base = id.split(":")[0];
  const index = RULES.findIndex((r) => r.id === (base === "cookies" ? "cookie-secure" : base));
  assert.notEqual(index, -1, `id ${id} maps to a rule`);
  return index;
}

/** Sentence terminators outside `code` spans. */
function sentenceCount(text) {
  const prose = text.replace(/`[^`]*`/g, "x");
  return (prose.match(/[.!?](?=\s|$)/g) ?? []).length;
}

/** Shape and copy rules every finding must satisfy. */
function checkFinding(f) {
  assert.deepEqual(Object.keys(f).sort(), FIELDS, "exactly 7 fields");
  for (const key of FIELDS) {
    assert.equal(typeof f[key], "string", `${f.id}.${key} is a string`);
    assert.ok(f[key].trim().length > 0, `${f.id}.${key} is not empty`);
  }
  assert.ok(SEVERITIES.includes(f.severity), `${f.id} severity ${f.severity}`);
  assert.ok(CATEGORIES.includes(f.category), `${f.id} category ${f.category}`);
  assert.equal(f.category, RULES[ruleIndexOf(f.id)].category, `${f.id} category matches its rule`);

  assert.ok(f.title.length <= 48, `title too long: "${f.title}"`);
  assert.match(f.title, /^[A-Z]/, `title starts with a capital: "${f.title}"`);
  assert.doesNotMatch(f.title, /[.!?]$/, `title has no trailing period: "${f.title}"`);

  assert.ok(f.evidence.length <= 64, `evidence too long (${f.evidence.length}): "${f.evidence}"`);
  assert.doesNotMatch(f.evidence, /[\u0000-\u001f]/, "evidence has no control characters");

  assert.match(f.desc, /\.$/, `desc ends with a period: "${f.desc}"`);
  assert.equal(sentenceCount(f.desc), 1, `desc is one sentence: "${f.desc}"`);
  assert.doesNotMatch(f.desc, /`/, "desc has no code");

  const fixSentences = sentenceCount(f.fix);
  assert.ok(fixSentences >= 1 && fixSentences <= 3, `fix has 1-3 sentences (${fixSentences}): "${f.fix}"`);
  assert.equal((f.fix.match(/`/g) ?? []).length % 2, 0, "fix has balanced backticks");

  for (const key of ["title", "desc", "fix"]) {
    assert.doesNotMatch(f[key], /[—–]/, `${f.id}.${key} has no dash asides`);
    assert.doesNotMatch(f[key], /worth noting/i, `${f.id}.${key} avoids filler`);
  }
}

/** Report-level invariants. */
function checkReport(report) {
  assert.deepEqual(Object.keys(report), ["target", "score", "level", "counts", "findings"]);
  assert.deepEqual(Object.keys(report.target), [
    "input",
    "url",
    "host",
    "status",
    "timingMs",
    "redirects",
    "scannedAt",
  ]);
  assert.ok(Array.isArray(report.findings));
  assert.equal(report.counts.total, report.findings.length);
  for (const sev of SEVERITIES) {
    assert.equal(report.counts[sev], report.findings.filter((f) => f.severity === sev).length, `count ${sev}`);
  }
  assert.equal(
    report.counts.crit + report.counts.warn + report.counts.info + report.counts.ok,
    report.counts.total
  );
  const expected = scoreFindings(report.findings);
  assert.equal(report.score, expected.score);
  assert.equal(report.level, expected.level);
  assert.ok(Number.isInteger(report.score) && report.score >= 0 && report.score <= 100);

  const ids = report.findings.map((f) => f.id);
  assert.equal(new Set(ids).size, ids.length, "finding ids are unique");

  for (const f of report.findings) checkFinding(f);

  for (let i = 1; i < report.findings.length; i++) {
    const a = report.findings[i - 1];
    const b = report.findings[i];
    const ra = SEVERITY_RANK[a.severity];
    const rb = SEVERITY_RANK[b.severity];
    assert.ok(ra <= rb, `sorted by severity: ${a.id} (${a.severity}) before ${b.id} (${b.severity})`);
    if (ra === rb) {
      assert.ok(ruleIndexOf(a.id) <= ruleIndexOf(b.id), `catalog order: ${a.id} before ${b.id}`);
    }
  }
}

const pairs = (report) => report.findings.map((f) => `${f.severity} ${f.id}`);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

/** Build findings with a given severity mix for scoring tests. */
function mix({ crit = 0, warn = 0, info = 0, ok = 0 }) {
  const list = [];
  const push = (severity, n) => {
    for (let i = 0; i < n; i++) list.push({ id: `x${list.length}`, severity });
  };
  push("crit", crit);
  push("warn", warn);
  push("info", info);
  push("ok", ok);
  return list;
}

// ---------------------------------------------------------------- catalog

describe("rule catalog", () => {
  test("has rules 1-19 in spec order with the right categories", () => {
    assert.deepEqual(
      RULES.map((r) => [r.id, r.category]),
      [
        ["server-header", "versions"],
        ["powered-by", "versions"],
        ["fingerprints", "versions"],
        ["https", "transport"],
        ["http-redirect", "transport"],
        ["hsts", "transport"],
        ["certificate", "transport"],
        ["csp", "headers"],
        ["clickjacking", "headers"],
        ["nosniff", "headers"],
        ["referrer-policy", "headers"],
        ["permissions-policy", "headers"],
        ["cookie-secure", "cookies"],
        ["cookie-httponly", "cookies"],
        ["cookie-samesite", "cookies"],
        ["cors", "cors"],
        ["hosting", "disclosure"],
        ["debug-headers", "disclosure"],
        ["status", "disclosure"],
      ]
    );
    for (const rule of RULES) assert.equal(typeof rule.run, "function");
  });

  test("every rule tolerates an empty snapshot", () => {
    for (const rule of RULES) {
      for (const input of [{}, undefined, null]) {
        assert.doesNotThrow(() => rule.run(input), rule.id);
      }
    }
  });
});

// ---------------------------------------------------------------- versions

describe("1. server-header", () => {
  test("absent -> ok", () => {
    expectFinding(one("server-header", snap()), {
      id: "server-header",
      severity: "ok",
      title: "Server software hidden",
      evidence: "Server: —",
    });
  });

  test("empty value counts as absent", () => {
    assert.equal(one("server-header", snap({ headers: { server: "  " } })).severity, "ok");
  });

  test("version -> warn with nginx, Apache and IIS directives", () => {
    const f = one("server-header", snap({ headers: { server: "nginx/1.18.0" } }));
    expectFinding(f, { severity: "warn", title: "Server version exposed", evidence: "Server: nginx/1.18.0" });
    assert.ok(f.fix.includes("`server_tokens off;`"));
    assert.ok(f.fix.includes("`ServerTokens Prod`"));
    assert.ok(f.fix.includes("`ServerSignature Off`"));
  });

  test("IIS fix names the Windows version removeServerHeader needs and an older-IIS route", () => {
    const f = one("server-header", snap({ headers: { server: "Microsoft-IIS/10.0" } }));
    assert.ok(f.fix.includes("Windows Server 2019 or later"), f.fix);
    assert.ok(f.fix.includes('removeServerHeader="true"'));
    assert.ok(f.fix.includes("`RESPONSE_SERVER`"));
    assert.ok(!f.fix.includes("IIS 10+"));
  });

  test("platform banners -> ok Hosting platform named, even with a build number", () => {
    for (const server of ["awselb/2.0", "AWSELB/2.0", "elb", "cloudflare", "Vercel", "GitHub.com", "Fly/51ee4ef9 (2024-11-06)"]) {
      const f = one("server-header", snap({ headers: { server } }));
      expectFinding(f, {
        severity: "ok",
        title: "Hosting platform named",
        desc: "Only your hosting platform's name is visible, nothing about your own software.",
        evidence: `Server: ${server}`,
      });
      assert.ok(f.fix.startsWith("Nothing to change."), server);
    }
  });

  test("both version patterns count", () => {
    for (const server of ["Apache/2", "Microsoft-IIS/10.0", "LiteSpeed 6.1", "Caddy / 2"]) {
      assert.equal(one("server-header", snap({ headers: { server } })).severity, "warn", server);
    }
  });

  test("name only -> info", () => {
    for (const server of ["nginx", "Apache", "openresty", "LiteSpeed"]) {
      expectFinding(one("server-header", snap({ headers: { server } })), {
        severity: "info",
        title: "Server software named",
        evidence: `Server: ${server}`,
      });
    }
  });

  test("fix depends on who sets the name", () => {
    const own = one("server-header", snap({ headers: { server: "nginx" } }));
    assert.ok(own.fix.includes("`server_tokens off;`"));
    assert.ok(own.fix.includes("`ServerTokens Prod`"));
    const cdn = one("server-header", snap({ headers: { server: "cloudflare" } }));
    assert.ok(cdn.fix.includes("can't be removed"));
    assert.ok(!cdn.fix.includes("server_tokens"));
  });

  test("header names are matched case-insensitively", () => {
    assert.equal(one("server-header", snap({ headers: { Server: "nginx/1.25.3" } })).severity, "warn");
  });
});

describe("2. powered-by", () => {
  test("absent -> ok", () => {
    expectFinding(one("powered-by", snap()), {
      severity: "ok",
      title: "No framework banner",
      evidence: "X-Powered-By: —",
    });
  });

  test("version -> warn with PHP, Express and Next.js fixes", () => {
    const f = one("powered-by", snap({ headers: { "x-powered-by": "PHP/7.4.3" } }));
    expectFinding(f, { severity: "warn", title: "Backend version leaked", evidence: "X-Powered-By: PHP/7.4.3" });
    assert.ok(f.fix.includes("`expose_php = Off`"));
    assert.ok(f.fix.includes("`app.disable('x-powered-by')`"));
    assert.ok(f.fix.includes("`poweredByHeader: false`"));
  });

  test("name only -> info", () => {
    for (const value of ["Express", "Next.js", "ASP.NET"]) {
      const f = one("powered-by", snap({ headers: { "x-powered-by": value } }));
      expectFinding(f, { severity: "info", title: "Backend framework named" });
      assert.ok(f.fix.includes("`poweredByHeader: false`"));
    }
  });
});

describe("3. fingerprints", () => {
  test("none -> single ok finding", () => {
    expectFinding(one("fingerprints", snap()), {
      id: "fingerprints",
      severity: "ok",
      title: "No CMS fingerprints",
    });
  });

  test("x-aspnet-version and x-aspnetmvc-version are always warn", () => {
    const list = run("fingerprints", snap({ headers: { "x-aspnet-version": "4.0.30319", "x-aspnetmvc-version": "5" } }));
    assert.deepEqual(
      list.map((f) => [f.id, f.severity]),
      [
        ["fingerprints:x-aspnet-version", "warn"],
        ["fingerprints:x-aspnetmvc-version", "warn"],
      ]
    );
    assert.equal(list[0].evidence, "X-AspNet-Version: 4.0.30319");
    assert.equal(list[1].evidence, "X-AspNetMvc-Version: 5");
    list.forEach(checkFinding);
  });

  test("x-generator: warn with a version, info without", () => {
    const versioned = one("fingerprints", snap({ headers: { "x-generator": "WordPress 6.4.2" } }));
    expectFinding(versioned, { id: "fingerprints:x-generator", severity: "warn" });
    const named = one("fingerprints", snap({ headers: { "x-generator": "Drupal 10 (https://www.drupal.org)" } }));
    expectFinding(named, { id: "fingerprints:x-generator", severity: "info" });
  });

  test("Drupal cache headers -> one info finding", () => {
    const both = run("fingerprints", snap({ headers: { "x-drupal-cache": "HIT", "x-drupal-dynamic-cache": "MISS" } }));
    assert.equal(both.length, 1);
    expectFinding(both[0], {
      id: "fingerprints:x-drupal-cache",
      severity: "info",
      title: "Drupal detected",
      evidence: "X-Drupal-Cache: HIT",
    });
    const dynamicOnly = one("fingerprints", snap({ headers: { "x-drupal-dynamic-cache": "UNCACHEABLE" } }));
    expectFinding(dynamicOnly, { id: "fingerprints:x-drupal-dynamic-cache", title: "Drupal detected" });
  });

  test("x-runtime -> info", () => {
    expectFinding(one("fingerprints", snap({ headers: { "x-runtime": "0.012345" } })), {
      id: "fingerprints:x-runtime",
      severity: "info",
      title: "Ruby runtime header",
      evidence: "X-Runtime: 0.012345",
    });
  });

  test("link with api.w.org -> WordPress info, other links ignored", () => {
    const wp = one(
      "fingerprints",
      snap({
        headers: {
          link: '<https://a-rather-long-blog-domain.example.org/wp-json/>; rel="https://api.w.org/", <https://x.example/>; rel=shortlink',
        },
      })
    );
    expectFinding(wp, { id: "fingerprints:link", severity: "info", title: "WordPress detected" });
    assert.ok(wp.evidence.includes("api.w.org"), wp.evidence);
    assert.ok(wp.evidence.startsWith("Link: "));

    const other = one("fingerprints", snap({ headers: { link: '</style.css>; rel=preload; as=style' } }));
    assert.equal(other.id, "fingerprints");
    assert.equal(other.severity, "ok");
  });

  test("several headers -> one finding each, in catalog order, no ok", () => {
    const list = run(
      "fingerprints",
      snap({
        headers: {
          link: '<https://b.example/wp-json/>; rel="https://api.w.org/"',
          "x-runtime": "0.1",
          "x-generator": "Hugo 0.120.4",
          "x-aspnet-version": "4.0.30319",
        },
      })
    );
    assert.deepEqual(
      list.map((f) => f.id),
      ["fingerprints:x-aspnet-version", "fingerprints:x-generator", "fingerprints:x-runtime", "fingerprints:link"]
    );
  });
});

// ---------------------------------------------------------------- transport

describe("4. https", () => {
  test("https -> ok with TLS protocol", () => {
    expectFinding(one("https", snap()), {
      id: "https",
      severity: "ok",
      title: "Served over HTTPS",
      evidence: "TLS: TLSv1.3",
    });
  });

  test("https without tls data -> evidence TLS: on", () => {
    assert.equal(one("https", snap({ tls: null })).evidence, "TLS: on");
    assert.equal(one("https", snap({ tls: { ...TLS_OK, protocol: null } })).evidence, "TLS: on");
  });

  test("http -> crit with the final URL as evidence", () => {
    expectFinding(one("https", httpSnap()), {
      severity: "crit",
      title: "No HTTPS",
      evidence: "http://example.com/",
    });
  });

  test("long URLs are shortened", () => {
    const url = `http://example.com/${"a".repeat(100)}`;
    const f = one("https", httpSnap({ finalUrl: url }));
    assert.equal(f.evidence.length, 64);
    assert.ok(f.evidence.endsWith("…"));
  });

  test("falls back to requestedUrl, null when no URL is known", () => {
    assert.equal(one("https", snap({ finalUrl: undefined })).severity, "ok");
    expectNull("https", snap({ finalUrl: undefined, requestedUrl: undefined }));
    expectNull("https", snap({ finalUrl: "ftp://example.com/", requestedUrl: undefined }));
  });
});

describe("5. http-redirect", () => {
  test("probe missing or failed -> null", () => {
    expectNull("http-redirect", snap({ httpProbe: null }));
    expectNull("http-redirect", snap({ httpProbe: undefined }));
    expectNull("http-redirect", snap({ httpProbe: { result: "error", status: null, location: null } }));
    expectNull("http-redirect", snap({ httpProbe: { result: "something-new", status: 200 } }));
  });

  test("redirects-to-https -> ok", () => {
    const f = one("http-redirect", snap({ httpProbe: { result: "redirects-to-https", status: 301, location: "https://example.com/" } }));
    expectFinding(f, { severity: "ok", title: "HTTP redirects to HTTPS", evidence: "301 → https" });
    assert.equal(f.fix, "Nothing to change.");
  });

  test("temporary redirect -> still ok, fix suggests a permanent one", () => {
    const f = one("http-redirect", snap({ httpProbe: { result: "redirects-to-https", status: 302, location: "https://example.com/" } }));
    expectFinding(f, { severity: "ok", evidence: "302 → https" });
    assert.ok(f.fix.includes("return 301"));
  });

  test("serves-http -> warn", () => {
    expectFinding(one("http-redirect", snap({ httpProbe: { result: "serves-http", status: 200, location: null } })), {
      severity: "warn",
      title: "Plain HTTP still works",
      evidence: "HTTP 200",
    });
  });

  test("no-http -> ok", () => {
    expectFinding(one("http-redirect", snap({ httpProbe: { result: "no-http", status: null, location: null } })), {
      severity: "ok",
      title: "Plain HTTP is closed",
      evidence: "port 80 closed",
    });
  });
});

describe("6. hsts", () => {
  const hsts = (value) => one("hsts", snap({ headers: { "strict-transport-security": value } }));

  test("plain-http site -> null", () => {
    expectNull("hsts", httpSnap({ headers: { "strict-transport-security": "max-age=31536000" } }));
    expectNull("hsts", {});
  });

  test("absent -> warn", () => {
    expectFinding(one("hsts", snap()), { severity: "warn", title: "HSTS not enabled", evidence: "HSTS: —" });
  });

  test("max-age below 180 days -> warn", () => {
    expectFinding(hsts("max-age=300"), { severity: "warn", title: "HSTS max-age too short", evidence: "max-age=300" });
    assert.equal(hsts("max-age=15551999").severity, "warn");
    expectFinding(hsts("includeSubDomains"), { severity: "warn", evidence: "max-age: —" });
  });

  test("max-age of 180 days or more -> ok", () => {
    expectFinding(hsts("max-age=15552000"), { severity: "ok", title: "HSTS enabled", evidence: "max-age=15552000" });
    expectFinding(hsts("max-age=31536000; includeSubDomains; preload"), {
      severity: "ok",
      evidence: "max-age=31536000; includeSubDomains",
    });
    expectFinding(hsts('MAX-AGE="63072000"; INCLUDESUBDOMAINS'), {
      severity: "ok",
      evidence: "max-age=63072000; includeSubDomains",
    });
  });
});

describe("7. certificate", () => {
  const cert = (tls) => one("certificate", snap({ tls: { ...TLS_OK, ...tls } }));

  test("no tls -> null", () => {
    expectNull("certificate", snap({ tls: null }));
    expectNull("certificate", httpSnap());
  });

  test("CERT_HAS_EXPIRED -> crit Certificate expired, with the day count when known", () => {
    const expired = cert({ valid: false, error: "CERT_HAS_EXPIRED", daysLeft: -3 });
    expectFinding(expired, { severity: "crit", title: "Certificate expired", evidence: "expired 3 days ago · Let's Encrypt" });
    assert.ok(expired.desc.includes("expired"));
    assert.ok(expired.fix.includes("`certbot renew`"));
    // Clock skew: the verifier says expired but our day count doesn't.
    expectFinding(cert({ valid: false, error: "CERT_HAS_EXPIRED", daysLeft: 0 }), {
      title: "Certificate expired",
      evidence: "CERT_HAS_EXPIRED",
    });
    expectFinding(cert({ valid: false, error: "CERT_HAS_EXPIRED", daysLeft: null }), { evidence: "CERT_HAS_EXPIRED" });
  });

  test("not trusted -> crit with the error code", () => {

    const selfSigned = cert({ valid: false, error: "DEPTH_ZERO_SELF_SIGNED_CERT" });
    expectFinding(selfSigned, { severity: "crit", evidence: "DEPTH_ZERO_SELF_SIGNED_CERT" });
    assert.ok(selfSigned.desc.includes("self-signed"));

    const altName = cert({ valid: false, error: "ERR_TLS_CERT_ALTNAME_INVALID" });
    assert.ok(altName.desc.includes("domain name"));

    expectFinding(cert({ valid: false, error: null }), { severity: "crit", evidence: "verification failed" });
    expectFinding(cert({ valid: false, error: "SOMETHING_ELSE" }), { severity: "crit", evidence: "SOMETHING_ELSE" });
  });

  test("past expiry -> crit Certificate expired", () => {
    expectFinding(cert({ daysLeft: -3 }), {
      severity: "crit",
      title: "Certificate expired",
      evidence: "expired 3 days ago · Let's Encrypt",
    });
    assert.equal(cert({ daysLeft: -1 }).evidence, "expired 1 day ago · Let's Encrypt");
  });

  test("under 14 days -> crit with the day count", () => {
    expectFinding(cert({ daysLeft: 13 }), {
      severity: "crit",
      title: "Certificate expires in 13 days",
      evidence: "13 days left · Let's Encrypt",
    });
    expectFinding(cert({ daysLeft: 1 }), { severity: "crit", title: "Certificate expires in 1 day" });
    expectFinding(cert({ daysLeft: 0 }), { severity: "crit", title: "Certificate expires today" });
  });

  test("14 to 29 days -> warn", () => {
    expectFinding(cert({ daysLeft: 14 }), { severity: "warn", title: "Certificate expires soon" });
    expectFinding(cert({ daysLeft: 29 }), { severity: "warn", evidence: "29 days left · Let's Encrypt" });
  });

  test("30 days or more -> ok", () => {
    expectFinding(cert({ daysLeft: 30 }), {
      severity: "ok",
      title: "Certificate valid",
      evidence: "30 days left · Let's Encrypt",
    });
    assert.equal(cert({ issuer: null }).evidence, "84 days left");
    assert.equal(cert({ daysLeft: null }).evidence, "trusted · Let's Encrypt");
    assert.equal(cert({ daysLeft: null }).severity, "ok");
  });
});

// ---------------------------------------------------------------- headers

describe("8. csp", () => {
  const csp = (value) => one("csp", snap({ headers: { "content-security-policy": value } }));

  test("absent -> warn", () => {
    expectFinding(one("csp", snap()), { severity: "warn", title: "No content security policy", evidence: "CSP: —" });
  });

  test("report-only -> info", () => {
    const f = one("csp", snap({ headers: { "content-security-policy-report-only": "default-src 'self'" } }));
    expectFinding(f, {
      severity: "info",
      title: "CSP in report-only mode",
      evidence: "CSP-Report-Only: default-src 'self'",
    });
  });

  test("enforced policy without unsafe-inline -> ok", () => {
    expectFinding(csp("default-src 'self'"), {
      severity: "ok",
      title: "Content security policy set",
      evidence: "CSP: default-src 'self'",
    });
    assert.equal(csp("default-src 'none'; script-src 'self' https://cdn.example.com").severity, "ok");
    assert.equal(csp("script-src 'nonce-abc' 'strict-dynamic' https:").severity, "ok", "strict CSP with scheme fallback");
  });

  test("policy that doesn't restrict scripts -> warn, like no policy", () => {
    for (const policy of ["frame-ancestors 'none'", "img-src 'self'", "upgrade-insecure-requests", "script-src *", "default-src https:", "script-src 'self' data:"]) {
      const f = csp(policy);
      assert.equal(f.severity, "warn", policy);
      assert.equal(f.title, "CSP doesn't restrict scripts", policy);
    }
    assert.equal(csp("img-src 'self'").evidence, "CSP script-src: —");
    assert.equal(csp("script-src *").evidence, "CSP: script-src: *");
    // A second policy that does restrict scripts makes the combination safe.
    assert.equal(csp("script-src *, script-src 'self'").severity, "ok");
  });

  test("unsafe-inline without nonce or hash -> info", () => {
    expectFinding(csp("default-src 'self'; script-src 'self' 'unsafe-inline'"), {
      severity: "info",
      title: "CSP allows inline scripts",
      evidence: "CSP script-src: 'unsafe-inline'",
    });
    expectFinding(csp("default-src 'self' 'unsafe-inline'"), {
      severity: "info",
      evidence: "CSP default-src: 'unsafe-inline'",
    });
    assert.equal(csp("SCRIPT-SRC 'SELF' 'UNSAFE-INLINE'").severity, "info");
  });

  test("script-src takes precedence over default-src", () => {
    assert.equal(csp("default-src 'unsafe-inline'; script-src 'self'").severity, "ok");
    assert.equal(csp("default-src 'self'; script-src 'unsafe-inline'").severity, "info");
  });

  test("nonce, hash or strict-dynamic neutralise unsafe-inline", () => {
    for (const source of ["'nonce-abc123'", "'sha256-xyz='", "'sha384-xyz='", "'sha512-xyz='", "'strict-dynamic'"]) {
      assert.equal(csp(`script-src 'self' 'unsafe-inline' ${source}`).severity, "ok", source);
    }
  });

  test("a second enforced policy that blocks inline wins", () => {
    assert.equal(csp("script-src 'unsafe-inline', script-src 'self'").severity, "ok");
  });
});

describe("9. clickjacking", () => {
  const cj = (headers) => one("clickjacking", snap({ headers }));

  test("DENY or SAMEORIGIN -> ok", () => {
    expectFinding(cj({ "x-frame-options": "DENY" }), {
      severity: "ok",
      title: "Clickjacking protection on",
      evidence: "X-Frame-Options: DENY",
    });
    assert.equal(cj({ "x-frame-options": "sameorigin" }).severity, "ok");
    assert.equal(cj({ "x-frame-options": "DENY, DENY" }).severity, "ok");
  });

  test("CSP frame-ancestors -> ok", () => {
    expectFinding(cj({ "content-security-policy": "default-src 'self'; frame-ancestors 'self'" }), {
      severity: "ok",
      evidence: "CSP frame-ancestors: 'self'",
    });
  });

  test("missing -> warn", () => {
    expectFinding(cj({}), {
      severity: "warn",
      title: "Clickjacking protection missing",
      evidence: "X-Frame-Options: —",
    });
  });

  test("ALLOW-FROM counts as missing", () => {
    const f = cj({ "x-frame-options": "ALLOW-FROM https://partner.example" });
    expectFinding(f, { severity: "warn", evidence: "X-Frame-Options: ALLOW-FROM https://partner.example" });
    assert.ok(f.desc.includes("ALLOW-FROM"));
    assert.ok(f.fix.includes("frame-ancestors"));
  });

  test("other values and report-only frame-ancestors do not protect", () => {
    assert.equal(cj({ "x-frame-options": "ALLOWALL" }).severity, "warn");
    assert.equal(cj({ "content-security-policy-report-only": "frame-ancestors 'self'" }).severity, "warn");
  });
});

describe("10. nosniff", () => {
  test("nosniff -> ok", () => {
    expectFinding(one("nosniff", snap({ headers: { "x-content-type-options": "nosniff" } })), {
      severity: "ok",
      title: "MIME sniffing blocked",
      evidence: "X-Content-Type-Options: nosniff",
    });
    assert.equal(one("nosniff", snap({ headers: { "x-content-type-options": "NoSniff" } })).severity, "ok");
  });

  test("absent or other value -> warn", () => {
    expectFinding(one("nosniff", snap()), {
      severity: "warn",
      title: "MIME sniffing not blocked",
      evidence: "X-Content-Type-Options: —",
    });
    assert.equal(one("nosniff", snap({ headers: { "x-content-type-options": "sniff" } })).severity, "warn");
  });
});

describe("11. referrer-policy", () => {
  const rp = (value) => one("referrer-policy", snap({ headers: value === undefined ? {} : { "referrer-policy": value } }));

  test("absent -> info that says the browser default is safe", () => {
    const f = rp(undefined);
    expectFinding(f, { severity: "info", title: "No referrer policy", evidence: "Referrer-Policy: —" });
    assert.match(f.desc, /default to a safe/);
  });

  test("unsafe-url or no-referrer-when-downgrade -> warn", () => {
    expectFinding(rp("unsafe-url"), { severity: "warn", title: "Referrer policy leaks full URLs" });
    assert.equal(rp("no-referrer-when-downgrade").severity, "warn");
    assert.equal(rp("No-Referrer-When-Downgrade").severity, "warn");
  });

  test("anything else -> ok", () => {
    for (const value of ["no-referrer", "strict-origin-when-cross-origin", "same-origin"]) {
      expectFinding(rp(value), { severity: "ok", title: "Referrer policy set" });
    }
  });
});

describe("12. permissions-policy", () => {
  test("present -> ok", () => {
    expectFinding(one("permissions-policy", snap({ headers: { "permissions-policy": "camera=()" } })), {
      severity: "ok",
      title: "Permissions policy set",
      evidence: "Permissions-Policy: camera=()",
    });
  });

  test("absent -> info", () => {
    expectFinding(one("permissions-policy", snap()), {
      severity: "info",
      title: "No permissions policy",
      evidence: "Permissions-Policy: —",
    });
  });
});

// ---------------------------------------------------------------- cookies

describe("13. cookie-secure", () => {
  test("no cookies -> ok with id cookies (https and http)", () => {
    for (const s of [snap(), httpSnap()]) {
      expectFinding(one("cookie-secure", s), {
        id: "cookies",
        category: "cookies",
        severity: "ok",
        title: "No cookies on first visit",
        evidence: "Set-Cookie: —",
      });
    }
  });

  test("https with a cookie missing Secure -> warn", () => {
    const f = one("cookie-secure", snap({ setCookies: ["PHPSESSID=abc; path=/", "theme=dark; Secure"] }));
    expectFinding(f, { id: "cookie-secure", severity: "warn", title: "Cookies sent without Secure", evidence: "PHPSESSID" });
  });

  test("evidence counts the rest", () => {
    const f = one("cookie-secure", snap({ setCookies: ["a=1", "b=2", "c=3; Secure", "d=4"] }));
    assert.equal(f.evidence, "a (+2 more)");
  });

  test("Secure is matched as an attribute, case-insensitively", () => {
    assert.equal(one("cookie-secure", snap({ setCookies: ["a=1; SECURE"] })).severity, "ok");
    assert.equal(one("cookie-secure", snap({ setCookies: ["pref=secure; path=/"] })).severity, "warn");
  });

  test("all Secure -> ok", () => {
    expectFinding(one("cookie-secure", snap({ setCookies: ["a=1; Secure", "b=2; Secure; HttpOnly"] })), {
      id: "cookie-secure",
      severity: "ok",
      title: "Cookies marked Secure",
      evidence: "2 cookies, all Secure",
    });
  });

  test("plain-http site with cookies -> null", () => {
    expectNull("cookie-secure", httpSnap({ setCookies: ["PHPSESSID=abc"] }));
  });

  test("very long cookie names stay within 64 characters", () => {
    const name = "n".repeat(120);
    const f = one("cookie-secure", snap({ setCookies: [`${name}=1`, "b=2"] }));
    assert.ok(f.evidence.length <= 64);
    assert.ok(f.evidence.endsWith("… (+1 more)"), f.evidence);
  });
});

describe("14. cookie-httponly", () => {
  const ho = (setCookies) => one("cookie-httponly", snap({ setCookies }));

  test("no cookies -> null", () => {
    expectNull("cookie-httponly", snap());
  });

  test("sensitive cookie without HttpOnly -> warn", () => {
    expectFinding(ho(["PHPSESSID=abc; Secure", "theme=dark"]), {
      severity: "warn",
      title: "Session cookie readable by scripts",
      evidence: "PHPSESSID",
    });
    for (const name of ["connect.sid", "auth_token", "jwt", "remember_me", "_csrf", "user_login", "user_SESSION", "wordpress_logged_in_abc123"]) {
      assert.equal(ho([`${name}=1`]).severity, "warn", name);
    }
  });

  test("CSRF cookies meant for front-end code are not treated as sensitive", () => {
    for (const name of ["XSRF-TOKEN", "csrftoken"]) {
      assert.equal(ho([`${name}=1`]).severity, "info", name);
    }
  });

  test("evidence lists only sensitive cookies", () => {
    assert.equal(ho(["theme=1", "sid=2", "token=3; HttpOnly", "auth=4"]).evidence, "sid (+1 more)");
  });

  test("only non-sensitive cookies readable -> info", () => {
    expectFinding(ho(["theme=dark", "session=abc; HttpOnly"]), {
      severity: "info",
      title: "Some cookies readable by scripts",
      evidence: "theme",
    });
    assert.equal(ho(["theme=session"]).severity, "info", "sensitivity comes from the name, not the value");
  });

  test("all HttpOnly -> ok", () => {
    expectFinding(ho(["a=1; httponly", "sid=2; HttpOnly"]), {
      severity: "ok",
      title: "Cookies are HttpOnly",
      evidence: "2 cookies, all HttpOnly",
    });
  });

  test("runs on plain-http sites too", () => {
    assert.equal(one("cookie-httponly", httpSnap({ setCookies: ["sid=1"] })).severity, "warn");
  });
});

describe("15. cookie-samesite", () => {
  const ss = (setCookies) => one("cookie-samesite", snap({ setCookies }));

  test("no cookies -> null", () => {
    expectNull("cookie-samesite", snap());
  });

  test("SameSite=None without Secure -> warn (beats missing)", () => {
    expectFinding(ss(["a=1; SameSite=None", "b=2"]), {
      severity: "warn",
      title: "SameSite=None without Secure",
      evidence: "a",
    });
  });

  test("missing SameSite -> info", () => {
    expectFinding(ss(["a=1; SameSite=Lax", "b=2", "c=3; SameSite=bogus"]), {
      severity: "info",
      title: "Cookies without SameSite",
      evidence: "b (+1 more)",
    });
  });

  test("all set -> ok", () => {
    expectFinding(ss(["a=1; samesite=strict", "b=2; SameSite=None; Secure"]), {
      severity: "ok",
      title: "Cookies set SameSite",
      evidence: "2 cookies, all SameSite",
    });
  });
});

// ---------------------------------------------------------------- cors

describe("16. cors", () => {
  const cors = (headers) => one("cors", snap({ headers }));

  test("absent -> ok, scoped to a normal request", () => {
    expectFinding(cors({}), {
      severity: "ok",
      title: "No cross-origin access",
      desc: "Your page sends no CORS headers to a normal request, so other websites can't read it from a visitor's browser.",
      evidence: "ACAO: —",
    });
  });

  test("* with credentials -> info: browsers ignore credentials with *", () => {
    const f = cors({ "access-control-allow-origin": "*", "access-control-allow-credentials": "true" });
    expectFinding(f, { severity: "info", title: "CORS credentials flag ignored", evidence: "ACAO: *, credentials: true" });
    assert.match(f.desc, /no effect/);
    assert.ok(f.fix.includes("`Access-Control-Allow-Credentials: true`"));
    assert.equal(
      cors({ "access-control-allow-origin": "*", "access-control-allow-credentials": "TRUE" }).severity,
      "info"
    );
  });

  test("* alone -> ok Public CORS, no logins", () => {
    const f = cors({ "access-control-allow-origin": "*" });
    expectFinding(f, { severity: "ok", title: "Public CORS, no logins", evidence: "ACAO: *" });
    assert.match(f.desc, /only anonymously/);
    assert.ok(f.fix.startsWith("Nothing to change."));
    assert.match(f.fix, /fine for public/);
    assert.equal(
      cors({ "access-control-allow-origin": "*", "access-control-allow-credentials": "false" }).severity,
      "ok"
    );
  });

  test("specific origin -> ok", () => {
    expectFinding(
      cors({ "access-control-allow-origin": "https://app.example.com", "access-control-allow-credentials": "true" }),
      { severity: "ok", title: "CORS restricted", evidence: "ACAO: https://app.example.com" }
    );
  });
});

// ---------------------------------------------------------------- disclosure

describe("17. hosting", () => {
  const host = (headers) => run("hosting", snap({ headers }));

  test("no match -> null", () => {
    expectNull("hosting", snap({ headers: { server: "nginx" } }));
  });

  test("each provider is recognised; evidence is the header that matched", () => {
    const cases = [
      [{ "cf-ray": "8d2f-AMS" }, "Cloudflare", "CF-Ray: 8d2f-AMS"],
      [{ server: "cloudflare" }, "Cloudflare", "Server: cloudflare"],
      [{ "x-vercel-id": "fra1::abc" }, "Vercel", "X-Vercel-Id: fra1::abc"],
      [{ "x-nf-request-id": "01H" }, "Netlify", "X-NF-Request-ID: 01H"],
      [{ "x-amz-cf-id": "abc==" }, "Amazon CloudFront", "X-Amz-Cf-Id: abc=="],
      [{ "x-fastly-request-id": "abc" }, "Fastly", "X-Fastly-Request-Id: abc"],
      [{ "x-served-by": "cache-fra-eddf8230102-FRA" }, "Fastly", "X-Served-By: cache-fra-eddf8230102-FRA"],
      [{ "x-github-request-id": "A1B2:3C4D" }, "GitHub Pages", "X-GitHub-Request-Id: A1B2:3C4D"],
      [{ "x-azure-ref": "20261022T" }, "Azure Front Door", "X-Azure-Ref: 20261022T"],
      [{ "fly-request-id": "01J" }, "Fly.io", "Fly-Request-Id: 01J"],
      [{ "x-render-origin-server": "Render" }, "Render", "X-Render-Origin-Server: Render"],
      [{ "x-shopid": "12345" }, "Shopify", "X-ShopId: 12345"],
      [{ server: "AkamaiGHost" }, "Akamai", "Server: AkamaiGHost"],
      [{ server: "Google Frontend" }, "Google", "Server: Google Frontend"],
      [{ server: "gws" }, "Google", "Server: gws"],
    ];
    for (const [headers, name, evidence] of cases) {
      const list = host(headers);
      assert.equal(list.length, 1, name);
      expectFinding(list[0], { id: "hosting", severity: "info", title: "Hosting provider identified", evidence });
      assert.ok(list[0].desc.includes(name), `${name} named in desc`);
      assert.ok(list[0].fix.includes(name), `${name} named in fix`);
    }
  });

  test("evidence never uses a made-up Via label", () => {
    const f = host({ "x-vercel-id": "fra1::iad1::abcd-1729600000000-0123456789ab" })[0];
    assert.doesNotMatch(f.evidence, /^via:/i);
    assert.ok(f.evidence.startsWith("X-Vercel-Id: "));
  });

  test("hosting platforms win over the CDN in front of them", () => {
    // GitHub Pages runs on Fastly; Render and Shopify run behind Cloudflare.
    const pages = host({ "x-github-request-id": "x", "x-fastly-request-id": "y", "x-served-by": "cache-fra-1" })[0];
    assert.ok(pages.desc.includes("GitHub Pages"));
    assert.ok(!pages.fix.includes("origin server"), "no origin lock-down advice for a platform");
    assert.ok(host({ "x-render-origin-server": "uvicorn", "cf-ray": "y", server: "cloudflare" })[0].desc.includes("Render"));
    assert.ok(host({ "x-shopid": "1", "cf-ray": "y" })[0].desc.includes("Shopify"));
    // Among CDNs, the order is unchanged.
    assert.equal(host({ "x-amz-cf-id": "x", "cf-ray": "y" })[0].evidence, "CF-Ray: y");
  });

  test("near misses do not match", () => {
    expectNull("hosting", snap({ headers: { server: "gws-proxy" } }));
    expectNull("hosting", snap({ headers: { "x-served-by": "web-01" } }));
  });
});

describe("18. debug-headers", () => {
  const dbg = (headers) => one("debug-headers", snap({ headers }));

  test("nothing -> ok", () => {
    expectFinding(dbg({}), { severity: "ok", title: "No debug headers" });
  });

  test("debug token -> crit", () => {
    expectFinding(dbg({ "x-debug-token": "a1b2c3" }), {
      severity: "crit",
      title: "Debug profiler exposed",
      evidence: "X-Debug-Token: a1b2c3",
    });
    expectFinding(dbg({ "x-debug-token-link": "https://x.example/_profiler/a1" }), {
      severity: "crit",
      evidence: "X-Debug-Token-Link: https://x.example/_profiler/a1",
    });
  });

  test("debug token and internal host leak are both reported", () => {
    const report = analyze(snap({ headers: { "x-debug-token": "a", "x-backend-server": "10.0.0.5" } }));
    const ids = report.findings.filter((f) => f.id.startsWith("debug-headers")).map((f) => [f.id, f.severity]);
    assert.deepEqual(ids, [
      ["debug-headers:token", "crit"],
      ["debug-headers:internal", "warn"],
    ]);
  });

  test("private addresses and internal names -> warn", () => {
    const leaks = [
      ["x-backend-server", "10.0.1.12"],
      ["x-server-name", "172.20.0.5:8080"],
      ["x-upstream", "192.168.1.10"],
      ["x-real-server", "127.0.0.1"],
      ["x-forwarded-server", "db.internal"],
      ["x-host", "web01.local"],
      ["x-served-by", "app.lan:3000"],
      ["x-upstream", "localhost:3000"],
      ["x-backend-server", "ip-10-0-3-17"],
    ];
    for (const [header, value] of leaks) {
      const f = dbg({ [header]: value });
      expectFinding(f, { severity: "warn", title: "Internal host name leaked" });
      assert.ok(f.evidence.endsWith(`: ${value}`), f.evidence);
      assert.ok(f.fix.includes(f.evidence.split(":")[0]), "fix names the header");
    }
    assert.equal(dbg({ "x-backend-server": "10.0.1.12" }).evidence, "X-Backend-Server: 10.0.1.12");
  });

  test("public values and unlisted headers -> ok", () => {
    const clean = [
      { "x-backend-server": "172.32.0.1" },
      { "x-backend-server": "8.8.8.8" },
      { "x-served-by": "cache-fra-etou8220110-FRA" },
      { "x-host": "www.localbusiness.com" },
      { "x-forwarded-server": "app-v1.10.3" },
      { "x-upstream": "local.example.com" },
      { "x-something-else": "10.0.0.1" },
    ];
    for (const headers of clean) assert.equal(dbg(headers).severity, "ok", JSON.stringify(headers));
  });
});

describe("19. status", () => {
  test("2xx and 3xx -> null", () => {
    for (const status of [200, 204, 301, 399]) expectNull("status", snap({ status }));
    expectNull("status", snap({ status: undefined }));
  });

  test("4xx -> info that says results may be partial", () => {
    for (const status of [400, 401, 403, 404, 429, 499]) {
      const f = one("status", snap({ status }));
      expectFinding(f, { severity: "info", title: `Page returned HTTP ${status}`, evidence: `HTTP ${status}` });
      assert.match(f.desc, /partial/);
    }
  });

  test("5xx -> warn", () => {
    for (const status of [500, 502, 503]) {
      expectFinding(one("status", snap({ status })), {
        severity: "warn",
        title: "Server returned an error",
        evidence: `HTTP ${status}`,
      });
    }
  });
});

// ---------------------------------------------------------------- scoring

describe("scoreFindings", () => {
  test("weights: crit 20, warn 8, info 1, ok 0", () => {
    assert.equal(scoreFindings(mix({ crit: 1 })).score, 20);
    assert.equal(scoreFindings(mix({ warn: 1 })).score, 8);
    assert.equal(scoreFindings(mix({ info: 1 })).score, 1);
    assert.equal(scoreFindings(mix({ ok: 10 })).score, 0);
    assert.equal(scoreFindings(mix({ crit: 1, warn: 2, info: 3, ok: 4 })).score, 39);
  });

  test("level thresholds", () => {
    const cases = [
      [mix({}), 0, "low"],
      [mix({ crit: 1, info: 4 }), 24, "low"],
      [mix({ warn: 3 }), 24, "low"],
      [mix({ crit: 1, info: 5 }), 25, "moderate"],
      [mix({ crit: 2, warn: 1, info: 6 }), 54, "moderate"],
      [mix({ crit: 2, warn: 1, info: 7 }), 55, "high"],
      [mix({ crit: 5 }), 100, "high"],
    ];
    for (const [findings, score, level] of cases) {
      const result = scoreFindings(findings);
      assert.equal(result.score, score);
      assert.equal(result.level, level, `score ${score}`);
    }
  });

  test("score is capped at 100", () => {
    assert.equal(scoreFindings(mix({ crit: 6 })).score, 100);
    assert.equal(scoreFindings(mix({ crit: 4, warn: 3 })).score, 100);
    assert.equal(scoreFindings(mix({ crit: 6 })).level, "high");
  });

  test("counts", () => {
    assert.deepEqual(scoreFindings(mix({ crit: 1, warn: 2, info: 3, ok: 4 })).counts, {
      total: 10,
      crit: 1,
      warn: 2,
      info: 3,
      ok: 4,
    });
  });

  test("tolerates bad input", () => {
    const empty = { score: 0, level: "low", counts: { total: 0, crit: 0, warn: 0, info: 0, ok: 0 } };
    assert.deepEqual(scoreFindings(undefined), empty);
    assert.deepEqual(scoreFindings(null), empty);
    assert.deepEqual(scoreFindings("crit"), empty);
    assert.equal(scoreFindings([null, { severity: "bogus" }, { severity: "crit" }]).score, 20);
  });
});

// ---------------------------------------------------------------- analyze

describe("analyze: sorting", () => {
  test("crit, warn, info, ok; catalog order within a severity", () => {
    const report = analyze(
      snap({
        headers: {
          server: "nginx",
          "x-powered-by": "Express",
          "x-runtime": "0.2",
          "x-aspnet-version": "4.0.30319",
          "x-content-type-options": "nosniff",
          "access-control-allow-origin": "*",
          "access-control-allow-credentials": "true",
        },
        status: 404,
      })
    );
    assert.deepEqual(pairs(report), [
      "warn fingerprints:x-aspnet-version",
      "warn hsts",
      "warn csp",
      "warn clickjacking",
      "info server-header",
      "info powered-by",
      "info fingerprints:x-runtime",
      "info referrer-policy",
      "info permissions-policy",
      "info cors",
      "info status",
      "ok https",
      "ok certificate",
      "ok nosniff",
      "ok cookies",
      "ok debug-headers",
    ]);
    checkReport(report);
  });
});

describe("analyze: target", () => {
  test("is built from the snapshot", () => {
    const report = analyze(loadFixture("hardened.json"));
    assert.deepEqual(report.target, {
      input: "hardened.example.com",
      url: "https://www.hardened.example.com/",
      host: "www.hardened.example.com",
      status: 200,
      timingMs: 212,
      redirects: 1,
      scannedAt: "2026-10-22T15:20:00.000Z",
    });
  });
});

describe("analyze: robustness", () => {
  test("almost-empty snapshot {} does not throw", () => {
    const report = analyze({});
    checkReport(report);
    assert.deepEqual(report.target, {
      input: "",
      url: "",
      host: "",
      status: null,
      timingMs: null,
      redirects: 0,
      scannedAt: null,
    });
    assert.deepEqual(pairs(report), [
      "warn csp",
      "warn clickjacking",
      "warn nosniff",
      "info referrer-policy",
      "info permissions-policy",
      "ok server-header",
      "ok powered-by",
      "ok fingerprints",
      "ok cookies",
      "ok cors",
      "ok debug-headers",
    ]);
    assert.equal(report.score, 26);
    assert.equal(report.level, "moderate");
  });

  test("non-object input does not throw", () => {
    for (const input of [undefined, null, "https://example.com", 42, [], true]) {
      assert.doesNotThrow(() => checkReport(analyze(input)), String(input));
    }
  });

  test("oddly typed fields do not throw", () => {
    const weird = [
      { headers: null, setCookies: null, tls: null, httpProbe: null, redirects: null },
      { headers: "server: nginx", setCookies: "PHPSESSID=1", tls: "yes", httpProbe: 5, redirects: "1" },
      {
        finalUrl: 42,
        requestedUrl: { href: "https://x" },
        status: "200",
        timingMs: "fast",
        headers: {
          server: ["nginx/1.2", "extra"],
          "x-powered-by": 7.4,
          "content-security-policy": { nested: true },
          "x-frame-options": null,
          "strict-transport-security": undefined,
          "": "empty name",
        },
        setCookies: [null, 5, "", "=", ";", "a", ";;; Secure", "=value; HttpOnly", { name: "x" }],
        tls: { valid: "no", daysLeft: "5", issuer: 9, protocol: {} },
        httpProbe: { result: 7, status: "301" },
      },
      { finalUrl: "not a url", headers: { "Content-Security-Policy": ";;;,,," } },
      { finalUrl: "https://example.com/", tls: { valid: true, daysLeft: NaN } },
    ];
    for (const s of weird) {
      let report;
      assert.doesNotThrow(() => {
        report = analyze(s);
      }, JSON.stringify(s));
      checkReport(report);
    }
  });

  test("header values with control characters or huge length stay tidy", () => {
    const report = analyze(
      snap({
        headers: {
          server: `nginx/1.18.0\r\n${"x".repeat(500)}`,
          "x-powered-by": "😀".repeat(80),
          "content-security-policy": "default-src " + "'self' ".repeat(50),
        },
        setCookies: [`${"😀".repeat(70)}=1`],
      })
    );
    checkReport(report);
  });

  test("does not mutate the snapshot and does not read the clock", () => {
    const original = loadFixture("leaky.json");
    const frozen = deepFreeze(structuredClone(original));
    const realNow = Date.now;
    Date.now = () => {
      throw new Error("analyze must not read the clock");
    };
    try {
      const first = analyze(frozen);
      const second = analyze(frozen);
      assert.deepEqual(first, second, "deterministic");
    } finally {
      Date.now = realNow;
    }
    assert.deepEqual(frozen, original);
  });
});

// ---------------------------------------------------------------- fixtures

describe("fixtures", () => {
  test("required fixtures exist", () => {
    for (const name of ["hardened.json", "leaky.json", "http-only.json", "expired-cert.json", "cdn.json"]) {
      assert.ok(FIXTURES.includes(name), name);
    }
  });

  for (const name of FIXTURES) {
    test(`${name}: report invariants and copy limits`, () => {
      checkReport(analyze(loadFixture(name)));
    });
  }

  test("hardened.json -> low, mostly ok", () => {
    const report = analyze(loadFixture("hardened.json"));
    assert.equal(report.score, 1);
    assert.equal(report.level, "low");
    assert.deepEqual(report.counts, { total: 17, crit: 0, warn: 0, info: 1, ok: 16 });
    assert.deepEqual(pairs(report), [
      "info server-header",
      "ok powered-by",
      "ok fingerprints",
      "ok https",
      "ok http-redirect",
      "ok hsts",
      "ok certificate",
      "ok csp",
      "ok clickjacking",
      "ok nosniff",
      "ok referrer-policy",
      "ok permissions-policy",
      "ok cookie-secure",
      "ok cookie-httponly",
      "ok cookie-samesite",
      "ok cors",
      "ok debug-headers",
    ]);
  });

  test("leaky.json -> high", () => {
    const report = analyze(loadFixture("leaky.json"));
    assert.equal(report.score, 95);
    assert.equal(report.level, "high");
    assert.deepEqual(report.counts, { total: 17, crit: 1, warn: 9, info: 3, ok: 4 });
    assert.deepEqual(pairs(report), [
      "crit debug-headers",
      "warn server-header",
      "warn powered-by",
      "warn http-redirect",
      "warn hsts",
      "warn csp",
      "warn clickjacking",
      "warn nosniff",
      "warn cookie-secure",
      "warn cookie-httponly",
      "info referrer-policy",
      "info permissions-policy",
      "info cookie-samesite",
      "ok fingerprints",
      "ok https",
      "ok certificate",
      "ok cors",
    ]);
    const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    assert.equal(byId["server-header"].evidence, "Server: nginx/1.18.0");
    assert.equal(byId["powered-by"].evidence, "X-Powered-By: PHP/7.4.3");
    assert.equal(byId["clickjacking"].evidence, "X-Frame-Options: —");
    assert.equal(byId["cookie-secure"].evidence, "PHPSESSID");
    assert.equal(byId["http-redirect"].evidence, "HTTP 200");
  });

  test("http-only.json -> no HTTPS, transport rules skipped", () => {
    const report = analyze(loadFixture("http-only.json"));
    assert.equal(report.score, 48);
    assert.equal(report.level, "moderate");
    assert.deepEqual(pairs(report), [
      "crit https",
      "warn server-header",
      "warn csp",
      "warn nosniff",
      "info referrer-policy",
      "info permissions-policy",
      "info cookie-httponly",
      "info cookie-samesite",
      "ok powered-by",
      "ok fingerprints",
      "ok clickjacking",
      "ok cors",
      "ok debug-headers",
    ]);
    const ids = report.findings.map((f) => f.id);
    for (const skipped of ["http-redirect", "hsts", "certificate", "cookie-secure", "cookies"]) {
      assert.ok(!ids.includes(skipped), `${skipped} is skipped`);
    }
    assert.equal(report.target.host, "old-shop.example.com");
  });

  test("expired-cert.json -> certificate expired", () => {
    const report = analyze(loadFixture("expired-cert.json"));
    assert.equal(report.score, 38);
    assert.equal(report.level, "moderate");
    assert.deepEqual(pairs(report), [
      "crit certificate",
      "warn csp",
      "warn referrer-policy",
      "info server-header",
      "info permissions-policy",
      "ok powered-by",
      "ok fingerprints",
      "ok https",
      "ok http-redirect",
      "ok hsts",
      "ok clickjacking",
      "ok nosniff",
      "ok cookies",
      "ok cors",
      "ok debug-headers",
    ]);
    const cert = report.findings[0];
    assert.equal(cert.title, "Certificate expired");
    assert.equal(cert.evidence, "expired 22 days ago · Let's Encrypt");
  });

  test("cdn.json -> Cloudflare, public CORS", () => {
    const report = analyze(loadFixture("cdn.json"));
    assert.equal(report.score, 26);
    assert.equal(report.level, "moderate");
    assert.deepEqual(pairs(report), [
      "warn hsts",
      "warn csp",
      "warn clickjacking",
      "info permissions-policy",
      "info hosting",
      "ok server-header",
      "ok powered-by",
      "ok fingerprints",
      "ok https",
      "ok http-redirect",
      "ok certificate",
      "ok nosniff",
      "ok referrer-policy",
      "ok cookie-secure",
      "ok cookie-httponly",
      "ok cookie-samesite",
      "ok cors",
      "ok debug-headers",
    ]);
    const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    assert.equal(byId.hosting.evidence, "CF-Ray: 8d2f6a1b3c4e5f60-AMS");
    assert.equal(byId.cors.evidence, "ACAO: *");
    assert.equal(byId["server-header"].evidence, "Server: cloudflare");
  });

  test("wordpress.json -> WordPress fingerprint, inline scripts", () => {
    const report = analyze(loadFixture("wordpress.json"));
    assert.equal(report.score, 23);
    assert.equal(report.level, "low");
    const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    assert.equal(byId["fingerprints:link"].title, "WordPress detected");
    assert.equal(byId["fingerprints:link"].evidence, 'Link: <…/wp-json/>; rel="https://api.w.org/"');
    assert.equal(byId.csp.severity, "info");
    assert.equal(byId["cookie-secure"].evidence, "wp_lang");
  });

  test("aspnet.json -> ASP.NET fingerprints, ignored CORS credentials, internal host", () => {
    const report = analyze(loadFixture("aspnet.json"));
    assert.equal(report.score, 98);
    assert.equal(report.level, "high");
    assert.deepEqual(
      report.findings.filter((f) => f.severity === "crit").map((f) => f.id),
      ["certificate"]
    );
    const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    assert.equal(byId.certificate.title, "Certificate expires in 9 days");
    assert.equal(byId["debug-headers"].severity, "warn");
    assert.equal(byId.cors.title, "CORS credentials flag ignored");
    assert.equal(byId["server-header"].severity, "warn");
    assert.ok(byId.hosting.evidence.startsWith("X-Azure-Ref: "));
    assert.ok(byId.hosting.desc.includes("Azure Front Door"));
    assert.equal(byId["http-redirect"].title, "Plain HTTP is closed");
  });
});

// ---------------------------------------------------------------- audit regressions

describe("audit regressions", () => {
  test("hostile header values are analysed in linear time", () => {
    const huge = "9".repeat(65_000);
    const cases = [
      { server: huge },
      { "x-powered-by": huge },
      { "x-generator": huge },
      { link: "api.w.org" + "<".repeat(65_000) },
      { server: "/" + " ".repeat(65_000) },
    ];
    for (const headers of cases) {
      const started = performance.now();
      analyze(snap({ headers }));
      const ms = performance.now() - started;
      assert.ok(ms < 250, `${Object.keys(headers)[0]} took ${ms.toFixed(1)} ms`);
    }
  });

  test("frame-ancestors that allows any site is not protection, even with X-Frame-Options", () => {
    for (const headers of [
      { "content-security-policy": "frame-ancestors *" },
      { "content-security-policy": "frame-ancestors https:" },
      { "x-frame-options": "DENY", "content-security-policy": "default-src 'self'; frame-ancestors *" },
    ]) {
      const f = one("clickjacking", snap({ headers }));
      assert.equal(f.severity, "warn", JSON.stringify(headers));
      assert.match(f.evidence, /^CSP frame-ancestors: /);
    }
    const ok = one("clickjacking", snap({ headers: { "x-frame-options": "DENY", "content-security-policy": "frame-ancestors 'self'" } }));
    assert.equal(ok.severity, "ok");
    assert.equal(ok.evidence, "CSP frame-ancestors: 'self'", "frame-ancestors wins as evidence");
  });

  test("CORS null origin is flagged", () => {
    expectFinding(one("cors", snap({ headers: { "access-control-allow-origin": "null", "access-control-allow-credentials": "true" } })), {
      severity: "crit",
      title: "CORS trusts the null origin",
      evidence: "ACAO: null, credentials: true",
    });
    expectFinding(one("cors", snap({ headers: { "access-control-allow-origin": "null" } })), {
      severity: "info",
      title: "CORS allows the null origin",
      evidence: "ACAO: null",
    });
  });

  test("an unfinished redirect chain adds a caveat", () => {
    const hops = Array.from({ length: 5 }, (_, i) => ({ from: `https://example.com/${i}`, to: `https://example.com/${i + 1}`, status: 302 }));
    const limit = run("status", snap({ status: 302, redirects: hops, redirectStop: "limit" }));
    assert.deepEqual(limit.map((f) => [f.id, f.severity, f.evidence]), [["status:redirects", "info", "HTTP 302 after 5 redirects"]]);

    const loop = run("status", snap({ status: 301, redirectStop: "loop" }));
    assert.deepEqual(loop.map((f) => [f.id, f.severity, f.title]), [["status:redirects", "warn", "Redirect loop"]]);

    const both = run("status", snap({ status: 503, redirectStop: "unfollowable" }));
    assert.deepEqual(both.map((f) => f.id), ["status", "status:redirects"]);

    assert.equal(ruleById("status").run(snap({ redirectStop: "bogus" })), null, "unknown values are ignored");
  });
});

// ---------------------------------------------------------------- detection audit (2026-10)

describe("detection audit: http-redirect without extra requests", () => {
  const probe = (p) => one("http-redirect", snap({ httpProbe: p }));

  test("a redirect to another http:// address -> warn (not followed), evidence shows where it goes", () => {
    const f = probe({ result: "serves-http", status: 301, location: "http://www.example.com/" });
    expectFinding(f, {
      severity: "warn",
      title: "HTTP redirects to another plain-HTTP address",
      evidence: "301 → http://www.example.com/",
    });
    assert.ok(f.fix.includes("return 301 https://$host$request_uri;"));
    const long = probe({ result: "serves-http", status: 302, location: `http://example.com/${"a".repeat(100)}` });
    assert.equal(long.evidence.length, 64);
  });

  test("port 80 answering 4xx or 5xx -> info Plain HTTP answers with an error", () => {
    for (const status of [400, 403, 404, 503]) {
      const f = probe({ result: "serves-http", status, location: null });
      expectFinding(f, { severity: "info", title: "Plain HTTP answers with an error", evidence: `HTTP ${status}` });
      assert.doesNotMatch(f.desc, /unencrypted page/);
    }
  });

  test("a real page, or a redirect without a usable Location, is still Plain HTTP still works", () => {
    for (const p of [
      { result: "serves-http", status: 200, location: null },
      { result: "serves-http", status: 301, location: null },
      { result: "serves-http", status: null, location: null },
    ]) {
      expectFinding(probe(p), { severity: "warn", title: "Plain HTTP still works" });
    }
  });
});

describe("detection audit: hsts", () => {
  const hsts = (value) => one("hsts", snap({ headers: { "strict-transport-security": value } }));

  test("missing or invalid max-age and a too-short max-age have different titles", () => {
    for (const value of ["includeSubDomains", "max-age=-1", "max-age=31536000.5", "max-age=31536000includeSubDomains"]) {
      expectFinding(hsts(value), { severity: "warn", title: "HSTS max-age missing", evidence: "max-age: —" });
    }
    expectFinding(hsts("max-age=0"), { severity: "warn", title: "HSTS max-age too short", evidence: "max-age=0" });
  });

  test("the ok fix doesn't ask for preload when it is already there", () => {
    const ready = hsts("max-age=63072000; includeSubDomains; preload");
    assert.equal(ready.severity, "ok");
    assert.doesNotMatch(ready.fix, /add `preload`/);
    assert.match(ready.fix, /hstspreload\.org/);

    const notReady = hsts("max-age=15552000; preload");
    assert.equal(notReady.severity, "ok");
    assert.doesNotMatch(notReady.fix, /add `preload`/);
    assert.ok(notReady.fix.includes("`includeSubDomains`") && notReady.fix.includes("31536000"));

    const subdomainsOnly = hsts("max-age=31536000; includeSubDomains");
    assert.match(subdomainsOnly.fix, /add `preload`/);
    assert.ok(subdomainsOnly.fix.includes("31536000"));
  });
});

describe("detection audit: certificate thresholds follow the certificate's lifetime", () => {
  const DAY = 86400000;
  const to = Date.parse("2027-01-01T00:00:00.000Z");
  const cert = (lifetimeDays, daysLeft) =>
    one(
      "certificate",
      snap({
        tls: {
          ...TLS_OK,
          validFrom: new Date(to - lifetimeDays * DAY).toISOString(),
          validTo: new Date(to).toISOString(),
          daysLeft,
        },
      })
    );
  const sev = (lifetime, days) => cert(lifetime, days).severity;

  test("90-day certificate: warn under 22.5 days, crit under 9", () => {
    assert.equal(sev(90, 29), "ok", "renewal is due at 30 days, not failing yet");
    assert.equal(sev(90, 23), "ok");
    assert.equal(sev(90, 22), "warn");
    assert.equal(sev(90, 9), "warn");
    assert.equal(sev(90, 8), "crit");
  });

  test("45-day certificate: warn under 11.25 days, crit under 4.5", () => {
    assert.equal(sev(45, 20), "ok");
    assert.equal(sev(45, 12), "ok");
    assert.equal(sev(45, 11), "warn");
    assert.equal(sev(45, 5), "warn");
    assert.equal(sev(45, 4), "crit");
  });

  test("6-day (160 h) certificate isn't flagged while renewing on schedule", () => {
    const lifetime = 160 / 24;
    assert.equal(sev(lifetime, 5), "ok");
    assert.equal(sev(lifetime, 2), "ok");
    assert.equal(sev(lifetime, 1), "warn");
    expectFinding(cert(lifetime, 0), { severity: "crit", title: "Certificate expires today" });
  });

  test("long-lived or unknown lifetime keeps the 30/14 day thresholds", () => {
    assert.equal(sev(397, 29), "warn");
    assert.equal(sev(397, 13), "crit");
    assert.equal(sev(397, 30), "ok");
    const unknown = (daysLeft) => one("certificate", snap({ tls: { ...TLS_OK, daysLeft } })).severity;
    assert.equal(unknown(29), "warn");
    assert.equal(unknown(13), "crit");
    const garbage = one("certificate", snap({ tls: { ...TLS_OK, validFrom: "nope", daysLeft: 29 } }));
    assert.equal(garbage.severity, "warn");
    const reversed = one("certificate", snap({ tls: { ...TLS_OK, validFrom: "2030-01-01T00:00:00.000Z", daysLeft: 29 } }));
    assert.equal(reversed.severity, "warn");
  });
});

describe("detection audit: csp", () => {
  const csp = (value) => one("csp", snap({ headers: { "content-security-policy": value } }));

  test("a nonce or hash does not neutralise wide sources; only 'strict-dynamic' does", () => {
    for (const policy of ["script-src https: 'nonce-abc'", "script-src * 'sha256-xyz='", "default-src 'self' https: 'nonce-a'"]) {
      expectFinding(csp(policy), { severity: "warn", title: "CSP doesn't restrict scripts" });
    }
    assert.equal(csp("script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'").severity, "ok");
  });

  test("a wide policy that also allows inline scripts is reported as not restricting scripts", () => {
    expectFinding(csp("script-src * 'unsafe-inline'"), { severity: "warn", title: "CSP doesn't restrict scripts" });
  });

  test("not restricting scripts weighs the same as no policy", () => {
    const none = analyze(snap()).score;
    const useless = analyze(snap({ headers: { "content-security-policy": "upgrade-insecure-requests" } })).score;
    assert.equal(useless, none);
  });
});

describe("detection audit: referrer-policy uses the last recognised token", () => {
  const rp = (value) => one("referrer-policy", snap({ headers: { "referrer-policy": value } }));

  test("fallback lists", () => {
    assert.equal(rp("no-referrer-when-downgrade, strict-origin-when-cross-origin").severity, "ok");
    assert.equal(rp("unsafe-url,no-referrer").severity, "ok");
    assert.equal(rp("strict-origin-when-cross-origin, unsafe-url").severity, "warn");
    assert.equal(rp("unsafe-url, some-future-policy").severity, "warn", "unknown tokens are skipped");
  });
});

describe("detection audit: cookies", () => {
  const cookies = (setCookies, extra = {}) => snap({ setCookies, ...extra });

  test("deletion cookies are ignored (Max-Age <= 0, or Expires before the scan)", () => {
    const deletions = [
      "PHPSESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/",
      "wordpress_logged_in_abc=+; Max-Age=-1; path=/",
      "sid=; expires=Wed, 21 Oct 2026 15:20:00 GMT; path=/",
    ];
    for (const raw of deletions) {
      const s = cookies([raw]);
      expectFinding(one("cookie-secure", s), { id: "cookies", title: "No cookies on first visit" });
      expectNull("cookie-httponly", s);
      expectNull("cookie-samesite", s);
    }
    const mixed = cookies([deletions[0], "theme=dark; Secure; HttpOnly; SameSite=Lax"]);
    assert.equal(one("cookie-secure", mixed).evidence, "1 cookie, all Secure");
  });

  test("live cookies are kept: future Expires, or a positive Max-Age that overrides a past Expires", () => {
    for (const raw of [
      "sid=1; expires=Fri, 23 Oct 2026 15:20:00 GMT",
      "sid=1; Max-Age=3600; expires=Thu, 01-Jan-1970 00:00:01 GMT",
      "sid=1; Max-Age=soon",
      "sid=1; expires=not a date",
    ]) {
      assert.equal(one("cookie-httponly", cookies([raw])).severity, "warn", raw);
    }
  });

  test("without scannedAt, Expires is compared with the current time", () => {
    assert.equal(one("cookie-secure", cookies(["sid=1; expires=Thu, 01-Jan-1970 00:00:01 GMT"], { scannedAt: undefined })).id, "cookies");
    assert.equal(one("cookie-secure", cookies(["sid=1; expires=Fri, 01 Jan 2100 00:00:00 GMT"], { scannedAt: undefined })).id, "cookie-secure");
  });

  test("'sid' counts only as its own word", () => {
    const ho = (name) => one("cookie-httponly", cookies([`${name}=1`])).severity;
    for (const name of ["sid", "SID", "_sid", "connect.sid", "app-sid", "sid2", "PHPSESSID", "SSID", "HSID", "APISID", "SAPISID", "__Secure-1PSID", "__Secure-3PSID", "usid"]) {
      assert.equal(ho(name), "warn", name);
    }
    for (const name of ["sidebar_state", "visid_incap_123", "consider_me"]) assert.equal(ho(name), "info", name);
  });

  test("cookie fixes give one nginx line naming the cookie, plus trust proxy for Express", () => {
    const s = cookies(["PHPSESSID=abc; path=/"]);
    const line = "`proxy_cookie_flags PHPSESSID secure httponly samesite=lax;`";
    const secure = one("cookie-secure", s);
    const httpOnly = one("cookie-httponly", s);
    const sameSite = one("cookie-samesite", s);
    for (const f of [secure, httpOnly, sameSite]) {
      assert.ok(f.fix.includes(line), `${f.id}: ${f.fix}`);
      assert.match(f.fix, /only the first line that matches/);
      assert.doesNotMatch(f.fix, /proxy_cookie_flags ~/);
      checkFinding(f);
    }
    assert.ok(secure.fix.includes("`app.set('trust proxy', 1)`"));
    const odd = one("cookie-secure", cookies(["we`ird=1"]));
    assert.ok(odd.fix.includes("`proxy_cookie_flags <cookie> secure samesite=lax;`"), odd.fix);
  });

  test("the nginx line adds only what the cookie lacks: no secure over plain HTTP, no samesite over SameSite=None", () => {
    const http = one("cookie-httponly", snap({ requestedUrl: "http://example.com/", finalUrl: "http://example.com/", setCookies: ["shop_sid=1; path=/"] }));
    assert.ok(http.fix.includes("`proxy_cookie_flags shop_sid httponly samesite=lax;`"), http.fix);
    const none = one("cookie-httponly", cookies(["PHPSESSID=1; Secure; SameSite=None"]));
    assert.ok(none.fix.includes("`proxy_cookie_flags PHPSESSID httponly;`"), none.fix);
  });
});

describe("detection audit: internal host names", () => {
  test("EC2 host names from any private range are internal", () => {
    const dbg = (value) => one("debug-headers", snap({ headers: { "x-backend-server": value } })).severity;
    for (const value of ["ip-172-31-23-45", "ip-192-168-1-5", "ip-10-0-3-17"]) assert.equal(dbg(value), "warn", value);
    for (const value of ["ip-172-32-1-1", "skip-10-1"]) assert.equal(dbg(value), "ok", value);
  });
});

describe("detection audit: a well-configured Vercel site", () => {
  test("platform banner, public CORS and hosting are not counted twice", () => {
    const report = analyze(
      snap({
        headers: {
          server: "Vercel",
          "x-vercel-id": "fra1::iad1::abcd-1729600000000-0123456789ab",
          "x-vercel-cache": "HIT",
          "access-control-allow-origin": "*",
          "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
          "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'",
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
          "referrer-policy": "strict-origin-when-cross-origin",
          "permissions-policy": "camera=(), microphone=(), geolocation=()",
        },
        httpProbe: { result: "redirects-to-https", status: 308, location: "https://example.com/" },
      })
    );
    checkReport(report);
    assert.equal(report.score, 1);
    assert.deepEqual(report.findings.filter((f) => f.severity !== "ok").map((f) => `${f.severity} ${f.id}`), ["info hosting"]);
    const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    assert.equal(byId["server-header"].title, "Hosting platform named");
    assert.equal(byId.cors.title, "Public CORS, no logins");
    assert.ok(byId.hosting.evidence.startsWith("X-Vercel-Id: fra1::"));
  });
});
