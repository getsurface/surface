// Tests for Agent B's backend: errors, guard (SSRF), fetcher, scan-core,
// api/scan.js handler and the dev server. No outbound internet needed: every
// network test talks to a server on 127.0.0.1 or uses an injected resolver.

import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dns from 'node:dns';

import { ScanError, ERROR_STATUS, errorResponse } from '../api/_lib/errors.js';
import {
  normalizeInput,
  isBlockedIp,
  checkHostname,
  validateUrl,
  safeLookup,
  createSafeLookup,
  checkResolvedAddresses,
  canonicalIPv4,
  allowPrivate,
  aresResolve,
} from '../api/_lib/guard.js';
import { isAllowedOrigin } from '../api/scan.js';

// The production resolver is c-ares (DNS only). These tests exercise the same
// safety wrapper over the system resolver, so /etc/hosts names like localhost
// resolve to a real loopback address that must be refused.
const systemSafeLookup = createSafeLookup((h, o, cb) => dns.lookup(h, o, cb));
// Requests from our own page carry this header (see assets/app.js).
const SAME_ORIGIN = { 'x-surface': '1' };
import { fetchSnapshot, collectHeaders, cookieName, USER_AGENT } from '../api/_lib/fetcher.js';
import { runScan, resetRateLimit, checkRateLimit, rateLimitKey, getClientIp, RATE_LIMIT } from '../api/_lib/scan-core.js';
import handler from '../api/scan.js';
import { createDevServer, resolveAsset, SECURITY_HEADERS } from '../server.js';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const ENV = 'SURFACE_ALLOW_PRIVATE';

async function withEnv(value, fn) {
  const prev = process.env[ENV];
  if (value === undefined) delete process.env[ENV];
  else process.env[ENV] = value;
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env[ENV];
    else process.env[ENV] = prev;
  }
}
const allowingPrivate = (fn) => withEnv('1', fn);
const blockingPrivate = (fn) => withEnv(undefined, fn);

function assertScanError(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(err instanceof ScanError, `expected ScanError, got ${err?.name}: ${err?.message}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code} (${err.message})`);
    return true;
  });
}

async function assertRejectsCode(promise, code) {
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof ScanError, `expected ScanError, got ${err?.name}: ${err?.message}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code} (${err.message})`);
    return true;
  });
}

/** Start a server on 127.0.0.1:0. Tracks requests and sockets. */
async function startServer(onRequest, { tls = null } = {}) {
  const requests = [];
  const sockets = new Set();
  const wrapped = (req, res) => {
    requests.push({ url: req.url, headers: req.headers, servername: req.socket.servername ?? null });
    onRequest(req, res);
  };
  const server = tls ? https.createServer(tls, wrapped) : http.createServer(wrapped);
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    server,
    port: server.address().port,
    requests,
    close: () =>
      new Promise((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }),
  };
}

/** Fake dns.lookup: records calls, answers from a table. */
function fakeResolver(table) {
  const calls = [];
  const fn = (hostname, options, cb) => {
    calls.push({ hostname, options });
    const answer = table[hostname];
    setImmediate(() => {
      if (answer instanceof Error) return cb(answer);
      if (!answer) {
        const e = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
        e.code = 'ENOTFOUND';
        e.syscall = 'getaddrinfo';
        return cb(e);
      }
      const list = answer.map((address) => ({ address, family: net.isIP(address) }));
      if (options?.all) cb(null, list);
      else cb(null, list[0].address, list[0].family);
    });
  };
  fn.calls = calls;
  return fn;
}

function lookupAsync(lookup, hostname, options) {
  return new Promise((resolve, reject) => {
    const cb = (err, address, family) => (err ? reject(err) : resolve({ address, family }));
    if (options === undefined) lookup(hostname, cb);
    else lookup(hostname, options, cb);
  });
}

// Long-lived self-signed test certificate (CN/SAN surface.test + IP 127.0.0.1,
// O=Surface Test, valid until 2126). Test-only key material.
const TEST_TLS = {
  key: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH53EdJih68wHYtS3
v4ihVGDQx50YDk4t9N8K3Ubwow6hRANCAATWHrdbeNWREeTNJjZFoDBbR3mYov/v
D4GN/z4V8o04//1xxSN1u45iwduLvh04W53Ij6/CQXrjTm4hJT4RnEDK
-----END PRIVATE KEY-----
`,
  cert: `-----BEGIN CERTIFICATE-----
MIIB0TCCAXigAwIBAgIUMBFrCp2IY/3UpggRrONKCNzHZvMwCgYIKoZIzj0EAwIw
LjEVMBMGA1UECgwMU3VyZmFjZSBUZXN0MRUwEwYDVQQDDAxzdXJmYWNlLnRlc3Qw
IBcNMjYxMDIyMTUyOTUwWhgPMjEyNjA5MjgxNTI5NTBaMC4xFTATBgNVBAoMDFN1
cmZhY2UgVGVzdDEVMBMGA1UEAwwMc3VyZmFjZS50ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE1h63W3jVkRHkzSY2RaAwW0d5mKL/7w+Bjf8+FfKNOP/9ccUj
dbuOYsHbi74dOFudyI+vwkF6405uISU+EZxAyqNyMHAwHQYDVR0OBBYEFMxBCaH6
4LGPz8GUgSAeafiBHPVGMB8GA1UdIwQYMBaAFMxBCaH64LGPz8GUgSAeafiBHPVG
MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0RBBYwFIIMc3VyZmFjZS50ZXN0hwR/AAAB
MAoGCCqGSM49BAMCA0cAMEQCIBQIHmAV+1SrmfDz8w6YIwA48eFuN8Gqh7C8PdTa
LLetAiB2b6btdBN1igpklHXXxQjmtCxaY33YmBfq2nW4SdQNxw==
-----END CERTIFICATE-----
`,
};

// Make sure no test inherits the flag from the shell.
before(() => {
  delete process.env[ENV];
});

// ---------------------------------------------------------------------------
// errors.js
// ---------------------------------------------------------------------------

describe('errors', () => {
  test('ScanError carries code, message and httpStatus per Contract 3', () => {
    const expected = {
      invalid_url: 400,
      blocked_target: 400,
      rate_limited: 429,
      dns_failed: 422,
      unreachable: 502,
      timeout: 504,
      method_not_allowed: 405,
      forbidden: 403,
      internal: 500,
    };
    assert.deepEqual({ ...ERROR_STATUS }, expected);
    for (const [code, status] of Object.entries(expected)) {
      const e = new ScanError(code);
      assert.equal(e.code, code);
      assert.equal(e.httpStatus, status);
      assert.ok(e.message.length > 0);
      assert.ok(e instanceof Error);
    }
    assert.equal(new ScanError('blocked_target', 'custom').message, 'custom');
    assert.equal(new ScanError('nonsense').code, 'internal');
  });

  test('errorResponse never leaks details of unexpected errors', () => {
    const r = errorResponse(new TypeError('secret internal detail at /srv/x.js:1'));
    assert.equal(r.status, 500);
    assert.deepEqual(r.body, { ok: false, error: { code: 'internal', message: 'Something went wrong on our side. Try again.' } });
    const r2 = errorResponse(new ScanError('timeout'));
    assert.equal(r2.status, 504);
    assert.equal(r2.body.error.code, 'timeout');
  });
});

// ---------------------------------------------------------------------------
// normalizeInput
// ---------------------------------------------------------------------------

describe('normalizeInput', () => {
  beforeEach(() => delete process.env[ENV]);

  test('prepends https:// when there is no scheme and keeps the path', () => {
    assert.equal(normalizeInput('example.com').href, 'https://example.com/');
    assert.equal(normalizeInput('  example.com/a/b  ').href, 'https://example.com/a/b');
    assert.equal(normalizeInput('www.example.co.uk/x/').href, 'https://www.example.co.uk/x/');
    assert.equal(normalizeInput('//example.com/p').href, 'https://example.com/p');
  });

  test('accepts http and https, normalizes case', () => {
    assert.equal(normalizeInput('http://example.com').href, 'http://example.com/');
    assert.equal(normalizeInput('https://example.com/Path').href, 'https://example.com/Path');
    assert.equal(normalizeInput('HTTPS://EXAMPLE.COM/Path').href, 'https://example.com/Path');
  });

  test('rejects other schemes', () => {
    for (const input of [
      'ftp://example.com/',
      'javascript:alert(1)',
      'javascript://example.com/%0aalert(1)',
      'file:///etc/passwd',
      'data:text/html,<script>alert(1)</script>',
      'mailto:a@example.com',
      'gopher://example.com/',
      'ws://example.com/',
      'chrome://settings',
    ]) {
      assertScanError(() => normalizeInput(input), 'invalid_url');
    }
  });

  test('rejects userinfo', () => {
    assertScanError(() => normalizeInput('https://user:pass@example.com/'), 'invalid_url');
    assertScanError(() => normalizeInput('https://user@example.com/'), 'invalid_url');
    assertScanError(() => normalizeInput('http://example.com:80@127.0.0.1/'), 'invalid_url');
    assertScanError(() => normalizeInput('user:pass@example.com'), 'invalid_url');
  });

  test('ports: empty/80/443 allowed, others blocked', () => {
    assert.equal(normalizeInput('https://example.com:443/').href, 'https://example.com/');
    assert.equal(normalizeInput('http://example.com:80/').href, 'http://example.com/');
    assert.equal(normalizeInput('https://example.com:80/').href, 'https://example.com:80/');
    assert.equal(normalizeInput('http://example.com:443/').href, 'http://example.com:443/');
    assert.equal(normalizeInput('example.com:443/x').href, 'https://example.com/x');
    for (const input of ['https://example.com:8080/', 'http://example.com:22/', 'example.com:8080', 'example.com:22/x', 'https://example.com:0/']) {
      assertScanError(() => normalizeInput(input), 'blocked_target');
    }
  });

  test('drops query and hash, keeps path', () => {
    const u = normalizeInput('https://example.com/a/b?token=secret&x=1#frag');
    assert.equal(u.href, 'https://example.com/a/b');
    assert.equal(u.search, '');
    assert.equal(u.hash, '');
    assert.equal(normalizeInput('example.com/?q=1').href, 'https://example.com/');
  });

  test('length limit: 2048 ok, 2049 rejected', () => {
    const base = 'example.com/';
    const ok = base + 'a'.repeat(2048 - base.length);
    assert.equal(ok.length, 2048);
    assert.ok(normalizeInput(ok));
    assertScanError(() => normalizeInput(ok + 'a'), 'invalid_url');
    assertScanError(() => normalizeInput('x'.repeat(5000)), 'invalid_url');
  });

  test('rejects empty, non-string and malformed input', () => {
    for (const input of ['', '   ', null, undefined, 42, {}, ['example.com']]) {
      assertScanError(() => normalizeInput(input), 'invalid_url');
    }
    for (const input of ['https://', 'http://exa mple.com', 'https://example..com', 'https://-/', 'http://[::1', '1.2.3.4.5', 'example.123']) {
      assertScanError(() => normalizeInput(input), 'invalid_url');
    }
  });

  test('single-label host names are rejected', () => {
    for (const input of ['router', 'https://printer/', 'http://wpad/', 'kubernetes', 'metadata', 'fileserver:443']) {
      assertScanError(() => normalizeInput(input), 'invalid_url');
    }
  });

  test('blocked host names and suffixes', () => {
    for (const input of [
      'localhost',
      'LOCALHOST',
      'localhost.',
      'http://localhost:80/',
      'foo.localhost',
      'printer.local',
      'metadata.google.internal',
      'router.lan',
      'nas.home.arpa',
      'wiki.intranet',
      'mail.corp',
      'localhost.localdomain',
      'a.b.c.internal.',
    ]) {
      assertScanError(() => normalizeInput(input), 'blocked_target');
    }
    // Look-alikes that are NOT those suffixes stay allowed.
    assert.ok(normalizeInput('notlocalhost.com'));
    assert.ok(normalizeInput('local.example.com'));
    assert.ok(normalizeInput('corp.example'));
    assert.ok(normalizeInput('internal.example.org'));
  });

  test('trailing dot stripped, IDN converted to punycode', () => {
    assert.equal(normalizeInput('Example.COM.').href, 'https://example.com/');
    assert.equal(normalizeInput('bücher.de').href, 'https://xn--bcher-kva.de/');
  });

  test('IP-literal hosts: private blocked, public allowed', () => {
    for (const input of [
      'http://127.0.0.1/',
      '127.0.0.1',
      'http://10.0.0.1/',
      'http://169.254.169.254/latest/meta-data/',
      'http://192.168.1.1/',
      'http://0.0.0.0/',
      'http://[::1]/',
      '[::1]',
      'http://[::]/',
      'http://[::ffff:127.0.0.1]/',
      'http://[0:0:0:0:0:ffff:7f00:1]/',
      'http://[::ffff:169.254.169.254]/',
      'http://[64:ff9b::127.0.0.1]/',
      'http://[64:ff9b::a9fe:a9fe]/',
      'http://[fe80::1]/',
      'http://[fd00:ec2::254]/',
    ]) {
      assertScanError(() => normalizeInput(input), 'blocked_target');
    }
    assert.equal(normalizeInput('http://1.1.1.1').href, 'http://1.1.1.1/');
    assert.equal(normalizeInput('8.8.8.8/dns').href, 'https://8.8.8.8/dns');
    assert.equal(normalizeInput('http://[2606:4700:4700::1111]/').href, 'http://[2606:4700:4700::1111]/');
    assert.equal(normalizeInput('[2001:4860:4860::8888]').href, 'https://[2001:4860:4860::8888]/');
  });

  test('integer / hex / octal / short IPv4 tricks are normalized and blocked', () => {
    const tricks = [
      'http://2130706433/', // 127.0.0.1 as one integer
      'http://0x7f.1/', // hex + short form
      'http://017700000001/', // octal integer
      'http://0x7f000001/', // hex integer
      'http://0x7F.0x0.0x0.0x1/', // hex per octet
      'http://0177.0.0.1/', // octal first octet
      'http://0177.0000.0000.0001/',
      'http://127.1/', // 2-part
      'http://127.0.1/', // 3-part
      'http://0/', // 0.0.0.0
      'http://0x0a.0.0.1/', // 10.0.0.1
      'http://3232235521/', // 192.168.0.1
      'http://0xa9fea9fe/', // 169.254.169.254
      'http://025177524776/', // 169.254.169.254 octal
      'http://127.0.0.1./', // trailing dot
      'http://①②⑦.0.0.1/', // enclosed alphanumerics -> NFKC
      'http://１２７．０．０．１/', // fullwidth digits and dots
      'http://127。0。0。1/', // ideographic full stops
      '2130706433', // without scheme
      '0x7f.1',
    ];
    for (const input of tricks) assertScanError(() => normalizeInput(input), 'blocked_target');
    // The same encodings of a PUBLIC address are fine (proves real canonicalization).
    assert.equal(normalizeInput('http://134744072/').href, 'http://8.8.8.8/');
    assert.equal(normalizeInput('http://0x8.0x8.0x8.0x8/').href, 'http://8.8.8.8/');
    assert.equal(normalizeInput('http://010.010.010.010/').href, 'http://8.8.8.8/');
  });
});

// ---------------------------------------------------------------------------
// isBlockedIp
// ---------------------------------------------------------------------------

describe('isBlockedIp', () => {
  // [first, last] of every IPv4 range in the SPEC, plus a middle sample.
  const V4_BLOCKED = {
    '0.0.0.0/8': ['0.0.0.0', '0.1.2.3', '0.255.255.255'],
    '10.0.0.0/8': ['10.0.0.0', '10.20.30.40', '10.255.255.255'],
    '100.64.0.0/10': ['100.64.0.0', '100.100.100.200', '100.127.255.255'],
    '127.0.0.0/8': ['127.0.0.0', '127.0.0.1', '127.255.255.255'],
    '169.254.0.0/16': ['169.254.0.0', '169.254.169.254', '169.254.255.255'],
    '172.16.0.0/12': ['172.16.0.0', '172.20.1.1', '172.31.255.255'],
    '192.0.0.0/24': ['192.0.0.0', '192.0.0.192', '192.0.0.255'],
    '192.0.2.0/24': ['192.0.2.0', '192.0.2.1', '192.0.2.255'],
    '192.88.99.0/24': ['192.88.99.0', '192.88.99.1', '192.88.99.255'],
    '192.168.0.0/16': ['192.168.0.0', '192.168.1.1', '192.168.255.255'],
    '198.18.0.0/15': ['198.18.0.0', '198.19.1.1', '198.19.255.255'],
    '198.51.100.0/24': ['198.51.100.0', '198.51.100.7', '198.51.100.255'],
    '203.0.113.0/24': ['203.0.113.0', '203.0.113.9', '203.0.113.255'],
    '224.0.0.0/4': ['224.0.0.0', '224.0.0.251', '239.255.255.255'],
    '240.0.0.0/4': ['240.0.0.0', '250.1.2.3', '255.255.255.255'],
  };

  for (const [range, ips] of Object.entries(V4_BLOCKED)) {
    test(`blocks IPv4 ${range}`, () => {
      for (const ip of ips) assert.equal(isBlockedIp(ip), true, ip);
    });
  }

  test('allows public IPv4, including neighbours of blocked ranges', () => {
    for (const ip of [
      '8.8.8.8',
      '1.1.1.1',
      '93.184.215.14',
      '9.255.255.255',
      '11.0.0.0',
      '100.63.255.255',
      '100.128.0.0',
      '126.255.255.255',
      '128.0.0.0',
      '169.253.255.255',
      '169.255.0.0',
      '172.15.255.255',
      '172.32.0.0',
      '192.0.1.0',
      '192.0.3.0',
      '192.88.98.255',
      '192.169.0.0',
      '198.17.255.255',
      '198.20.0.0',
      '198.51.99.255',
      '203.0.112.255',
      '223.255.255.255',
    ]) {
      assert.equal(isBlockedIp(ip), false, ip);
    }
  });

  const V6_BLOCKED = {
    '::/128': ['::', '0:0:0:0:0:0:0:0'],
    '::1/128': ['::1', '0:0:0:0:0:0:0:1', '[::1]'],
    'fc00::/7': ['fc00::', 'fd00::1', 'fd00:ec2::254', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
    'fe80::/10': ['fe80::', 'fe80::1', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fe80::1%eth0', '[fe80::1%25eth0]'],
    'ff00::/8': ['ff00::', 'ff02::1', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
    '2001:db8::/32': ['2001:db8::', '2001:db8::1', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'],
    '100::/64': ['100::', '100::1', '100::ffff:ffff:ffff:ffff'],
  };

  for (const [range, ips] of Object.entries(V6_BLOCKED)) {
    test(`blocks IPv6 ${range}`, () => {
      for (const ip of ips) assert.equal(isBlockedIp(ip), true, ip);
    });
  }

  test('IPv4-mapped IPv6 is checked against the IPv4 list', () => {
    for (const ip of [
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
      '0:0:0:0:0:ffff:7f00:1',
      '::ffff:10.0.0.1',
      '::ffff:a00:1',
      '::ffff:169.254.169.254',
      '::ffff:192.168.0.1',
      '::ffff:0.0.0.0',
      '[::ffff:127.0.0.1]',
      '::FFFF:7F00:1',
    ]) {
      assert.equal(isBlockedIp(ip), true, ip);
    }
    assert.equal(isBlockedIp('::ffff:8.8.8.8'), false);
    assert.equal(isBlockedIp('::ffff:808:808'), false);
  });

  test('NAT64 (64:ff9b::/96) is checked against the IPv4 list', () => {
    for (const ip of ['64:ff9b::127.0.0.1', '64:ff9b::7f00:1', '64:ff9b::a00:1', '64:ff9b::a9fe:a9fe', '64:ff9b::c0a8:101', '64:ff9b::']) {
      assert.equal(isBlockedIp(ip), true, ip);
    }
    assert.equal(isBlockedIp('64:ff9b::8.8.8.8'), false);
    assert.equal(isBlockedIp('64:ff9b::101:101'), false);
    assert.equal(isBlockedIp('64:ff9b:1::8.8.8.8'), true, 'local-use NAT64 prefix');
  });

  test('other non-public IPv6 forms are blocked', () => {
    for (const ip of [
      '::127.0.0.1', // IPv4-compatible (deprecated)
      '::7f00:1',
      '::ffff:0:7f00:1', // IPv4-translated
      '2002:7f00:1::1', // 6to4 wrapping 127.0.0.1
      '2002:a9fe:a9fe::', // 6to4 wrapping 169.254.169.254
      '2001::1', // Teredo
      'fec0::1', // site-local
      '3fff::1', // documentation (RFC 9637)
      '4000::1', // outside 2000::/3
    ]) {
      assert.equal(isBlockedIp(ip), true, ip);
    }
  });

  test('allows public IPv6', () => {
    for (const ip of ['2606:4700:4700::1111', '[2606:4700:4700::1111]', '2001:4860:4860::8888', '2a00:1450:4001:80b::200e', '2002:808:808::1']) {
      assert.equal(isBlockedIp(ip), false, ip);
    }
  });

  test('integer / hex / octal IPv4 spellings are canonicalized before checking', () => {
    for (const ip of ['2130706433', '0x7f.1', '017700000001', '0x7f000001', '127.1', '0177.0.0.1', '0', '3232235521', '0xa9fea9fe']) {
      assert.equal(isBlockedIp(ip), true, ip);
    }
    assert.equal(canonicalIPv4('2130706433'), '127.0.0.1');
    assert.equal(canonicalIPv4('0x7f.1'), '127.0.0.1');
    assert.equal(canonicalIPv4('017700000001'), '127.0.0.1');
    assert.equal(canonicalIPv4('134744072'), '8.8.8.8');
    assert.equal(isBlockedIp('134744072'), false, '8.8.8.8 as an integer is public');
    assert.equal(canonicalIPv4('cafe.be'), null);
  });

  test('fails closed on anything that is not an IP', () => {
    for (const v of ['example.com', 'localhost', '', '1.2.3.4.5', '999.1.1.1', ':::', null, undefined, 42, {}]) {
      assert.equal(isBlockedIp(v), true, String(v));
    }
  });

  test('isBlockedIp is pure: ignores SURFACE_ALLOW_PRIVATE', () =>
    allowingPrivate(() => {
      assert.equal(isBlockedIp('127.0.0.1'), true);
      assert.equal(isBlockedIp('8.8.8.8'), false);
    }));
});

// ---------------------------------------------------------------------------
// checkHostname / validateUrl
// ---------------------------------------------------------------------------

describe('checkHostname and validateUrl', () => {
  beforeEach(() => delete process.env[ENV]);

  test('checkHostname returns the canonical host', () => {
    assert.equal(checkHostname('Example.COM.'), 'example.com');
    assert.equal(checkHostname('[2606:4700:4700::1111]'), '2606:4700:4700::1111');
    assert.equal(checkHostname('8.8.8.8'), '8.8.8.8');
    assertScanError(() => checkHostname('[::1]'), 'blocked_target');
    assertScanError(() => checkHostname('localhost'), 'blocked_target');
    assertScanError(() => checkHostname('0x7f.1'), 'blocked_target');
    assertScanError(() => checkHostname('single'), 'invalid_url');
    assertScanError(() => checkHostname(''), 'invalid_url');
    assertScanError(() => checkHostname('a'.repeat(64) + '.com'), 'invalid_url');
  });

  test('validateUrl (used for every redirect hop) applies the same rules', () => {
    assert.equal(validateUrl(new URL('https://example.com/a?b=1#c')).href, 'https://example.com/a?b=1');
    assertScanError(() => validateUrl('http://127.0.0.1/', { redirect: true }), 'blocked_target');
    assertScanError(() => validateUrl('https://example.com:8443/', { redirect: true }), 'blocked_target');
    assertScanError(() => validateUrl('ftp://example.com/', { redirect: true }), 'blocked_target');
    assertScanError(() => validateUrl('https://u:p@example.com/', { redirect: true }), 'blocked_target');
    assertScanError(() => validateUrl('http://[::ffff:a9fe:a9fe]/', { redirect: true }), 'blocked_target');
    assertScanError(() => validateUrl('ftp://example.com/'), 'invalid_url');
  });
});

// ---------------------------------------------------------------------------
// safeLookup
// ---------------------------------------------------------------------------

describe('safeLookup', () => {
  beforeEach(() => delete process.env[ENV]);

  test('rejects when ANY of several resolved addresses is private', async () => {
    const resolver = fakeResolver({
      'mixed.example': ['93.184.215.14', '10.0.0.5'],
      'mixed6.example': ['2606:4700:4700::1111', 'fd00::1'],
      'mapped.example': ['8.8.8.8', '::ffff:127.0.0.1'],
      'nat64.example': ['64:ff9b::a9fe:a9fe'],
      'cross.example': ['8.8.8.8', '::1'],
    });
    const lookup = createSafeLookup(resolver);
    for (const host of ['mixed.example', 'mixed6.example', 'mapped.example', 'nat64.example']) {
      for (const opts of [{ all: true }, {}, { family: 4 }, { family: 6, all: true }, { hints: 32, all: true }, undefined, 0]) {
        await assert.rejects(lookupAsync(lookup, host, opts), (err) => {
          assert.ok(err instanceof ScanError);
          assert.equal(err.code, 'blocked_target');
          return true;
        }, `${host} ${JSON.stringify(opts)}`);
      }
    }
    // Even when only IPv4 is requested, a private AAAA record blocks the host.
    await assert.rejects(lookupAsync(lookup, 'cross.example', { family: 4 }), { code: 'blocked_target' });
  });

  test('always resolves every family with all:true, then answers in the requested shape', async () => {
    const resolver = fakeResolver({ 'ok.example': ['93.184.215.14', '2606:2800:21f:cb07:6820:80da:af6b:8b2c'] });
    const lookup = createSafeLookup(resolver);

    const all = await new Promise((resolve, reject) =>
      lookup('ok.example', { all: true }, (err, addrs) => (err ? reject(err) : resolve(addrs))),
    );
    assert.deepEqual(all, [
      { address: '93.184.215.14', family: 4 },
      { address: '2606:2800:21f:cb07:6820:80da:af6b:8b2c', family: 6 },
    ]);

    assert.deepEqual(await lookupAsync(lookup, 'ok.example', {}), { address: '93.184.215.14', family: 4 });
    assert.deepEqual(await lookupAsync(lookup, 'ok.example', undefined), { address: '93.184.215.14', family: 4 });
    assert.deepEqual(await lookupAsync(lookup, 'ok.example', { family: 6 }), {
      address: '2606:2800:21f:cb07:6820:80da:af6b:8b2c',
      family: 6,
    });
    assert.deepEqual(await lookupAsync(lookup, 'ok.example', 6), {
      address: '2606:2800:21f:cb07:6820:80da:af6b:8b2c',
      family: 6,
    });
    const v4only = await new Promise((resolve, reject) =>
      lookup('ok.example', { all: true, family: 4 }, (err, addrs) => (err ? reject(err) : resolve(addrs))),
    );
    assert.deepEqual(v4only, [{ address: '93.184.215.14', family: 4 }]);

    for (const call of resolver.calls) {
      assert.equal(call.options.all, true);
      assert.equal(call.options.family, 0);
    }
  });

  test('passes DNS errors through, empty answers become ENOTFOUND', async () => {
    const eagain = Object.assign(new Error('getaddrinfo EAI_AGAIN x'), { code: 'EAI_AGAIN', syscall: 'getaddrinfo' });
    const lookup = createSafeLookup(fakeResolver({ 'slow.example': eagain }));
    await assert.rejects(lookupAsync(lookup, 'slow.example', {}), { code: 'EAI_AGAIN' });
    await assert.rejects(lookupAsync(lookup, 'missing.example', {}), { code: 'ENOTFOUND' });
    const v4only = createSafeLookup(fakeResolver({ 'v4.example': ['8.8.8.8'] }));
    await assert.rejects(lookupAsync(v4only, 'v4.example', { family: 6 }), { code: 'ENOTFOUND' });
  });

  test('checkResolvedAddresses is the pure core of the check', () => {
    assert.deepEqual(checkResolvedAddresses('h', [{ address: '8.8.8.8', family: 4 }]), [{ address: '8.8.8.8', family: 4 }]);
    assert.deepEqual(checkResolvedAddresses('h', ['2606:4700:4700::1111']), [{ address: '2606:4700:4700::1111', family: 6 }]);
    assertScanError(() => checkResolvedAddresses('h', [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }]), 'blocked_target');
    assertScanError(() => checkResolvedAddresses('h', ['not-an-ip']), 'blocked_target');
    assert.throws(() => checkResolvedAddresses('h', []), { code: 'ENOTFOUND' });
  });

  test('real dns.lookup: localhost (from /etc/hosts) is rejected', async () => {
    await assert.rejects(lookupAsync(systemSafeLookup, 'localhost', { all: true }), { code: 'blocked_target' });
    await assert.rejects(lookupAsync(systemSafeLookup, 'localhost', {}), { code: 'blocked_target' });
  });

  test('production resolver (c-ares) fails fast with a DNS error code, never hangs', async () => {
    const started = Date.now();
    const err = await new Promise((resolve) => aresResolve('surface-test.invalid', {}, (e) => resolve(e)));
    assert.ok(err, 'a .invalid name must not resolve');
    assert.ok(['ENOTFOUND', 'EAI_AGAIN'].includes(err.code), err.code);
    assert.ok(Date.now() - started < 12_000, 'bounded by timeout x tries');
  });

  test('lookup happens inside the socket connect: blocked before any byte is sent', async () => {
    const srv = await startServer((req, res) => res.end('hi'));
    let connections = 0;
    srv.server.on('connection', () => connections++);
    try {
      const err = await new Promise((resolve) => {
        const req = http.request({ host: 'localhost', port: srv.port, path: '/', lookup: systemSafeLookup, agent: new http.Agent() });
        req.on('error', resolve);
        req.on('response', () => resolve(new Error('unexpected response')));
        req.end();
      });
      assert.ok(err instanceof ScanError);
      assert.equal(err.code, 'blocked_target');
      assert.equal(connections, 0);
      assert.equal(srv.requests.length, 0);
    } finally {
      await srv.close();
    }
  });

  test('a rebinding resolver cannot slip a private address in: every connect is checked', async () => {
    // First answer public, second private: each connection's own answer is validated.
    let n = 0;
    const rebinding = (host, opts, cb) => {
      n++;
      const address = n === 1 ? '8.8.8.8' : '127.0.0.1';
      opts.all ? cb(null, [{ address, family: 4 }]) : cb(null, address, 4);
    };
    const lookup = createSafeLookup(rebinding);
    assert.deepEqual(await lookupAsync(lookup, 'rebind.example', {}), { address: '8.8.8.8', family: 4 });
    await assert.rejects(lookupAsync(lookup, 'rebind.example', {}), { code: 'blocked_target' });
  });
});

// ---------------------------------------------------------------------------
// SURFACE_ALLOW_PRIVATE
// ---------------------------------------------------------------------------

describe('SURFACE_ALLOW_PRIVATE flag', () => {
  test('is read at call time and disables host, IP and port policy', async () => {
    await blockingPrivate(async () => {
      assert.equal(allowPrivate(), false);
      assertScanError(() => normalizeInput('http://127.0.0.1:8080/'), 'blocked_target');
      assertScanError(() => normalizeInput('localhost'), 'blocked_target');
      await assert.rejects(lookupAsync(systemSafeLookup, 'localhost', {}), { code: 'blocked_target' });
    });
    await allowingPrivate(async () => {
      assert.equal(allowPrivate(), true);
      assert.equal(normalizeInput('http://127.0.0.1:8080/x').href, 'http://127.0.0.1:8080/x');
      assert.equal(normalizeInput('localhost:3000').href, 'https://localhost:3000/');
      assert.equal(normalizeInput('http://[::1]:22/').href, 'http://[::1]:22/');
      assert.deepEqual(await lookupAsync(safeLookup, 'localhost', { family: 4 }), { address: '127.0.0.1', family: 4 });
      // Scheme and userinfo rules still apply.
      assertScanError(() => normalizeInput('file:///etc/passwd'), 'invalid_url');
      assertScanError(() => normalizeInput('http://u:p@127.0.0.1/'), 'invalid_url');
    });
    await withEnv('true', () => {
      assert.equal(allowPrivate(), false, 'only the exact value "1" enables it');
      assertScanError(() => normalizeInput('127.0.0.1'), 'blocked_target');
    });
    assert.equal(allowPrivate(), false);
  });

  test('is ignored on a Vercel deployment', async () => {
    await allowingPrivate(async () => {
      process.env.VERCEL = '1';
      try {
        assert.equal(allowPrivate(), false);
        assertScanError(() => normalizeInput('http://127.0.0.1/'), 'blocked_target');
      } finally {
        delete process.env.VERCEL;
      }
      assert.equal(allowPrivate(), true);
    });
  });
});

// ---------------------------------------------------------------------------
// fetcher helpers
// ---------------------------------------------------------------------------

describe('audit regressions: fetcher', () => {
  test('collectHeaders caps each value and follows only the first Location', () => {
    const { headers } = collectHeaders([
      'Server', '9'.repeat(70_000),
      'Location', '/a',
      'Location', '/b',
      'X-Repeat', 'x'.repeat(6000),
      'X-Repeat', 'y'.repeat(6000),
    ]);
    assert.equal(headers.server.length, 8192);
    assert.equal(headers.location, '/a');
    assert.ok(headers['x-repeat'].length <= 8192);
  });

  test('redirect limit and loops are reported in the snapshot', () =>
    allowingPrivate(async () => {
      let n = 0;
      const srv = await startServer((req, res) => {
        if (req.url === '/loop') {
          res.writeHead(301, { Location: '/loop' });
          return res.end();
        }
        res.writeHead(302, { Location: `/hop${++n}` });
        res.end();
      });
      try {
        const endless = await fetchSnapshot(normalizeInput(`http://127.0.0.1:${srv.port}/start`), 'x');
        assert.equal(endless.redirectStop, 'limit');
        assert.equal(endless.redirects.length, 5);
        assert.equal(endless.status, 302);

        const loop = await fetchSnapshot(normalizeInput(`http://127.0.0.1:${srv.port}/loop`), 'x');
        assert.equal(loop.redirectStop, 'loop');
        assert.equal(loop.status, 301);
      } finally {
        await srv.close();
      }
    }));
});

describe('fetcher helpers', () => {
  test('collectHeaders lowercases names, joins repeats, separates set-cookie', () => {
    const { headers, setCookies } = collectHeaders([
      'Server', 'nginx',
      'X-A', '1',
      'x-a', '2',
      'Set-Cookie', 'a=1',
      'SET-COOKIE', 'b=2',
      '__proto__', 'x',
    ]);
    assert.deepEqual(headers, { server: 'nginx', 'x-a': '1, 2' });
    assert.deepEqual(setCookies, ['a=1', 'b=2']);
    assert.equal(Object.getPrototypeOf(headers), Object.prototype);
  });

  test('cookieName', () => {
    assert.equal(cookieName('PHPSESSID=abc; path=/'), 'PHPSESSID');
    assert.equal(cookieName(' theme = dark ; Secure'), 'theme');
    assert.equal(cookieName('flag; HttpOnly'), 'flag');
    assert.equal(cookieName('a=b=c'), 'a');
  });
});

// ---------------------------------------------------------------------------
// fetchSnapshot (integration, local servers only)
// ---------------------------------------------------------------------------

describe('fetchSnapshot', () => {
  let site;
  before(async () => {
    site = await startServer((req, res) => {
      const path = req.url;
      if (path === '/start?x=1' || path === '/start') {
        res.writeHead(301, {
          Location: '/final',
          'Set-Cookie': ['theme=light; Path=/', 'PHPSESSID=hop1; path=/'],
          Server: 'hop-one',
        });
        return res.end();
      }
      if (path === '/final') {
        res.setHeader('Server', 'nginx/1.18.0');
        res.setHeader('X-Powered-By', 'PHP/7.4.3');
        res.setHeader('X-Repeat', ['one', 'two']);
        res.setHeader('Set-Cookie', ['theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax']);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        // Body is written slowly and never finished: fetchSnapshot must not wait for it.
        res.write('<html>');
        return;
      }
      if (path === '/loop-a') {
        res.writeHead(302, { Location: '/loop-b' });
        return res.end();
      }
      if (path === '/loop-b') {
        res.writeHead(302, { Location: '/loop-a' });
        return res.end();
      }
      const m = /^\/chain\/(\d+)$/.exec(path);
      if (m) {
        res.writeHead(302, { Location: `/chain/${Number(m[1]) + 1}` });
        return res.end();
      }
      if (path === '/to-ftp') {
        res.writeHead(302, { Location: 'ftp://example.com/' });
        return res.end();
      }
      if (path === '/to-userinfo') {
        res.writeHead(302, { Location: `http://user:pw@127.0.0.1:${req.socket.localPort}/final?u` });
        return res.end();
      }
      if (path === '/flip-to-metadata') {
        delete process.env[ENV];
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        return res.end();
      }
      if (path === '/flip-flag') {
        // Simulate production rules applying to the next hop.
        delete process.env[ENV];
        res.writeHead(302, { Location: '/final' });
        return res.end();
      }
      if (path === '/hang') return; // never respond
      res.writeHead(404);
      res.end();
    });
  });
  after(() => site.close());
  beforeEach(() => delete process.env[ENV]);

  test('returns a Contract 1 Snapshot (redirect, cookies, headers, tls null)', () =>
    allowingPrivate(async () => {
      const t0 = Date.now();
      const url = normalizeInput(`http://127.0.0.1:${site.port}/start?x=1#frag`);
      const snap = await fetchSnapshot(url, `  http://127.0.0.1:${site.port}/start?x=1#frag  `);
      assert.ok(Date.now() - t0 < 3000, 'did not wait for the unfinished body');

      const base = `http://127.0.0.1:${site.port}`;
      assert.deepEqual(Object.keys(snap).sort(), [
        'finalUrl', 'headers', 'httpProbe', 'input', 'redirectStop', 'redirects', 'requestedUrl', 'scannedAt', 'setCookies', 'status', 'timingMs', 'tls',
      ]);
      assert.equal(snap.redirectStop, null, 'chain reached a real page');
      assert.equal(snap.input, `http://127.0.0.1:${site.port}/start?x=1#frag`);
      assert.equal(snap.requestedUrl, `${base}/start`);
      assert.equal(snap.finalUrl, `${base}/final`);
      assert.equal(snap.status, 200);
      assert.deepEqual(snap.redirects, [{ from: `${base}/start`, to: `${base}/final`, status: 301 }]);
      // Final response headers only, lowercased, repeats joined, no set-cookie.
      assert.equal(snap.headers.server, 'nginx/1.18.0');
      assert.equal(snap.headers['x-powered-by'], 'PHP/7.4.3');
      assert.equal(snap.headers['x-repeat'], 'one, two');
      assert.equal(snap.headers['content-type'], 'text/html');
      assert.equal(snap.headers['set-cookie'], undefined);
      for (const name of Object.keys(snap.headers)) assert.equal(name, name.toLowerCase());
      // Cookies from all hops, deduped by name, last wins.
      assert.deepEqual(snap.setCookies, ['PHPSESSID=hop1; path=/', 'theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax']);
      assert.equal(snap.tls, null);
      assert.equal(snap.httpProbe, null, 'final URL is http: probe not reported');
      assert.equal(typeof snap.timingMs, 'number');
      assert.ok(snap.timingMs >= 0);
      assert.equal(new Date(snap.scannedAt).toISOString(), snap.scannedAt);
      // Query was not sent; our User-Agent and identity encoding were.
      const first = site.requests.find((r) => r.url.startsWith('/start'));
      assert.equal(first.url, '/start');
      assert.equal(first.headers['user-agent'], USER_AGENT);
      assert.equal(first.headers['accept-encoding'], 'identity');
      assert.equal(first.headers.cookie, undefined, 'cookies are never sent back');
    }));

  test('without the flag, 127.0.0.1 and localhost are blocked_target (and nothing is contacted)', async () => {
    const before = site.requests.length;
    await assertRejectsCode(fetchSnapshot(new URL(`http://127.0.0.1:${site.port}/final`), 'x'), 'blocked_target');
    await assertRejectsCode(fetchSnapshot(new URL('http://127.0.0.1/'), 'x'), 'blocked_target');
    await assertRejectsCode(fetchSnapshot(new URL('http://localhost/'), 'x'), 'blocked_target');
    await assertRejectsCode(fetchSnapshot('http://[::1]/', 'x'), 'blocked_target');
    await assertRejectsCode(fetchSnapshot('http://2130706433/', 'x'), 'blocked_target');
    assertScanError(() => normalizeInput('127.0.0.1'), 'blocked_target');
    assertScanError(() => normalizeInput('localhost'), 'blocked_target');
    assert.equal(site.requests.length, before);
  });

  test('a public-looking host that resolves to a private IP is blocked at connect time', async () => {
    const resolver = fakeResolver({ 'evil.example': ['93.184.215.14', '127.0.0.1'] });
    await assertRejectsCode(fetchSnapshot(new URL('http://evil.example/'), 'evil.example', { dnsLookup: resolver }), 'blocked_target');
    assert.ok(resolver.calls.some((c) => c.hostname === 'evil.example'));
  });

  test('DNS is resolved by the injected lookup at connect; Host header keeps the name', () =>
    allowingPrivate(async () => {
      const resolver = fakeResolver({ 'site.test': ['127.0.0.1'] });
      const snap = await fetchSnapshot(new URL(`http://site.test:${site.port}/final`), 'site.test', { dnsLookup: resolver });
      assert.equal(snap.status, 200);
      assert.ok(resolver.calls.some((c) => c.hostname === 'site.test' && c.options.all === true));
      const req = site.requests.at(-1);
      assert.equal(req.headers.host, `site.test:${site.port}`);
    }));

  test('every redirect hop is re-validated (flag turned off mid-chain -> blocked_target)', () =>
    allowingPrivate(async () => {
      const before = site.requests.filter((r) => r.url === '/final').length;
      await assertRejectsCode(fetchSnapshot(new URL(`http://127.0.0.1:${site.port}/flip-flag`), 'x'), 'blocked_target');
      assert.equal(site.requests.filter((r) => r.url === '/final').length, before, 'second hop never requested');
    }));

  test('redirect to the cloud metadata IP is refused before connecting', () =>
    allowingPrivate(async () => {
      // /flip-to-metadata turns the flag off, then redirects to 169.254.169.254.
      const t0 = Date.now();
      await assertRejectsCode(fetchSnapshot(new URL(`http://127.0.0.1:${site.port}/flip-to-metadata`), 'x'), 'blocked_target');
      assert.ok(Date.now() - t0 < 2000, 'no connection attempt to the metadata address');
    }));

  test('redirect targets go through validateUrl even with the flag on (userinfo Location)', () =>
    allowingPrivate(async () => {
      await assert.rejects(fetchSnapshot(new URL(`http://127.0.0.1:${site.port}/to-userinfo`), 'x'), (err) => {
        assert.ok(err instanceof ScanError);
        assert.equal(err.code, 'blocked_target');
        assert.match(err.message, /redirects/);
        return true;
      });
      assert.equal(site.requests.filter((r) => r.url === '/final?u').length, 0);
    }));

  test('a non-http(s) Location is not followed', () =>
    allowingPrivate(async () => {
      const snap = await fetchSnapshot(new URL(`http://127.0.0.1:${site.port}/to-ftp`), 'x');
      assert.equal(snap.status, 302);
      assert.deepEqual(snap.redirects, []);
      assert.equal(snap.headers.location, 'ftp://example.com/');
    }));

  test('redirect loops stop at the repeated URL', () =>
    allowingPrivate(async () => {
      const snap = await fetchSnapshot(new URL(`http://127.0.0.1:${site.port}/loop-a`), 'x');
      const base = `http://127.0.0.1:${site.port}`;
      assert.deepEqual(snap.redirects, [{ from: `${base}/loop-a`, to: `${base}/loop-b`, status: 302 }]);
      assert.equal(snap.finalUrl, `${base}/loop-b`);
      assert.equal(snap.status, 302);
    }));

  test('at most 5 redirects are followed', () =>
    allowingPrivate(async () => {
      const snap = await fetchSnapshot(new URL(`http://127.0.0.1:${site.port}/chain/0`), 'x');
      assert.equal(snap.redirects.length, 5);
      assert.equal(snap.finalUrl, `http://127.0.0.1:${site.port}/chain/5`);
      assert.equal(snap.status, 302);
    }));

  test('HTTPS first, falls back to http:// on connection failure', () =>
    allowingPrivate(async () => {
      // The server speaks plain HTTP, so the TLS handshake fails.
      const url = normalizeInput(`127.0.0.1:${site.port}/final`);
      assert.equal(url.protocol, 'https:');
      const snap = await fetchSnapshot(url, 'x');
      assert.equal(snap.requestedUrl, `https://127.0.0.1:${site.port}/final`);
      assert.equal(snap.finalUrl, `http://127.0.0.1:${site.port}/final`);
      assert.equal(snap.status, 200);
      assert.equal(snap.tls, null);
      assert.equal(snap.httpProbe, null);
    }));

  test('dns_failed, unreachable and timeout mapping', () =>
    allowingPrivate(async () => {
      const resolver = fakeResolver({});
      await assertRejectsCode(fetchSnapshot(new URL('https://nope.example/'), 'x', { dnsLookup: resolver }), 'dns_failed');
      const eagain = Object.assign(new Error('EAI_AGAIN'), { code: 'EAI_AGAIN', syscall: 'getaddrinfo' });
      await assertRejectsCode(
        fetchSnapshot(new URL('https://flaky.example/'), 'x', { dnsLookup: fakeResolver({ 'flaky.example': eagain }) }),
        'dns_failed',
      );
      // Port 1: nothing listening; https then http both refused.
      await assertRejectsCode(fetchSnapshot(normalizeInput('127.0.0.1:1'), 'x'), 'unreachable');
      // Accepts the connection but never answers.
      const t0 = Date.now();
      await assertRejectsCode(
        fetchSnapshot(new URL(`http://127.0.0.1:${site.port}/hang`), 'x', { hopTimeoutMs: 300 }),
        'timeout',
      );
      assert.ok(Date.now() - t0 < 3000);
      // Whole-scan budget caps everything, including the https -> http fallback.
      const t1 = Date.now();
      await assertRejectsCode(fetchSnapshot(new URL(`https://127.0.0.1:${site.port}/hang`), 'x', { budgetMs: 400 }), 'timeout');
      assert.ok(Date.now() - t1 < 3000);
    }));

  test('a silent TLS server times out, falls back to http, and the budget is respected', () =>
    allowingPrivate(async () => {
      const silent = net.createServer((s) => s.on('error', () => {})); // accepts, never speaks
      await new Promise((r) => silent.listen(0, '127.0.0.1', r));
      const port = silent.address().port;
      try {
        const t0 = Date.now();
        await assertRejectsCode(fetchSnapshot(new URL(`https://127.0.0.1:${port}/`), 'x', { hopTimeoutMs: 250 }), 'timeout');
        const elapsed = Date.now() - t0;
        assert.ok(elapsed >= 450 && elapsed < 3000, `two 250 ms attempts, got ${elapsed} ms`);
      } finally {
        silent.close();
      }
    }));

  test('HTTPS: certificate info, SNI, and the unverified retry on a cert error', () =>
    allowingPrivate(async () => {
      const tlsSite = await startServer(
        (req, res) => {
          res.setHeader('Strict-Transport-Security', 'max-age=31536000');
          res.setHeader('Set-Cookie', 'sid=1; Secure; HttpOnly');
          res.writeHead(200);
          res.end();
        },
        { tls: TEST_TLS },
      );
      try {
        const resolver = fakeResolver({ 'surface.test': ['127.0.0.1'] });
        const snap = await fetchSnapshot(new URL(`https://surface.test:${tlsSite.port}/`), 'surface.test', {
          dnsLookup: resolver,
          probeTimeoutMs: 1000,
        });
        assert.equal(snap.status, 200);
        assert.equal(snap.finalUrl, `https://surface.test:${tlsSite.port}/`);
        assert.equal(snap.headers['strict-transport-security'], 'max-age=31536000');
        assert.deepEqual(snap.setCookies, ['sid=1; Secure; HttpOnly']);
        assert.equal(snap.tls.valid, false);
        assert.equal(snap.tls.error, 'DEPTH_ZERO_SELF_SIGNED_CERT');
        assert.equal(snap.tls.issuer, 'Surface Test');
        assert.match(snap.tls.protocol, /^TLSv1\.[23]$/);
        assert.equal(snap.tls.validTo, '2126-09-28T15:29:50.000Z');
        assert.equal(snap.tls.daysLeft, Math.floor((Date.parse(snap.tls.validTo) - Date.now()) / 86400000));
        // SNI carried the host name (not the IP) on the retried connection.
        assert.equal(tlsSite.requests.length, 1, 'verified attempt never got to send a request');
        assert.equal(tlsSite.requests[0].servername, 'surface.test');
        // Final URL is https, so the plain-HTTP probe result is reported.
        assert.ok(snap.httpProbe && typeof snap.httpProbe === 'object');
        assert.ok(['redirects-to-https', 'serves-http', 'no-http', 'error'].includes(snap.httpProbe.result));
        assert.deepEqual(Object.keys(snap.httpProbe).sort(), ['location', 'result', 'status']);

        // IP-literal https: no SNI is sent.
        const snap2 = await fetchSnapshot(new URL(`https://127.0.0.1:${tlsSite.port}/`), 'x', { probeTimeoutMs: 500 });
        assert.equal(snap2.tls.valid, false);
        assert.equal(tlsSite.requests.at(-1).servername, false);
      } finally {
        await tlsSite.close();
      }
    }));

  test('HTTP probe classification (needs to bind 127.0.0.1:80)', async (t) => {
    let mode = 'redirect';
    const port80 = http.createServer((req, res) => {
      if (mode === 'redirect') res.writeHead(301, { Location: 'https://surface.test/' });
      else res.writeHead(200);
      res.end();
    });
    const ok = await new Promise((resolve) => {
      port80.once('error', () => resolve(false));
      port80.listen(80, '127.0.0.1', () => resolve(true));
    });
    if (!ok) {
      t.skip('cannot bind port 80 here');
      return;
    }
    const tlsSite = await startServer((req, res) => res.end(), { tls: TEST_TLS });
    try {
      await allowingPrivate(async () => {
        const resolver = fakeResolver({ 'surface.test': ['127.0.0.1'] });
        const url = new URL(`https://surface.test:${tlsSite.port}/`);
        let snap = await fetchSnapshot(url, 'x', { dnsLookup: resolver });
        assert.deepEqual(snap.httpProbe, { result: 'redirects-to-https', status: 301, location: 'https://surface.test/' });
        mode = 'serve';
        snap = await fetchSnapshot(url, 'x', { dnsLookup: resolver });
        assert.deepEqual(snap.httpProbe, { result: 'serves-http', status: 200, location: null });
        await new Promise((r) => port80.close(r));
        snap = await fetchSnapshot(url, 'x', { dnsLookup: resolver });
        assert.deepEqual(snap.httpProbe, { result: 'no-http', status: null, location: null });
      });
    } finally {
      port80.close();
      await tlsSite.close();
    }
  });
});

// ---------------------------------------------------------------------------
// scan-core
// ---------------------------------------------------------------------------

describe('runScan', () => {
  let site;
  before(async () => {
    site = await startServer((req, res) => {
      res.setHeader('Server', 'test');
      res.end();
    });
  });
  after(() => site.close());
  beforeEach(() => {
    resetRateLimit();
    delete process.env[ENV];
  });

  test('happy path with an injected analyze()', () =>
    allowingPrivate(async () => {
      let seen;
      const analyze = (snapshot) => {
        seen = snapshot;
        return { target: { url: snapshot.finalUrl }, score: 0 };
      };
      const r = await runScan(` http://127.0.0.1:${site.port}/ `, { clientIp: '203.0.113.1', analyze });
      assert.equal(r.status, 200);
      assert.deepEqual(r.body, { ok: true, report: { target: { url: `http://127.0.0.1:${site.port}/` }, score: 0 } });
      assert.equal(seen.input, `http://127.0.0.1:${site.port}/`);
      assert.equal(seen.headers.server, 'test');
    }));

  test('maps guard errors to the JSON error shape', async () => {
    const analyze = () => assert.fail('analyze must not run');
    let r = await runScan('not a url at all', { clientIp: '1', analyze });
    assert.equal(r.status, 400);
    assert.equal(r.body.ok, false);
    assert.equal(r.body.error.code, 'invalid_url');
    assert.equal(typeof r.body.error.message, 'string');
    r = await runScan('localhost', { clientIp: '1', analyze });
    assert.deepEqual([r.status, r.body.error.code], [400, 'blocked_target']);
    r = await runScan('127.0.0.1', { clientIp: '1', analyze });
    assert.deepEqual([r.status, r.body.error.code], [400, 'blocked_target']);
    r = await runScan(null, { clientIp: '1', analyze });
    assert.deepEqual([r.status, r.body.error.code], [400, 'invalid_url']);
  });

  test('unexpected errors become `internal` without leaking details', async () => {
    const original = console.error;
    console.error = () => {};
    try {
      const r = await runScan('example.com', {
        clientIp: '1',
        fetchSnapshot: async () => ({ fake: true }),
        analyze: () => {
          throw new Error('boom at /srv/secret/path.js:12');
        },
      });
      assert.equal(r.status, 500);
      assert.deepEqual(r.body, { ok: false, error: { code: 'internal', message: 'Something went wrong on our side. Try again.' } });
      assert.ok(!JSON.stringify(r.body).includes('secret'));
    } finally {
      console.error = original;
    }
  });

  test('rate limit: 8 per 60 s per client IP', async () => {
    const fetchStub = async (url, input) => ({ input, finalUrl: url.href });
    const analyze = (s) => s;
    for (let i = 0; i < RATE_LIMIT.max; i++) {
      const r = await runScan('example.com', { clientIp: '198.51.100.9', analyze, fetchSnapshot: fetchStub });
      assert.equal(r.status, 200, `scan ${i + 1}`);
    }
    const limited = await runScan('example.com', { clientIp: '198.51.100.9', analyze, fetchSnapshot: fetchStub });
    assert.equal(limited.status, 429);
    assert.equal(limited.body.error.code, 'rate_limited');
    // Invalid input still counts and is still limited.
    assert.equal((await runScan('', { clientIp: '198.51.100.9' })).status, 429);
    // Other clients are unaffected.
    assert.equal((await runScan('example.com', { clientIp: '198.51.100.10', analyze, fetchSnapshot: fetchStub })).status, 200);
  });

  test('rate limit window slides and old entries are pruned', () => {
    const t = 1_000_000;
    for (let i = 0; i < 8; i++) assert.equal(checkRateLimit('a', t + i), true);
    assert.equal(checkRateLimit('a', t + 100), false);
    assert.equal(checkRateLimit('a', t + 59_999), false, 'first hit still inside the window');
    assert.equal(checkRateLimit('a', t + 60_000), true, 'oldest hit expired');
    assert.equal(checkRateLimit('a', t + 60_000), false, 'and the window is full again');
    assert.equal(checkRateLimit('b', t + 200_000), true, 'prune runs without breaking new clients');
    assert.equal(checkRateLimit('a', t + 200_000), true);
  });

  test('rate limit keys: IPv6 by /64, IPv4-mapped as IPv4', () => {
    assert.equal(rateLimitKey('2001:db8:1:2:3:4:5:6'), '2001:db8:1:2::/64');
    assert.equal(rateLimitKey('2001:db8:1:2::9'), '2001:db8:1:2::/64');
    assert.equal(rateLimitKey('::ffff:203.0.113.7'), '203.0.113.7');
    assert.equal(rateLimitKey(' 203.0.113.7 '), '203.0.113.7');
    assert.equal(rateLimitKey(undefined), 'unknown');
  });

  test('getClientIp: x-forwarded-for first entry, then x-real-ip, then socket', () => {
    assert.equal(getClientIp({ headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.1' }, socket: { remoteAddress: '127.0.0.1' } }), '203.0.113.5');
    assert.equal(getClientIp({ headers: { 'x-real-ip': '203.0.113.6' }, socket: { remoteAddress: '127.0.0.1' } }), '203.0.113.6');
    assert.equal(getClientIp({ headers: {}, socket: { remoteAddress: '127.0.0.1' } }), '127.0.0.1');
    assert.equal(getClientIp({ headers: { 'x-forwarded-for': ' ' }, socket: {} }), 'unknown');
  });
});

// ---------------------------------------------------------------------------
// api/scan.js handler + server.js
// ---------------------------------------------------------------------------

describe('HTTP: handler and dev server', () => {
  let dev;
  let base;
  before(async () => {
    dev = createDevServer();
    await new Promise((r) => dev.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${dev.address().port}`;
  });
  after(() => new Promise((r) => dev.close(r)));
  beforeEach(() => {
    resetRateLimit();
    delete process.env[ENV];
  });

  function assertApiHeaders(res) {
    assert.equal(res.headers.get('content-type'), 'application/json; charset=utf-8');
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('access-control-allow-origin'), null);
  }

  test('GET only: other methods get 405 + Allow: GET', async () => {
    for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS']) {
      const res = await fetch(`${base}/api/scan?url=example.com`, { method });
      assert.equal(res.status, 405, method);
      assert.equal(res.headers.get('allow'), 'GET');
      assertApiHeaders(res);
      assert.deepEqual(await res.json(), { ok: false, error: { code: 'method_not_allowed', message: 'Use GET.' } });
    }
  });

  test('GET errors use the JSON error shape and required headers', async () => {
    let res = await fetch(`${base}/api/scan`, { headers: SAME_ORIGIN });
    assert.equal(res.status, 400);
    assertApiHeaders(res);
    assert.equal((await res.json()).error.code, 'invalid_url');

    res = await fetch(`${base}/api/scan?url=localhost`, { headers: SAME_ORIGIN });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error.code, 'blocked_target');

    res = await fetch(`${base}/api/scan?url=${encodeURIComponent('http://169.254.169.254/latest/meta-data/')}`, { headers: SAME_ORIGIN });
    assert.equal((await res.json()).error.code, 'blocked_target');

    res = await fetch(`${base}/api/scan?url=${encodeURIComponent('http://0x7f.1/')}`, { headers: SAME_ORIGIN });
    assert.equal((await res.json()).error.code, 'blocked_target');
  });

  test('only our own page may start scans, and refusals do not use up the rate limit', async () => {
    assert.equal(isAllowedOrigin({ headers: { 'x-surface': '1' } }), true);
    assert.equal(isAllowedOrigin({ headers: { 'x-surface': '1', 'sec-fetch-site': 'same-origin' } }), true);
    assert.equal(isAllowedOrigin({ headers: {} }), false, 'missing marker header');
    assert.equal(isAllowedOrigin({ headers: { 'x-surface': '1', 'sec-fetch-site': 'cross-site' } }), false);
    assert.equal(isAllowedOrigin({ headers: { 'x-surface': '1', 'sec-fetch-site': 'same-site' } }), false);
    assert.equal(isAllowedOrigin({ headers: { 'sec-fetch-site': 'same-origin' } }), false);

    for (let i = 0; i < RATE_LIMIT.max + 2; i++) {
      const res = await fetch(`${base}/api/scan?url=localhost`, { headers: { 'sec-fetch-site': 'cross-site', 'x-surface': '1' } });
      assert.equal(res.status, 403);
      assertApiHeaders(res);
      assert.equal((await res.json()).error.code, 'forbidden');
    }
    // The visitor's own quota is untouched by those refused cross-site attempts.
    const own = await fetch(`${base}/api/scan?url=localhost`, { headers: SAME_ORIGIN });
    assert.equal((await own.json()).error.code, 'blocked_target');
  });

  test('handler works with a minimal res (statusCode / setHeader / end only)', async () => {
    const headers = {};
    let body;
    const res = {
      statusCode: 0,
      headersSent: false,
      setHeader: (k, v) => (headers[k.toLowerCase()] = v),
      end: (b) => (body = b),
    };
    await handler({ method: 'GET', url: '/api/scan?url=ftp%3A%2F%2Fexample.com', headers: { ...SAME_ORIGIN }, socket: {} }, res);
    assert.equal(res.statusCode, 400);
    assert.equal(headers['content-type'], 'application/json; charset=utf-8');
    assert.equal(JSON.parse(body).error.code, 'invalid_url');
  });

  test('serves index.html with the security headers', async () => {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) assert.equal(res.headers.get(k), v, k);
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.match(await res.text(), /<html/i);
  });

  test('static files: path traversal is refused', async () => {
    for (const p of [
      '/assets/../package.json',
      '/assets/%2e%2e/package.json',
      '/assets/..%2fpackage.json',
      '/assets/..%2Fapi%2Fscan.js',
      '/assets/..%5cpackage.json',
      '/assets/%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '/assets/.hidden',
      '/assets/%00',
      '/assets/%E0%A4%A',
      '/server.js',
      '/SPEC.md',
      '/package.json',
    ]) {
      const res = await fetch(base + p);
      assert.equal(res.status, 404, p);
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      await res.arrayBuffer();
    }
    assert.equal(await resolveAsset('/assets/../x'), null);
    assert.equal(await resolveAsset('/assets/a/../../x'), null);
    assert.match(await resolveAsset('/assets/app.css'), /assets[/\\]app\.css$/);
    const res = await fetch(`${base}/`, { method: 'POST' });
    assert.equal(res.status, 405);
  });
});
