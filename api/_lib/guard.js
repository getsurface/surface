// Input normalization + SSRF protection.
//
// Layers (each one is sufficient on its own for the case it covers):
//   1. normalizeInput / validateUrl — scheme, userinfo, port, host-name and
//      IP-literal checks on the WHATWG-parsed URL. WHATWG parsing already
//      canonicalizes legacy IPv4 spellings (2130706433, 0x7f.1, 017700000001,
//      127.1, fullwidth digits …) to dotted-quad, so they are checked as IPs.
//      Node's net layer skips DNS for IP literals, so this check is the gate
//      for them.
//   2. safeLookup — used as the `lookup` option of http/https.request(), i.e.
//      DNS is resolved *inside the socket connect* and the addresses handed to
//      the socket are exactly the ones we just validated (no TOCTOU, defeats
//      DNS rebinding). If ANY resolved address is non-public, the connection
//      fails before a single packet is sent to the target.
//   3. fetcher.js additionally checks socket.remoteAddress (belt and braces).
//
// SURFACE_ALLOW_PRIVATE=1 disables the IP/host-name blocklists and the port
// policy, for local testing only. It is read at call time.

import net from 'node:net';
import dns from 'node:dns';
import { ScanError } from './errors.js';

export const MAX_INPUT_LENGTH = 2048;
export const ALLOWED_PORTS = new Set(['80', '443']);

// Host names (and every subdomain of them) that never point at the public web.
// The SPEC list, plus `localdomain` (as in localhost.localdomain).
export const BLOCKED_HOST_SUFFIXES = Object.freeze([
  'localhost',
  'local',
  'internal',
  'lan',
  'home.arpa',
  'intranet',
  'corp',
  'localdomain',
]);

const MSG = {
  scheme: 'Only http:// and https:// addresses can be checked.',
  userinfo: "Addresses with a username or password can't be checked.",
  tooLong: `That address is too long (${MAX_INPUT_LENGTH.toLocaleString('en-US')} characters max).`,
  port: 'Only the standard web ports (80 and 443) can be checked.',
  privateHost: "That address points to a private or local network, so it can't be checked.",
  privateDns: "That domain points to a private or local network address, so it can't be checked.",
  redirect: "The site redirects to a private or local address, so it can't be checked.",
  redirectPort: 'The site redirects to a non-standard port (only 80 and 443 can be checked).',
};

/** True when SURFACE_ALLOW_PRIVATE=1 (read at call time so tests can toggle it). */
export function allowPrivate() {
  // Never honoured on a Vercel deployment, so a dashboard env var can't open SSRF.
  if (process.env.VERCEL) return false;
  return process.env.SURFACE_ALLOW_PRIVATE === '1';
}

// ---------------------------------------------------------------------------
// IP blocklists
// ---------------------------------------------------------------------------

const V4_RANGES = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT (also Alibaba metadata 100.100.100.200)
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local (cloud metadata 169.254.169.254)
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments (Oracle metadata 192.0.0.192)
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast 255.255.255.255
];

// The SPEC list, plus a few more non-public ranges. On top of this, anything
// outside global unicast 2000::/3 is blocked (see isBlockedV6), except the
// IPv4-mapped and NAT64 prefixes, which are judged by their embedded IPv4.
const V6_RANGES = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['::', 96], // IPv4-compatible (deprecated) — includes :: and ::1
  ['::ffff:0:0:0', 96], // IPv4-translated (SIIT)
  ['64:ff9b:1::', 48], // local-use NAT64 (RFC 8215)
  ['100::', 64], // discard-only
  ['2001::', 23], // IETF protocol assignments (Teredo, ORCHID, benchmarking …)
  ['2001:db8::', 32], // documentation
  ['3fff::', 20], // documentation (RFC 9637)
  ['5f00::', 16], // SRv6 SIDs
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['fec0::', 10], // site-local (deprecated)
  ['ff00::', 8], // multicast
];

const V4_BLOCK = new net.BlockList();
for (const [addr, prefix] of V4_RANGES) V4_BLOCK.addSubnet(addr, prefix, 'ipv4');

const V6_BLOCK = new net.BlockList();
for (const [addr, prefix] of V6_RANGES) V6_BLOCK.addSubnet(addr, prefix, 'ipv6');

/** Strict dotted-quad -> [a,b,c,d] or null. */
function parseIPv4(s) {
  if (net.isIP(s) !== 4) return null;
  return s.split('.').map(Number);
}

/** Canonical (zone-free) IPv6 string -> Uint8Array(16) or null. */
export function parseIPv6(input) {
  let s = input;
  if (net.isIP(s) !== 6) return null;
  // Embedded dotted IPv4 tail (::ffff:1.2.3.4, 64:ff9b::1.2.3.4) -> two hex words.
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseIPv4(tail);
    if (!v4) return null;
    s = `${s.slice(0, lastColon + 1)}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let words;
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 0) return null;
    words = [...head, ...Array(fill).fill('0'), ...rest];
  } else {
    words = head;
  }
  if (words.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(words[i])) return null;
    const w = parseInt(words[i], 16);
    bytes[i * 2] = w >> 8;
    bytes[i * 2 + 1] = w & 0xff;
  }
  return bytes;
}

function v4FromBytes(bytes, offset) {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

function startsWith(bytes, prefix) {
  for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false;
  return true;
}

const MAPPED_PREFIX = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]; // ::ffff:0:0/96
const NAT64_PREFIX = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]; // 64:ff9b::/96
const SIX_TO_FOUR_PREFIX = [0x20, 0x02]; // 2002::/16

function isBlockedV4(dotted) {
  return V4_BLOCK.check(dotted, 'ipv4');
}

function isBlockedV6(addr, bytes) {
  // IPv4-mapped and NAT64: judge by the embedded IPv4 address.
  if (startsWith(bytes, MAPPED_PREFIX)) return isBlockedV4(v4FromBytes(bytes, 12));
  if (startsWith(bytes, NAT64_PREFIX)) return isBlockedV4(v4FromBytes(bytes, 12));
  // 6to4 embeds an IPv4 address in bits 16..47.
  if (startsWith(bytes, SIX_TO_FOUR_PREFIX) && isBlockedV4(v4FromBytes(bytes, 2))) return true;
  if (V6_BLOCK.check(addr, 'ipv6')) return true;
  // Only global unicast (2000::/3) is public.
  return (bytes[0] & 0xe0) !== 0x20;
}

/**
 * Canonicalize legacy IPv4 spellings (integer, octal, hex, 1-3 part forms)
 * the same way browsers and inet_aton do, via the WHATWG host parser.
 * Returns dotted-quad, or null if `s` is not such a spelling.
 */
export function canonicalIPv4(s) {
  if (typeof s !== 'string' || !/^[0-9a-fx.]+$/i.test(s)) return null;
  try {
    const h = new URL(`http://${s}/`).hostname;
    return net.isIP(h) === 4 ? h : null;
  } catch {
    return null;
  }
}

/**
 * true when `ip` is not a public unicast address.
 * Accepts IPv4 (incl. legacy integer/octal/hex spellings), IPv6 (with or
 * without brackets, incl. IPv4-mapped / NAT64 / embedded-dotted forms).
 * Fail-closed: anything that is not an IP address at all returns true, and so
 * does any IPv6 address carrying a zone id (%eth0). Pure: ignores the env flag.
 */
export function isBlockedIp(ip) {
  if (typeof ip !== 'string') return true;
  let s = ip.trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (s.includes('%')) return true;
  let version = net.isIP(s);
  if (version === 0) {
    const canon = canonicalIPv4(s);
    if (!canon) return true;
    s = canon;
    version = 4;
  }
  if (version === 4) return isBlockedV4(s);
  const bytes = parseIPv6(s);
  if (!bytes) return true;
  return isBlockedV6(s, bytes);
}

// ---------------------------------------------------------------------------
// Host names and URLs
// ---------------------------------------------------------------------------

const LABEL_RE = /^[a-z0-9_-]{1,63}$/;

function hostSuffixBlocked(h) {
  return BLOCKED_HOST_SUFFIXES.some((s) => h === s || h.endsWith(`.${s}`));
}

/**
 * Validate a host name (as found in URL.hostname: lowercase, punycode, IPv6 in
 * brackets). Returns the canonical host (no trailing dot, IPv6 without
 * brackets). Throws ScanError: blocked_target for private/local targets,
 * invalid_url for things that are not usable public host names.
 */
export function checkHostname(hostname, { redirect = false } = {}) {
  if (typeof hostname !== 'string') throw new ScanError('invalid_url');
  let h = hostname.trim().toLowerCase();
  const bracketed = h.startsWith('[') && h.endsWith(']');
  if (bracketed) h = h.slice(1, -1);
  h = h.replace(/\.+$/, '');
  if (!h) throw new ScanError('invalid_url');
  const allow = allowPrivate();
  const blocked = () => new ScanError('blocked_target', redirect ? MSG.redirect : MSG.privateHost);

  // IP literals: net skips DNS for these, so this check is their only gate.
  const version = net.isIP(h);
  if (version) {
    if (h.includes('%')) throw blocked();
    if (!allow && isBlockedIp(h)) throw blocked();
    return h;
  }
  if (bracketed) throw new ScanError('invalid_url');
  const legacy = canonicalIPv4(h);
  if (legacy) {
    if (!allow && isBlockedIp(legacy)) throw blocked();
    return legacy;
  }

  // DNS names.
  if (h.length > 253) throw new ScanError('invalid_url');
  const labels = h.split('.');
  if (!labels.every((l) => LABEL_RE.test(l))) throw new ScanError('invalid_url');
  if (/^\d+$/.test(labels[labels.length - 1])) throw new ScanError('invalid_url');
  if (!allow) {
    if (hostSuffixBlocked(h)) throw blocked();
    if (labels.length < 2) throw new ScanError('invalid_url');
  }
  return h;
}

/**
 * Validate an absolute URL against the target policy (scheme, userinfo, port,
 * host / IP literal). Used for the user's input and for EVERY redirect hop.
 * Returns a cleaned copy (canonical host, no trailing dot, no fragment).
 * Does not resolve DNS — that happens at connect time in safeLookup.
 */
export function validateUrl(url, { redirect = false } = {}) {
  let u;
  try {
    u = new URL(url instanceof URL ? url.href : String(url));
  } catch {
    throw new ScanError('invalid_url');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw redirect ? new ScanError('blocked_target', MSG.redirect) : new ScanError('invalid_url', MSG.scheme);
  }
  if (u.username || u.password) {
    throw redirect ? new ScanError('blocked_target', MSG.redirect) : new ScanError('invalid_url', MSG.userinfo);
  }
  if (u.port && !allowPrivate() && !ALLOWED_PORTS.has(u.port)) {
    throw new ScanError('blocked_target', redirect ? MSG.redirectPort : MSG.port);
  }
  const host = checkHostname(u.hostname, { redirect });
  const wanted = net.isIP(host) === 6 ? `[${host}]` : host;
  if (u.hostname !== wanted) u.hostname = wanted;
  u.hash = '';
  return u;
}

/**
 * User input -> normalized URL (throws ScanError).
 * Trim, ≤ 2048 chars, https:// when no scheme, http/https only, no userinfo,
 * port empty/80/443, query and hash dropped, path kept.
 */
export function normalizeInput(input) {
  if (typeof input !== 'string') throw new ScanError('invalid_url');
  const raw = input.trim();
  if (!raw) throw new ScanError('invalid_url');
  if (raw.length > MAX_INPUT_LENGTH) throw new ScanError('invalid_url', MSG.tooLong);

  let candidate;
  if (raw.startsWith('//')) {
    candidate = `https:${raw}`;
  } else {
    const m = /^([a-z][a-z0-9+.-]*):(.*)$/is.exec(raw);
    // "example.com:443/x" and "localhost:8080" are host:port, not a scheme.
    if (!m || m[2] === '' || /^\d+(?:[/?#\\]|$)/.test(m[2])) {
      candidate = `https://${raw}`;
    } else {
      const scheme = m[1].toLowerCase();
      if (scheme !== 'http' && scheme !== 'https') throw new ScanError('invalid_url', MSG.scheme);
      candidate = raw;
    }
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new ScanError('invalid_url');
  }
  const u = validateUrl(parsed);
  u.search = '';
  u.hash = '';
  return u;
}

// ---------------------------------------------------------------------------
// DNS: lookup at connect time
// ---------------------------------------------------------------------------

function normFamily(f) {
  if (f === 4 || f === 'IPv4') return 4;
  if (f === 6 || f === 'IPv6') return 6;
  return 0;
}

/**
 * Pure check of a resolver result. Returns the normalized list
 * [{ address, family }]. Throws ScanError('blocked_target') if ANY address is
 * non-public (unless SURFACE_ALLOW_PRIVATE=1), and an ENOTFOUND error if the
 * list is empty.
 */
export function checkResolvedAddresses(hostname, addresses) {
  const list = (Array.isArray(addresses) ? addresses : [addresses])
    .filter((a) => a != null)
    .map((a) => (typeof a === 'string' ? { address: a, family: net.isIP(a) } : { address: a.address, family: normFamily(a.family) || net.isIP(a.address) }));
  if (list.length === 0) {
    const e = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
    e.code = 'ENOTFOUND';
    e.hostname = hostname;
    throw e;
  }
  if (!allowPrivate()) {
    for (const a of list) {
      if (typeof a.address !== 'string' || !net.isIP(a.address) || isBlockedIp(a.address)) {
        const e = new ScanError('blocked_target', MSG.privateDns);
        e.hostname = hostname;
        throw e;
      }
    }
  }
  return list;
}

/**
 * Build a `lookup` function for http/https/net/tls with an injectable resolver
 * (same signature as dns.lookup). It always resolves ALL addresses of every
 * family, validates every one of them, then answers in the shape the caller
 * asked for: honours `options.all` (array of { address, family }) and
 * `options.family` (4 / 6 / 0).
 */
const DNS_TIMEOUT_MS = 2500;
const DNS_TRIES = 2;

/**
 * Resolve A and AAAA records with c-ares (dns.Resolver) instead of
 * getaddrinfo. getaddrinfo runs on libuv's 4-thread pool and can't be
 * cancelled, so a few domains whose nameservers never answer could stall every
 * scan on the instance. c-ares is fully async and bounded by timeout × tries.
 * Same callback shape as dns.lookup(host, { all: true }).
 */
export function aresResolve(hostname, _opts, callback) {
  const resolver = new dns.Resolver({ timeout: DNS_TIMEOUT_MS, tries: DNS_TRIES });
  const found = [];
  let pending = 2;
  let firstError = null;
  const settle = (family) => (err, addresses) => {
    if (err) firstError ??= err;
    else for (const address of addresses) found.push({ address, family });
    if (--pending > 0) return;
    if (found.length) return callback(null, found);
    const e = new Error(`DNS lookup failed for ${hostname}`);
    e.code = firstError?.code === 'ETIMEOUT' ? 'EAI_AGAIN' : 'ENOTFOUND';
    e.hostname = hostname;
    callback(e);
  };
  resolver.resolve4(hostname, settle(4));
  resolver.resolve6(hostname, settle(6));
}

// Local testing with SURFACE_ALLOW_PRIVATE=1 keeps getaddrinfo so /etc/hosts
// names (localhost) still resolve; production always uses c-ares.
function defaultResolve(host, opts, cb) {
  if (allowPrivate()) return dns.lookup(host, opts, cb);
  return aresResolve(host, opts, cb);
}

export function createSafeLookup(resolve = defaultResolve) {
  return function safeLookup(hostname, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    } else if (typeof options === 'number') {
      options = { family: options };
    } else if (options == null || typeof options !== 'object') {
      options = {};
    }
    const wantFamily = normFamily(options.family);
    const opts = { all: true, family: 0 };
    if (options.order !== undefined) opts.order = options.order;
    else if (options.verbatim !== undefined) opts.verbatim = options.verbatim;

    let called = false;
    const done = (...args) => {
      if (called) return;
      called = true;
      callback(...args);
    };
    try {
      resolve(hostname, opts, (err, addresses) => {
        if (err) return done(err);
        let list;
        try {
          list = checkResolvedAddresses(hostname, addresses);
        } catch (e) {
          return done(e);
        }
        const filtered = wantFamily ? list.filter((a) => a.family === wantFamily) : list;
        if (filtered.length === 0) {
          const e = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
          e.code = 'ENOTFOUND';
          e.hostname = hostname;
          return done(e);
        }
        if (options.all) return done(null, filtered.map((a) => ({ address: a.address, family: a.family })));
        return done(null, filtered[0].address, filtered[0].family);
      });
    } catch (e) {
      done(e);
    }
  };
}

/** Drop-in `lookup` for http/https.request(), backed by c-ares in production. */
export const safeLookup = createSafeLookup();
