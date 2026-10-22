// Safe HTTP(S) client -> Snapshot (SPEC Contract 1).
//
// Every connection goes through node:http / node:https request() with
// `lookup: safeLookup`, so DNS is resolved inside the socket connect and the
// socket only ever connects to addresses that were validated in that same
// lookup call (no DNS-rebinding window). IP-literal hosts never hit `lookup`
// (Node skips DNS for them), so every URL — the first one and each redirect
// hop — is passed through validateUrl() before it is requested. As a last
// line of defence the connected socket's remoteAddress is checked again.
//
// Bodies are never read: status, headers and certificate are captured on the
// 'response' event and the socket is destroyed immediately.

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { ScanError } from './errors.js';
import { allowPrivate, createSafeLookup, isBlockedIp, safeLookup, validateUrl } from './guard.js';

export const USER_AGENT = 'SurfaceCheck/1.0 (+passive header check)';

export const LIMITS = Object.freeze({
  hopTimeoutMs: 8000, // per request hop
  probeTimeoutMs: 5000, // plain-HTTP probe
  budgetMs: 15000, // whole scan
  maxRedirects: 5,
});

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_HEADER_BYTES = 16 * 1024; // Node's default
const MAX_HEADER_VALUE = 8 * 1024; // per value, before analysis
const DAY_MS = 86_400_000;

const DNS_ERROR_CODES = new Set([
  'ENOTFOUND',
  'EAI_AGAIN',
  'EAI_FAIL',
  'EAI_NODATA',
  'EAI_NONAME',
  'EAI_ADDRFAMILY',
  'ENODATA',
  'ESERVFAIL',
]);

const CERT_ERROR_CODES = new Set([
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'CERT_REVOKED',
  'CERT_UNTRUSTED',
  'CERT_REJECTED',
  'CERT_SIGNATURE_FAILURE',
  'CERT_CHAIN_TOO_LONG',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_DECRYPT_CERT_SIGNATURE',
  'UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY',
  'ERROR_IN_CERT_NOT_BEFORE_FIELD',
  'ERROR_IN_CERT_NOT_AFTER_FIELD',
  'INVALID_CA',
  'INVALID_PURPOSE',
  'PATH_LENGTH_EXCEEDED',
  'HOSTNAME_MISMATCH',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'ERR_TLS_CERT_ALTNAME_FORMAT',
]);

// "Nothing listening on port 80" for the plain-HTTP probe.
const NO_LISTENER_CODES = new Set([
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EHOSTDOWN',
  'ENETDOWN',
  'EADDRNOTAVAIL',
  'ETIMEDOUT',
  'ERR_SOCKET_CONNECTION_TIMEOUT',
]);

export function isDnsError(err) {
  return Boolean(err) && (err.syscall === 'getaddrinfo' || DNS_ERROR_CODES.has(err.code));
}

export function isCertError(err) {
  return Boolean(err) && CERT_ERROR_CODES.has(err.code);
}

/** Map a low-level failure to a ScanError. Non-network errors (bugs) are rethrown as-is. */
export function toScanError(err) {
  if (err instanceof ScanError) return err;
  if (isDnsError(err)) return new ScanError('dns_failed');
  if (err && (typeof err.code === 'string' || err instanceof AggregateError)) return new ScanError('unreachable');
  return err;
}

// HTTPS -> HTTP fallback applies to connection-level failures only: refused,
// reset, timeout, TLS protocol errors … not to DNS failures or blocked targets.
function shouldFallback(err) {
  // A timeout while DNS was still resolving says nothing about HTTPS; falling
  // back would only repeat the slow lookup.
  if (err instanceof ScanError) return err.code === 'timeout' && err.resolved !== false;
  if (isDnsError(err)) return false;
  return Boolean(err) && (typeof err.code === 'string' || err instanceof AggregateError);
}

function stripBrackets(host) {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/** rawHeaders -> { headers (lowercased, repeats joined with ", "), setCookies[] } */
export function collectHeaders(rawHeaders) {
  const headers = {};
  const setCookies = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = String(rawHeaders[i]).toLowerCase();
    const value = String(rawHeaders[i + 1]).slice(0, MAX_HEADER_VALUE);
    if (name === 'set-cookie') setCookies.push(value);
    else if (name === '__proto__') continue;
    // Browsers refuse conflicting Location headers; follow only the first one.
    else if (name === 'location' && Object.hasOwn(headers, name)) continue;
    else headers[name] = Object.hasOwn(headers, name) ? `${headers[name]}, ${value}`.slice(0, MAX_HEADER_VALUE) : value;
  }
  return { headers, setCookies };
}

/** Cookie name per SPEC: text before the first "=" of the first ";"-part. */
export function cookieName(raw) {
  const first = String(raw).split(';', 1)[0];
  const eq = first.indexOf('=');
  return (eq === -1 ? first : first.slice(0, eq)).trim();
}

function addCookies(map, list) {
  for (const raw of list) {
    const name = cookieName(raw);
    map.delete(name); // last one wins, and moves to the end
    map.set(name, raw);
  }
}

function firstName(v) {
  if (Array.isArray(v)) v = v[0];
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

function buildTls(raw, certError, now = Date.now()) {
  if (!raw) return null;
  const ms = raw.validTo ? Date.parse(raw.validTo) : NaN;
  const ok = Number.isFinite(ms);
  const error = certError || (raw.authorized === false ? raw.authorizationError || 'UNKNOWN_CERT_ERROR' : null);
  return {
    valid: !error,
    error: error ? String(error) : null,
    validTo: ok ? new Date(ms).toISOString() : null,
    daysLeft: ok ? Math.floor((ms - now) / DAY_MS) : null,
    issuer: firstName(raw.issuer?.O) ?? firstName(raw.issuer?.CN) ?? null,
    protocol: raw.protocol || null,
  };
}

function resolveLocation(location, base) {
  if (location == null || location === '') return null;
  let u;
  try {
    u = new URL(location, base);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  u.hash = '';
  return u;
}

function checkRemote(sock) {
  const addr = sock?.remoteAddress;
  if (addr && !allowPrivate() && isBlockedIp(addr)) return new ScanError('blocked_target');
  return null;
}

/**
 * One GET, no body. Resolves { status, headers, setCookies, location, tls, remoteAddress }.
 * Rejects with the raw network error (annotated with `.connected`) or a
 * ScanError ('timeout', 'blocked_target').
 */
function requestOnce(url, ctx, { rejectUnauthorized = true, timeoutMs = ctx.hopTimeoutMs } = {}) {
  return new Promise((resolve, reject) => {
    const remaining = ctx.deadline - Date.now();
    const limit = Math.min(timeoutMs, remaining);
    if (limit <= 0) {
      reject(Object.assign(new ScanError('timeout'), { connected: false }));
      return;
    }
    if (ctx.signal?.aborted) {
      reject(Object.assign(new Error('aborted'), { code: 'SURFACE_ABORTED', connected: false }));
      return;
    }

    const isHttps = url.protocol === 'https:';
    const mod = isHttps ? https : http;
    const host = stripBrackets(url.hostname);
    const options = {
      method: 'GET',
      host,
      port: url.port ? Number(url.port) : isHttps ? 443 : 80,
      path: `${url.pathname || '/'}${url.search}`,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'identity',
        Connection: 'close',
      },
      // Fresh agent: no keep-alive, no socket or TLS-session reuse across
      // hosts, and no environment proxy (the global agent may pick one up).
      agent: new mod.Agent({ keepAlive: false, maxSockets: 1 }),
      lookup: ctx.lookup,
      maxHeaderSize: MAX_HEADER_BYTES,
    };
    if (isHttps) {
      // SNI: the host name; never an IP literal (not permitted by RFC 6066).
      options.servername = net.isIP(host) ? '' : host;
      options.rejectUnauthorized = rejectUnauthorized;
    }

    let settled = false;
    let connected = false;
    let resolved = net.isIP(host) !== 0; // IP literals skip the DNS lookup
    let req;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ctx.signal?.removeEventListener('abort', onAbort);
      fn(value);
    };
    const fail = (err) => {
      if (err && typeof err === 'object' && err.connected === undefined) {
        try {
          err.connected = connected;
        } catch {
          /* frozen */
        }
      }
      finish(reject, err);
      req?.destroy();
    };
    const onAbort = () => fail(Object.assign(new Error('aborted'), { code: 'SURFACE_ABORTED' }));
    const timer = setTimeout(() => {
      const e = new ScanError('timeout');
      e.connected = connected;
      e.resolved = resolved;
      fail(e);
    }, limit);

    try {
      req = mod.request(options);
    } catch (err) {
      fail(err);
      return;
    }
    ctx.signal?.addEventListener('abort', onAbort, { once: true });

    // A GET never asks to switch protocols; a 101 would otherwise hold the hop
    // until its timeout.
    req.on('upgrade', (res, sock) => {
      sock.destroy();
      fail(new ScanError('unreachable'));
    });

    req.on('socket', (sock) => {
      sock.once('lookup', () => {
        resolved = true;
      });
      const onConnect = () => {
        connected = true;
        const blocked = checkRemote(sock);
        if (blocked) fail(blocked);
      };
      if (sock.connecting === false && sock.remoteAddress) onConnect();
      else sock.once('connect', onConnect);
    });

    req.on('response', (res) => {
      res.on('error', () => {});
      const sock = res.socket;
      const blocked = checkRemote(sock);
      if (blocked) {
        res.destroy();
        fail(blocked);
        return;
      }
      let tlsRaw = null;
      if (isHttps && sock && typeof sock.getPeerCertificate === 'function') {
        let cert = {};
        try {
          cert = sock.getPeerCertificate(false) || {};
        } catch {
          cert = {};
        }
        tlsRaw = {
          validTo: cert.valid_to || null,
          issuer: cert.issuer || null,
          protocol: typeof sock.getProtocol === 'function' ? sock.getProtocol() : null,
          authorized: sock.authorized,
          authorizationError: sock.authorizationError ? String(sock.authorizationError.code || sock.authorizationError) : null,
        };
      }
      const { headers, setCookies } = collectHeaders(res.rawHeaders || []);
      const out = {
        status: res.statusCode,
        headers,
        setCookies,
        location: headers.location ?? null,
        tls: tlsRaw,
        remoteAddress: sock?.remoteAddress ?? null,
      };
      // Never read the body.
      res.destroy();
      req.destroy();
      finish(resolve, out);
    });

    req.on('error', (err) => fail(err));
    req.end();
  });
}

/** One hop with the certificate retry: verified first, unverified once on a cert error. */
async function fetchHop(url, ctx) {
  try {
    return { ...(await requestOnce(url, ctx, { rejectUnauthorized: true })), certError: null };
  } catch (err) {
    if (url.protocol === 'https:' && isCertError(err)) {
      const res = await requestOnce(url, ctx, { rejectUnauthorized: false });
      return { ...res, certError: err.code };
    }
    throw err;
  }
}

/** Follow redirects manually, validating every hop. Errors carry `.hop`. */
async function runChain(startUrl, ctx) {
  let current;
  try {
    current = validateUrl(startUrl);
  } catch (err) {
    err.hop = 0;
    throw err;
  }
  const redirects = [];
  const visited = new Set([current.href]);
  const cookies = new Map();

  for (let hop = 0; ; hop++) {
    let res;
    try {
      res = await fetchHop(current, ctx);
    } catch (err) {
      if (err && typeof err === 'object') {
        try {
          err.hop = hop;
        } catch {
          /* frozen */
        }
      }
      throw err;
    }
    addCookies(cookies, res.setCookies);

    const final = (redirectStop = null) => ({
      finalUrl: current.href,
      status: res.status,
      headers: res.headers,
      cookies,
      redirects,
      redirectStop,
      tls: current.protocol === 'https:' ? buildTls(res.tls, res.certError) : null,
    });
    // Stop (and report this response) when there is nothing followable, the
    // redirect limit is reached, or the target was already visited (loop).
    // redirectStop tells the report that it describes a redirect, not a page.
    const next = REDIRECT_STATUSES.has(res.status) ? resolveLocation(res.location, current) : null;
    if (!next) return final(REDIRECT_STATUSES.has(res.status) && res.location ? 'unfollowable' : null);
    if (redirects.length >= ctx.maxRedirects) return final('limit');
    // Re-validate scheme, port, host and IP literal for the next hop. Its DNS
    // answer is validated at connect time by safeLookup.
    const safeNext = validateUrl(next, { redirect: true });
    // Drop the query on every hop, as for the user's input: a redirect must not
    // turn Surface into a relay that sends chosen query strings to other sites.
    safeNext.search = '';
    safeNext.hash = '';
    if (visited.has(safeNext.href)) return final('loop');
    redirects.push({ from: current.href, to: safeNext.href, status: res.status });
    visited.add(safeNext.href);
    current = safeNext;
  }
}

async function runChainWithFallback(startUrl, ctx) {
  try {
    return await runChain(startUrl, ctx);
  } catch (err) {
    const canFallback =
      startUrl.protocol === 'https:' && err?.hop === 0 && shouldFallback(err) && ctx.deadline - Date.now() > 0;
    if (!canFallback) throw err;
    const httpUrl = new URL(startUrl.href);
    httpUrl.protocol = 'http:';
    return runChain(httpUrl, ctx);
  }
}

/** GET http://<host>/ without following redirects. Never throws. */
async function runProbe(host, ctx, timeoutMs, port = 80) {
  try {
    const url = validateUrl(new URL(`http://${host}${port === 80 ? '' : `:${port}`}/`));
    const res = await requestOnce(url, ctx, { timeoutMs });
    const loc = resolveLocation(res.location, url);
    if (REDIRECT_STATUSES.has(res.status) && loc?.protocol === 'https:') {
      return { result: 'redirects-to-https', status: res.status, location: loc.href };
    }
    return { result: 'serves-http', status: res.status, location: loc ? loc.href : null };
  } catch (err) {
    const notListening =
      NO_LISTENER_CODES.has(err?.code) || (err instanceof ScanError && err.code === 'timeout' && !err.connected);
    return { result: notListening ? 'no-http' : 'error', status: null, location: null };
  }
}

/**
 * Fetch a site passively and return a Snapshot (SPEC Contract 1).
 * @param {URL|string} url   normalized URL (from normalizeInput); re-validated here
 * @param {string} input     raw user input (stored trimmed in the snapshot)
 * @param {object} [opts]    test hooks: { dnsLookup, hopTimeoutMs, probeTimeoutMs, budgetMs, maxRedirects }
 *                           dnsLookup is a dns.lookup-compatible resolver; its answers are still
 *                           validated by the safe lookup wrapper.
 * @throws {ScanError} invalid_url | blocked_target | dns_failed | unreachable | timeout
 */
export async function fetchSnapshot(url, input, opts = {}) {
  const cfg = {
    hopTimeoutMs: opts.hopTimeoutMs ?? LIMITS.hopTimeoutMs,
    probeTimeoutMs: opts.probeTimeoutMs ?? LIMITS.probeTimeoutMs,
    budgetMs: Math.min(opts.budgetMs ?? LIMITS.budgetMs, LIMITS.budgetMs),
    maxRedirects: Math.min(opts.maxRedirects ?? LIMITS.maxRedirects, LIMITS.maxRedirects),
    probePort: allowPrivate() ? (opts.probePort ?? 80) : 80, // test hook, local only
  };
  const startUrl = validateUrl(url);
  const started = Date.now();
  const controller = new AbortController();
  const ctx = {
    lookup: typeof opts.dnsLookup === 'function' ? createSafeLookup(opts.dnsLookup) : safeLookup,
    deadline: started + cfg.budgetMs,
    hopTimeoutMs: cfg.hopTimeoutMs,
    maxRedirects: cfg.maxRedirects,
    signal: controller.signal,
  };

  // Plain-HTTP probe in parallel with the main chain (same host, port 80, no follow).
  const probe = runProbe(startUrl.hostname, ctx, cfg.probeTimeoutMs, cfg.probePort);

  let chain;
  try {
    chain = await runChainWithFallback(startUrl, ctx);
  } catch (err) {
    controller.abort();
    await probe;
    throw toScanError(err);
  }
  const timingMs = Date.now() - started;

  let httpProbe = null;
  if (chain.finalUrl.startsWith('https:')) {
    httpProbe = await probe;
  } else {
    // Site is only reachable over plain HTTP: the probe is moot.
    controller.abort();
    await probe;
  }

  return {
    input: String(input ?? '').trim(),
    requestedUrl: startUrl.href,
    finalUrl: chain.finalUrl,
    status: chain.status,
    redirects: chain.redirects,
    redirectStop: chain.redirectStop ?? null, // "limit" | "loop" | "unfollowable" | null
    headers: chain.headers,
    setCookies: [...chain.cookies.values()],
    httpProbe,
    tls: chain.tls,
    timingMs,
    scannedAt: new Date(started).toISOString(),
  };
}
