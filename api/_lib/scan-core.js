// runScan(): rate limit -> guard -> fetch -> analyze -> { status, body }.

import net from 'node:net';
import { ScanError, errorResponse } from './errors.js';
import { normalizeInput } from './guard.js';
import { fetchSnapshot as defaultFetchSnapshot } from './fetcher.js';

export const RATE_LIMIT = Object.freeze({ max: 8, windowMs: 60_000 });
const MAX_TRACKED_CLIENTS = 10_000;

// key -> ascending timestamps of accepted scans within the window.
// In-memory and per instance: best effort on serverless.
const hits = new Map();
let lastPrune = 0;

function prune(now) {
  const cutoff = now - RATE_LIMIT.windowMs;
  for (const [key, times] of hits) {
    if (times.length === 0 || times[times.length - 1] <= cutoff) hits.delete(key);
  }
  // Hard cap: evict least recently active clients (Map keeps insertion order).
  while (hits.size > MAX_TRACKED_CLIENTS) hits.delete(hits.keys().next().value);
  lastPrune = now;
}

/** Bucket key for a client IP: IPv4-mapped -> IPv4, IPv6 -> its /64. */
export function rateLimitKey(ip) {
  let s = typeof ip === 'string' ? ip.trim().toLowerCase() : '';
  if (s.startsWith('[') && s.includes(']')) s = s.slice(1, s.indexOf(']'));
  if (s.startsWith('::ffff:') && net.isIP(s.slice(7)) === 4) s = s.slice(7);
  if (net.isIP(s) === 6) {
    const [head, tail = ''] = s.split('%')[0].split('::');
    const left = head ? head.split(':') : [];
    const right = tail ? tail.split(':') : [];
    const words = s.includes('::') ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right] : left;
    return `${words.slice(0, 4).map((w) => w.replace(/^0+(?=.)/, '')).join(':')}::/64`;
  }
  return s || 'unknown';
}

/** Records a scan for `ip`; false when the client is over the limit. */
export function checkRateLimit(ip, now = Date.now()) {
  if (now - lastPrune >= RATE_LIMIT.windowMs || hits.size > MAX_TRACKED_CLIENTS) prune(now);
  const key = rateLimitKey(ip);
  const cutoff = now - RATE_LIMIT.windowMs;
  const times = (hits.get(key) || []).filter((t) => t > cutoff);
  hits.delete(key);
  if (times.length >= RATE_LIMIT.max) {
    hits.set(key, times);
    return false;
  }
  times.push(now);
  hits.set(key, times);
  return true;
}

/** Test helper. */
export function resetRateLimit() {
  hits.clear();
  lastPrune = 0;
}

function headerValue(v) {
  return (Array.isArray(v) ? v[0] : v) ?? '';
}

function pickIp(value, which = 'first') {
  const parts = String(headerValue(value)).split(',');
  const ip = (which === 'last' ? parts[parts.length - 1] : parts[0]).trim();
  return net.isIP(ip) ? ip : '';
}

/**
 * Client IP for rate limiting. Forwarding headers are only trusted where a
 * proxy we control writes them: on Vercel (its edge overwrites them) or with
 * TRUST_PROXY=1 behind one proxy, which sets X-Real-IP or appends the client
 * to X-Forwarded-For (so the LAST entry is the one it saw; earlier entries are
 * whatever the client sent). Anywhere else the socket address is used. Values
 * that aren't a plain IP are ignored, which also keeps the limiter's keys short.
 */
export function getClientIp(req, env = process.env) {
  const h = req?.headers || {};
  const socketIp = req?.socket?.remoteAddress || 'unknown';
  if (env.VERCEL) {
    return pickIp(h['x-vercel-forwarded-for']) || pickIp(h['x-forwarded-for']) || pickIp(h['x-real-ip']) || socketIp;
  }
  if (env.TRUST_PROXY === '1') {
    return pickIp(h['x-real-ip']) || pickIp(h['x-forwarded-for'], 'last') || socketIp;
  }
  return socketIp;
}

let analyzeModule;
async function loadAnalyze() {
  analyzeModule ??= import('./analyze.js');
  try {
    const mod = await analyzeModule;
    if (typeof mod.analyze !== 'function') throw new Error('analyze.js does not export analyze()');
    return mod.analyze;
  } catch (err) {
    analyzeModule = undefined; // retry the import next time
    throw err;
  }
}

/**
 * @param {unknown} input   raw ?url= value
 * @param {object} [options]
 * @param {string} [options.clientIp]
 * @param {Function} [options.analyze]        override (tests); default: analyze() from ./analyze.js
 * @param {Function} [options.fetchSnapshot]  override (tests); default: ./fetcher.js
 * @param {object} [options.fetchOptions]     passed to fetchSnapshot (tests)
 * @returns {Promise<{ status: number, body: object }>}
 */
export async function runScan(input, options = {}) {
  const { clientIp, analyze, fetchSnapshot = defaultFetchSnapshot, fetchOptions } = options;
  try {
    if (!checkRateLimit(clientIp)) throw new ScanError('rate_limited');
    const url = normalizeInput(input);
    const snapshot = await fetchSnapshot(url, String(input).trim(), fetchOptions);
    const analyzeFn = typeof analyze === 'function' ? analyze : await loadAnalyze();
    const report = await analyzeFn(snapshot);
    return { status: 200, body: { ok: true, report } };
  } catch (err) {
    if (!(err instanceof ScanError)) {
      // Server log only; the client gets the generic `internal` message.
      console.error('[surface] unexpected scan error:', err);
    }
    return errorResponse(err);
  }
}
