// GET /api/scan?url=<input>  (SPEC Contract 3)
//
// Vercel Node function. Uses only res.statusCode / res.setHeader / res.end so
// the same handler runs unchanged on plain node:http (see server.js).

import { ScanError, errorResponse } from './_lib/errors.js';
import { getClientIp, runScan } from './_lib/scan-core.js';

function send(res, status, body, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  for (const [name, value] of Object.entries(extraHeaders)) res.setHeader(name, value);
  res.end(JSON.stringify(body));
}

// Only our own page may start scans. Browsers send Sec-Fetch-Site on every
// request, and a cross-site page can't add the custom X-Surface header without a
// CORS preflight, which this endpoint never approves. Checked before the rate
// limiter so other sites can't burn a visitor's quota.
export function isAllowedOrigin(req) {
  const h = req.headers || {};
  const site = h['sec-fetch-site'];
  if (site !== undefined && site !== 'same-origin') return false;
  return h['x-surface'] === '1';
}

export default async function handler(req, res) {
  try {
    if (req.method !== 'GET') {
      const { status, body } = errorResponse(new ScanError('method_not_allowed'));
      send(res, status, body, { Allow: 'GET' });
      return;
    }
    if (!isAllowedOrigin(req)) {
      const { status, body } = errorResponse(new ScanError('forbidden'));
      send(res, status, body);
      return;
    }
    let input = null;
    try {
      input = new URL(req.url || '/', 'http://localhost').searchParams.get('url');
    } catch {
      input = null;
    }
    const { status, body } = await runScan(input ?? '', { clientIp: getClientIp(req) });
    send(res, status, body);
  } catch (err) {
    console.error('[surface] handler error:', err);
    if (!res.headersSent) {
      const { status, body } = errorResponse(err);
      send(res, status, body);
    } else {
      res.end();
    }
  }
}
