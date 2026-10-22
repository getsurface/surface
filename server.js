// Zero-dependency local dev server: `node server.js` (PORT, default 3000; HOST, default 127.0.0.1).
//   /            -> index.html
//   /assets/*    -> static files (path-traversal safe)
//   /api/scan    -> the same handler Vercel runs

import http from 'node:http';
import { readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import scanHandler from './api/scan.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = path.join(ROOT, 'assets');
const INDEX_FILE = path.join(ROOT, 'index.html');

export const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; " +
    "img-src data:; connect-src 'self'; " +
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; " +
    "require-trusted-types-for 'script'; trusted-types 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
});

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.webmanifest': 'application/manifest+json',
};

function sendText(req, res, status, text, extra = {}) {
  res.statusCode = status;
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(req.method === 'HEAD' ? undefined : text);
}

async function sendFile(req, res, file) {
  let info;
  try {
    info = await stat(file);
  } catch {
    return sendText(req, res, 404, 'Not found');
  }
  if (!info.isFile()) return sendText(req, res, 404, 'Not found');
  const body = await readFile(file);
  res.statusCode = 200;
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  res.setHeader('Content-Type', CONTENT_TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream');
  res.setHeader('Content-Length', body.length);
  res.setHeader('Cache-Control', 'no-cache');
  res.end(req.method === 'HEAD' ? undefined : body);
}

async function sendNotFound(req, res) {
  let body;
  try {
    body = await readFile(path.join(ROOT, '404.html'));
  } catch {
    return sendText(req, res, 404, 'Not found');
  }
  res.statusCode = 404;
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  res.setHeader('Content-Type', CONTENT_TYPES['.html']);
  res.setHeader('Content-Length', body.length);
  res.setHeader('Cache-Control', 'no-cache');
  res.end(req.method === 'HEAD' ? undefined : body);
}

/** "/assets/<rel>" -> absolute file path inside assets/, or null when unsafe. */
export async function resolveAsset(pathname) {
  if (!pathname.startsWith('/assets/')) return null;
  let rel;
  try {
    rel = decodeURIComponent(pathname.slice('/assets/'.length));
  } catch {
    return null;
  }
  if (!rel || rel.includes('\0') || rel.includes('\\')) return null;
  const segments = rel.split('/');
  if (segments.some((s) => s === '' || s === '.' || s === '..' || s.startsWith('.'))) return null;
  const full = path.resolve(ASSETS_DIR, ...segments);
  if (!full.startsWith(ASSETS_DIR + path.sep)) return null;
  // Symlinks must not lead out of assets/ either.
  try {
    const [realFile, realDir] = await Promise.all([realpath(full), realpath(ASSETS_DIR)]);
    if (!realFile.startsWith(realDir + path.sep)) return null;
  } catch {
    // Missing file: let sendFile answer 404.
  }
  return full;
}

export function createDevServer() {
  return http.createServer(async (req, res) => {
    try {
      let pathname;
      try {
        pathname = new URL(req.url || '/', 'http://localhost').pathname;
      } catch {
        return sendText(req, res, 400, 'Bad request');
      }

      if (pathname === '/api/scan') return await scanHandler(req, res);

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        return sendText(req, res, 405, 'Method not allowed', { Allow: 'GET, HEAD' });
      }
      if (pathname === '/' || pathname === '/index.html') return await sendFile(req, res, INDEX_FILE);
      if (pathname === '/robots.txt') return await sendFile(req, res, path.join(ROOT, 'robots.txt'));
      if (pathname === '/.well-known/security.txt') return await sendFile(req, res, path.join(ROOT, '.well-known', 'security.txt'));
      if (pathname.startsWith('/assets/')) {
        const file = await resolveAsset(pathname);
        if (!file) return sendText(req, res, 404, 'Not found');
        return await sendFile(req, res, file);
      }
      return await sendNotFound(req, res);
    } catch (err) {
      console.error('[surface] dev server error:', err);
      if (!res.headersSent) sendText(req, res, 500, 'Internal error');
      else res.end();
    }
  });
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  createDevServer().listen(port, host, () => {
    console.log(`Surface dev server: http://${host === '0.0.0.0' ? 'localhost' : host}:${port}`);
    if (process.env.SURFACE_ALLOW_PRIVATE === '1') {
      console.warn('SURFACE_ALLOW_PRIVATE=1: private/local targets are allowed. Local testing only.');
    }
  });
}
