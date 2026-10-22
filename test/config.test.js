// Production (vercel.json) and the dev server must send the same security headers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SECURITY_HEADERS } from '../server.js';

const vercel = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8'));
const all = Object.fromEntries(
  vercel.headers.find((h) => h.source === '/(.*)').headers.map((h) => [h.key, h.value]),
);

test('vercel.json and server.js security headers match', () => {
  const { 'Strict-Transport-Security': hsts, ...prod } = all; // HSTS is meaningless on http://localhost
  assert.match(hsts, /max-age=\d{8}/);
  assert.deepEqual({ ...SECURITY_HEADERS }, prod);
});
