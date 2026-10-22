// The example report shown before any scan must be exactly what analyze()
// produces for the snapshot described next to SAMPLE_REPORT in assets/app.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyze } from '../api/_lib/analyze.js';

const SNAPSHOT = {
  input: 'example.com',
  requestedUrl: 'https://example.com/',
  finalUrl: 'https://example.com/',
  status: 200,
  redirects: [],
  redirectStop: null,
  headers: {
    server: 'nginx/1.18.0',
    'x-powered-by': 'PHP/7.4.3',
    'cf-ray': '8d2f1c3b9a7e4f21-FRA',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-content-type-options': 'nosniff',
    'content-type': 'text/html; charset=UTF-8',
  },
  setCookies: ['PHPSESSID=3f9a1c7e2b; path=/; Secure; HttpOnly', 'theme=light; path=/; Secure; SameSite=Lax'],
  httpProbe: { result: 'redirects-to-https', status: 301, location: 'https://example.com/' },
  tls: {
    valid: true,
    error: null,
    validFrom: '2026-10-15T00:00:00.000Z',
    validTo: '2027-01-13T00:00:00.000Z',
    daysLeft: 84,
    issuer: "Let's Encrypt",
    protocol: 'TLSv1.3',
  },
  timingMs: 312,
  scannedAt: '2026-10-22T15:20:00.000Z',
};

test('SAMPLE_REPORT in assets/app.js matches analyze()', () => {
  const src = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
  const m = /var SAMPLE_REPORT = (\{[\s\S]*?\n {2}\});/.exec(src);
  assert.ok(m, 'SAMPLE_REPORT literal found');
  const sample = JSON.parse(m[1]);
  const fresh = analyze(SNAPSHOT);
  assert.deepEqual(
    { score: sample.score, level: sample.level, counts: sample.counts, findings: sample.findings },
    { score: fresh.score, level: fresh.level, counts: fresh.counts, findings: fresh.findings },
  );
});
