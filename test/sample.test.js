// The example report shown before any scan must be exactly what analyze()
// produces for test/fixtures/example-report.json. Fix drift with
// `node scripts/update-sample.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyze } from '../api/_lib/analyze.js';

test('SAMPLE_REPORT in assets/app.js matches analyze()', () => {
  const snapshot = JSON.parse(readFileSync(new URL('./fixtures/example-report.json', import.meta.url), 'utf8'));
  const src = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
  const m = /var SAMPLE_REPORT = (\{[\s\S]*?\n {2}\});/.exec(src);
  assert.ok(m, 'SAMPLE_REPORT literal found');
  const sample = JSON.parse(m[1]);
  const fresh = analyze(snapshot);
  assert.deepEqual(
    { score: sample.score, level: sample.level, counts: sample.counts, findings: sample.findings },
    { score: fresh.score, level: fresh.level, counts: fresh.counts, findings: fresh.findings },
  );
});
