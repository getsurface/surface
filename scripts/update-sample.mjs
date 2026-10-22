// Regenerates SAMPLE_REPORT in assets/app.js from test/fixtures/example-report.json.
// Run after changing rules: `node scripts/update-sample.mjs`. test/sample.test.js
// fails until the two match.
import { readFileSync, writeFileSync } from 'node:fs';
import { analyze } from '../api/_lib/analyze.js';

const root = new URL('../', import.meta.url);
const snapshot = JSON.parse(readFileSync(new URL('test/fixtures/example-report.json', root), 'utf8'));
const report = analyze(snapshot);
const target = {
  input: 'example.com',
  url: 'https://example.com/',
  host: 'example.com',
  status: 200,
  timingMs: 312,
  redirects: 0,
  scannedAt: '2026-10-22T15:20:00.000Z',
};
const literal = JSON.stringify(
  { target, score: report.score, level: report.level, counts: report.counts, findings: report.findings },
  null,
  2,
)
  .split('\n')
  .map((line, i) => (i === 0 ? `  var SAMPLE_REPORT = ${line}` : `  ${line}`));
literal[literal.length - 1] += ';';

const file = new URL('assets/app.js', root);
const lines = readFileSync(file, 'utf8').split('\n');
const start = lines.findIndex((l) => l.startsWith('  var SAMPLE_REPORT = {'));
let end = start;
while (lines[end] !== '  };') end++;
lines.splice(start, end - start + 1, ...literal);
writeFileSync(file, lines.join('\n'));
console.log(`SAMPLE_REPORT: score ${report.score} (${report.level}), ${report.findings.length} findings`);
