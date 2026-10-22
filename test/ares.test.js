import { test } from 'node:test';
import assert from 'node:assert/strict';
import { aresResolve } from '../api/_lib/guard.js';

const fake = (a4, a6) => ({
  resolve4: (h, cb) => setImmediate(() => (a4 instanceof Error ? cb(a4) : cb(null, a4))),
  resolve6: (h, cb) => setImmediate(() => (a6 instanceof Error ? cb(a6) : cb(null, a6))),
});
const run = (r) => new Promise((res) => aresResolve('example.com', {}, (e, l) => res({ e, l }), r));
const err = (code) => Object.assign(new Error(code), { code });

test('aresResolve: production resolver success path', async () => {
  assert.deepEqual((await run(fake(['93.184.216.34'], ['2606:2800::1']))).l,
    [{ address: '93.184.216.34', family: 4 }, { address: '2606:2800::1', family: 6 }].sort(() => 0));
  assert.deepEqual((await run(fake(['93.184.216.34'], err('ENODATA')))).l, [{ address: '93.184.216.34', family: 4 }]);
  assert.equal((await run(fake(err('ETIMEOUT'), err('ETIMEOUT')))).e.code, 'EAI_AGAIN');
  assert.equal((await run(fake(err('ENOTFOUND'), err('ENODATA')))).e.code, 'ENOTFOUND');
});
