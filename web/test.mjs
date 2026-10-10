import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
await import('../dist/wasm/wasm_exec.js');
const { loadNockchain } = await import('../dist/wasm/nockchain.mjs');
const bytes = await readFile(new URL('../dist/wasm/nockchain.wasm', import.meta.url));
const api = await loadNockchain(bytes);
const fixture = JSON.parse(await readFile(new URL('../testdata/reference.json', import.meta.url), 'utf8'));
const consensus = JSON.parse(await readFile(new URL('../testdata/consensus.json', import.meta.url), 'utf8'));
const feeFor = id => String(consensus.transactions.find(v => v.id === id).minimumFee);
const key = fixture.keys.find(k => k.path.length === 0);
const child = fixture.keys.find(k => k.seed === key.seed && k.path.length === 1 && k.path[0] === 5);
assert.deepEqual(api.call('receive', { zpub: key.zpub, index: 5 }), { index: 5, address: child.address, lockRoot: child.lock });
assert.equal(api.call('derivePublic', { zpub: key.zpub, path: 'm/5' }).zpub, child.zpub);
assert.equal(api.call('parseNocks', { amount: '1.25' }), '81920');
assert.equal(api.call('formatNocks', { nicks: '81920' }), '1.25');
assert.equal(api.call('parseNocks', { amount: api.call('formatNocks', { nicks: '18446744073709551615' }) }), '18446744073709551615');
assert.throws(() => api.call('formatNocks', { nicks: 9007199254740992 }), /invalid request/);
assert.throws(() => api.call('formatNocks', { nicks: '01' }), /canonical decimal/);
assert.throws(() => api.call('receive', { zpub: key.zprv, index: 0 }));
assert.throws(() => api.call('inspect', { jam: '00' }));
assert.throws(() => api.call('unknown'));
for (const v of fixture.transactions) {
  const review = api.call('inspect', { jam: v.jam });
  assert.equal(review.id, v.id);
  assert.equal(review.feeNicks, String(v.fee));
  assert.equal(review.minimumFeeNicks, feeFor(v.id));
  assert.equal(api.call('verifySignatures', { jam: v.jam }), true);
}
// Digest values cross the bridge as Base58 strings, never rounded JSON numbers.
for (const v of fixture.multisig) {
  const review = api.call('inspect', { jam: v.jam });
  const lock = { threshold: review.spends[0].lock.threshold, keys: review.spends[0].lock.keys, timelock: review.spends[0].lock.timelock };
  const note = { first: review.spends[0].first, last: review.spends[0].last, originPage: String(v.note.originPage), nicks: String(v.note.nicks), noteDataJam: fixture.nouns.find(n => n.noun === 0).jam };
  assert.equal(api.call('lock', { inputLocks: [lock] }).first, note.first);
  assert.equal(api.call('minimumFee', { inputLocks: [lock], outputLocks: [lock] }), feeFor(v.id));
  const plan = api.call('prepareTransaction', { plans: [{ note, lock, fee: String(v.fee), outputs: [{ lock, nicks: String(v.gift) }] }] });
  assert.throws(() => api.call('verifySignatures', { jam: plan.jam }), /signature/);
  const signerA = fixture.keys.find(k => k.seed === v.seeds[0] && k.path.length === 0);
  const a = api.call('signTransaction', { jam: plan.jam, key: signerA.zprv });
  assert.equal(a.jam, v.partialJam);
  // The Rust fixture supplies the second signature independently.
  const merged = api.call('mergeSignatures', { jam: a.jam, otherJam: v.jam });
  assert.equal(merged.jam, v.jam);
  assert.equal(api.call('verifySignatures', { jam: merged.jam }), true);
  assert.equal(api.call('validateInputs', { jam: merged.jam, notes: [note], height: '105' }), true);
  if (v.timed) assert.throws(() => api.call('validateInputs', { jam: merged.jam, notes: [note], height: '104' }), /timelock/);
}
await assert.rejects(() => loadNockchain(bytes), /already loaded/);
console.log('WebAssembly: derivation, exact amounts, Rust transactions, multisig, timelocks, signing, merging and errors pass.');
process.exit(0);
