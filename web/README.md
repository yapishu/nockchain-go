# WebAssembly

Build the Go package into an executable `js/wasm` module with a typed JavaScript
wrapper. The adapter covers public derivation, exact amounts, lock construction,
fee estimation, transaction preparation, inspection, partial signing, signature
merging, and input validation.

## Build and run

```sh
./scripts/build-wasm.sh
node web/test.mjs
python3 -m http.server 8080 --directory dist/wasm
```

Open `http://localhost:8080` for the public-key receiving example. The build emits:

| File | Purpose |
| --- | --- |
| `nockchain.wasm` | Compiled Go executable |
| `wasm_exec.js` | Runtime support from the same Go toolchain |
| `nockchain.mjs` | ES module loader and API wrapper |
| `nockchain.d.mts` | TypeScript API declarations |
| `index.html` | Browser receiving example |
| `licenses/` | Library, Go runtime and compiled dependency licenses |

The compiler and `wasm_exec.js` must match. The build script selects the runtime
from the compiler in use, following the [Go WebAssembly documentation](https://go.dev/wiki/WebAssembly).
Generated files live in ignored `dist/wasm/`. Release archives include these files.

## Browser

```html
<script src="./wasm_exec.js"></script>
<script type="module">
  import { loadNockchain } from './nockchain.mjs';
  const nockchain = await loadNockchain();
  const address = nockchain.call('receive', { zpub: publicBranch, index: 42 });
</script>
```

Serve the files over HTTP, with `application/wasm` for the module. The loader also
accepts a URL, `Uint8Array`, `ArrayBuffer`, or compiled `WebAssembly.Module`. It
starts one Go runtime per JavaScript realm. For expensive operations, load it in
a Worker and terminate the Worker when done; calls are synchronous.

The adapter does not fetch chain data, persist keys, or broadcast transactions.
The loader's only request fetches the module. The example accepts public keys
only and does not use local storage or third-party resources.

## Node.js

```js
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
await import('./wasm_exec.js');
const { loadNockchain } = await import('./nockchain.mjs');
const nockchain = await loadNockchain(await readFile('./nockchain.wasm'));
const nicks = nockchain.call('parseNocks', { amount: '1.25' }); // '81920'
```

Use a maintained Node.js release with WebAssembly and Web Crypto support. The
integration test runs the actual compiled module against the Rust wire fixtures and canonical Hoon fee oracle.

## Values and methods

Amounts and heights use **canonical decimal strings**; JavaScript numbers cannot
represent all uint64 values exactly. Digests use Base58 strings. Jam bytes use
hex strings. Only bounded counts such as an index or signature threshold use
JavaScript numbers. Returned amounts retain string representation.

`call(method, parameters)` returns the result or throws an `Error`. It accepts
only the documented fields. See [nockchain.d.mts](nockchain.d.mts) for complete types.

| Method | Parameters | Result |
| --- | --- | --- |
| `receive` | `zpub`, `index` | Address and lock root |
| `derivePublic` | `zpub`, `path` | Derived public key, address and lock root |
| `parseNocks` | `amount` | Exact nicks string |
| `formatNocks` | `nicks` | Exact NOCK string |
| `lock` | `inputLocks: [lock]` | Root, first note-name component, policy |
| `minimumFee` | `inputLocks`, `outputLocks` | Minimum nicks string |
| `prepareTransaction` | `plans` | Unsigned jam and review |
| `inspect` | `jam` | ID, spends, outputs, fees and signer review |
| `verifySignatures` | `jam` | `true`, or an error |
| `signTransaction` | `jam`, `key` (zprv) | Partially or fully signed jam and review |
| `mergeSignatures` | `jam`, `otherJam` | Combined jam and review |
| `validateInputs` | `jam`, `notes`, `height` | `true`, or an error |

A lock is `{ threshold: 2, keys: [alicePKH, bobPKH, carolPKH], timelock: null }`.
Optional timelocks have `relative` and `absolute` ranges, each with `min` and `max`
strings or null. A complete input note supplies `originPage`, `first`, `last`,
`noteDataJam`, and `nicks`. Even empty metadata is explicit: its jam is `"02"`.
Never omit stored metadata when calculating input commitments.

```js
const unsigned = nockchain.call('prepareTransaction', {
  plans: [{
    note: verifiedNote,
    lock: inputLock,
    fee: '2000000',
    outputs: [{ lock: recipientLock, nicks: '8000000' }],
  }],
});
// Review unsigned.summary before accessing a spending key.
const partial = nockchain.call('signTransaction', { jam: unsigned.jam, key: privateKey });
const combined = nockchain.call('mergeSignatures', { jam: partial.jam, otherJam: cosignerJam });
nockchain.call('verifySignatures', { jam: combined.jam });
nockchain.call('validateInputs', { jam: combined.jam, notes: [verifiedNote], height: '150' });
```

Successful parsing does not imply valid signatures, satisfied timelocks, unspent
inputs, or finality. All Go transaction scope and limits also apply here. Adapter
requests are limited to 4 MiB and transaction hex strings to 2 MiB.

Signing remains variable-time in WebAssembly. Use controlled offline tooling;
loading spending keys into an untrusted page is unsafe. The adapter returns no
private keys, but JavaScript and Go may retain copies of a supplied key in memory.
