/** Start one Go runtime per JavaScript realm. Load matching wasm_exec.js first. */
export async function loadNockchain(source = new URL('./nockchain.wasm', import.meta.url)) {
  if (typeof globalThis.Go !== 'function') throw new Error('Load wasm_exec.js before nockchain.mjs');
  if (globalThis.nockchainGoCall || globalThis.nockchainGoStarting) throw new Error('Nockchain is already loaded in this realm');
  globalThis.nockchainGoStarting = true;
  try {
    const go = new globalThis.Go();
    let bytes = source;
    if (!(source instanceof Uint8Array) && !(source instanceof ArrayBuffer) && !(source instanceof WebAssembly.Module)) {
      const response = await fetch(source);
      if (!response.ok) throw new Error(`Unable to load WebAssembly (${response.status})`);
      bytes = await response.arrayBuffer();
    }
    const compiled = await WebAssembly.instantiate(bytes, go.importObject);
    const instance = compiled instanceof WebAssembly.Instance ? compiled : compiled.instance;
    const running = go.run(instance);
    if (typeof globalThis.nockchainGoCall !== 'function') {
      await running;
      throw new Error('Nockchain WebAssembly did not initialize');
    }
    let runtimeError;
    running.catch(error => { runtimeError = error; });
    const bridge = globalThis.nockchainGoCall;
    return Object.freeze({
      /** Calls are synchronous. Use a Worker for signing or batches. */
      call(method, parameters = {}) {
        if (runtimeError) throw runtimeError;
        const response = JSON.parse(bridge(JSON.stringify({ ...parameters, method })));
        if (response.error) throw new Error(response.error);
        return response.result;
      },
    });
  } finally {
    delete globalThis.nockchainGoStarting;
  }
}
