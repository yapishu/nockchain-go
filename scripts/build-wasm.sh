#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist/wasm
GOOS=js GOARCH=wasm go build -trimpath -o dist/wasm/nockchain.wasm ./cmd/nockchain-wasm
# Go's runtime location is selected from the compiler actually in use.
runtime_dir="$(go env GOROOT)/lib/wasm"
if [ ! -f "$runtime_dir/wasm_exec.js" ]; then runtime_dir="$(go env GOROOT)/misc/wasm"; fi
install -m 644 "$runtime_dir/wasm_exec.js" dist/wasm/wasm_exec.js
install -m 644 web/nockchain.mjs web/nockchain.d.mts web/index.html dist/wasm/
install -m 644 web/README.md dist/wasm/README.md
mkdir -p dist/wasm/licenses
install -m 644 LICENSE dist/wasm/licenses/nockchain-go.txt
install -m 644 "$(go env GOROOT)/LICENSE" dist/wasm/licenses/go.txt
for module in github.com/tyler-smith/go-bip39 golang.org/x/crypto golang.org/x/text; do
  module_dir="$(go list -m -f '{{.Dir}}' "$module")"
  license_name="$(printf '%s' "$module" | tr / _)"
  install -m 644 "$module_dir/LICENSE" "dist/wasm/licenses/$license_name.txt"
done
printf 'Built dist/wasm using %s\n' "$(go version)"
