//go:build js && wasm

// nockchain-wasm exposes the package through a synchronous JSON bridge.
package main

import (
	"syscall/js"

	"github.com/yapishu/nockchain-go/internal/wasmapi"
)

func main() {
	callback := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return `{"error":"expected one JSON string"}`
		}
		return wasmapi.Call(args[0].String())
	})
	js.Global().Set("nockchainGoCall", callback)
	select {}
}
