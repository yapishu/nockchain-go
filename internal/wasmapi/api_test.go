package wasmapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONBoundary(t *testing.T) {
	for _, request := range []string{`{}`, `{"method":"formatNocks","nicks":1}`, `{"method":"formatNocks","nicks":"01"}`, `{"method":"formatNocks","nicks":"-1"}`, `{"method":"parseNocks","amount":"1","unknown":true}`, `{"method":"parseNocks","amount":"1"} {}`, strings.Repeat(" ", 4<<20+1)} {
		var got map[string]any
		if e := json.Unmarshal([]byte(Call(request)), &got); e != nil {
			t.Fatal(e)
		}
		if got["error"] == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if got := Call(`{"method":"formatNocks","nicks":"81920"}`); got != `{"result":"1.25"}` {
		t.Fatal(got)
	}
}
func FuzzCall(f *testing.F) {
	f.Add(`{"method":"parseNocks","amount":"1"}`)
	f.Add(`{"method":"inspect","jam":"02"}`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 65536 {
			return
		}
		if !json.Valid([]byte(Call(s))) {
			t.Fatal("response is not JSON")
		}
	})
}
