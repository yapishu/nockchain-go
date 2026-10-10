// Decode the Hoon oracle result into a small, reviewable public fixture.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	nockchain "github.com/yapishu/nockchain-go"
)

type fixture struct {
	Source       string        `json:"source"`
	Commit       string        `json:"commit"`
	Transactions []transaction `json:"transactions"`
}
type transaction struct {
	ID           string             `json:"id"`
	MinimumFee   uint64             `json:"minimumFee"`
	ParentHashes []nockchain.Digest `json:"parentHashes"`
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func tuple(n nockchain.Noun, count int) []nockchain.Noun {
	out := make([]nockchain.Noun, 0, count)
	for i := 1; i < count; i++ {
		h, t, ok := n.AsCell()
		if !ok {
			fail(fmt.Errorf("invalid oracle tuple"))
		}
		out = append(out, h)
		n = t
	}
	return append(out, n)
}
func atom(n nockchain.Noun) uint64 {
	v, ok := n.AsAtom()
	if !ok {
		fail(fmt.Errorf("invalid oracle atom"))
	}
	return v
}
func digest(n nockchain.Noun) nockchain.Digest {
	p := tuple(n, 5)
	var out nockchain.Digest
	for i, v := range p {
		out[i] = atom(v)
	}
	return out
}
func list(n nockchain.Noun) []nockchain.Noun {
	out := []nockchain.Noun{}
	for {
		if a, ok := n.AsAtom(); ok {
			if a != 0 {
				fail(fmt.Errorf("invalid oracle list terminator"))
			}
			return out
		}
		h, t, _ := n.AsCell()
		out = append(out, h)
		n = t
	}
}
func main() {
	if len(os.Args) != 3 {
		fail(fmt.Errorf("usage: decode.go ORACLE_JAM NOCKCHAIN_COMMIT"))
	}
	b, e := os.ReadFile(os.Args[1])
	fail(e)
	// The Hoon CLI writes jam atoms as whole machine words.
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	noun, e := nockchain.Cue(b)
	fail(e)
	out := fixture{Source: "https://github.com/zorp-corp/nockchain", Commit: os.Args[2]}
	for _, n := range list(noun) {
		p := tuple(n, 4)
		if atom(p[2]) != 0 {
			fail(fmt.Errorf("Hoon rejects a fixture transaction"))
		}
		v := transaction{ID: digest(p[0]).String(), MinimumFee: atom(p[1])}
		for _, input := range list(p[3]) {
			q := tuple(input, 4)
			for _, check := range q[1:] {
				if atom(check) != 0 {
					fail(fmt.Errorf("Hoon rejects a fixture input"))
				}
			}
			v.ParentHashes = append(v.ParentHashes, digest(q[0]))
		}
		out.Transactions = append(out.Transactions, v)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	fail(encoder.Encode(out))
}
