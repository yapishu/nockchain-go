package nockchain

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type consensusVector struct {
	ID           string
	MinimumFee   uint64
	ParentHashes []Digest
}

func consensusVectors(t *testing.T) map[string]consensusVector {
	t.Helper()
	b, e := os.ReadFile("testdata/consensus.json")
	if e != nil {
		t.Fatal(e)
	}
	var corpus struct {
		Commit       string
		Transactions []consensusVector
	}
	if e = json.Unmarshal(b, &corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.Commit != "1eac02083a053c104b6a1299e80a8a51447017dc" || len(corpus.Transactions) != 6 {
		t.Fatal("unexpected Hoon oracle corpus")
	}
	out := map[string]consensusVector{}
	for _, v := range corpus.Transactions {
		out[v.ID] = v
	}
	return out
}
func consensusFee(t *testing.T, id string) uint64 {
	t.Helper()
	v, ok := consensusVectors(t)[id]
	if !ok {
		t.Fatal("missing Hoon oracle transaction")
	}
	return v.MinimumFee
}
func TestCanonicalHoonOracle(t *testing.T) {
	oracle := consensusVectors(t)
	type input struct {
		jam, id string
		notes   []NoteV1
	}
	var cases []input
	for _, v := range transactionVectors(t) {
		c := input{jam: v.Jam, id: v.ID}
		for _, p := range v.Plans {
			c.notes = append(c.notes, p.Note)
		}
		cases = append(cases, c)
	}
	for _, v := range multisigVectors(t) {
		cases = append(cases, input{v.Jam, v.ID, []NoteV1{v.Note}})
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			expected, ok := oracle[c.id]
			if !ok {
				t.Fatal("missing consensus vector")
			}
			b, _ := hex.DecodeString(c.jam)
			tx, e := ParseTransactionV1(b)
			if e != nil {
				t.Fatal(e)
			}
			summary, _ := tx.Summary()
			if summary.ID.String() != expected.ID || summary.MinimumFeeNicks != expected.MinimumFee {
				t.Fatal("Hoon ID/fee mismatch")
			}
			if len(c.notes) != len(expected.ParentHashes) {
				t.Fatal("Hoon input count mismatch")
			}
			for i, n := range c.notes {
				h, e := n.Hash()
				if e != nil || h != expected.ParentHashes[i] {
					t.Fatal("Hoon input hash mismatch", e)
				}
			}
			if e = tx.VerifySignatures(); e != nil {
				t.Fatal(e)
			}
			if e = tx.ValidateInputs(c.notes, 105); e != nil {
				t.Fatal(e)
			}
		})
	}
}
