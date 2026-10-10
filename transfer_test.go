package nockchain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type transactionVector struct {
	Seed                                   string
	Plans                                  []SpendPlanV1
	Jam, ID                                string
	MinimumFee, Fee, ExternalTotal, Change uint64
}

func transactionVectors(t *testing.T) []transactionVector {
	t.Helper()
	b, e := os.ReadFile("testdata/reference.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures struct{ Transactions []transactionVector }
	if e = json.Unmarshal(b, &fixtures); e != nil {
		t.Fatal(e)
	}
	if len(fixtures.Transactions) != 4 {
		t.Fatal("missing transaction fixtures")
	}
	return fixtures.Transactions
}
func TestReferenceTransfers(t *testing.T) {
	for i, v := range transactionVectors(t) {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			seed, _ := hex.DecodeString(v.Seed)
			key, e := Master(seed)
			if e != nil {
				t.Fatal(e)
			}
			tx, e := key.SignTransferV1(v.Plans)
			if e != nil {
				t.Fatal(e)
			}
			id, _ := tx.ID()
			if id.String() != v.ID {
				t.Errorf("transaction ID differs: %s", id)
			}
			jam, _ := tx.Jam()
			want, _ := hex.DecodeString(v.Jam)
			if !bytes.Equal(jam, want) {
				t.Errorf("signed jam differs (%d vs %d bytes)", len(jam), len(want))
			}
			var recipients []Digest
			for _, p := range v.Plans {
				for _, o := range p.Outputs {
					recipients = append(recipients, o.Recipient)
				}
			}
			fee, e := MinimumTransferFeeV1(len(v.Plans), recipients)
			if e != nil || fee != consensusFee(t, v.ID) {
				t.Errorf("fee %d, Hoon %d: %v", fee, consensusFee(t, v.ID), e)
			}
			noun, e := Cue(want)
			if e != nil {
				t.Fatal(e)
			}
			encoded, e := Jam(noun)
			if e != nil || !bytes.Equal(encoded, want) {
				t.Fatal("Rust transaction codec round trip differs")
			}
		})
	}
}

func TestTransferRejectsInvalidPlans(t *testing.T) {
	fixture := transactionVectors(t)[0]
	seed, _ := hex.DecodeString(fixture.Seed)
	key, _ := Master(seed)
	tests := map[string]func([]SpendPlanV1) []SpendPlanV1{
		"empty":          func(p []SpendPlanV1) []SpendPlanV1 { return nil },
		"duplicate note": func(p []SpendPlanV1) []SpendPlanV1 { return append(p, p[0]) },
		"wrong lock":     func(p []SpendPlanV1) []SpendPlanV1 { p[0].LockRoot = Digest{}; return p },
		"nonfield name":  func(p []SpendPlanV1) []SpendPlanV1 { p[0].Note.Name.First[0] = Prime; return p },
		"balance":        func(p []SpendPlanV1) []SpendPlanV1 { p[0].Note.Nicks++; return p },
		"low fee":        func(p []SpendPlanV1) []SpendPlanV1 { p[0].Note.Nicks -= p[0].Fee; p[0].Fee = 0; return p },
		"zero output":    func(p []SpendPlanV1) []SpendPlanV1 { p[0].Outputs[0].Nicks = 0; return p },
		"duplicate recipient": func(p []SpendPlanV1) []SpendPlanV1 {
			p[0].Outputs = append(p[0].Outputs, p[0].Outputs[0])
			p[0].Note.Nicks += p[0].Outputs[0].Nicks
			return p
		},
		"nonfield recipient": func(p []SpendPlanV1) []SpendPlanV1 { p[0].Outputs[0].Recipient[0] = Prime; return p },
		"overflow":           func(p []SpendPlanV1) []SpendPlanV1 { p[0].Outputs[0].Nicks = Prime - 1; return p },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := append([]SpendPlanV1(nil), fixture.Plans...)
			p[0].Outputs = append([]PaymentV1(nil), p[0].Outputs...)
			if _, e := key.SignTransferV1(mutate(p)); e == nil {
				t.Fatal("invalid transfer accepted")
			}
		})
	}
	if _, e := key.Public().SignTransferV1(fixture.Plans); e == nil {
		t.Fatal("public signer accepted")
	}
	if _, e := (TransferV1{}).ID(); e == nil {
		t.Fatal("zero transfer accepted")
	}
	if _, e := (TransferV1{}).Noun(); e == nil {
		t.Fatal("zero noun accepted")
	}
	if _, e := (TransferV1{}).Jam(); e == nil {
		t.Fatal("zero jam accepted")
	}
	// Input ordering must not affect the canonical tree or signatures.
	multi := transactionVectors(t)[3]
	a, e := key.SignTransferV1(multi.Plans)
	if e != nil {
		t.Fatal(e)
	}
	p := multi.Plans
	p[0], p[2] = p[2], p[0]
	for i := range p {
		for l, r := 0, len(p[i].Outputs)-1; l < r; l, r = l+1, r-1 {
			p[i].Outputs[l], p[i].Outputs[r] = p[i].Outputs[r], p[i].Outputs[l]
		}
	}
	b, e := key.SignTransferV1(p)
	if e != nil {
		t.Fatal(e)
	}
	aj, _ := a.Jam()
	bj, _ := b.Jam()
	if !bytes.Equal(aj, bj) {
		t.Fatal("input/output ordering changes transaction")
	}
}
