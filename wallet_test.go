package nockchain

import (
	"encoding/hex"
	"testing"
)

func TestPrepareTransfer(t *testing.T) {
	fixture := transactionVectors(t)[2]
	seed, _ := hex.DecodeString(fixture.Seed)
	key, _ := Master(seed)
	notes := []UnspentNote{}
	for _, p := range fixture.Plans {
		notes = append(notes, UnspentNote{p.Note, p.LockRoot})
	}
	address := fixture.Plans[0].Outputs[0].Recipient.String()
	payments := []Payment{{address, "10"}, {address, "20"}}
	prepared, e := PrepareTransfer(key.Public(), notes, payments, TransferOptions{})
	if e != nil {
		t.Fatal(e)
	}
	summary := prepared.Summary()
	if summary.InputNicks != 16_000_000 || summary.PaymentNicks != 30*65536 || summary.InputNicks != summary.PaymentNicks+summary.FeeNicks+summary.ChangeNicks {
		t.Fatal("review totals differ")
	}
	// Caller mutations cannot change the signed payment.
	notes[0].Note.Nicks = 1
	payments[0].Amount = "999"
	summary.Payments[0].Amount = "999"
	if prepared.Summary().Payments[0].Amount != "10" {
		t.Fatal("review aliases payment state")
	}
	if _, e = prepared.Sign(key); e != nil {
		t.Fatal(e)
	}
	other, _ := Master(make([]byte, 64))
	if _, e = prepared.Sign(other); e == nil {
		t.Fatal("wrong signing key accepted")
	}
	if _, e = prepared.Sign(key.Public()); e == nil {
		t.Fatal("public signing key accepted")
	}
	if _, e = (PreparedTransfer{}).Sign(key); e == nil {
		t.Fatal("empty plan accepted")
	}
}
func TestTransferFeeAndChange(t *testing.T) {
	fixture := transactionVectors(t)[0]
	seed, _ := hex.DecodeString(fixture.Seed)
	key, _ := Master(seed)
	p := fixture.Plans[0]
	recipient := p.Outputs[0].Recipient
	payment := []Payment{{recipient.String(), "1"}}
	minimum, _ := MinimumTransferFeeV1(1, []Digest{recipient})
	note := UnspentNote{p.Note, p.LockRoot}
	note.Note.Nicks = 65536 + minimum
	plan, e := PrepareTransfer(key.Public(), []UnspentNote{note}, payment, TransferOptions{})
	if e != nil {
		t.Fatal(e)
	}
	s := plan.Summary()
	if s.ChangeNicks != 0 || s.FeeNicks != minimum {
		t.Fatal("exact payment fee differs")
	}
	if _, e = plan.Sign(key); e != nil {
		t.Fatal(e)
	}
	// A supplied change address is committed and included in the fee calculation.
	note.Note.Nicks += 2_000_000
	plan, e = PrepareTransfer(key, []UnspentNote{note}, payment, TransferOptions{ChangeAddress: recipient.String()})
	if e != nil {
		t.Fatal(e)
	}
	s = plan.Summary()
	if s.FeeNicks != minimum || s.ChangeNicks != 2_000_000 {
		t.Fatal("merged change fee differs")
	}
	if _, e = plan.Sign(key); e != nil {
		t.Fatal(e)
	}
	for name, opts := range map[string]TransferOptions{"low fee": {FeeNicks: 1}, "overspend": {FeeNicks: note.Note.Nicks}, "bad change": {ChangeAddress: "invalid"}} {
		t.Run(name, func(t *testing.T) {
			if _, e := PrepareTransfer(key, []UnspentNote{note}, payment, opts); e == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
	for _, bad := range []Payment{{recipient.String(), "0"}, {recipient.String(), "0.00000001"}, {"invalid", "1"}, {recipient.String(), "999999999"}} {
		if _, e = PrepareTransfer(key, []UnspentNote{note}, []Payment{bad}, TransferOptions{}); e == nil {
			t.Fatal("invalid payment accepted")
		}
	}
	if _, e = PrepareTransfer(key, []UnspentNote{note, note}, payment, TransferOptions{}); e == nil {
		t.Fatal("duplicate note accepted")
	}
}
func TestReceiveAddressHelper(t *testing.T) {
	key, _ := Master(make([]byte, 64))
	zpub, _ := key.Zpub()
	got, e := DeriveReceiveAddress(zpub, 42)
	if e != nil {
		t.Fatal(e)
	}
	child, _ := key.Child(42)
	address, _ := child.Address()
	lock, _ := child.LockAddress()
	if got.Address != address || got.LockRoot != lock || got.Index != 42 {
		t.Fatal("receive derivation differs")
	}
	if _, e = DeriveReceiveAddress(zpub, 1<<31); e == nil {
		t.Fatal("hardened public derivation accepted")
	}
	zprv, _ := key.Zprv()
	if _, e = DeriveReceiveAddress(zprv, 0); e == nil {
		t.Fatal("private receiving key accepted")
	}
}
