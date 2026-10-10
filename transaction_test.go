package nockchain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type multisigVector struct {
	Seeds                 []string
	Keys                  []Digest
	Timed                 bool
	Root, Parent          Digest
	Note                  NoteV1
	Fee, Gift, MinimumFee uint64
	Jam, PartialJam, ID   string
}

func multisigVectors(t *testing.T) []multisigVector {
	t.Helper()
	b, e := os.ReadFile("testdata/reference.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct{ Multisig []multisigVector }
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if len(v.Multisig) != 2 {
		t.Fatal("missing multisig fixtures")
	}
	return v.Multisig
}
func testKey(t *testing.T, s string) ExtendedKey {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	k, e := Master(b)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func bound(v uint64) *uint64 { return &v }
func vectorLock(t *testing.T, v multisigVector) LockV1 {
	t.Helper()
	var tm *TimelockV1
	if v.Timed {
		tm = &TimelockV1{HeightRange{bound(5), bound(50)}, HeightRange{bound(100), bound(200)}}
	}
	l, e := NewPKHLockV1(2, v.Keys, tm)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func TestReferenceTransactionInspection(t *testing.T) {
	for _, v := range transactionVectors(t) {
		b, _ := hex.DecodeString(v.Jam)
		tx, e := ParseTransactionV1(b)
		if e != nil {
			t.Fatal(e)
		}
		s, e := tx.Summary()
		if e != nil || s.ID.String() != v.ID || s.FeeNicks != v.Fee || s.MinimumFeeNicks != consensusFee(t, v.ID) {
			t.Fatalf("incorrect review: %+v %v", s, e)
		}
		if e = tx.VerifySignatures(); e != nil {
			t.Fatal(e)
		}
		notes := []NoteV1{}
		for _, p := range v.Plans {
			notes = append(notes, p.Note)
		}
		if e = tx.ValidateInputs(notes, 200); e != nil {
			t.Fatal(e)
		}
		got, _ := tx.Jam()
		if !bytes.Equal(b, got) {
			t.Fatal("parse changed bytes")
		}
		for _, sp := range s.Spends {
			for _, out := range sp.Outputs {
				if _, e := out.Lock(); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
}
func TestReferenceMultisigTimelocks(t *testing.T) {
	for _, v := range multisigVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			l := vectorLock(t, v)
			if l.root != v.Root {
				t.Fatal("Rust lock root differs")
			}
			parent, e := v.Note.Hash()
			if e != nil || parent != v.Parent {
				t.Fatal("Rust note parent differs", e)
			}
			tx, e := PrepareTransactionV1([]LockedSpendPlanV1{{Note: v.Note, Lock: l, Fee: v.Fee, Outputs: []LockedPaymentV1{{l, v.Gift}}}})
			if e != nil {
				t.Fatal(e)
			}
			if e = tx.VerifySignatures(); e == nil {
				t.Fatal("unsigned accepted")
			}
			a, e := tx.Sign(testKey(t, v.Seeds[0]))
			if e != nil {
				t.Fatal(e)
			}
			aj, _ := a.Jam()
			want, _ := hex.DecodeString(v.PartialJam)
			if !bytes.Equal(aj, want) {
				t.Fatal("Rust partial bytes differ")
			}
			if e = a.VerifySignatures(); e == nil {
				t.Fatal("partial accepted")
			}
			b, e := tx.Sign(testKey(t, v.Seeds[1]))
			if e != nil {
				t.Fatal(e)
			}
			signed, e := a.MergeSignatures(b)
			if e != nil {
				t.Fatal(e)
			}
			wire, _ := signed.Jam()
			want, _ = hex.DecodeString(v.Jam)
			if !bytes.Equal(wire, want) {
				t.Fatal("Rust signed bytes differ")
			}
			sum, _ := signed.Summary()
			if sum.ID.String() != v.ID || sum.MinimumFeeNicks != consensusFee(t, v.ID) {
				t.Fatalf("Hoon id/fee differs %+v", sum)
			}
			if e = signed.VerifySignatures(); e != nil {
				t.Fatal(e)
			}
			parsed, e := ParseTransactionV1(wire)
			if e != nil {
				t.Fatal(e)
			}
			if e = parsed.VerifySignatures(); e != nil {
				t.Fatal(e)
			}
			if e = parsed.ValidateInputs([]NoteV1{v.Note}, 105); e != nil {
				t.Fatal(e)
			}
			if v.Timed {
				for _, h := range []uint64{99, 100, 104, 151, 201} {
					if e = parsed.ValidateInputs([]NoteV1{v.Note}, h); e == nil {
						t.Fatalf("height %d accepted", h)
					}
				}
				for _, h := range []uint64{105, 150} {
					if e = parsed.ValidateInputs([]NoteV1{v.Note}, h); e != nil {
						t.Fatal(e)
					}
				}
			}
			tampered := v.Note
			tampered.OriginPage++
			if e = parsed.ValidateInputs([]NoteV1{tampered}, 110); e == nil {
				t.Fatal("wrong parent accepted")
			}
			tampered = v.Note
			tampered.Nicks++
			if e = parsed.ValidateInputs([]NoteV1{tampered}, 110); e == nil {
				t.Fatal("wrong balance accepted")
			}
			if _, e = signed.Sign(testKey(t, v.Seeds[2])); e == nil {
				t.Fatal("excess signature accepted")
			}
			third, _ := tx.Sign(testKey(t, v.Seeds[2]))
			if _, e = signed.MergeSignatures(third); e == nil {
				t.Fatal("excess merge accepted")
			}
			again, e := signed.Sign(testKey(t, v.Seeds[0]))
			if e != nil {
				t.Fatal(e)
			}
			same, _ := again.Jam()
			if !bytes.Equal(same, wire) {
				t.Fatal("repeat signature changes bytes")
			}
			if len(tx.spends[0].signatures) != 0 || len(a.spends[0].signatures) != 1 {
				t.Fatal("signing mutates existing plan")
			}
			sum.Spends[0].Outputs[0].Nicks = 1
			keys := l.Keys()
			keys[0] = Digest{}
			if v.Timed {
				tm := l.Timelock()
				*tm.Relative.Min = 999
			}
			if e = signed.VerifySignatures(); e != nil {
				t.Fatal("summary mutation changes plan")
			}
		})
	}
}
func TestTransactionRejectsMalformed(t *testing.T) {
	v := transactionVectors(t)[0]
	wire, _ := hex.DecodeString(v.Jam)
	tx, e := ParseTransactionV1(wire)
	if e != nil {
		t.Fatal(e)
	}
	root, _ := parts(tx.raw, 3)
	check := func(name string, n Noun) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			b, e := Jam(n)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = ParseTransactionV1(b); e == nil {
				t.Fatal("malformed transaction accepted")
			}
		})
	}
	check("wrong id", Tuple(root[0], digestNoun(Digest{}), root[2]))
	check("version", Tuple(Noun{atom: 2}, root[1], root[2]))
	check("empty", Tuple(root[0], root[1], Noun{}))
	check("bad shape", Noun{})
	s := tx.spends[0].clone()
	s.fee++
	changed, _ := assembleTransaction([]transactionSpend{s})
	b, _ := changed.Jam()
	parsed, e := ParseTransactionV1(b)
	if e != nil {
		t.Fatal(e)
	}
	if e = parsed.VerifySignatures(); e == nil {
		t.Fatal("fee tampering accepted")
	}
	if _, e = tx.MergeSignatures(changed); e == nil {
		t.Fatal("different plans merged")
	}
	for k, v := range s.signatures {
		v.signature.Challenge[0] ^= 1
		s.signatures[k] = v
	}
	changed, _ = assembleTransaction([]transactionSpend{s})
	if _, e = changed.Sign(testKey(t, v.Seed)); e == nil {
		t.Fatal("signed over bad signature")
	}
	// A valid ID cannot make duplicate tree entries canonical.
	tree, _ := parts(root[2], 3)
	duplicate := Tuple(tree[0], root[2], tree[2])
	check("duplicate map", Tuple(root[0], root[1], duplicate))
	deep := Noun{}
	for i := 0; i < 300; i++ {
		deep = Cell(Noun{}, deep)
	}
	check("depth", deep)
	if _, e = (TransactionV1{}).ID(); e == nil {
		t.Fatal("empty ID")
	}
	if _, e = (TransactionV1{}).Jam(); e == nil {
		t.Fatal("empty jam")
	}
	if e = (TransactionV1{}).VerifySignatures(); e == nil {
		t.Fatal("empty verification")
	}
}
func TestLockValidation(t *testing.T) {
	k := Digest{1, 2, 3, 4, 5}
	for _, m := range []int{0, 2} {
		if _, e := NewPKHLockV1(m, []Digest{k}, nil); e == nil {
			t.Fatal("threshold accepted")
		}
	}
	if _, e := NewPKHLockV1(1, []Digest{k, k}, nil); e == nil {
		t.Fatal("duplicate keys")
	}
	if _, e := NewPKHLockV1(1, []Digest{k}, &TimelockV1{Relative: HeightRange{bound(9), bound(1)}}); e == nil {
		t.Fatal("inverted range")
	}
	tm := TimelockV1{Absolute: HeightRange{bound(10), bound(20)}}
	if tm.Allows(9, 0) || tm.Allows(21, 0) || tm.Allows(15, 16) || !tm.Allows(10, 0) || !tm.Allows(20, 0) {
		t.Fatal("inclusive bounds")
	}
}
func TestSelectionAndRemainderFees(t *testing.T) {
	v := transactionVectors(t)[0]
	key := testKey(t, v.Seed)
	p := v.Plans[0]
	recipient := p.Outputs[0].Recipient
	payment := []Payment{{recipient.String(), "1"}}
	minimum, _ := MinimumTransferFeeV1(1, []Digest{recipient})
	n := UnspentNote{p.Note, p.LockRoot}
	n.Note.Nicks = minimum + 65536 + 1
	plan, e := SelectTransfer(key.Public(), []UnspentNote{n}, payment, TransferOptions{})
	if e != nil {
		t.Fatal(e)
	}
	s := plan.Summary()
	if s.ChangeNicks != 0 || s.FeeNicks != minimum+1 {
		t.Fatal("remainder not assigned to fee")
	}
	if _, e = plan.Sign(key); e != nil {
		t.Fatal(e)
	}
	big := n
	big.Note.Name.Last[0]++
	big.Note.Nicks = 10_000_000
	small := n
	small.Note.Name.Last[0] += 2
	small.Note.Nicks = 100
	plan, e = SelectTransfer(key.Public(), []UnspentNote{small, n, big}, payment, TransferOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.Notes()) != 1 || plan.Notes()[0].Name != big.Note.Name {
		t.Fatal("largest selection")
	}
	copyNotes := plan.Notes()
	copyNotes[0].Nicks = 0
	if plan.Notes()[0].Nicks == 0 {
		t.Fatal("notes alias")
	}
	if _, e = SelectTransfer(key, []UnspentNote{big, big}, payment, TransferOptions{}); e == nil {
		t.Fatal("duplicate selection")
	}
	// Every input retains at least one nick for a required output seed.
	plan, e = PrepareTransfer(key, []UnspentNote{small, big}, payment, TransferOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.plans[0].Outputs) == 0 {
		t.Fatal("input has no output seed")
	}
	if _, e = plan.Sign(key); e != nil {
		t.Fatal(e)
	}
}
func FuzzParseTransactionV1(f *testing.F) {
	b, e := os.ReadFile("testdata/reference.json")
	if e != nil {
		f.Fatal(e)
	}
	var fixtures struct {
		Transactions []transactionVector
		Multisig     []multisigVector
	}
	if e = json.Unmarshal(b, &fixtures); e != nil {
		f.Fatal(e)
	}
	for _, v := range fixtures.Transactions {
		b, _ := hex.DecodeString(v.Jam)
		f.Add(b)
	}
	for _, v := range fixtures.Multisig {
		b, _ := hex.DecodeString(v.Jam)
		f.Add(b)
	}
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			return
		}
		tx, e := ParseTransactionV1(b)
		if e != nil {
			return
		}
		out, e := tx.Jam()
		if e != nil {
			t.Fatal(e)
		}
		again, e := ParseTransactionV1(out)
		if e != nil || again.id != tx.id {
			t.Fatal("unstable parse")
		}
	})
}

func TestCompleteNoteMetadataAndLockAuthentication(t *testing.T) {
	v := multisigVectors(t)[0]
	lock := vectorLock(t, v)
	note := v.Note
	note.NoteData = lock.metadata()
	emptyHash, _ := v.Note.Hash()
	fullHash, e := note.Hash()
	if e != nil || fullHash == emptyHash {
		t.Fatal("note metadata is not committed", e)
	}
	tx, e := PrepareTransactionV1([]LockedSpendPlanV1{{Note: note, Lock: lock, Fee: v.Fee, Outputs: []LockedPaymentV1{{Lock: lock, Nicks: v.Gift}}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.ValidateInputs([]NoteV1{note}, 100); e != nil {
		t.Fatal(e)
	}
	if e = tx.ValidateInputs([]NoteV1{v.Note}, 100); e == nil {
		t.Fatal("missing input metadata accepted")
	}
	wire, _ := tx.Jam()
	parsed, e := ParseTransactionV1(wire)
	if e != nil {
		t.Fatal(e)
	}
	if e = parsed.ValidateInputs([]NoteV1{note}, 100); e != nil {
		t.Fatal(e)
	}
	sum, _ := parsed.Summary()
	out := sum.Spends[0].Outputs[0]
	out.LockRoot[0] ^= 1
	if _, e = out.Lock(); e == nil {
		t.Fatal("uncommitted metadata authenticated")
	}
	bad := note
	bad.Name.First[0] ^= 1
	if _, e = PrepareTransactionV1([]LockedSpendPlanV1{{Note: bad, Lock: lock, Fee: v.Fee, Outputs: []LockedPaymentV1{{Lock: lock, Nicks: v.Gift}}}}); e == nil {
		t.Fatal("foreign lock accepted")
	}
}

func TestTransactionRejectsUnsupportedAndInvalidProofs(t *testing.T) {
	v := transactionVectors(t)[0]
	b, _ := hex.DecodeString(v.Jam)
	tx, e := ParseTransactionV1(b)
	if e != nil {
		t.Fatal(e)
	}
	root, _ := parts(tx.raw, 3)
	tree, _ := parts(root[2], 3)
	pair, _ := parts(tree[0], 2)
	spend, _ := parts(pair[1], 4)
	witness, _ := parts(spend[1], 4)
	proof, _ := parts(witness[0], 4)
	tests := map[string]Noun{
		"axis":                  Tuple(proof[0], proof[1], Noun{atom: 2}, proof[3]),
		"proof tag":             Tuple(Noun{atom: 123}, proof[1], proof[2], proof[3]),
		"root":                  Tuple(proof[0], proof[1], proof[2], Cell(digestNoun(Digest{}), Noun{})),
		"unsupported primitive": Tuple(proof[0], List(Cell(Noun{atom: 0x6e7262}, Noun{})), proof[2], proof[3]),
	}
	for name, badProof := range tests {
		t.Run(name, func(t *testing.T) {
			badWitness := Tuple(badProof, witness[1], witness[2], witness[3])
			badSpend := Tuple(spend[0], badWitness, spend[2], spend[3])
			badTree := Tuple(Cell(pair[0], badSpend), tree[1], tree[2])
			raw := Tuple(root[0], root[1], badTree)
			jam, _ := Jam(raw)
			if _, e := ParseTransactionV1(jam); e == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}

func TestConsensusRequiresOutputPerInput(t *testing.T) {
	v := multisigVectors(t)[0]
	lock := vectorLock(t, v)
	if _, e := PrepareTransactionV1([]LockedSpendPlanV1{{Note: v.Note, Lock: lock, Fee: v.Note.Nicks}}); e == nil {
		t.Fatal("fee-only input accepted")
	}
	b, _ := hex.DecodeString(v.Jam)
	tx, e := ParseTransactionV1(b)
	if e != nil {
		t.Fatal(e)
	}
	sp := tx.spends[0].clone()
	sp.seeds = nil
	sp.outputs = nil
	malformed, e := assembleTransaction([]transactionSpend{sp})
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := malformed.Jam()
	if _, e = ParseTransactionV1(wire); e == nil {
		t.Fatal("seedless wire input accepted")
	}
}

func TestConsensusMetadataFeeAndLimit(t *testing.T) {
	// One flattened metadata entry [key value ~] has three words; its tree has four.
	metadata := Tuple(Cell(Noun{atom: 1}, Noun{atom: 2}), Noun{}, Noun{})
	v := multisigVectors(t)[0]
	lock := vectorLock(t, v)
	tx := TransactionV1{spends: []transactionSpend{{lock: lock, outputs: []OutputV1{{LockRoot: v.Root, NoteData: metadata}}}}}
	got, e := tx.minimumFee()
	witnessWords := leaves(lock.proof()) + 2*35 + 3
	want := uint64(3)*(1<<14) + witnessWords*(1<<12)
	if e != nil || got != want {
		t.Fatalf("flattened fee: %d want %d: %v", got, want, e)
	}
	second := Tuple(Cell(Noun{atom: 3}, Noun{atom: 4}), Noun{}, Noun{})
	tx.spends[0].outputs = append(tx.spends[0].outputs, OutputV1{LockRoot: v.Root, NoteData: second})
	got, e = tx.minimumFee()
	if e != nil || got != want+2*(1<<14) {
		t.Fatal("merged metadata fee", got, e)
	}
	tx.spends[0].outputs = append(tx.spends[0].outputs, OutputV1{LockRoot: v.Root, NoteData: metadata})
	got, e = tx.minimumFee()
	if e != nil || got != want+2*(1<<14) {
		t.Fatal("identical metadata charged twice", got, e)
	}
	large := Noun{}
	for i := 0; i < 11; i++ {
		large = Cell(large, large)
	} // 2,048 value leaves plus key and terminator.
	tx.spends[0].outputs = []OutputV1{{LockRoot: v.Root, NoteData: Tuple(Cell(Noun{atom: 1}, large), Noun{}, Noun{})}}
	if _, e = tx.minimumFee(); e == nil {
		t.Fatal("oversized output metadata accepted")
	}
}
