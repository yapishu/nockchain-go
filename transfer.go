package nockchain

import (
	"errors"
)

// NoteName identifies a V1 input note by its two digests.
type NoteName struct{ First, Last Digest }

func (n NoteName) noun() Noun { return List(digestNoun(n.First), digestNoun(n.Last)) }

// Hash returns the note-name commitment.
func (n NoteName) Hash() (Digest, error) {
	if !n.First.Valid() || !n.Last.Valid() {
		return Digest{}, errors.New("invalid note name")
	}
	return hashCell(n.First, hashCell(n.Last, hashAtom(0))), nil
}

// PaymentV1 pays nicks to a single-signature public-key hash. Change is explicit.
type PaymentV1 struct {
	Recipient Digest
	Nicks     uint64
}

// SpendPlanV1 consumes one plain single-signature note. Note and LockRoot must
// come from verified chain state. Every nick must be assigned to outputs or Fee.
type SpendPlanV1 struct {
	Note     NoteV1
	LockRoot Digest
	Outputs  []PaymentV1
	Fee      uint64
}

// TransferV1 is an immutable signed V1 transaction with full PKH lock proofs.
// Construction checks declared balances and fees, not input existence or finality.
type TransferV1 struct {
	raw   Noun
	id    Digest
	valid bool
}

// ID returns the V1 transaction identifier, or an error for an uninitialized value.
func (t TransferV1) ID() (Digest, error) {
	if !t.valid {
		return Digest{}, errors.New("uninitialized transfer")
	}
	return t.id, nil
}

// Noun returns the immutable [1 id spends] transaction noun.
func (t TransferV1) Noun() (Noun, error) {
	if !t.valid {
		return Noun{}, errors.New("uninitialized transfer")
	}
	return t.raw, nil
}

// Jam encodes the signed transaction for wallet/RPC transport.
func (t TransferV1) Jam() ([]byte, error) {
	if !t.valid {
		return nil, errors.New("uninitialized transfer")
	}
	return Jam(t.raw)
}

// MaxTransferInputs bounds the number of input notes in a transaction.
const MaxTransferInputs = 64

// MaxTransferOutputs bounds the total number of output seeds across inputs.
const MaxTransferOutputs = 256

// MinimumTransferFeeV1 computes the V1 fee for plain PKH inputs and outputs.
// Output lock metadata is merged per recipient. The caller supplies every
// recipient, including change, across all input spends.
func MinimumTransferFeeV1(inputs int, recipients []Digest) (uint64, error) {
	if inputs < 1 || inputs > MaxTransferInputs || len(recipients) < 1 || len(recipients) > MaxTransferOutputs {
		return 0, errors.New("transfer size out of range")
	}
	unique := map[Digest]bool{}
	for _, p := range recipients {
		if !p.Valid() {
			return 0, errors.New("invalid recipient")
		}
		unique[p] = true
	}
	// Each merged lock metadata map has 13 flattened leaves; a signed full PKH witness has 56.
	return uint64(len(unique))*13*(1<<14) + uint64(inputs)*56*(1<<12), nil
}

// SignTransferV1 builds and signs up to 64 input spends with this one key. It
// supports plain 1-of-1 PKH locks, explicit outputs/change, and full lock proofs.
// It rejects duplicate notes/recipients, mismatched locks, imbalanced values,
// insufficient fees, and non-field amounts. Run offline; arithmetic is variable-time.
func (k ExtendedKey) SignTransferV1(plans []SpendPlanV1) (TransferV1, error) {
	plansWithLocks := make([]LockedSpendPlanV1, len(plans))
	address, e := k.Address()
	if e != nil {
		return TransferV1{}, e
	}
	pkh, _ := ParseDigest(address)
	lock, _ := NewPKHLockV1(1, []Digest{pkh}, nil)
	for i, p := range plans {
		if p.LockRoot != lock.root {
			return TransferV1{}, errors.New("input lock does not authorize this key")
		}
		next := LockedSpendPlanV1{Note: p.Note, Lock: lock, Fee: p.Fee}
		for _, o := range p.Outputs {
			l, e := NewPKHLockV1(1, []Digest{o.Recipient}, nil)
			if e != nil {
				return TransferV1{}, e
			}
			next.Outputs = append(next.Outputs, LockedPaymentV1{l, o.Nicks})
		}
		plansWithLocks[i] = next
	}
	tx, e := PrepareTransactionV1(plansWithLocks)
	if e != nil {
		return TransferV1{}, e
	}
	tx, e = tx.Sign(k)
	if e != nil {
		return TransferV1{}, e
	}
	return TransferV1{tx.raw, tx.id, true}, nil
}

func digestNoun(d Digest) Noun {
	var a [5]Noun
	for i, v := range d {
		a[i] = Noun{atom: v}
	}
	return Tuple(a[:]...)
}
func publicNoun(p point) Noun {
	p = p.affine()
	var x, y [6]Noun
	for i := range x {
		x[i] = Noun{atom: p.x[i]}
		y[i] = Noun{atom: p.y[i]}
	}
	return Tuple(Tuple(x[:]...), Tuple(y[:]...), Noun{atom: 1})
}
func mustHashNoun(n Noun) Digest {
	d, e := HashNoun(n)
	if e != nil {
		panic(e)
	}
	return d
}
func hashEach(n Noun) Digest {
	if n.cell == nil {
		return hashAtom(n.atom)
	}
	return hashCell(hashEach(n.cell.head), hashEach(n.cell.tail))
}
func foldHashes(d ...Digest) Digest {
	r := d[len(d)-1]
	for i := len(d) - 2; i >= 0; i-- {
		r = hashCell(d[i], r)
	}
	return r
}

// Internal treaps operate only on bounded, constructed transaction nouns.
type nounTree struct {
	key, value                         Noun
	regular, signature, sort, priority Digest
	left, right                        *nounTree
	isMap                              bool
}

func newTree(k, v Noun, regular, signature Digest, isMap bool) *nounTree {
	h := mustHashNoun(k)
	return &nounTree{key: k, value: v, regular: regular, signature: signature, sort: h, priority: hashCell(h, h), isMap: isMap}
}
func (t *nounTree) noun() Noun {
	if t == nil {
		return Noun{}
	}
	v := t.key
	if t.isMap {
		v = Cell(v, t.value)
	}
	return Tuple(v, t.left.noun(), t.right.noun())
}
func (t *nounTree) digest(sig bool) Digest {
	if t == nil {
		return hashAtom(0)
	}
	d := t.regular
	if sig {
		d = t.signature
	}
	return hashCell(d, hashCell(t.left.digest(sig), t.right.digest(sig)))
}
func digestLess(a, b Digest) bool {
	for i := 4; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
func nounEqual(a, b Noun) bool {
	if a.cell == nil || b.cell == nil {
		return a.cell == nil && b.cell == nil && a.atom == b.atom
	}
	return nounEqual(a.cell.head, b.cell.head) && nounEqual(a.cell.tail, b.cell.tail)
}
func nounLess(a, b Noun) bool {
	if nounEqual(a, b) {
		return true
	}
	if a.cell == nil || b.cell == nil {
		return a.cell == nil && b.cell == nil && a.atom < b.atom
	}
	if nounEqual(a.cell.head, b.cell.head) {
		return nounLess(a.cell.tail, b.cell.tail)
	}
	return nounLess(a.cell.head, b.cell.head)
}
func treeLess(a, b *nounTree, priority bool) bool {
	x, y := a.sort, b.sort
	if priority {
		x, y = a.priority, b.priority
	}
	if x == y {
		return nounLess(a.key, b.key)
	}
	return digestLess(x, y)
}
func treePut(t, n *nounTree) *nounTree {
	if t == nil {
		return n
	}
	if nounEqual(t.key, n.key) {
		n.left, n.right = t.left, t.right
		return n
	}
	if treeLess(n, t, false) {
		t.left = treePut(t.left, n)
		if !treeLess(t, t.left, true) {
			r := t.left
			t.left = r.right
			r.right = t
			return r
		}
	} else {
		t.right = treePut(t.right, n)
		if !treeLess(t, t.right, true) {
			r := t.right
			t.right = r.left
			r.left = t
			return r
		}
	}
	return t
}
