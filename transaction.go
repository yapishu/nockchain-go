package nockchain

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
)

// LockedPaymentV1 creates an output with the lock's full metadata.
type LockedPaymentV1 struct {
	Lock  LockV1
	Nicks uint64
}

// LockedSpendPlanV1 assigns the complete value of one verified note to outputs
// and fee. Every input retains at least one nonzero output seed.
type LockedSpendPlanV1 struct {
	Note    NoteV1
	Lock    LockV1
	Outputs []LockedPaymentV1
	Fee     uint64
}

// OutputV1 describes a committed seed. Metadata is immutable and must be checked
// against LockRoot before interpreting it as a recipient lock.
type OutputV1 struct {
	LockRoot   Digest
	NoteData   Noun
	Nicks      uint64
	ParentHash Digest
}

// Lock returns the authenticated PKH lock in this output's metadata, if present.
func (o OutputV1) Lock() (LockV1, error) {
	var found LockV1
	_, e := readTree(o.NoteData, true, 64, func(k, v Noun) (Digest, Digest, error) {
		if k == (Noun{atom: 0x6b636f6c}) {
			p, e := parts(v, 2)
			if e != nil || !zero(p[0]) {
				return Digest{}, Digest{}, errMalformed
			}
			l, e := parseCondition(p[1])
			if e != nil {
				return Digest{}, Digest{}, e
			}
			found = l
		}
		return Digest{}, Digest{}, nil
	})
	if e != nil {
		return LockV1{}, e
	}
	if found.threshold == 0 || found.root != o.LockRoot {
		return LockV1{}, errors.New("output metadata does not authenticate its lock")
	}
	return found, nil
}

// SpendSummaryV1 is a detached input review; SignedKeys describes present signatures.
type SpendSummaryV1 struct {
	Name          NoteName
	Lock          LockV1
	Fee           uint64
	Outputs       []OutputV1
	SignedKeys    []Digest
	SignatureHash Digest
}

// TransactionSummaryV1 reports committed amounts, without inferring chain validity.
type TransactionSummaryV1 struct {
	ID                                     Digest
	FeeNicks, OutputNicks, MinimumFeeNicks uint64
	Spends                                 []SpendSummaryV1
}
type signedPKH struct {
	public    []byte
	signature Signature
}
type transactionSpend struct {
	name       NoteName
	lock       LockV1
	fee        uint64
	seeds      *nounTree
	outputs    []OutputV1
	signatures map[Digest]signedPKH
}

func (s transactionSpend) signatureHash() Digest {
	return hashCell(s.seeds.digest(true), hashAtom(s.fee))
}
func (s transactionSpend) signatureTree() *nounTree {
	var tree *nounTree
	for k, v := range s.signatures {
		p, _ := parsePoint(v.public)
		pn, sn := publicNoun(p), v.signature.noun()
		h := hashCell(k, hashCell(mustHashNoun(pn), mustHashNoun(sn)))
		tree = treePut(tree, newTree(digestNoun(k), Cell(pn, sn), h, h, true))
	}
	return tree
}
func (s transactionSpend) witness() Noun {
	return Tuple(s.lock.proof(), s.signatureTree().noun(), Noun{}, Noun{})
}
func (s transactionSpend) hash() Digest {
	w := foldHashes(s.lock.proofHash(), s.signatureTree().digest(false), hashAtom(0), hashAtom(0))
	return foldHashes(hashAtom(1), w, s.seeds.digest(false), hashAtom(s.fee))
}
func (s transactionSpend) noun() Noun {
	return Tuple(Noun{atom: 1}, s.witness(), s.seeds.noun(), Noun{atom: s.fee})
}
func (s transactionSpend) clone() transactionSpend {
	m := map[Digest]signedPKH{}
	for k, v := range s.signatures {
		m[k] = v
	}
	s.signatures = m
	s.outputs = append([]OutputV1(nil), s.outputs...)
	return s
}

// TransactionV1 is an immutable unsigned, partially signed, or signed transaction.
// Every signature changes its ID. Signing commits each input's seeds and fee.
type TransactionV1 struct {
	raw    Noun
	id     Digest
	spends []transactionSpend
}

// ID returns the commitment to the transaction including signatures.
func (t TransactionV1) ID() (Digest, error) {
	if len(t.spends) == 0 {
		return Digest{}, errors.New("uninitialized transaction")
	}
	return t.id, nil
}

// Noun returns the immutable [1 id spends] transaction noun.
func (t TransactionV1) Noun() (Noun, error) {
	if len(t.spends) == 0 {
		return Noun{}, errors.New("uninitialized transaction")
	}
	return t.raw, nil
}

// Jam returns the canonical transaction encoding for transport.
func (t TransactionV1) Jam() ([]byte, error) {
	n, e := t.Noun()
	if e != nil {
		return nil, e
	}
	return Jam(n)
}
func addAmount(a, b uint64) (uint64, error) {
	n, c := bits.Add64(a, b, 0)
	if c != 0 {
		return 0, errors.New("amount overflow")
	}
	return n, nil
}
func leaves(n Noun) uint64 {
	if n.cell == nil {
		return 1
	}
	return leaves(n.cell.head) + leaves(n.cell.tail)
}

// MaxNoteDataWordsV1 is the consensus limit for flattened metadata per output lock.
const MaxNoteDataWordsV1 = 2048

func (t TransactionV1) minimumFee() (uint64, error) {
	var witness uint64
	metadata := map[Digest]map[uint64]Noun{}
	for _, s := range t.spends {
		count := len(s.signatures)
		if count < s.lock.threshold {
			count = s.lock.threshold
		}
		// A signature map has 35 leaves per entry plus the empty terminator.
		witness += leaves(s.lock.proof()) + uint64(count)*35 + 1 + 2
		for _, o := range s.outputs {
			entries, exists := metadata[o.LockRoot]
			if !exists {
				entries = map[uint64]Noun{}
				metadata[o.LockRoot] = entries
			}
			_, e := readTree(o.NoteData, true, 64, func(k, v Noun) (Digest, Digest, error) {
				tag, e := atomValue(k)
				if e != nil {
					return Digest{}, Digest{}, e
				}
				if old, exists := entries[tag]; exists && !nounEqual(old, v) {
					return Digest{}, Digest{}, errors.New("conflicting output metadata for one lock")
				}
				entries[tag] = v
				return Digest{}, Digest{}, nil
			})
			if e != nil {
				return 0, e
			}
		}
	}
	var data uint64
	for _, entries := range metadata {
		// tx-engine/count-seed-words-merged folds entries into [key value tail].
		// It charges one list terminator, not the map's branching structure.
		words := uint64(1)
		for _, v := range entries {
			words += 1 + leaves(v)
		}
		if words > MaxNoteDataWordsV1 {
			return 0, errors.New("output metadata exceeds consensus word limit")
		}
		data += words
	}
	fee := data*(1<<14) + witness*(1<<12)
	if fee < 256 {
		fee = 256
	}
	return fee, nil
}

func assembleTransaction(spends []transactionSpend) (TransactionV1, error) {
	var tree *nounTree
	outputs := 0
	for _, s := range spends {
		outputs += len(s.outputs)
		if outputs > MaxTransferOutputs {
			return TransactionV1{}, errors.New("output count out of range")
		}
		n, _ := s.name.Hash()
		h := hashCell(n, s.hash())
		tree = treePut(tree, newTree(s.name.noun(), s.noun(), h, h, true))
	}
	id := hashCell(hashAtom(1), tree.digest(false))
	t := TransactionV1{Tuple(Noun{atom: 1}, digestNoun(id), tree.noun()), id, spends}
	if e := boundedNoun(t.raw); e != nil {
		return TransactionV1{}, e
	}
	if _, e := t.Summary(); e != nil {
		return TransactionV1{}, e
	}
	return t, nil
}

// Summary computes fees for at least the threshold number of signatures per input.
func (t TransactionV1) Summary() (TransactionSummaryV1, error) {
	if len(t.spends) == 0 {
		return TransactionSummaryV1{}, errors.New("uninitialized transaction")
	}
	out := TransactionSummaryV1{ID: t.id}
	var e error
	for _, s := range t.spends {
		out.FeeNicks, e = addAmount(out.FeeNicks, s.fee)
		if e != nil {
			return out, e
		}
		v := SpendSummaryV1{Name: s.name, Lock: s.lock, Fee: s.fee, Outputs: append([]OutputV1(nil), s.outputs...), SignatureHash: s.signatureHash()}
		for _, k := range s.lock.keys {
			if _, ok := s.signatures[k]; ok {
				v.SignedKeys = append(v.SignedKeys, k)
			}
		}
		for _, o := range s.outputs {
			out.OutputNicks, e = addAmount(out.OutputNicks, o.Nicks)
			if e != nil {
				return out, e
			}
		}
		out.Spends = append(out.Spends, v)
	}
	out.MinimumFeeNicks, e = t.minimumFee()
	return out, e
}

// PrepareTransactionV1 validates note commitments, declared balances and fees,
// and builds an unsigned transaction for independent review and signing.
func PrepareTransactionV1(plans []LockedSpendPlanV1) (TransactionV1, error) {
	if len(plans) < 1 || len(plans) > MaxTransferInputs {
		return TransactionV1{}, errors.New("input count out of range")
	}
	seen := map[NoteName]bool{}
	spends := make([]transactionSpend, 0, len(plans))
	for _, p := range plans {
		parent, e := p.Note.Hash()
		if e != nil {
			return TransactionV1{}, e
		}
		bound, _ := NoteFirstV1(p.Lock.root)
		if p.Lock.threshold == 0 || p.Note.Name.First != bound || seen[p.Note.Name] || p.Fee >= Prime || len(p.Outputs) == 0 {
			return TransactionV1{}, errors.New("invalid, duplicate, or lock-mismatched input")
		}
		seen[p.Note.Name] = true
		s := transactionSpend{name: p.Note.Name, lock: p.Lock, fee: p.Fee, signatures: map[Digest]signedPKH{}}
		total := p.Fee
		roots := map[Digest]bool{}
		for _, o := range p.Outputs {
			if o.Lock.threshold == 0 || o.Nicks == 0 || o.Nicks >= Prime || roots[o.Lock.root] {
				return TransactionV1{}, errors.New("invalid or duplicate output lock")
			}
			roots[o.Lock.root] = true
			total, e = addAmount(total, o.Nicks)
			if e != nil {
				return TransactionV1{}, e
			}
			metadata := o.Lock.metadata()
			dh, _ := metadataHash(metadata)
			regular := foldHashes(o.Lock.root, dh, hashAtom(o.Nicks), parent)
			seed := Tuple(Noun{}, digestNoun(o.Lock.root), metadata, Noun{atom: o.Nicks}, digestNoun(parent))
			s.seeds = treePut(s.seeds, newTree(seed, Noun{}, regular, hashCell(hashAtom(0), regular), false))
			s.outputs = append(s.outputs, OutputV1{o.Lock.root, metadata, o.Nicks, parent})
		}
		if total != p.Note.Nicks {
			return TransactionV1{}, errors.New("input value differs from outputs plus fee")
		}
		spends = append(spends, s)
	}
	tx, e := assembleTransaction(spends)
	if e != nil {
		return TransactionV1{}, e
	}
	summary, _ := tx.Summary()
	if summary.FeeNicks < summary.MinimumFeeNicks {
		return TransactionV1{}, fmt.Errorf("fee below minimum %d nicks", summary.MinimumFeeNicks)
	}
	return tx, nil
}

func (t TransactionV1) verify(requireThreshold bool) error {
	if len(t.spends) == 0 {
		return errors.New("uninitialized transaction")
	}
	for _, s := range t.spends {
		if len(s.signatures) > s.lock.threshold || (requireThreshold && len(s.signatures) != s.lock.threshold) {
			return errors.New("signature count must equal the threshold")
		}
		for k, v := range s.signatures {
			p, e := parsePoint(v.public)
			if e != nil || publicKeyHash(p) != k || !s.lock.authorizes(k) || !VerifyDigest(v.public, s.signatureHash(), v.signature) {
				return errors.New("invalid or unauthorized signature")
			}
		}
	}
	return nil
}

// VerifySignatures checks every signature, authorization and threshold, and the
// fee for the witnesses present. It does not check chain state or timelocks.
func (t TransactionV1) VerifySignatures() error {
	if e := t.verify(true); e != nil {
		return e
	}
	s, e := t.Summary()
	if e != nil {
		return e
	}
	if s.FeeNicks < s.MinimumFeeNicks {
		return errors.New("fee below minimum")
	}
	return nil
}

// Sign adds signatures for every input authorizing this key. Existing signatures
// are verified first. The result owns its signature maps; the receiver is unchanged.
func (t TransactionV1) Sign(key ExtendedKey) (TransactionV1, error) {
	if key.secret == nil {
		return TransactionV1{}, errors.New("private signing key required")
	}
	if e := t.verify(false); e != nil {
		return TransactionV1{}, e
	}
	pkh := publicKeyHash(key.pub)
	pub, _ := key.PublicBytes()
	spends := make([]transactionSpend, len(t.spends))
	matched := false
	for i, s := range t.spends {
		s = s.clone()
		if s.lock.authorizes(pkh) {
			matched = true
			if _, exists := s.signatures[pkh]; !exists && len(s.signatures) >= s.lock.threshold {
				return TransactionV1{}, errors.New("input already has its required signatures")
			}
			sig, e := key.SignDigest(s.signatureHash())
			if e != nil {
				return TransactionV1{}, e
			}
			s.signatures[pkh] = signedPKH{pub, sig}
		}
		spends[i] = s
	}
	if !matched {
		return TransactionV1{}, errors.New("key is not authorized by any input")
	}
	out, e := assembleTransaction(spends)
	if e != nil {
		return TransactionV1{}, e
	}
	summary, _ := out.Summary()
	if summary.FeeNicks < summary.MinimumFeeNicks {
		return TransactionV1{}, errors.New("fee cannot cover additional signatures")
	}
	return out, nil
}

// MergeSignatures combines independently signed copies of the exact same plan.
func (t TransactionV1) MergeSignatures(other TransactionV1) (TransactionV1, error) {
	if e := t.verify(false); e != nil {
		return TransactionV1{}, e
	}
	if e := other.verify(false); e != nil {
		return TransactionV1{}, e
	}
	if len(t.spends) != len(other.spends) {
		return TransactionV1{}, errors.New("different transaction plans")
	}
	byName := map[NoteName]transactionSpend{}
	for _, s := range other.spends {
		byName[s.name] = s
	}
	out := make([]transactionSpend, len(t.spends))
	for i, s := range t.spends {
		o, ok := byName[s.name]
		if !ok || s.fee != o.fee || !nounEqual(s.lock.condition, o.lock.condition) || !nounEqual(s.seeds.noun(), o.seeds.noun()) {
			return TransactionV1{}, errors.New("different transaction plans")
		}
		s = s.clone()
		for k, v := range o.signatures {
			if old, ok := s.signatures[k]; ok && (!bytes.Equal(old.public, v.public) || old.signature != v.signature) {
				return TransactionV1{}, errors.New("conflicting signature")
			}
			s.signatures[k] = v
		}
		if len(s.signatures) > s.lock.threshold {
			return TransactionV1{}, errors.New("merged signatures exceed the threshold")
		}
		out[i] = s
	}
	tx, e := assembleTransaction(out)
	if e != nil {
		return TransactionV1{}, e
	}
	sum, _ := tx.Summary()
	if sum.FeeNicks < sum.MinimumFeeNicks {
		return TransactionV1{}, errors.New("fee cannot cover merged signatures")
	}
	return tx, nil
}

// ValidateInputs checks exact supplied records, parent commitments, balances and
// timelocks at height. The caller authenticates these records against chain state.
func (t TransactionV1) ValidateInputs(notes []NoteV1, height uint64) error {
	if len(t.spends) == 0 || len(notes) != len(t.spends) || height >= Prime {
		return errors.New("input records or height invalid")
	}
	m := map[NoteName]NoteV1{}
	for _, n := range notes {
		if _, ok := m[n.Name]; ok {
			return errors.New("duplicate input record")
		}
		m[n.Name] = n
	}
	for _, s := range t.spends {
		n, ok := m[s.name]
		if !ok {
			return errors.New("missing input record")
		}
		parent, e := n.Hash()
		if e != nil {
			return e
		}
		if n.OriginPage > height || (s.lock.time != nil && !s.lock.time.Allows(height, n.OriginPage)) {
			return errors.New("input timelock or origin is not satisfied")
		}
		total := s.fee
		for _, o := range s.outputs {
			if o.ParentHash != parent {
				return errors.New("output parent does not match input note")
			}
			total, e = addAmount(total, o.Nicks)
			if e != nil {
				return e
			}
		}
		if total != n.Nicks {
			return errors.New("input value differs from outputs plus fee")
		}
	}
	return nil
}

// MinimumTransactionFeeV1 estimates the fee with exactly each input lock's
// required signatures and merged full lock metadata for the outputs. It uses
// the pinned V1 fee schedule; no placeholder signatures leave this function.
func MinimumTransactionFeeV1(inputs, outputs []LockV1) (uint64, error) {
	if len(inputs) < 1 || len(inputs) > MaxTransferInputs || len(outputs) == 0 || len(outputs) > MaxTransferOutputs {
		return 0, errors.New("transaction size out of range")
	}
	tx := TransactionV1{spends: make([]transactionSpend, len(inputs))}
	for i, l := range inputs {
		if l.threshold == 0 {
			return 0, errors.New("uninitialized input lock")
		}
		tx.spends[i].lock = l
	}
	for _, l := range outputs {
		if l.threshold == 0 {
			return 0, errors.New("uninitialized output lock")
		}
		tx.spends[0].outputs = append(tx.spends[0].outputs, OutputV1{LockRoot: l.root, NoteData: l.metadata()})
	}
	return tx.minimumFee()
}
