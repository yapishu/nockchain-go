package nockchain

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var errMalformed = errors.New("malformed or unsupported V1 transaction")

func parts(n Noun, count int) ([]Noun, error) {
	out := make([]Noun, 0, count)
	for i := 1; i < count; i++ {
		if n.cell == nil {
			return nil, errMalformed
		}
		out = append(out, n.cell.head)
		n = n.cell.tail
	}
	return append(out, n), nil
}
func zero(n Noun) bool { return n.cell == nil && n.atom == 0 }
func atomValue(n Noun) (uint64, error) {
	if n.cell != nil {
		return 0, errMalformed
	}
	return n.atom, nil
}
func nounDigest(n Noun) (Digest, error) {
	a, e := parts(n, 5)
	if e != nil {
		return Digest{}, e
	}
	var d Digest
	for i, v := range a {
		d[i], e = atomValue(v)
		if e != nil {
			return Digest{}, e
		}
	}
	return d, nil
}
func boundedNoun(n Noun) error {
	type frame struct {
		n     Noun
		depth int
	}
	stack := []frame{{n, 0}}
	count := 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		count++
		if count > 65536 || f.depth > 256 {
			return errors.New("transaction noun exceeds inspection limits")
		}
		if f.n.cell != nil {
			stack = append(stack, frame{f.n.cell.head, f.depth + 1}, frame{f.n.cell.tail, f.depth + 1})
		}
	}
	return nil
}

// readTree reconstructs a bounded treap and rejects duplicate keys and noncanonical shape.
func readTree(n Noun, isMap bool, max int, entry func(Noun, Noun) (Digest, Digest, error)) (*nounTree, error) {
	if e := boundedNoun(n); e != nil {
		return nil, e
	}
	var tree *nounTree
	stack := []Noun{n}
	count := 0
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if zero(v) {
			continue
		}
		p, e := parts(v, 3)
		if e != nil {
			return nil, e
		}
		count++
		if count > max {
			return nil, errors.New("tree entry limit exceeded")
		}
		k, val := p[0], Noun{}
		if isMap {
			kv, e := parts(k, 2)
			if e != nil {
				return nil, e
			}
			k, val = kv[0], kv[1]
		}
		r, s, e := entry(k, val)
		if e != nil {
			return nil, e
		}
		tree = treePut(tree, newTree(k, val, r, s, isMap))
		stack = append(stack, p[1], p[2])
	}
	if !nounEqual(n, tree.noun()) {
		return nil, errors.New("noncanonical or duplicate tree entries")
	}
	return tree, nil
}
func metadataHash(n Noun) (Digest, error) {
	t, e := readTree(n, true, 64, func(k, v Noun) (Digest, Digest, error) {
		tag, e := atomValue(k)
		if e != nil {
			return Digest{}, Digest{}, e
		}
		h := hashCell(hashAtom(tag), hashEach(v))
		return h, h, nil
	})
	if e != nil {
		return Digest{}, e
	}
	return t.digest(false), nil
}
func parseOptional(n Noun) (*uint64, error) {
	if zero(n) {
		return nil, nil
	}
	p, e := parts(n, 2)
	if e != nil || !zero(p[0]) {
		return nil, errMalformed
	}
	v, e := atomValue(p[1])
	return &v, e
}
func parseRange(n Noun) (HeightRange, error) {
	p, e := parts(n, 2)
	if e != nil {
		return HeightRange{}, e
	}
	lo, e := parseOptional(p[0])
	if e != nil {
		return HeightRange{}, e
	}
	hi, e := parseOptional(p[1])
	r := HeightRange{lo, hi}
	if e != nil || !r.valid() {
		return HeightRange{}, errMalformed
	}
	return r, nil
}
func parseCondition(n Noun) (LockV1, error) {
	if n.cell == nil {
		return LockV1{}, errMalformed
	}
	p, e := parts(n.cell.head, 3)
	if e != nil || p[0] != (Noun{atom: 0x686b70}) {
		return LockV1{}, errMalformed
	}
	m, e := atomValue(p[1])
	if e != nil || m > 32 {
		return LockV1{}, errMalformed
	}
	var keys []Digest
	_, e = readTree(p[2], false, 32, func(k, v Noun) (Digest, Digest, error) { d, e := nounDigest(k); keys = append(keys, d); return d, d, e })
	if e != nil {
		return LockV1{}, e
	}
	tail := n.cell.tail
	var tm *TimelockV1
	if !zero(tail) {
		if tail.cell == nil || !zero(tail.cell.tail) {
			return LockV1{}, errMalformed
		}
		p, e := parts(tail.cell.head, 3)
		if e != nil || p[0] != (Noun{atom: 0x6d6974}) {
			return LockV1{}, errMalformed
		}
		r, e := parseRange(p[1])
		if e != nil {
			return LockV1{}, e
		}
		a, e := parseRange(p[2])
		if e != nil {
			return LockV1{}, e
		}
		tm = &TimelockV1{r, a}
	}
	return NewPKHLockV1(int(m), keys, tm)
}
func parseProof(n Noun) (LockV1, error) {
	p, e := parts(n, 4)
	if e != nil || p[0] != (Noun{atom: 0x6c6c7566}) || p[2] != (Noun{atom: 1}) {
		return LockV1{}, errMalformed
	}
	l, e := parseCondition(p[1])
	if e != nil {
		return LockV1{}, e
	}
	if !nounEqual(l.proof(), n) {
		return LockV1{}, errors.New("lock proof does not match its root")
	}
	return l, nil
}
func parsePublic(n Noun) ([]byte, error) {
	p, e := parts(n, 3)
	if e != nil || p[2] != (Noun{atom: 1}) {
		return nil, errMalformed
	}
	out := make([]byte, 97)
	out[0] = 1
	for j := 0; j < 2; j++ {
		v, e := parts(p[j], 6)
		if e != nil {
			return nil, e
		}
		for i, x := range v {
			a, e := atomValue(x)
			if e != nil {
				return nil, e
			}
			offset := 1 + (1-j)*48 + (5-i)*8
			binary.BigEndian.PutUint64(out[offset:offset+8], a)
		}
	}
	if _, e := parsePoint(out); e != nil {
		return nil, e
	}
	return out, nil
}
func parseSignature(n Noun) (Signature, error) {
	p, e := parts(n, 2)
	if e != nil {
		return Signature{}, e
	}
	var out Signature
	for j := 0; j < 2; j++ {
		v, e := parts(p[j], 8)
		if e != nil {
			return Signature{}, e
		}
		for i, x := range v {
			a, e := atomValue(x)
			if e != nil || a > 0xffffffff {
				return Signature{}, errMalformed
			}
			if j == 0 {
				out.Challenge[i] = uint32(a)
			} else {
				out.Response[i] = uint32(a)
			}
		}
	}
	if !validScalar(limbsScalar(out.Challenge)) || !validScalar(limbsScalar(out.Response)) {
		return Signature{}, errMalformed
	}
	return out, nil
}

// ParseTransactionV1 decodes canonical V1 transactions using full PKH proofs,
// optional conjunctive timelocks, and ordinary output seeds. It rejects other
// lock/proof forms, source-constrained outputs, malformed trees and mismatched IDs.
// Call VerifySignatures and ValidateInputs explicitly before considering a spend.
func ParseTransactionV1(jam []byte) (TransactionV1, error) {
	n, e := Cue(jam)
	if e != nil {
		return TransactionV1{}, e
	}
	if e = boundedNoun(n); e != nil {
		return TransactionV1{}, e
	}
	p, e := parts(n, 3)
	if e != nil || p[0] != (Noun{atom: 1}) {
		return TransactionV1{}, errMalformed
	}
	embedded, e := nounDigest(p[1])
	if e != nil {
		return TransactionV1{}, e
	}
	var spends []transactionSpend
	_, e = readTree(p[2], true, MaxTransferInputs, func(k, v Noun) (Digest, Digest, error) {
		nameParts, e := parts(k, 3)
		if e != nil || !zero(nameParts[2]) {
			return Digest{}, Digest{}, errMalformed
		}
		first, e := nounDigest(nameParts[0])
		if e != nil {
			return Digest{}, Digest{}, e
		}
		last, e := nounDigest(nameParts[1])
		if e != nil {
			return Digest{}, Digest{}, e
		}
		name := NoteName{first, last}
		sp, e := parts(v, 4)
		if e != nil || sp[0] != (Noun{atom: 1}) {
			return Digest{}, Digest{}, errMalformed
		}
		w, e := parts(sp[1], 4)
		if e != nil || !zero(w[2]) || !zero(w[3]) {
			return Digest{}, Digest{}, errMalformed
		}
		lock, e := parseProof(w[0])
		if e != nil {
			return Digest{}, Digest{}, e
		}
		bound, _ := NoteFirstV1(lock.root)
		if name.First != bound {
			return Digest{}, Digest{}, errors.New("note name does not bind input lock")
		}
		fee, e := atomValue(sp[3])
		if e != nil {
			return Digest{}, Digest{}, e
		}
		s := transactionSpend{name: name, lock: lock, fee: fee, signatures: map[Digest]signedPKH{}}
		_, e = readTree(w[1], true, 32, func(k, v Noun) (Digest, Digest, error) {
			d, e := nounDigest(k)
			if e != nil {
				return Digest{}, Digest{}, e
			}
			pv, e := parts(v, 2)
			if e != nil {
				return Digest{}, Digest{}, e
			}
			pub, e := parsePublic(pv[0])
			if e != nil {
				return Digest{}, Digest{}, e
			}
			sig, e := parseSignature(pv[1])
			if e != nil {
				return Digest{}, Digest{}, e
			}
			if mustHashNoun(pv[0]) != d || !lock.authorizes(d) {
				return Digest{}, Digest{}, errors.New("unauthorized signature key")
			}
			s.signatures[d] = signedPKH{pub, sig}
			h := hashCell(d, hashCell(mustHashNoun(pv[0]), mustHashNoun(pv[1])))
			return h, h, nil
		})
		if e != nil {
			return Digest{}, Digest{}, e
		}
		if zero(sp[2]) {
			return Digest{}, Digest{}, errors.New("each input requires an output seed")
		}
		s.seeds, e = readTree(sp[2], false, MaxTransferOutputs, func(k, v Noun) (Digest, Digest, error) {
			q, e := parts(k, 5)
			if e != nil || !zero(q[0]) {
				return Digest{}, Digest{}, errMalformed
			}
			root, e := nounDigest(q[1])
			if e != nil {
				return Digest{}, Digest{}, e
			}
			data, e := metadataHash(q[2])
			if e != nil {
				return Digest{}, Digest{}, e
			}
			amount, e := atomValue(q[3])
			if e != nil || amount == 0 {
				return Digest{}, Digest{}, errMalformed
			}
			parent, e := nounDigest(q[4])
			if e != nil {
				return Digest{}, Digest{}, e
			}
			s.outputs = append(s.outputs, OutputV1{LockRoot: root, NoteData: q[2], Nicks: amount, ParentHash: parent})
			h := foldHashes(root, data, hashAtom(amount), parent)
			return h, hashCell(hashAtom(0), h), nil
		})
		if e != nil {
			return Digest{}, Digest{}, e
		}
		spends = append(spends, s)
		h := s.hash()
		nh, _ := name.Hash()
		h = hashCell(nh, h)
		return h, h, nil
	})
	if e != nil {
		return TransactionV1{}, fmt.Errorf("parse transaction: %w", e)
	}
	if len(spends) == 0 {
		return TransactionV1{}, errors.New("empty transaction")
	}
	tx, e := assembleTransaction(spends)
	if e != nil {
		return TransactionV1{}, e
	}
	if tx.id != embedded {
		return TransactionV1{}, errors.New("transaction ID does not match contents")
	}
	return tx, nil
}
