package nockchain

import "errors"

// HeightRange is an inclusive interval. Nil endpoints are unbounded.
type HeightRange struct{ Min, Max *uint64 }

// TimelockV1 requires both the absolute height and age since the input's origin
// to fall within their ranges. Heights come from verified chain state.
type TimelockV1 struct{ Relative, Absolute HeightRange }

func cloneRange(r HeightRange) HeightRange {
	if r.Min != nil {
		v := *r.Min
		r.Min = &v
	}
	if r.Max != nil {
		v := *r.Max
		r.Max = &v
	}
	return r
}
func (t TimelockV1) clone() TimelockV1 {
	return TimelockV1{cloneRange(t.Relative), cloneRange(t.Absolute)}
}
func (r HeightRange) valid() bool {
	return (r.Min == nil || *r.Min < Prime) && (r.Max == nil || *r.Max < Prime) && (r.Min == nil || r.Max == nil || *r.Min <= *r.Max)
}
func (r HeightRange) contains(v uint64) bool {
	return (r.Min == nil || v >= *r.Min) && (r.Max == nil || v <= *r.Max)
}

// Allows checks inclusive absolute and relative bounds without arithmetic wraparound.
func (t TimelockV1) Allows(height, origin uint64) bool {
	return t.Relative.valid() && t.Absolute.valid() && height < Prime && origin <= height && t.Absolute.contains(height) && t.Relative.contains(height-origin)
}
func optionalHeight(v *uint64) Noun {
	if v == nil {
		return Noun{}
	}
	return Cell(Noun{}, Noun{atom: *v})
}
func rangeNoun(r HeightRange) Noun { return Cell(optionalHeight(r.Min), optionalHeight(r.Max)) }
func optionalHash(v *uint64) Digest {
	if v == nil {
		return hashAtom(0)
	}
	return hashCell(hashAtom(0), hashAtom(*v))
}
func rangeHash(r HeightRange) Digest { return hashCell(optionalHash(r.Min), optionalHash(r.Max)) }

// LockV1 is an immutable full PKH lock with an optional conjunctive timelock.
// It supports 1-of-1 and m-of-n signatures, with at most 32 distinct keys.
type LockV1 struct {
	threshold int
	keys      []Digest
	time      *TimelockV1
	condition Noun
	root      Digest
}

// NewPKHLockV1 constructs a canonical lock and takes a copy of its inputs.
func NewPKHLockV1(threshold int, keys []Digest, timelock *TimelockV1) (LockV1, error) {
	if threshold < 1 || threshold > len(keys) || len(keys) > 32 {
		return LockV1{}, errors.New("invalid signature threshold or key count")
	}
	var set *nounTree
	seen := map[Digest]bool{}
	for _, k := range keys {
		if !k.Valid() || seen[k] {
			return LockV1{}, errors.New("invalid or duplicate lock key")
		}
		seen[k] = true
		set = treePut(set, newTree(digestNoun(k), Noun{}, k, k, false))
	}
	pkh := Tuple(Noun{atom: 0x686b70}, Noun{atom: uint64(threshold)}, set.noun())
	tail := Noun{}
	tailHash := hashAtom(0)
	var tm *TimelockV1
	if timelock != nil {
		if !timelock.Relative.valid() || !timelock.Absolute.valid() {
			return LockV1{}, errors.New("invalid timelock bounds")
		}
		v := timelock.clone()
		tm = &v
		p := Tuple(Noun{atom: 0x6d6974}, rangeNoun(v.Relative), rangeNoun(v.Absolute))
		tail = List(p)
		tailHash = hashCell(foldHashes(hashAtom(0x6d6974), rangeHash(v.Relative), rangeHash(v.Absolute)), tailHash)
	}
	cond := Cell(pkh, tail)
	root := hashCell(foldHashes(hashAtom(0x686b70), hashAtom(uint64(threshold)), set.digest(false)), tailHash)
	return LockV1{threshold, append([]Digest(nil), keys...), tm, cond, root}, nil
}

// Root returns the output lock commitment.
func (l LockV1) Root() (Digest, error) {
	if l.threshold == 0 {
		return Digest{}, errors.New("uninitialized lock")
	}
	return l.root, nil
}

// Keys returns a detached copy of the authorized public-key hashes.
func (l LockV1) Keys() []Digest { return append([]Digest(nil), l.keys...) }

// Threshold returns the exact number of signatures required per input.
func (l LockV1) Threshold() int { return l.threshold }

// Timelock returns a detached copy of the height constraints, or nil.
func (l LockV1) Timelock() *TimelockV1 {
	if l.time == nil {
		return nil
	}
	t := l.time.clone()
	return &t
}
func (l LockV1) authorizes(k Digest) bool {
	for _, v := range l.keys {
		if v == k {
			return true
		}
	}
	return false
}
func (l LockV1) metadata() Noun {
	return Tuple(Cell(Noun{atom: 0x6b636f6c}, Cell(Noun{}, l.condition)), Noun{}, Noun{})
}
func (l LockV1) proof() Noun {
	return Tuple(Noun{atom: 0x6c6c7566}, l.condition, Noun{atom: 1}, Cell(digestNoun(l.root), Noun{}))
}
func (l LockV1) proofHash() Digest {
	return foldHashes(hashAtom(0x6c6c7566), l.root, hashAtom(1), hashCell(l.root, hashAtom(0)))
}

// NoteFirstV1 computes the lock-bound first component of a V1 note name.
func NoteFirstV1(lockRoot Digest) (Digest, error) {
	if !lockRoot.Valid() {
		return Digest{}, errors.New("invalid lock root")
	}
	return hashCell(hashAtom(0), lockRoot), nil
}

// NoteV1 contains the complete input record required for parent commitments.
// NoteData is a canonical based-noun metadata map, including every stored entry.
// The application verifies the record's existence, unspent status and finality.
type NoteV1 struct {
	OriginPage uint64
	Name       NoteName
	NoteData   Noun
	Nicks      uint64
}

// Hash commits the complete version, origin, name, metadata and asset value.
func (n NoteV1) Hash() (Digest, error) {
	name, e := n.Name.Hash()
	if e != nil {
		return Digest{}, e
	}
	if n.OriginPage >= Prime || n.Nicks == 0 || n.Nicks >= Prime {
		return Digest{}, errors.New("invalid note height or value")
	}
	data, e := metadataHash(n.NoteData)
	if e != nil {
		return Digest{}, e
	}
	return foldHashes(hashAtom(1), hashAtom(n.OriginPage), name, data, hashAtom(n.Nicks)), nil
}
