package nockchain

import (
	"errors"
	"sort"
)

// SelectTransfer selects the fewest largest notes sufficient for payments and
// fees, with deterministic note-name tie breaking. It ignores foreign locks,
// rejects invalid or duplicate records, and leaves the supplied slice unchanged.
// The caller supplies verified, spendable notes for this plain single-key lock.
func SelectTransfer(sender ExtendedKey, notes []UnspentNote, payments []Payment, options TransferOptions) (PreparedTransfer, error) {
	address, e := sender.Address()
	if e != nil {
		return PreparedTransfer{}, e
	}
	pkh, _ := ParseDigest(address)
	root, _ := LockRoot(pkh)
	bound, _ := NoteFirstV1(root)
	candidates := make([]UnspentNote, 0, len(notes))
	seen := map[NoteName]bool{}
	for _, n := range notes {
		if _, e := n.Note.Hash(); e != nil {
			return PreparedTransfer{}, e
		}
		if seen[n.Note.Name] {
			return PreparedTransfer{}, errors.New("duplicate input note")
		}
		seen[n.Note.Name] = true
		if n.LockRoot == root && n.Note.Name.First == bound {
			candidates = append(candidates, n)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i].Note, candidates[j].Note
		if a.Nicks != b.Nicks {
			return a.Nicks > b.Nicks
		}
		if a.Name.First != b.Name.First {
			return digestLess(a.Name.First, b.Name.First)
		}
		return digestLess(a.Name.Last, b.Name.Last)
	})
	var last error = errors.New("no spendable notes")
	for count := 1; count <= len(candidates) && count <= MaxTransferInputs; count++ {
		p, e := PrepareTransfer(sender, candidates[:count], payments, options)
		if e == nil {
			return p, nil
		}
		last = e
	}
	return PreparedTransfer{}, last
}

// Notes returns a detached copy of the complete records selected for this plan.
func (p PreparedTransfer) Notes() []NoteV1 {
	out := make([]NoteV1, len(p.plans))
	for i, s := range p.plans {
		out[i] = s.Note
	}
	return out
}
