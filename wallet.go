package nockchain

import (
	"bytes"
	"errors"
	"math/bits"
)

// ReceiveAddress identifies a non-hardened child of a public receiving branch.
// Address is the wallet destination; LockRoot is its indexed output lock.
type ReceiveAddress struct {
	Index             uint32
	Address, LockRoot string
}

// DeriveReceiveAddress validates a zpub and derives the requested receiving
// child. Reserve the index durably before handing its address to a payer.
func DeriveReceiveAddress(zpub string, index uint32) (ReceiveAddress, error) {
	k, e := ParsePublicKey(zpub)
	if e != nil {
		return ReceiveAddress{}, e
	}
	child, e := k.Child(index)
	if e != nil {
		return ReceiveAddress{}, e
	}
	a, e := child.Address()
	if e != nil {
		return ReceiveAddress{}, e
	}
	lock, e := child.LockAddress()
	if e != nil {
		return ReceiveAddress{}, e
	}
	return ReceiveAddress{index, a, lock}, nil
}

// UnspentNote describes an input from a trusted chain-state source. The library
// does not establish that it exists, is unspent, or has reached finality.
type UnspentNote struct {
	Note     NoteV1
	LockRoot Digest
}

// Payment is a wallet address and exact decimal NOCK amount, such as "1.25".
type Payment struct{ Address, Amount string }

// TransferOptions controls explicit change and fees. Empty ChangeAddress sends
// change to the sender. FeeNicks=0 selects the minimum fee for the resulting plan.
type TransferOptions struct {
	ChangeAddress string
	FeeNicks      uint64
}

// TransferSummary is a detached review of a prepared payment. Amounts are nicks.
type TransferSummary struct {
	InputCount                                      int
	InputNicks, PaymentNicks, FeeNicks, ChangeNicks uint64
	ChangeAddress                                   string
	Payments                                        []Payment
}

// PreparedTransfer is an immutable, unsigned payment plan ready for review.
type PreparedTransfer struct {
	plans   []SpendPlanV1
	summary TransferSummary
	public  []byte
}

// Summary returns a detached copy. Altering it cannot change the plan being signed.
func (p PreparedTransfer) Summary() TransferSummary {
	s := p.summary
	s.Payments = append([]Payment(nil), s.Payments...)
	return s
}

// Sign checks the signing key against the reviewed sender and signs the plan.
// Private-key arithmetic is variable-time; signing belongs in offline tooling.
func (p PreparedTransfer) Sign(key ExtendedKey) (TransferV1, error) {
	pub, e := key.PublicBytes()
	if e != nil || len(p.plans) == 0 || !bytes.Equal(pub, p.public) {
		return TransferV1{}, errors.New("signing key does not match prepared transfer")
	}
	return key.SignTransferV1(p.plans)
}

// PrepareTransfer consumes all supplied notes, pays the requested recipients,
// computes fees, and adds explicit change. It accepts a public-only sender so
// review can happen separately from signing. Supply notes controlled by that
// exact key and verify chain state before calling this function. SelectTransfer
// selects a sufficient subset when consuming every note is unnecessary.
func PrepareTransfer(sender ExtendedKey, notes []UnspentNote, payments []Payment, options TransferOptions) (PreparedTransfer, error) {
	if len(notes) < 1 || len(notes) > MaxTransferInputs || len(payments) < 1 || len(payments) > MaxTransferOutputs {
		return PreparedTransfer{}, errors.New("transfer size out of range")
	}
	public, e := sender.PublicBytes()
	if e != nil {
		return PreparedTransfer{}, e
	}
	address, _ := sender.Address()
	pkh, _ := ParseDigest(address)
	lock, _ := LockRoot(pkh)
	change := options.ChangeAddress
	if change == "" {
		change = address
	}
	changePKH, e := ParseDigest(change)
	if e != nil {
		return PreparedTransfer{}, errors.New("invalid change address")
	}
	summary := TransferSummary{InputCount: len(notes), ChangeAddress: change}
	names := map[NoteName]bool{}
	for _, n := range notes {
		if _, e := n.Note.Hash(); e != nil {
			return PreparedTransfer{}, e
		}
		bound, _ := NoteFirstV1(lock)
		if names[n.Note.Name] || n.Note.Name.First != bound || n.LockRoot != lock || n.Note.Nicks == 0 || n.Note.Nicks >= Prime {
			return PreparedTransfer{}, errors.New("duplicate, invalid, or unauthorized input")
		}
		names[n.Note.Name] = true
		sum, c := bits.Add64(summary.InputNicks, n.Note.Nicks, 0)
		if c != 0 {
			return PreparedTransfer{}, errors.New("input total overflow")
		}
		summary.InputNicks = sum
	}
	recipients := []Digest{}
	amounts := []uint64{}
	positions := map[Digest]int{}
	for _, p := range payments {
		recipient, e := ParseDigest(p.Address)
		if e != nil {
			return PreparedTransfer{}, errors.New("invalid payment address")
		}
		n, e := ParseNocks(p.Amount)
		if e != nil || n == 0 || n >= Prime {
			return PreparedTransfer{}, errors.New("invalid or inexact NOCK payment amount")
		}
		total, c := bits.Add64(summary.PaymentNicks, n, 0)
		if c != 0 {
			return PreparedTransfer{}, errors.New("payment total overflow")
		}
		summary.PaymentNicks = total
		if index, ok := positions[recipient]; ok {
			sum, c := bits.Add64(amounts[index], n, 0)
			if c != 0 {
				return PreparedTransfer{}, errors.New("recipient amount overflow")
			}
			amounts[index] = sum
		} else {
			positions[recipient] = len(recipients)
			recipients = append(recipients, recipient)
			amounts = append(amounts, n)
		}
		summary.Payments = append(summary.Payments, Payment{p.Address, FormatNocks(n)})
	}
	if summary.PaymentNicks >= summary.InputNicks {
		return PreparedTransfer{}, errors.New("insufficient funds for payment and fees")
	}
	available := summary.InputNicks - summary.PaymentNicks
	minimum, _ := MinimumTransferFeeV1(len(notes), recipients)
	fee := options.FeeNicks
	if fee == 0 {
		fee = minimum
		if available > fee {
			withChange := append([]Digest(nil), recipients...)
			if _, exists := positions[changePKH]; !exists {
				withChange = append(withChange, changePKH)
			}
			fee, e = MinimumTransferFeeV1(len(notes), withChange)
			if e == nil && fee > available && available >= minimum {
				fee = available
			}
			if e != nil {
				return PreparedTransfer{}, e
			}
		}
	}
	if fee > available {
		return PreparedTransfer{}, errors.New("insufficient funds for payment and fees")
	}
	changeNicks := available - fee
	if changeNicks > 0 {
		if index, ok := positions[changePKH]; ok {
			amounts[index] += changeNicks
		} else {
			recipients = append(recipients, changePKH)
			amounts = append(amounts, changeNicks)
		}
	}
	minimum, e = MinimumTransferFeeV1(len(notes), recipients)
	if e != nil {
		return PreparedTransfer{}, e
	}
	if fee < minimum {
		return PreparedTransfer{}, errors.New("fee below minimum")
	}
	summary.FeeNicks, summary.ChangeNicks = fee, changeNicks
	plans := make([]SpendPlanV1, 0, len(notes))
	remainingFee := fee
	output := 0
	outputCount := 0
	for _, note := range notes {
		inputFee := remainingFee
		if inputFee >= note.Note.Nicks {
			inputFee = note.Note.Nicks - 1
		}
		remainingFee -= inputFee
		plan := SpendPlanV1{Note: note.Note, LockRoot: note.LockRoot, Fee: inputFee}
		remaining := note.Note.Nicks - inputFee
		for remaining > 0 {
			if output >= len(amounts) {
				return PreparedTransfer{}, errors.New("input values cannot be allocated to the requested outputs")
			}
			value := amounts[output]
			if value > remaining {
				value = remaining
			}
			plan.Outputs = append(plan.Outputs, PaymentV1{recipients[output], value})
			outputCount++
			if outputCount > MaxTransferOutputs {
				return PreparedTransfer{}, errors.New("output count out of range")
			}
			remaining -= value
			amounts[output] -= value
			if amounts[output] == 0 {
				output++
			}
		}
		plans = append(plans, plan)
	}
	if remainingFee != 0 {
		return PreparedTransfer{}, errors.New("notes cannot cover the requested fee")
	}
	return PreparedTransfer{plans, summary, public}, nil
}
