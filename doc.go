// Package nockchain implements Nockchain V1 wallet keys, TIP5 hashing, based noun
// codecs, transaction inspection, full PKH multisig/timelock locks, and signing.
//
// Receiving services use a dedicated public extended key with ParsePublicKey and
// DeriveReceiveAddress. Wallets use SelectTransfer or PrepareTransfer for plain
// single-key payments, or PrepareTransactionV1 for explicit multisig plans.
// TransactionV1 supports immutable partial signing and signature merging.
//
// ParseTransactionV1 checks supported wire structure and its embedded ID.
// VerifySignatures checks authorization, exact signature counts and fees.
// ValidateInputs checks supplied note records, parent commitments, balances and
// timelocks. Applications authenticate those records and determine finality.
//
// Native NOCK amounts use 65,536 nicks per NOCK. ParseNocks and FormatNocks use
// exact decimal strings. Nouns contain only Goldilocks field-valued atoms.
//
// Private-key operations use variable-time arithmetic and belong in offline,
// trusted tooling. The package does not fetch chain state or broadcast payments.
package nockchain
