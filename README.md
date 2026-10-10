# nockchain-go

Nockchain V1 wallet and transaction tools in Go. Derive receiving addresses,
review transactions, prepare payments, and sign single-key or multisig spends.
Use the same package natively or through its WebAssembly adapter.

[![Go checks](https://github.com/yapishu/nockchain-go/actions/workflows/ci.yml/badge.svg)](https://github.com/yapishu/nockchain-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/yapishu/nockchain-go.svg)](https://pkg.go.dev/github.com/yapishu/nockchain-go)

```sh
go get github.com/yapishu/nockchain-go@v0.1.0
```

Requires **Go 1.23+**. Import as `nockchain "github.com/yapishu/nockchain-go"`.

## Capabilities

| Area | API |
| --- | --- |
| Wallets and recovery | `GenerateWallet`, `RestoreWallet`, `Master`, `ParseExtendedKey` |
| Public receiving branches | `ParsePublicKey`, `DeriveReceiveAddress` |
| Exact native NOCK amounts | `ParseNocks`, `FormatNocks` |
| Coin selection and change | `SelectTransfer`, `PrepareTransfer` |
| Multisig and timelocks | `NewPKHLockV1`, `PrepareTransactionV1` |
| Transaction inspection | `ParseTransactionV1`, `Summary`, `ID` |
| Independent signing | `Sign`, `MergeSignatures`, `VerifySignatures` |
| Input records and height checks | `NoteV1.Hash`, `ValidateInputs` |
| Protocol primitives | Cheetah Schnorr, TIP5, immutable based nouns, `Jam`, `Cue` |
| JavaScript | [WebAssembly build, typed wrapper, and browser example](web/README.md) |

## Receive without a spending key

```go
// Reserve the index durably before giving its address to a payer.
receive, err := nockchain.DeriveReceiveAddress(zpub, 42)
if err != nil { return err }
// receive.Address is the wallet destination.
// receive.LockRoot is the indexed output lock.
```

Use a dedicated non-hardened public receiving branch. `ParsePublicKey` rejects
private extended keys; `key.Public()` removes private material. Derivation paths
are relative to the supplied key: `key.Derive("m/44'/0'/0'/9000")`. Store the branch
path and scan its allocated indices during recovery. A public extended key is
privacy-sensitive.

## Generate or recover a wallet

```go
key, recovery, err := nockchain.GenerateWallet("") // optional BIP39 passphrase
if err != nil { return err }
// Back up recovery.Words() privately before receiving funds. Never log it.
restored, err := nockchain.RestoreWallet(recovery.Words(), "")
if err != nil { return err }
_ = key
_ = restored
```

`GenerateWallet` creates a 24-word English mnemonic. Recovery accepts valid 12,
15, 18, 21, or 24-word phrases with BIP39 Unicode normalization. A wrong passphrase
produces a different valid wallet. `Zprv` explicitly exports spending authority;
`Zpub` exports a public branch. Diagnostic formatting redacts secrets.

For seed-based integrations, `GenerateSeed` creates 64 random bytes and `Master`
accepts an existing 64-byte seed. These seeds have no mnemonic unless derived
through `SeedFromMnemonic`; back them up as seed bytes or a zprv.

## Select coins, review, and sign

```go
// Each verifiedNote contains OriginPage, Name, complete NoteData, and Nicks.
notes := []nockchain.UnspentNote{{Note: verifiedNote, LockRoot: inputLock}}
plan, err := nockchain.SelectTransfer(key.Public(), notes,
    []nockchain.Payment{{Address: destination, Amount: "1.25"}},
    nockchain.TransferOptions{})
if err != nil { return err }
review := plan.Summary()
// Present review and obtain the wallet user's authorization before signing.
tx, err := plan.Sign(key)
if err != nil { return err }
wire, err := tx.Jam()
_ = review
_ = wire
```

`SelectTransfer` chooses a sufficient subset using largest amounts first with
stable note-name ordering. It ignores foreign locks and rejects malformed or
duplicate records. `PrepareTransfer` consumes all supplied notes. Both support
plain 1-of-1 PKH inputs, merge repeated recipients, estimate fees, and return
change to the sender unless `ChangeAddress` is set. `FeeNicks` selects an explicit
fee. With automatic fees, a remainder too small to cover change metadata becomes
part of the fee; the review shows the exact amount.

`1 NOCK = 65,536 nicks`. Decimal payment strings are exact; inexact values are
rejected. Reviews and selected `Notes()` are detached copies. Low-level
`SignTransferV1` accepts explicit per-input `SpendPlanV1` allocations.

**Supply the complete input record.** Output parent commitments include the
note's version, origin, name, all metadata, and value. `NoteFirstV1(lockRoot)`
computes its lock-bound first name component; it does not establish that the note
exists. Decode metadata with `Cue` from the chain's based-noun encoding. Empty
metadata is the zero `Noun` only when the stored record is actually empty.

## Multisig and timelocks

```go
minAge, maxHeight := uint64(10), uint64(500_000)
lock, err := nockchain.NewPKHLockV1(2, []nockchain.Digest{alicePKH, bobPKH, carolPKH},
    &nockchain.TimelockV1{
        Relative: nockchain.HeightRange{Min: &minAge},
        Absolute: nockchain.HeightRange{Max: &maxHeight},
    })
if err != nil { return err }
fee, err := nockchain.MinimumTransactionFeeV1(
    []nockchain.LockV1{lock}, []nockchain.LockV1{recipientLock})
if err != nil { return err }
plan, err := nockchain.PrepareTransactionV1([]nockchain.LockedSpendPlanV1{{
    Note: verifiedNote, Lock: lock, Fee: fee,
    Outputs: []nockchain.LockedPaymentV1{{Lock: recipientLock, Nicks: verifiedNote.Nicks-fee}},
}})
if err != nil { return err }
// Alice and Bob independently review the same plan.
a, err := plan.Sign(aliceKey)
if err != nil { return err }
b, err := plan.Sign(bobKey)
if err != nil { return err }
signed, err := a.MergeSignatures(b)
```

A lock supports up to 32 distinct keys and requires **exactly m signatures**.
Extra signatures are rejected. Height bounds are inclusive; nil endpoints are
unbounded. Relative bounds measure height minus the input's origin page.
Signing does not assert that a timelock is satisfied. `ValidateInputs` checks it
against the caller's authenticated records and chain height.

Partial signatures can travel as jam bytes and be parsed independently. Each
signature changes the transaction ID. Merging requires identical notes, locks,
outputs, and fees; conflicting signatures and altered plans are rejected.
See the [executable multisig example](transaction_example_test.go).

## Inspect and validate explicitly

```go
tx, err := nockchain.ParseTransactionV1(wire)
if err != nil { return err }
review, err := tx.Summary()
if err != nil { return err }
if err := tx.VerifySignatures(); err != nil { return err }
if err := tx.ValidateInputs(verifiedNotes, chainHeight); err != nil { return err }
_ = review
```

These operations establish different facts:

| Operation | Checks |
| --- | --- |
| `ParseTransactionV1` | Supported V1 structure, canonical trees, key encoding, lock proofs, and embedded ID |
| `Summary` | Committed outputs, fees, signature hashes, present signers, and fee estimate |
| `OutputV1.Lock` | Output lock metadata matches its committed root |
| `VerifySignatures` | Every signature, key authorization, exact required count, and minimum fee |
| `ValidateInputs` | Supplied input records, full parent hashes, balances, origin heights, and timelocks |

The application establishes input existence, unspent status, canonical chain,
and finality. The library neither fetches chain state nor broadcasts payments.

## Scope and limits

Transactions use full axis-1 PKH proofs, optionally followed by a conjunctive
timelock, and ordinary output seeds. Other proof forms, hashlocks, burn locks,
source-constrained outputs, and bridge construction return unsupported errors.
Input and output metadata is preserved as immutable based nouns; the builder
creates full lock metadata for its outputs.

Every input requires a nonzero output seed. Limits are 64 inputs, 256 total
output seeds, 32 keys per lock, 64 entries per metadata map, 2,048 flattened
metadata words per output lock, 65,536 logical transaction nodes, and depth 256.
These limits apply together.
Noun atoms must be below the Goldilocks prime. `Jam`/`Cue` are bounded based-noun
codecs, not arbitrary-precision Nock atom containers.

Fee sizing follows the canonical Hoon engine's current mainnet V1 schedule:
flattened metadata entries are merged per output lock, witnesses include exactly
the required signatures, and conflicting values for one metadata key are rejected. Applications must track network rule changes.
Base ERC-20 NOCK has **16 decimal places**; its units differ from native nicks.

Private-key arithmetic is **variable-time**. Use offline, trusted signing tools,
not remotely exposed signing services. No independent cryptographic audit is
claimed. See [SECURITY.md](SECURITY.md).

## Build and verify

```sh
go test -race ./...
go vet ./...
go test -run '^$' -fuzz FuzzParseTransactionV1 -fuzztime 10s -parallel 2
./scripts/build-wasm.sh
node web/test.mjs
```

CI checks Go 1.23 and the current stable toolchain, parser fuzz smoke tests, and
compiled WebAssembly. Public fixtures contain 35 wallet vectors, 105 signatures,
13 TIP5 word vectors, seven noun encodings, four single-key transactions, and two
2-of-3 transactions with partial signatures and optional timelocks. Tests compare
complete Rust bytes, IDs, signatures and lock roots. A separate Hoon oracle
checks the same transactions against the canonical engine for validity, input
commitments and minimum fees.

The protocol source of truth is the pinned Nockchain Hoon implementation. Rust
wallet fixtures provide an additional wire-format interoperability check.

Reference sources:

- [zorp-corp/nockchain](https://github.com/zorp-corp/nockchain/tree/1eac02083a053c104b6a1299e80a8a51447017dc),
  `1eac02083a053c104b6a1299e80a8a51447017dc`: `hoon/common/tx-engine.hoon`,
  `tx-engine-1.hoon`, `ztd/three.hoon` and `slip10.hoon` define fees, note
  commitments, spend validation, lock semantics and cryptography.

- [SWPSCO/tx-types](https://github.com/SWPSCO/tx-types/tree/5f9ab2b38f1685a908f19a0e8f18e7845b3e7f35),
  `5f9ab2b38f1685a908f19a0e8f18e7845b3e7f35`: Cheetah, TIP5, note commitments,
  canonical noun trees and codecs.
- [SWPSCO/nockster](https://github.com/SWPSCO/nockster/tree/d62110560dd005827ae8a46126c9841c86db0d6a),
  `d62110560dd005827ae8a46126c9841c86db0d6a`: wallet addresses, V1 signing,
  transaction IDs and multisig signing.
- [Trezor BIP39 vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json):
  24 English entropy, mnemonic and seed fixtures.

```sh
python3 testdata/reference-generator/generate.py /path/to/tx-types /path/to/nockster
python3 testdata/consensus-generator/generate.py /path/to/nockchain
# Optional private wallet-export check; the file stays outside version control:
NOCKCHAIN_TEST_KEY=/private/path/test.key go test -run TestLocalWalletExport
```

Regenerating the consensus fixture requires Nockchain’s `hoon` executable.
Normal tests use checked-in fixtures and need no Hoon/Rust toolchain or network.
**Never send funds to public test-vector addresses.**

MIT licensed. See [LICENSE](LICENSE).
