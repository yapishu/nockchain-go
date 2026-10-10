# Security

## Intended use

Online services accept a **dedicated V1 public extended key** through
`ParsePublicKey`, derive non-hardened children, and keep spending keys offline.
That parser rejects private extended keys, invalid checksums, unsupported
versions, noncanonical coordinates, points outside the curve's prime-order
subgroup, and inconsistent master metadata. Parsing is length-bounded.

Private key generation, derivation, and signing use variable-time arithmetic, including
`math/big` and scalar-dependent branches. They are for offline wallet tools and
tests. They are not constant-time primitives and must not be exposed as a
remote signing or key-derivation service.

`Zprv`, `RecoveryPhrase.Words`, and `Seed.Bytes` deliberately export secrets. Treat their results, seed input, and every
copy of a private key as spending authority. String formatting redacts key
material, but callers remain responsible for storage, logging, backups, and
access control. Go's allocator and garbage collector do not provide a guarantee
that all copies of secret material are erased.

A public extended key is privacy-sensitive. Sharing a non-hardened child private
key together with its parent extended public key can expose the parent private
key. Never export individual receiving private keys to untrusted parties.

Address allocation, recovery paths, payment attribution, canonical-chain checks,
confirmation policy, and transaction replay protection belong to the integrating
application. A syntactically valid address or lock root does not establish
ownership of a payment or its finality.

Transaction construction supports full V1 PKH locks with exactly m-of-n
signatures and optional conjunctive timelocks. It checks complete note parent
commitments, declared balances, recipient amounts and fees. Parsing checks
supported structure and the embedded transaction ID; signature and input-state
checks are explicit separate methods. The caller authenticates input note
records, unspent status and finality against trusted chain state.

The supported transaction subset excludes other Merkle proof forms, hashlocks,
burn locks and source-constrained outputs. Metadata is bounded and immutable;
output metadata only authenticates a recipient policy when its computed lock
matches the committed root. This package does not provide full consensus
validation, transaction submission or bridge construction.

WebAssembly uses the same cryptographic implementation and retains its timing
and memory limitations. The JavaScript adapter represents uint64 amounts and
heights as strings to avoid precision loss. Use a trusted execution environment
for signing; a Worker isolates execution but does not make hostile page code safe.

The test corpus checks the canonical Nockchain Hoon engine and interoperability
with pinned Rust wallet implementations. It is not a substitute for an independent cryptographic audit.

## Reporting

Report suspected vulnerabilities privately to the repository owner through
GitHub's private vulnerability reporting when available, or an established
private contact. Do not include real seeds, private extended keys, API tokens,
or identifying wallet data in an issue or reproduction.
