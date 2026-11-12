# HUC UTXO Model — Prototype 0.1

## Outputs

- Active certificate output: `<certificate_id>:0`
- Revocation output: `<certificate_id>:revocation`

## State transitions

1. **Issue** validates the certificate signature and creates one active output.
2. **Revoke** consumes the active output and creates a revocation output.
3. A consumed output is removed from the unspent set and cannot be consumed again.
4. Verification succeeds only when the referenced output is active, the signature is valid and the certificate is not expired.

## Invariants

- An output can be consumed at most once.
- Only a validly signed certificate can be issued.
- A certificate identifier cannot be issued twice to the same ledger instance.
- Revoked outputs are not valid certificate outputs.

## Not specified yet

Persistent storage, global uniqueness, transaction serialization, concurrent spends, consensus, network synchronization and portable proofs of state. This implementation is not a distributed UTXO network.
