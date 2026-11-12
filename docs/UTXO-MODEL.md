# HUC Logical UTXO Model — 0.8.0

HUC uses a logical unspent-output state model for certificate lifecycle. It does not transfer currency and is not a blockchain.

## Lifecycle

- **ISSUE:** creates the first active certificate output.
- **RENEW:** consumes/supersedes the prior active output and creates a successor output linked to the prior outpoint.
- **REVOKE:** consumes the active output and records the revoked terminal state.

## State integrity

Each accepted transition is bound to a sequence and parent/head hash. In replicated mode, a transition is applied only after a valid CommitCertificate and local revalidation. State export/sync reconstructs and verifies committed history and rejects rollback or forks.

## Double-consumption and equivocation

The state machine rejects attempts to consume an already spent output. BFT validators persist votes and prepared locks to prevent conflicting signatures for the same consensus slot. Durable production storage must protect these records against rollback.

## Important distinction

A local standalone ledger and a replicated BFT ledger have different trust and freshness properties. Offline verification can only evaluate the signed state evidence available to it; it cannot discover a later revocation without updated evidence.
