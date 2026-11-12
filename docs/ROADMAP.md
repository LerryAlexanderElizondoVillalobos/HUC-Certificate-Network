# HUC Roadmap

## Milestone 0 — Reference prototype
- [x] Ed25519 certificate signatures
- [x] Deterministic certificate identifiers
- [x] In-memory UTXO-inspired state
- [x] Revocation by consuming active output
- [x] Unit tests and GitHub Actions

## Milestone 1 — Protocol hardening
- [ ] Formal transaction and output schemas
- [ ] Strict input validation and size limits
- [ ] Issuer identity and key rotation model
- [ ] Signed revocation records and status proofs
- [ ] Property-based and adversarial tests

## Milestone 2 — Durable infrastructure
- [ ] Transactional persistent storage
- [ ] Atomic double-spend prevention under concurrency
- [ ] Append-only audit history
- [ ] Recovery and backup specification

## Milestone 3 — Interoperability
- [ ] Versioned public API
- [ ] Portable certificate and proof formats
- [ ] HUC Direct SDK
- [ ] Android and enterprise integration examples

## Milestone 4 — Network research
- [ ] Peer communication requirements
- [ ] Deterministic validation rules
- [ ] Consensus/finality decision, if a multi-operator network is required
- [ ] Independent security and performance assessment

A milestone is complete only after tests pass and acceptance criteria are documented.
