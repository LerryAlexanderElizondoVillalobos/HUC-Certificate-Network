# HUC Certificate Network

Experimental certificate infrastructure using cryptographic signatures and a UTXO-inspired state model.

> Status: research prototype. Not production-ready. No Bitcoin dependency.

## First milestone

- Ed25519 signed certificates
- Deterministic certificate identifiers
- UTXO-inspired issue and revocation transitions
- Rejection of tampered signatures and double consumption
- Automated GitHub Actions checks

## Planned structure

`src/huc/` contains the reference implementation; `tests/` contains automated tests; `docs/` specifies architecture, certificate format, state model, security boundaries and roadmap; `.github/workflows/` runs CI.

## Important limitation

The initial ledger is an in-memory reference model, not a distributed network, durable database or consensus protocol. It is intended for tests and protocol development only.

## License

No open-source license has been granted. All rights reserved unless a license or separate permission is provided.
