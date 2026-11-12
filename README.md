# HUC Certificate Network

**HUC** is an experimental certificate infrastructure built around cryptographically signed attestations and a UTXO-inspired state model.

> **Status:** early prototype / research software. Not production-ready. No Bitcoin dependency and no external blockchain dependency.

## Project goals

- Issue digitally signed certificates.
- Verify issuer signatures and certificate integrity.
- Track certificate state as unspent outputs.
- Revoke a certificate by consuming its active output and creating a revocation output.
- Reject replay and double-consumption attempts.
- Run repeatable checks through GitHub Actions.

## Current prototype

The first milestone is a small Python reference implementation. It uses Ed25519 signatures through the `cryptography` package and an in-memory UTXO-style ledger. The ledger is a test model, not a distributed consensus network or durable production database.

## Quick start

Requires Python 3.12 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
ruff check src tests
```

## Repository structure

- `src/huc/`: certificate, cryptography and ledger primitives.
- `tests/`: automated unit tests.
- `docs/`: protocol decisions, security boundaries and roadmap.
- `.github/workflows/`: automated CI and dependency checks.

## Initial certificate lifecycle

1. An issuer creates an Ed25519 key pair.
2. HUC canonicalizes the certificate payload and signs it.
3. The certificate identifier is derived from the canonical payload.
4. Issuance creates an active certificate output in the ledger.
5. Verification checks the payload hash, issuer signature, expiry and active ledger state.
6. Revocation consumes the active output and creates a revocation output. A consumed output cannot be consumed again.

## Important limitations

- The ledger is process-local and loses state when the process exits.
- There is no peer-to-peer networking, consensus, persistence, identity registry or production key management.
- A signature proves control of a signing key, not legal authority or truth of the certificate claims.
- Revocation is meaningful only relative to the ledger state consulted by the verifier.
- Do not use real personal data, production credentials or valuable certificates in this prototype.

See [Architecture](docs/ARCHITECTURE.md), [UTXO model](docs/UTXO-MODEL.md), [certificate specification](docs/CERTIFICATE-SPECIFICATION.md), [security](docs/SECURITY.md) and [roadmap](docs/ROADMAP.md).

## License and commercial rights

No open-source license has been granted at this stage. All rights are reserved by the copyright holder. Reuse, redistribution and commercial use require separate permission unless a license or written agreement is added.
