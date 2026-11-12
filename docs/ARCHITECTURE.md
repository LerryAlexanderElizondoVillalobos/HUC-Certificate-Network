# HUC Architecture — Prototype 0.1

## Components

- **Issuer:** owns an Ed25519 private key and signs certificate payloads.
- **Certificate:** canonical JSON claims, issuer public key, timestamps, identifier and signature.
- **Verifier:** validates identifier, signature, expiry and ledger state.
- **UTXO-inspired ledger:** tracks unspent certificate outputs and state transitions.
- **Automation:** GitHub Actions runs tests, lint and dependency audits.

## Trust boundaries

A valid signature proves that the holder of a particular private key signed the payload. It does not prove issuer authorization, factual truth of claims or uncompromised key custody. Those require governance, identity and key lifecycle controls not implemented here.

## Prototype boundary

The ledger is in-memory and single-process. It demonstrates state transitions only. A future network must separately specify persistence, deterministic validation, consensus/finality, conflict handling, availability and recovery.
