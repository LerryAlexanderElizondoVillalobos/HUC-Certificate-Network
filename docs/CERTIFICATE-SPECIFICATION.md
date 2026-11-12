# HUC Certificate and Evidence Specification — 0.8.0

## Certificate layer: X.509

HUC uses X.509 for subject identity, public key, issuer, validity interval and CA signature. The holder's private key is generated and retained by the holder; the issuer receives a CSR, not the holder's private key.

## Authorization layer: HUC-CC

HUC-CC is a signed protocol attestation that binds certificate evidence, issuer policy and the relevant logical UTXO outpoint/state. It is not a blockchain block and is not itself a BFT vote. Validators independently validate X.509 and HUC-CC before accepting an applicable state transition.

## State layer: logical UTXO

ISSUE creates an active output. RENEW consumes/supersedes the previous active output and creates a successor output. REVOKE consumes the active output and records a revoked state. Sequence and head hashes bind the append-only state history.

## Replicated-state evidence

CommitCertificates, prepared evidence and view-change certificates prove that a state transition passed the configured validator quorum. They are separate from the X.509 CA signature and HUC-CC issuer signature.

## Verification requirements

A verifier must validate the X.509 chain and validity, certificate DER hash, HUC-CC canonical hash/signatures/binding, trust anchor, UTXO state evidence and freshness policy. For BFT-backed state, it must also validate commit and view history against the pinned network manifest.

## Interoperability status

HUC 0.8.0 is an experimental implementation-specific format. Canonical JSON conventions, schema evolution, claim vocabularies, portable status proofs and cross-language test vectors require further standardization.
