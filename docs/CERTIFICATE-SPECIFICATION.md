# HUC Certificate Specification — 0.1

## Encoding

UTF-8 JSON, sorted keys, compact separators and Unicode preserved.

## Fields

| Field | Meaning |
|---|---|
| schema | Format identifier: `huc-certificate/0.1` |
| issuer | Base64-encoded raw Ed25519 public key |
| subject | Subject reference; use test identifiers in this prototype |
| claims | JSON object containing asserted attributes |
| issued_at | UTC ISO-8601 issue time |
| expires_at | Optional UTC ISO-8601 expiry |
| certificate_id | SHA-256 of canonical unsigned payload |
| signature | Base64 Ed25519 signature over canonical unsigned payload |

## Verification

Reconstruct the unsigned payload, recompute the identifier and verify the Ed25519 signature. Expiry and ledger state are additional checks.

This is an experimental format, not a finalized interoperability standard. Schema evolution, claim vocabularies, issuer identifiers, key rotation and privacy rules remain open.
