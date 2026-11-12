# Security Notes

- Keep issuer private keys secret. No production key vault is provided.
- Never commit private keys, credentials, real personal data or production certificates.
- A valid Ed25519 signature does not prove issuer legitimacy.
- Copying a certificate is possible; authoritative state verification requires access to the same trusted ledger state.
- The in-memory ledger is not durable, distributed or resistant to process compromise.
- Expiry timestamps must include a timezone; invalid timestamps fail closed.
- Production use requires threat modeling, key lifecycle controls, durable atomic state transitions, auditability, backup/recovery and independent security review.
