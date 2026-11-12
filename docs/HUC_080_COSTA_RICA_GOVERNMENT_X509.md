# HUC 0.8.0 — Costa Rica Government X.509 Complementary Adapter

## Objective
Integrate externally issued Costa Rican government X.509 certificates as existing identity/signature credentials. HUC does not issue, replace, renew or revoke those certificates. HUC creates a separate, signed, single-use authorization bound to the DER SHA-256 fingerprint of the existing certificate and consumes its UTXO exactly once.

## Implemented in this branch
- External X.509 leaf + intermediate chain validation against explicitly supplied trust roots.
- Certificate validity, issuer signatures, end-entity BasicConstraints and digitalSignature KeyUsage checks.
- Certificate-bound authorization signed by the matching holder private key (RSA-PSS, ECDSA or EdDSA).
- SQLite atomic consume-once registry using BEGIN IMMEDIATE and unique outpoints.
- Synthetic test-only certificate chain. No government certificate, private key, personal data or national trust anchor is committed.

## Important limitations
This first adapter is a bounded chain validator, not a complete RFC 5280 path-building/policy implementation. It does not fetch or validate CRL/OCSP, AIA, name constraints, certificate policies or national trust-list updates. Its output explicitly says revocation_status=NOT_CHECKED and production_ready=false. A production relying party must fail closed until an approved CRL/OCSP integration returns a sufficiently fresh status. A single SQLite database gives atomicity on one host; it is not four-institution distributed consensus.

## Local Linux test
```bash
python -m pip install -r requirements.txt
python -m unittest tests.test_huc_x509_external -v
```

## Government-certificate test procedure
Use only a public test certificate or a test certificate explicitly supplied for this purpose by the competent certification authority. Keep private keys in a smart card, HSM or approved cryptographic device. Export only the public leaf certificate and required intermediate certificates. Obtain root certificates and their SHA-256 fingerprints independently from official MICITT/BCCR channels. Never commit live certificates tied to real people, private keys, PINs, production trust anchors or personal data.

The adapter test fixture is synthetic and does not establish legal validity, national hierarchy compatibility or institutional approval.
