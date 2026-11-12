# Python SDK — LAEV HUC Direct

Install from this folder:

```bash
python -m pip install .
# Optional enterprise HTTP adapter
python -m pip install '.[api]'
```

Basic SDK use:

```python
from pathlib import Path
from huc_direct import HucIssuer, HucVerifier, HucPresenter, generate_csr

issuer, trust_pin = HucIssuer.initialize("./issuer-workspace", issuer_id="ACME-ISSUER")
csr_path, holder_private_key = generate_csr("Alex Example", "./holder")
credential = issuer.issue(csr_path.read_bytes(), days=365)

verifier = HucVerifier(trust_pin)
result = verifier.verify_bundle(credential.bundle)
assert result["result"] == "VALID"

challenge = verifier.create_challenge(credential.certificate_sha256, "hr.acme.example")
response = HucPresenter.create_response(challenge, credential.bundle, holder_private_key)
proof = verifier.verify_response(response, challenge, "hr.acme.example", "./replay-store.json")
assert proof["holder_proof_of_possession"]
```

The holder private key is generated and retained locally. The issuer receives only the CSR public request. The credential ZIP contains public certificates, public keys, trust metadata and signed state; never the subject's private key.

See `../docs/API_INTEGRATION.md` and `../docs/SECURITY.md` before exposing an API.

Refresh a credential's current signed state (for example after `INDETERMINATE` or after renewal/revocation):

```python
attestation, refreshed_bundle = issuer.refresh_bundle(certificate_pem)
```

The refreshed package may contain `ACTIVE`, `SUPERSEDED` or `REVOKED` status according to the issuer's current UTXO ledger.
